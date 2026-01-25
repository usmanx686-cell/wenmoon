
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { User, IPAddress, Session, ActivityLog } = require('../models');
const EmailService = require('../services/emailService');
const IPService = require('../services/ipService');
const logger = require('../utils/logger');
const validator = require('../utils/validators');

class AuthController {
  // Generate JWT token
  generateToken(userId) {
    return jwt.sign(
      { userId },
      process.env.JWT_SECRET,
      { expiresIn: process.env.JWT_EXPIRE || '7d' }
    );
  }

  // Generate refresh token
  generateRefreshToken(userId) {
    return jwt.sign(
      { userId, type: 'refresh' },
      process.env.JWT_REFRESH_SECRET,
      { expiresIn: process.env.JWT_REFRESH_EXPIRE || '30d' }
    );
  }

  // User registration
  async register(req, res) {
    try {
      const { email, password, username, referral_code } = req.body;
      const ip = req.clientIp;
      
      // Validate input
      if (!validator.isEmail(email)) {
        return res.status(400).json({
          success: false,
          message: 'Invalid email format'
        });
      }

      if (!validator.isStrongPassword(password)) {
        return res.status(400).json({
          success: false,
          message: 'Password must be at least 8 characters with uppercase, lowercase, number and special character'
        });
      }

      // Check IP limit
      const ipCheck = await IPService.checkIPLimit(ip);
      if (!ipCheck.allowed) {
        return res.status(403).json({
          success: false,
          message: ipCheck.reason,
          ipInfo: ipCheck
        });
      }

      // Check if user exists
      const existingUser = await User.findOne({ where: { email } });
      if (existingUser) {
        return res.status(400).json({
          success: false,
          message: 'User already exists'
        });
      }

      // Handle referral
      let referrer = null;
      if (referral_code) {
        referrer = await User.findOne({ where: { referral_code } });
        if (!referrer) {
          return res.status(400).json({
            success: false,
            message: 'Invalid referral code'
          });
        }
      }

      // Create user
      const user = await User.create({
        email,
        username: username || email.split('@')[0],
        password_hash: password,
        ip_address: ip,
        referred_by: referrer ? referrer.referral_code : null
      });

      // Update IP count
      await IPService.incrementIPCount(ip);

      // Create session
      const token = this.generateToken(user.id);
      const refreshToken = this.generateRefreshToken(user.id);

      // Save session
      await Session.create({
        user_id: user.id,
        session_token: crypto.randomBytes(32).toString('hex'),
        ip_address: ip,
        user_agent: req.headers['user-agent'],
        expires_at: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000) // 7 days
      });

      // Log activity
      await ActivityLog.create({
        user_id: user.id,
        action: 'register',
        details: { ip, user_agent: req.headers['user-agent'] },
        ip_address: ip
      });

      // Send verification email
      await EmailService.sendVerificationEmail(user.email, user.id);

      // Award referral points if applicable
      if (referrer) {
        await this.handleReferral(referrer.id, user.id);
      }

      // Award signup bonus
      await user.update({
        moon_points: 50,
        total_points_earned: 50
      });

      res.status(201).json({
        success: true,
        message: 'Registration successful',
        data: {
          user: user.toJSON(),
          token,
          refreshToken,
          ipInfo: ipCheck
        }
      });

    } catch (error) {
      logger.error('Registration error:', error);
      res.status(500).json({
        success: false,
        message: 'Registration failed',
        error: process.env.NODE_ENV === 'development' ? error.message : undefined
      });
    }
  }

  // User login
  async login(req, res) {
    try {
      const { email, password, captcha } = req.body;
      const ip = req.clientIp;

      // Check brute force
      const bruteForceCheck = await IPService.checkBruteForce(ip, email);
      if (bruteForceCheck.blocked) {
        return res.status(429).json({
          success: false,
          message: 'Too many failed attempts. Try again later.'
        });
      }

      // Find user
      const user = await User.findOne({ where: { email } });
      if (!user) {
        await IPService.logFailedAttempt(ip, email);
        return res.status(401).json({
          success: false,
          message: 'Invalid credentials'
        });
      }

      // Check password
      const isPasswordValid = await user.comparePassword(password);
      if (!isPasswordValid) {
        await IPService.logFailedAttempt(ip, email);
        return res.status(401).json({
          success: false,
          message: 'Invalid credentials'
        });
      }

      // Check if user is active
      if (!user.is_active) {
        return res.status(403).json({
          success: false,
          message: 'Account is disabled'
        });
      }

      // Update last login
      await user.update({ last_login: new Date() });

      // Create session
      const token = this.generateToken(user.id);
      const refreshToken = this.generateRefreshToken(user.id);

      await Session.create({
        user_id: user.id,
        session_token: crypto.randomBytes(32).toString('hex'),
        ip_address: ip,
        user_agent: req.headers['user-agent'],
        expires_at: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000)
      });

      // Log activity
      await ActivityLog.create({
        user_id: user.id,
        action: 'login',
        details: { ip, user_agent: req.headers['user-agent'] },
        ip_address: ip
      });

      // Award daily login bonus
      await this.awardDailyLoginBonus(user.id);

      res.json({
        success: true,
        message: 'Login successful',
        data: {
          user: user.toJSON(),
          token,
          refreshToken
        }
      });

    } catch (error) {
      logger.error('Login error:', error);
      res.status(500).json({
        success: false,
        message: 'Login failed'
      });
    }
  }

  // Social login (Google/Telegram)
  async socialLogin(req, res) {
    try {
      const { provider, token, email, name } = req.body;
      const ip = req.clientIp;

      // Validate provider
      if (!['google', 'telegram'].includes(provider)) {
        return res.status(400).json({
          success: false,
          message: 'Invalid provider'
        });
      }

      // Check IP limit
      const ipCheck = await IPService.checkIPLimit(ip);
      if (!ipCheck.allowed) {
        return res.status(403).json({
          success: false,
          message: ipCheck.reason,
          ipInfo: ipCheck
        });
      }

      // Find or create user
      const userField = `${provider}_id`;
      let user = await User.findOne({ where: { [userField]: token } });

      if (!user && email) {
        user = await User.findOne({ where: { email } });
      }

      if (!user) {
        // Create new user
        user = await User.create({
          email: email || `${token}@${provider}.com`,
          username: name || `user_${Date.now()}`,
          password_hash: crypto.randomBytes(16).toString('hex'),
          [userField]: token,
          ip_address: ip
        });

        // Update IP count
        await IPService.incrementIPCount(ip);

        // Award signup bonus
        const bonus = provider === 'telegram' ? 30 : 25;
        await user.update({
          moon_points: bonus,
          total_points_earned: bonus
        });
      }

      // Update IP address
      await user.update({ ip_address: ip, last_login: new Date() });

      // Generate tokens
      const authToken = this.generateToken(user.id);
      const refreshToken = this.generateRefreshToken(user.id);

      // Create session
      await Session.create({
        user_id: user.id,
        session_token: crypto.randomBytes(32).toString('hex'),
        ip_address: ip,
        user_agent: req.headers['user-agent'],
        expires_at: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000)
      });

      // Log activity
      await ActivityLog.create({
        user_id: user.id,
        action: `social_login_${provider}`,
        details: { ip, user_agent: req.headers['user-agent'] },
        ip_address: ip
      });

      res.json({
        success: true,
        message: 'Social login successful',
        data: {
          user: user.toJSON(),
          token: authToken,
          refreshToken,
          ipInfo: ipCheck
        }
      });

    } catch (error) {
      logger.error('Social login error:', error);
      res.status(500).json({
        success: false,
        message: 'Social login failed'
      });
    }
  }

  // Logout
  async logout(req, res) {
    try {
      const token = req.headers.authorization?.split(' ')[1];
      
      if (token) {
        // Invalidate session
        await Session.destroy({
          where: {
            session_token: token
          }
        });

        // Log activity
        await ActivityLog.create({
          user_id: req.user.id,
          action: 'logout',
          ip_address: req.clientIp
        });
      }

      res.json({
        success: true,
        message: 'Logged out successfully'
      });
    } catch (error) {
      logger.error('Logout error:', error);
      res.status(500).json({
        success: false,
        message: 'Logout failed'
      });
    }
  }

  // Refresh token
  async refreshToken(req, res) {
    try {
      const { refreshToken } = req.body;

      if (!refreshToken) {
        return res.status(400).json({
          success: false,
          message: 'Refresh token required'
        });
      }

      // Verify refresh token
      const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
      
      if (decoded.type !== 'refresh') {
        return res.status(401).json({
          success: false,
          message: 'Invalid token type'
        });
      }

      // Check if user exists
      const user = await User.findByPk(decoded.userId);
      if (!user || !user.is_active) {
        return res.status(401).json({
          success: false,
          message: 'User not found or inactive'
        });
      }

      // Generate new tokens
      const newToken = this.generateToken(user.id);
      const newRefreshToken = this.generateRefreshToken(user.id);

      res.json({
        success: true,
        data: {
          token: newToken,
          refreshToken: newRefreshToken
        }
      });

    } catch (error) {
      logger.error('Refresh token error:', error);
      res.status(401).json({
        success: false,
        message: 'Invalid refresh token'
      });
    }
  }

  // Verify email
  async verifyEmail(req, res) {
    try {
      const { token } = req.params;
      
      // Decode token (simple implementation)
      const userId = Buffer.from(token, 'base64').toString('ascii');
      
      const user = await User.findByPk(userId);
      if (!user) {
        return res.status(400).json({
          success: false,
          message: 'Invalid verification token'
        });
      }

      if (user.email_verified) {
        return res.status(400).json({
          success: false,
          message: 'Email already verified'
        });
      }

      // Update user
      await user.update({
        email_verified: true,
        moon_points: user.moon_points + 25, // Verification bonus
        total_points_earned: user.total_points_earned + 25
      });

      // Log activity
      await ActivityLog.create({
        user_id: user.id,
        action: 'email_verified',
        ip_address: req.clientIp
      });

      res.json({
        success: true,
        message: 'Email verified successfully. You earned 25 Moon Points!'
      });

    } catch (error) {
      logger.error('Email verification error:', error);
      res.status(500).json({
        success: false,
        message: 'Email verification failed'
      });
    }
  }

  // Helper methods
  async handleReferral(referrerId, referredId) {
    try {
      const referrer = await User.findByPk(referrerId);
      const referred = await User.findByPk(referredId);

      if (referrer && referred) {
        // Award points to referrer
        await referrer.update({
          moon_points: referrer.moon_points + 100,
          total_points_earned: referrer.total_points_earned + 100
        });

        // Create referral record
        await ActivityLog.create({
          user_id: referrer.id,
          action: 'referral_award',
          details: { referred_user_id: referred.id, points: 100 }
        });

        await ActivityLog.create({
          user_id: referred.id,
          action: 'referred_by',
          details: { referrer_id: referrer.id }
        });
      }
    } catch (error) {
      logger.error('Referral handling error:', error);
    }
  }

  async awardDailyLoginBonus(userId) {
    try {
      const user = await User.findByPk(userId);
      const today = new Date().toDateString();
      const lastLogin = user.last_login ? new Date(user.last_login).toDateString() : null;

      if (lastLogin !== today) {
        await user.update({
          moon_points: user.moon_points + 5,
          total_points_earned: user.total_points_earned + 5
        });

        await ActivityLog.create({
          user_id: userId,
          action: 'daily_login_bonus',
          details: { points: 5 }
        });
      }
    } catch (error) {
      logger.error('Daily bonus error:', error);
    }
  }
}

module.exports = new AuthController();
