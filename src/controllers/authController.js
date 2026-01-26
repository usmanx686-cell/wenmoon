const User = require('../models/User');
const IPLog = require('../models/IPLog');
const SecurityLog = require('../models/SecurityLog');
const jwt = require('jsonwebtoken');
const logger = require('../utils/logger');
const { generateDeviceFingerprint, checkHeadlessBrowser } = require('../middleware/security');
const { validateSignup, validateLogin } = require('../utils/validators');
const fraudDetection = require('../services/fraudDetection');
const captchaService = require('../services/captchaService');

// Generate JWT token
const generateToken = (userId) => {
    return jwt.sign(
        { id: userId },
        process.env.JWT_SECRET,
        { expiresIn: process.env.JWT_EXPIRES_IN || '7d' }
    );
};

// Signup controller
const signup = async (req, res) => {
    try {
        const { email, password, name, captchaToken } = req.body;
        
        // Validate input
        const validation = validateSignup({ email, password, name });
        if (!validation.valid) {
            return res.status(400).json({
                status: 'error',
                message: validation.errors[0]
            });
        }

        // Verify CAPTCHA
        if (process.env.CAPTCHA_ENABLED === 'true') {
            const captchaValid = await captchaService.verify(captchaToken, req.ip);
            if (!captchaValid) {
                return res.status(400).json({
                    status: 'error',
                    message: 'CAPTCHA verification failed'
                });
            }
        }

        // Check if user already exists
        const existingUser = await User.findOne({
            $or: [
                { email: email.toLowerCase() },
                { name: { $regex: new RegExp(`^${name}$`, 'i') } }
            ]
        });

        if (existingUser) {
            return res.status(400).json({
                status: 'error',
                message: 'User with this email or username already exists'
            });
        }

        // Generate device fingerprint
        const deviceFingerprint = generateDeviceFingerprint(req);
        
        // Check for headless browser
        const isHeadless = checkHeadlessBrowser(req);
        if (isHeadless) {
            await SecurityLog.create({
                type: 'headless_browser',
                ipAddress: req.clientIP,
                userAgent: req.useragent?.source,
                severity: 'high',
                details: { email }
            });
            
            return res.status(403).json({
                status: 'error',
                message: 'Automated browsers are not allowed'
            });
        }

        // Run fraud detection
        const fraudScore = await fraudDetection.analyzeSignup({
            ip: req.clientIP,
            email,
            name,
            userAgent: req.useragent?.source,
            deviceFingerprint
        });

        // Create user with risk score
        const user = await User.create({
            email: email.toLowerCase(),
            password,
            name,
            deviceFingerprint,
            riskScore: fraudScore.totalScore,
            isSuspicious: fraudScore.totalScore > 50,
            flags: fraudScore.flags
        });

        // Update IP history
        await User.findByIdAndUpdate(user._id, {
            $push: {
                ipHistory: {
                    ip: req.clientIP,
                    firstSeen: new Date(),
                    lastSeen: new Date(),
                    count: 1
                }
            }
        });

        // Log IP activity
        await IPLog.create({
            ipAddress: req.clientIP,
            userId: user._id,
            action: 'signup',
            userAgent: req.useragent?.source,
            riskScore: fraudScore.totalScore,
            isBlocked: false
        });

        // Generate token
        const token = generateToken(user._id);

        // Remove sensitive data
        user.password = undefined;

        logger.info(`New user signed up: ${user.email} from IP: ${req.clientIP}`);

        res.status(201).json({
            status: 'success',
            data: {
                user,
                token,
                moonPoints: user.moonPoints
            }
        });

    } catch (error) {
        logger.error('Signup error:', error);
        res.status(500).json({
            status: 'error',
            message: 'An error occurred during signup'
        });
    }
};

// Social signup/login controller
const socialAuth = async (req, res) => {
    try {
        const { provider, token, name, email } = req.body;
        
        // Validate provider
        if (!['google', 'telegram'].includes(provider)) {
            return res.status(400).json({
                status: 'error',
                message: 'Invalid authentication provider'
            });
        }

        // In production, validate the OAuth token here
        // For demo, we'll trust the token
        
        // Check if user exists
        const query = provider === 'google' 
            ? { googleId: token }
            : { telegramId: token };
            
        let user = await User.findOne(query);

        if (user) {
            // Update last login
            user.lastLogin = new Date();
            await user.save();
            
            // Log IP activity for login
            await IPLog.create({
                ipAddress: req.clientIP,
                userId: user._id,
                action: 'login',
                userAgent: req.useragent?.source,
                riskScore: user.riskScore || 0
            });
        } else {
            // Create new user
            const deviceFingerprint = generateDeviceFingerprint(req);
            
            // Run fraud detection
            const fraudScore = await fraudDetection.analyzeSignup({
                ip: req.clientIP,
                email,
                name,
                userAgent: req.useragent?.source,
                deviceFingerprint,
                provider
            });

            user = await User.create({
                [provider === 'google' ? 'googleId' : 'telegramId']: token,
                email: email?.toLowerCase(),
                name,
                deviceFingerprint,
                riskScore: fraudScore.totalScore,
                isSuspicious: fraudScore.totalScore > 50,
                flags: fraudScore.flags
            });

            // Give bonus points for social signup
            const bonusPoints = provider === 'telegram' ? 30 : 25;
            user.moonPoints += bonusPoints;
            await user.save();

            // Log IP activity for signup
            await IPLog.create({
                ipAddress: req.clientIP,
                userId: user._id,
                action: 'signup',
                userAgent: req.useragent?.source,
                riskScore: fraudScore.totalScore
            });

            logger.info(`Social signup: ${provider} - ${user.name} from IP: ${req.clientIP}`);
        }

        // Generate token
        const authToken = generateToken(user._id);

        // Remove sensitive data
        user.password = undefined;

        res.status(200).json({
            status: 'success',
            data: {
                user,
                token: authToken,
                moonPoints: user.moonPoints,
                bonusPoints: !user.lastLogin ? (provider === 'telegram' ? 30 : 25) : 0
            }
        });

    } catch (error) {
        logger.error('Social auth error:', error);
        res.status(500).json({
            status: 'error',
            message: 'An error occurred during authentication'
        });
    }
};

// Login controller
const login = async (req, res) => {
    try {
        const { email, password } = req.body;
        
        // Validate input
        const validation = validateLogin({ email, password });
        if (!validation.valid) {
            return res.status(400).json({
                status: 'error',
                message: validation.errors[0]
            });
        }

        // Find user with password
        const user = await User.findOne({ email: email.toLowerCase() })
            .select('+password +loginAttempts +lockUntil');
        
        if (!user) {
            return res.status(401).json({
                status: 'error',
                message: 'Invalid email or password'
            });
        }

        // Check if account is locked
        if (user.isLocked()) {
            return res.status(423).json({
                status: 'error',
                message: 'Account is temporarily locked. Please try again later.',
                lockUntil: user.lockUntil
            });
        }

        // Check password
        const isPasswordValid = await user.comparePassword(password);
        
        if (!isPasswordValid) {
            // Increment login attempts
            await user.incLoginAttempts();
            
            return res.status(401).json({
                status: 'error',
                message: 'Invalid email or password',
                remainingAttempts: 5 - (user.loginAttempts + 1)
            });
        }

        // Reset login attempts on successful login
        await user.updateOne({
            loginAttempts: 0,
            lockUntil: undefined,
            lastLogin: new Date()
        });

        // Generate device fingerprint
        const deviceFingerprint = generateDeviceFingerprint(req);
        
        // Check for device change
        if (user.deviceFingerprint && user.deviceFingerprint !== deviceFingerprint) {
            await SecurityLog.create({
                type: 'device_change',
                userId: user._id,
                ipAddress: req.clientIP,
                severity: 'medium',
                details: {
                    oldDevice: user.deviceFingerprint,
                    newDevice: deviceFingerprint
                }
            });
        }

        // Update IP history
        const ipHistory = user.ipHistory.find(ip => ip.ip === req.clientIP);
        if (ipHistory) {
            ipHistory.lastSeen = new Date();
            ipHistory.count += 1;
        } else {
            user.ipHistory.push({
                ip: req.clientIP,
                firstSeen: new Date(),
                lastSeen: new Date(),
                count: 1
            });
        }
        
        await user.save();

        // Log IP activity
        await IPLog.create({
            ipAddress: req.clientIP,
            userId: user._id,
            action: 'login',
            userAgent: req.useragent?.source
        });

        // Generate token
        const token = generateToken(user._id);

        // Remove sensitive data
        user.password = undefined;
        user.loginAttempts = undefined;
        user.lockUntil = undefined;

        logger.info(`User logged in: ${user.email} from IP: ${req.clientIP}`);

        res.status(200).json({
            status: 'success',
            data: {
                user,
                token,
                moonPoints: user.moonPoints
            }
        });

    } catch (error) {
        logger.error('Login error:', error);
        res.status(500).json({
            status: 'error',
            message: 'An error occurred during login'
        });
    }
};

// Logout controller
const logout = async (req, res) => {
    try {
        // In JWT, we can't invalidate token without a token blacklist
        // For now, we'll just clear the client-side token
        
        // You could implement a token blacklist here
        
        res.status(200).json({
            status: 'success',
            message: 'Logged out successfully'
        });
    } catch (error) {
        logger.error('Logout error:', error);
        res.status(500).json({
            status: 'error',
            message: 'An error occurred during logout'
        });
    }
};

// Get current user
const getMe = async (req, res) => {
    try {
        const user = await User.findById(req.userId);
        
        if (!user) {
            return res.status(404).json({
                status: 'error',
                message: 'User not found'
            });
        }

        res.status(200).json({
            status: 'success',
            data: {
                user,
                moonPoints: user.moonPoints
            }
        });
    } catch (error) {
        logger.error('Get user error:', error);
        res.status(500).json({
            status: 'error',
            message: 'An error occurred'
        });
    }
};

module.exports = {
    signup,
    socialAuth,
    login,
    logout,
    getMe
};
