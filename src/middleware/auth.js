const jwt = require('jsonwebtoken');
const { User, Session } = require('../models');
const logger = require('../utils/logger');

const auth = {
  // Verify JWT token
  verifyToken: async (req, res, next) => {
    try {
      const token = req.headers.authorization?.split(' ')[1];
      
      if (!token) {
        return res.status(401).json({
          success: false,
          message: 'Access token required'
        });
      }

      // Verify token
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      
      // Check session
      const session = await Session.findOne({
        where: {
          user_id: decoded.userId,
          expires_at: { [Op.gt]: new Date() }
        }
      });

      if (!session) {
        return res.status(401).json({
          success: false,
          message: 'Session expired'
        });
      }

      // Get user
      const user = await User.findByPk(decoded.userId);
      
      if (!user || !user.is_active) {
        return res.status(401).json({
          success: false,
          message: 'User not found or inactive'
        });
      }

      // Attach user to request
      req.user = user;
      req.userId = user.id;
      next();

    } catch (error) {
      logger.error('Token verification error:', error);
      
      if (error.name === 'JsonWebTokenError') {
        return res.status(401).json({
          success: false,
          message: 'Invalid token'
        });
      }
      
      if (error.name === 'TokenExpiredError') {
        return res.status(401).json({
          success: false,
          message: 'Token expired'
        });
      }

      res.status(500).json({
        success: false,
        message: 'Authentication failed'
      });
    }
  },

  // Check if user is admin
  isAdmin: (req, res, next) => {
    if (!req.user || !req.user.is_admin) {
      return res.status(403).json({
        success: false,
        message: 'Admin access required'
      });
    }
    next();
  },

  // Rate limiting per user
  userRateLimit: (maxRequests = 100, windowMinutes = 15) => {
    const rateLimit = require('express-rate-limit');
    
    return rateLimit({
      windowMs: windowMinutes * 60 * 1000,
      max: maxRequests,
      keyGenerator: (req) => req.userId || req.ip,
      message: {
        success: false,
        message: `Too many requests from this user. Please try again after ${windowMinutes} minutes.`
      }
    });
  }
};

module.exports = auth;
