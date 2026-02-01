const jwt = require('jsonwebtoken');
const User = require('../models/User');
const logger = require('../utils/logger');
const securityConfig = require('../config/security');

/**
 * JWT Authentication Middleware
 * Verifies JWT token and attaches user to request
 */
const authenticate = async (req, res, next) => {
    try {
        // Get token from header
        const authHeader = req.headers.authorization;
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({
                status: 'error',
                message: 'Authentication token required',
                code: 'TOKEN_REQUIRED'
            });
        }

        const token = authHeader.split(' ')[1];
        
        // Verify token
        const decoded = jwt.verify(token, securityConfig.APP_SECURITY.JWT_SECRET);
        
        // Find user
        const user = await User.findById(decoded.id)
            .select('-password -twoFactorSecret -verificationToken');
        
        if (!user) {
            return res.status(401).json({
                status: 'error',
                message: 'User not found',
                code: 'USER_NOT_FOUND'
            });
        }

        // Check if user is active
        if (user.status !== 'active') {
            let message = 'Account is suspended';
            if (user.status === 'suspended') {
                message = `Account suspended: ${user.suspensionReason}`;
                if (user.suspensionExpires) {
                    message += ` until ${user.suspensionExpires.toISOString()}`;
                }
            } else if (user.status === 'banned') {
                message = 'Account has been banned';
            } else if (user.status === 'deleted') {
                message = 'Account has been deleted';
            }
            
            return res.status(403).json({
                status: 'error',
                message,
                code: 'ACCOUNT_INACTIVE'
            });
        }

        // Check if user is suspicious (requires manual review)
        if (user.isSuspicious && user.restrictions.includes('manual_review')) {
            return res.status(403).json({
                status: 'error',
                message: 'Account requires manual review',
                code: 'ACCOUNT_UNDER_REVIEW'
            });
        }

        // Update last activity
        user.lastActivity = new Date();
        await user.save();

        // Attach user to request
        req.user = user;
        req.userId = user._id;

        next();
    } catch (error) {
        if (error.name === 'JsonWebTokenError') {
            return res.status(401).json({
                status: 'error',
                message: 'Invalid token',
                code: 'INVALID_TOKEN'
            });
        } else if (error.name === 'TokenExpiredError') {
            return res.status(401).json({
                status: 'error',
                message: 'Token expired',
                code: 'TOKEN_EXPIRED'
            });
        }
        
        logger.error('Authentication error:', error);
        res.status(500).json({
            status: 'error',
            message: 'Authentication failed',
            code: 'AUTH_FAILED'
        });
    }
};

/**
 * Optional authentication middleware
 * Attaches user if token is valid, but doesn't require it
 */
const authenticateOptional = async (req, res, next) => {
    try {
        const authHeader = req.headers.authorization;
        
        if (authHeader && authHeader.startsWith('Bearer ')) {
            const token = authHeader.split(' ')[1];
            
            try {
                const decoded = jwt.verify(token, securityConfig.APP_SECURITY.JWT_SECRET);
                const user = await User.findById(decoded.id)
                    .select('-password -twoFactorSecret -verificationToken');
                
                if (user && user.status === 'active') {
                    req.user = user;
                    req.userId = user._id;
                    
                    // Update last activity
                    user.lastActivity = new Date();
                    await user.save();
                }
            } catch (error) {
                // Token is invalid, but that's OK for optional auth
                // We'll just continue without user
            }
        }
        
        next();
    } catch (error) {
        logger.error('Optional authentication error:', error);
        next();
    }
};

/**
 * Role-based authorization middleware
 */
const authorize = (...roles) => {
    return (req, res, next) => {
        if (!req.user) {
            return res.status(401).json({
                status: 'error',
                message: 'Authentication required',
                code: 'AUTH_REQUIRED'
            });
        }

        // Check if user has required role
        // You can implement roles in your User model
        // For now, we'll check for admin flag in metadata
        const isAdmin = req.user.metadata && req.user.metadata.get('isAdmin') === true;
        
        if (roles.includes('admin') && !isAdmin) {
            return res.status(403).json({
                status: 'error',
                message: 'Admin access required',
                code: 'ADMIN_REQUIRED'
            });
        }

        next();
    };
};

/**
 * Generate JWT token
 */
const generateToken = (userId, expiresIn = null) => {
    const options = {
        expiresIn: expiresIn || securityConfig.APP_SECURITY.JWT_EXPIRES_IN
    };
    
    return jwt.sign(
        { id: userId },
        securityConfig.APP_SECURITY.JWT_SECRET,
        options
    );
};

/**
 * Refresh token middleware
 */
const refreshToken = async (req, res) => {
    try {
        const { refreshToken } = req.body;
        
        if (!refreshToken) {
            return res.status(400).json({
                status: 'error',
                message: 'Refresh token required',
                code: 'REFRESH_TOKEN_REQUIRED'
            });
        }

        // Verify refresh token (you might want to use a different secret for refresh tokens)
        const decoded = jwt.verify(refreshToken, securityConfig.APP_SECURITY.JWT_SECRET);
        
        // Find user
        const user = await User.findById(decoded.id);
        if (!user || user.status !== 'active') {
            return res.status(401).json({
                status: 'error',
                message: 'Invalid refresh token',
                code: 'INVALID_REFRESH_TOKEN'
            });
        }

        // Generate new access token
        const newToken = generateToken(user._id);
        
        res.status(200).json({
            status: 'success',
            data: {
                token: newToken,
                expiresIn: securityConfig.APP_SECURITY.JWT_EXPIRES_IN
            }
        });
    } catch (error) {
        if (error.name === 'JsonWebTokenError') {
            return res.status(401).json({
                status: 'error',
                message: 'Invalid refresh token',
                code: 'INVALID_REFRESH_TOKEN'
            });
        } else if (error.name === 'TokenExpiredError') {
            return res.status(401).json({
                status: 'error',
                message: 'Refresh token expired',
                code: 'REFRESH_TOKEN_EXPIRED'
            });
        }
        
        logger.error('Refresh token error:', error);
        res.status(500).json({
            status: 'error',
            message: 'Failed to refresh token',
            code: 'REFRESH_FAILED'
        });
    }
};

module.exports = {
    authenticate,
    authenticateOptional,
    authorize,
    generateToken,
    refreshToken
};
