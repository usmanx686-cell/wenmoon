const express = require('express');
const router = express.Router();
const authController = require('../controllers/authController');
const { validate } = require('../middleware/validation');
const { requireCaptcha } = require('../middleware/security');
const ipLimitMiddleware = require('../middleware/ipLimit');

// Apply IP logging to all auth routes
router.use(ipLimitMiddleware.logIPActivity);

// Signup with email
router.post('/signup', 
    requireCaptcha,
    validate('signup'),
    authController.signup
);

// Social signup/login
router.post('/social',
    requireCaptcha,
    validate('socialAuth'),
    authController.socialAuth
);

// Email login
router.post('/login',
    validate('login'),
    authController.login
);

// Logout
router.post('/logout',
    authController.logout
);

// Get current user
router.get('/me',
    authController.getMe
);

// Refresh token
router.post('/refresh',
    authController.refreshToken
);

// Forgot password
router.post('/forgot-password',
    requireCaptcha,
    validate('forgotPassword'),
    authController.forgotPassword
);

// Reset password
router.post('/reset-password',
    validate('resetPassword'),
    authController.resetPassword
);

// Verify email
router.get('/verify-email/:token',
    authController.verifyEmail
);

// Resend verification email
router.post('/resend-verification',
    requireCaptcha,
    authController.resendVerification
);

module.exports = router;
