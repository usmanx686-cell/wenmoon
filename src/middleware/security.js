const securityConfig = require('../config/security');
const SecurityLog = require('../models/SecurityLog');
const logger = require('../utils/logger');

/**
 * Detect bots based on user agent and behavior
 */
const detectBot = (req, res, next) => {
    if (!securityConfig.BOT_DETECTION.ENABLED) {
        return next();
    }

    const userAgent = req.useragent?.source || '';
    const isBot = isBotUserAgent(userAgent);

    if (isBot) {
        logger.warn(`Bot detected: ${userAgent.substring(0, 100)}`);
        
        // Log the bot attempt
        SecurityLog.create({
            type: 'bot_detected',
            ipAddress: req.ip,
            userAgent,
            severity: 'medium',
            details: { userAgent }
        }).catch(err => logger.error('Failed to log bot detection:', err));

        return res.status(403).json({
            status: 'error',
            message: 'Bot activity detected. Please use a standard web browser.',
            code: 'BOT_DETECTED'
        });
    }

    // Add bot detection flag to request
    req.isBot = isBot;
    next();
};

/**
 * Check for suspicious patterns in request
 */
const validateRequest = (req, res, next) => {
    const suspiciousPatterns = securityConfig.BOT_DETECTION.SUSPICIOUS_PATTERNS;
    const userAgent = (req.useragent?.source || '').toLowerCase();
    
    // Check for suspicious patterns in user agent
    for (const pattern of suspiciousPatterns) {
        if (userAgent.includes(pattern)) {
            logger.warn(`Suspicious pattern detected: ${pattern} in user agent`);
            
            SecurityLog.create({
                type: 'suspicious_pattern',
                ipAddress: req.ip,
                userAgent,
                severity: 'high',
                details: { pattern, userAgent }
            }).catch(err => logger.error('Failed to log suspicious pattern:', err));

            return res.status(403).json({
                status: 'error',
                message: 'Suspicious activity detected.',
                code: 'SUSPICIOUS_ACTIVITY'
            });
        }
    }

    // Check for missing or malformed headers
    if (!req.headers['user-agent'] || req.headers['user-agent'].length < 10) {
        return res.status(400).json({
            status: 'error',
            message: 'Invalid request headers.',
            code: 'INVALID_HEADERS'
        });
    }

    // Check for too many headers (DDoS indicator)
    if (Object.keys(req.headers).length > 50) {
        return res.status(400).json({
            status: 'error',
            message: 'Request contains too many headers.',
            code: 'TOO_MANY_HEADERS'
        });
    }

    next();
};

/**
 * Check if user agent belongs to a known bot
 */
function isBotUserAgent(userAgent) {
    if (!userAgent) return false;
    
    const botUserAgents = securityConfig.BOT_DETECTION.BOT_USER_AGENTS;
    const ua = userAgent.toLowerCase();
    
    return botUserAgents.some(botUA => ua.includes(botUA.toLowerCase()));
}

/**
 * Generate device fingerprint
 */
const generateDeviceFingerprint = (req) => {
    const fingerprint = {
        userAgent: req.headers['user-agent'],
        accept: req.headers['accept'],
        acceptEncoding: req.headers['accept-encoding'],
        acceptLanguage: req.headers['accept-language'],
        screenResolution: req.headers['screen-resolution'],
        timezone: req.headers['timezone'],
        platform: req.headers['platform']
    };
    
    return Buffer.from(JSON.stringify(fingerprint)).toString('base64');
};

/**
 * Check for headless browser
 */
const checkHeadlessBrowser = (req) => {
    const tests = {
        hasChrome: req.headers['user-agent']?.includes('Chrome') || false,
        hasPlugins: req.headers['sec-ch-ua'] ? true : false,
        hasLanguages: req.headers['accept-language'] ? true : false,
        hasWebDriver: req.headers['webdriver'] === 'true' ? true : false,
        hasPermissions: req.headers['permissions'] ? true : false
    };
    
    // Headless browsers often miss some of these headers
    const score = Object.values(tests).filter(Boolean).length;
    return score < 3;
};

module.exports = {
    detectBot,
    validateRequest,
    generateDeviceFingerprint,
    checkHeadlessBrowser
};
