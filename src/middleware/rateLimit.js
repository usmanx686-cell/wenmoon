const rateLimit = require('express-rate-limit');
const slowDown = require('express-slow-down');
const RedisStore = require('rate-limit-redis');
const Redis = require('ioredis');
const logger = require('../utils/logger');

// Create Redis client for distributed rate limiting
const redisClient = new Redis(process.env.REDIS_URL || 'redis://localhost:6379');

// Generic rate limiter
const genericLimiter = rateLimit({
    store: new RedisStore({
        client: redisClient,
        prefix: 'rl:'
    }),
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // Limit each IP to 100 requests per windowMs
    message: {
        status: 'error',
        message: 'Too many requests from this IP, please try again later.',
        code: 'RATE_LIMIT_EXCEEDED'
    },
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: (req) => {
        return req.clientIP || req.ip;
    }
});

// Authentication rate limiter (stricter)
const authLimiter = rateLimit({
    store: new RedisStore({
        client: redisClient,
        prefix: 'rl:auth:'
    }),
    windowMs: 60 * 60 * 1000, // 1 hour
    max: 5, // 5 attempts per hour per IP
    message: {
        status: 'error',
        message: 'Too many authentication attempts from this IP, please try again later.',
        code: 'AUTH_RATE_LIMIT'
    },
    skipSuccessfulRequests: true // Don't count successful logins
});

// Signup rate limiter (very strict)
const signupLimiter = rateLimit({
    store: new RedisStore({
        client: redisClient,
        prefix: 'rl:signup:'
    }),
    windowMs: 24 * 60 * 60 * 1000, // 24 hours
    max: 3, // Only 3 signups per day per IP
    message: {
        status: 'error',
        message: 'Maximum daily signup limit reached for this network.',
        code: 'SIGNUP_LIMIT_EXCEEDED'
    }
});

// Task completion rate limiter
const taskLimiter = rateLimit({
    store: new RedisStore({
        client: redisClient,
        prefix: 'rl:tasks:'
    }),
    windowMs: 5 * 60 * 1000, // 5 minutes
    max: 10, // 10 task completions per 5 minutes
    message: {
        status: 'error',
        message: 'Too many task completions, please slow down.',
        code: 'TASK_RATE_LIMIT'
    }
});

// API key rate limiter (for future use)
const apiKeyLimiter = rateLimit({
    store: new RedisStore({
        client: redisClient,
        prefix: 'rl:apikey:'
    }),
    windowMs: 60 * 60 * 1000, // 1 hour
    max: 1000, // 1000 requests per hour per API key
    keyGenerator: (req) => {
        return req.headers['x-api-key'] || req.ip;
    },
    message: {
        status: 'error',
        message: 'API rate limit exceeded.',
        code: 'API_RATE_LIMIT'
    }
});

// Slow down for suspicious activity
const slowDownMiddleware = slowDown({
    windowMs: 15 * 60 * 1000, // 15 minutes
    delayAfter: 50, // Start delaying after 50 requests
    delayMs: (used, req) => {
        // Increase delay based on risk score
        const riskScore = req.riskScore || 0;
        const baseDelay = 100;
        const riskMultiplier = 1 + (riskScore / 100);
        return baseDelay * riskMultiplier;
    }
});

module.exports = {
    genericLimiter,
    authLimiter,
    signupLimiter,
    taskLimiter,
    apiKeyLimiter,
    slowDownMiddleware
};
