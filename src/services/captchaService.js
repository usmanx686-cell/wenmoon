const axios = require('axios');
const logger = require('../utils/logger');
const securityConfig = require('../config/security');

class CaptchaService {
    constructor() {
        this.provider = securityConfig.CAPTCHA.PROVIDER;
        this.enabled = securityConfig.CAPTCHA.ENABLED;
        
        // Provider configurations
        this.providers = {
            hcaptcha: {
                verifyUrl: 'https://hcaptcha.com/siteverify',
                secret: securityConfig.CAPTCHA.HCAPTCHA_SECRET
            },
            recaptcha: {
                verifyUrl: 'https://www.google.com/recaptcha/api/siteverify',
                secret: securityConfig.CAPTCHA.RECAPTCHA_SECRET
            }
        };
    }
    
    /**
     * Verify CAPTCHA token
     */
    async verify(token, remoteip = null) {
        // Skip if CAPTCHA is disabled
        if (!this.enabled) {
            return { success: true, score: 1.0, bypassed: true };
        }
        
        // Check if token is provided
        if (!token) {
            logger.warn('CAPTCHA token missing');
            return { 
                success: false, 
                error: 'CAPTCHA token required',
                score: 0.0
            };
        }
        
        try {
            const provider = this.providers[this.provider];
            if (!provider || !provider.secret) {
                logger.error(`CAPTCHA provider not configured: ${this.provider}`);
                return { success: false, error: 'CAPTCHA service not configured' };
            }
            
            // Verify with provider
            const response = await axios.post(provider.verifyUrl, null, {
                params: {
                    secret: provider.secret,
                    response: token,
                    remoteip: remoteip
                },
                timeout: 5000 // 5 second timeout
            });
            
            const result = response.data;
            
            // Log CAPTCHA verification
            logger.debug('CAPTCHA verification result', {
                provider: this.provider,
                success: result.success,
                score: result.score || null,
                hostname: result.hostname,
                remoteip
            });
            
            // Check if verification was successful
            if (!result.success) {
                logger.warn('CAPTCHA verification failed', {
                    provider: this.provider,
                    errorCodes: result['error-codes'] || [],
                    remoteip
                });
                
                return {
                    success: false,
                    error: 'CAPTCHA verification failed',
                    errorCodes: result['error-codes'] || [],
                    score: result.score || 0.0
                };
            }
            
            // For reCAPTCHA v3, check score threshold
            if (result.score !== undefined) {
                const minScore = securityConfig.CAPTCHA.MIN_SCORE;
                if (result.score < minScore) {
                    logger.warn('CAPTCHA score too low', {
                        provider: this.provider,
                        score: result.score,
                        minScore,
                        remoteip
                    });
                    
                    return {
                        success: false,
                        error: 'CAPTCHA score too low',
                        score: result.score,
                        minScore
                    };
                }
            }
            
            // For hCaptcha, check hostname if in production
            if (result.hostname && process.env.NODE_ENV === 'production') {
                const expectedHostname = new URL(process.env.FRONTEND_URL).hostname;
                if (result.hostname !== expectedHostname) {
                    logger.warn('CAPTCHA hostname mismatch', {
                        provider: this.provider,
                        hostname: result.hostname,
                        expectedHostname,
                        remoteip
                    });
                    
                    return {
                        success: false,
                        error: 'CAPTCHA hostname mismatch',
                        hostname: result.hostname,
                        expectedHostname
                    };
                }
            }
            
            return {
                success: true,
                score: result.score || 1.0,
                hostname: result.hostname,
                challengeTs: result.challenge_ts,
                action: result.action
            };
            
        } catch (error) {
            logger.error('CAPTCHA verification error:', error);
            
            // In production, fail closed (reject if CAPTCHA service is down)
            // In development, you might want to fail open for testing
            if (process.env.NODE_ENV === 'production') {
                return {
                    success: false,
                    error: 'CAPTCHA service unavailable',
                    score: 0.0
                };
            } else {
                // In development, allow bypass for testing
                logger.warn('CAPTCHA service error, bypassing for development');
                return { 
                    success: true, 
                    score: 1.0, 
                    bypassed: true,
                    warning: 'CAPTCHA bypassed due to service error'
                };
            }
        }
    }
    
    /**
     * Check if CAPTCHA is required for a specific action
     */
    isRequiredFor(action) {
        if (!this.enabled) return false;
        
        const requiredFor = securityConfig.CAPTCHA.REQUIRED_FOR || [];
        return requiredFor.includes(action);
    }
    
    /**
     * Generate CAPTCHA configuration for frontend
     */
    getFrontendConfig() {
        if (!this.enabled) {
            return { enabled: false };
        }
        
        const config = {
            enabled: true,
            provider: this.provider,
            siteKey: this.provider === 'hcaptcha' 
                ? securityConfig.CAPTCHA.HCAPTCHA_SITE_KEY
                : securityConfig.CAPTCHA.RECAPTCHA_SITE_KEY,
            theme: 'dark',
            size: 'normal'
        };
        
        return config;
    }
    
    /**
     * Batch verify multiple tokens (for rate limiting)
     */
    async batchVerify(tokensWithIPs) {
        const results = [];
        
        for (const { token, remoteip } of tokensWithIPs) {
            const result = await this.verify(token, remoteip);
            results.push({
                token,
                remoteip,
                ...result
            });
        }
        
        return results;
    }
    
    /**
     * Get CAPTCHA statistics
     */
    async getStats(days = 7) {
        // This would typically query your database for CAPTCHA verification logs
        // For now, return mock stats
        
        return {
            totalVerifications: 0,
            successRate: 0,
            averageScore: 0,
            byProvider: {}
        };
    }
}

module.exports = new CaptchaService();
