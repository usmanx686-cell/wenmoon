const nodemailer = require('nodemailer');
const logger = require('../utils/logger');
const crypto = require('crypto');

class EmailService {
    constructor() {
        this.enabled = process.env.EMAIL_ENABLED === 'true';
        this.fromEmail = process.env.EMAIL_FROM || 'noreply@wenmoon.com';
        this.fromName = process.env.EMAIL_FROM_NAME || 'WENMOON Team';
        
        // Create transporter
        if (this.enabled) {
            this.transporter = nodemailer.createTransport({
                host: process.env.SMTP_HOST,
                port: parseInt(process.env.SMTP_PORT || '587'),
                secure: process.env.SMTP_SECURE === 'true',
                auth: {
                    user: process.env.SMTP_USER,
                    pass: process.env.SMTP_PASS
                },
                // Additional options for better deliverability
                pool: true,
                maxConnections: 5,
                maxMessages: 100
            });
            
            // Verify connection
            this.verifyConnection();
        }
    }
    
    /**
     * Verify SMTP connection
     */
    async verifyConnection() {
        if (!this.enabled || !this.transporter) {
            logger.warn('Email service is disabled');
            return false;
        }
        
        try {
            await this.transporter.verify();
            logger.info('SMTP connection verified successfully');
            return true;
        } catch (error) {
            logger.error('SMTP connection failed:', error);
            return false;
        }
    }
    
    /**
     * Send email
     */
    async sendEmail(to, subject, html, text = null) {
        if (!this.enabled) {
            logger.warn('Email service disabled, skipping send to:', to);
            return { sent: false, error: 'Email service disabled' };
        }
        
        try {
            const mailOptions = {
                from: `"${this.fromName}" <${this.fromEmail}>`,
                to,
                subject,
                html,
                text: text || this.htmlToText(html),
                // Headers for better deliverability
                headers: {
                    'X-Priority': '3',
                    'X-Mailer': 'WENMOON Airdrop Platform'
                }
            };
            
            const info = await this.transporter.sendMail(mailOptions);
            
            logger.info('Email sent successfully', {
                to,
                subject,
                messageId: info.messageId
            });
            
            return { 
                sent: true, 
                messageId: info.messageId,
                response: info.response 
            };
            
        } catch (error) {
            logger.error('Failed to send email:', error);
            return { 
                sent: false, 
                error: error.message,
                stack: error.stack 
            };
        }
    }
    
    /**
     * Send welcome email
     */
    async sendWelcomeEmail(user) {
        const subject = 'Welcome to WENMOON Airdrop!';
        const html = `
            <!DOCTYPE html>
            <html>
            <head>
                <style>
                    body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
                    .container { max-width: 600px; margin: 0 auto; padding: 20px; }
                    .header { background: linear-gradient(135deg, #7c3aed 0%, #06b6d4 100%); color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; }
                    .content { background: #f9f9f9; padding: 30px; border-radius: 0 0 10px 10px; }
                    .button { display: inline-block; background: #7c3aed; color: white; padding: 12px 24px; text-decoration: none; border-radius: 5px; font-weight: bold; }
                    .points { background: #fff3cd; border: 1px solid #ffc107; padding: 15px; border-radius: 5px; margin: 20px 0; }
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header">
                        <h1>🚀 Welcome to WENMOON!</h1>
                        <p>Your journey to earning WEN tokens begins now</p>
                    </div>
                    <div class="content">
                        <h2>Hello ${user.name}!</h2>
                        <p>Welcome to the WENMOON airdrop platform. We're excited to have you join our community!</p>
                        
                        <div class="points">
                            <h3>🎉 You've earned 50 bonus Moon Points!</h3>
                            <p>For signing up, you've received <strong>50 Moon Points</strong>. Complete tasks to earn more!</p>
                        </div>
                        
                        <h3>What's next?</h3>
                        <ol>
                            <li><strong>Complete tasks</strong> to earn Moon Points</li>
                            <li><strong>Connect your wallet</strong> to receive tokens at TGE</li>
                            <li><strong>Invite friends</strong> with your referral link to earn bonus points</li>
                        </ol>
                        
                        <p>
                            <a href="${process.env.FRONTEND_URL}/tasks" class="button">Start Earning Points</a>
                        </p>
                        
                        <h3>Your Referral Code</h3>
                        <p>Share this code with friends: <strong>${user.referralCode}</strong></p>
                        <p>Or use this link: ${process.env.FRONTEND_URL}/ref/${user.referralCode}</p>
                        
                        <hr>
                        
                        <p><small>If you didn't create an account with WENMOON, please ignore this email.</small></p>
                    </div>
                </div>
            </body>
            </html>
        `;
        
        return this.sendEmail(user.email, subject, html);
    }
    
    /**
     * Send verification email
     */
    async sendVerificationEmail(user, verificationToken) {
        const verificationUrl = `${process.env.FRONTEND_URL}/verify-email/${verificationToken}`;
        const subject = 'Verify your WENMOON account';
        const html = `
            <!DOCTYPE html>
            <html>
            <head>
                <style>
                    body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
                    .container { max-width: 600px; margin: 0 auto; padding: 20px; }
                    .header { background: linear-gradient(135deg, #7c3aed 0%, #06b6d4 100%); color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; }
                    .content { background: #f9f9f9; padding: 30px; border-radius: 0 0 10px 10px; }
                    .button { display: inline-block; background: #7c3aed; color: white; padding: 12px 24px; text-decoration: none; border-radius: 5px; font-weight: bold; }
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header">
                        <h1>🔐 Verify Your Email</h1>
                        <p>WENMOON Airdrop Platform</p>
                    </div>
                    <div class="content">
                        <h2>Hello ${user.name}!</h2>
                        <p>Please verify your email address to complete your WENMOON account setup.</p>
                        
                        <p>
                            <a href="${verificationUrl}" class="button">Verify Email Address</a>
                        </p>
                        
                        <p>Or copy and paste this link in your browser:</p>
                        <p><code>${verificationUrl}</code></p>
                        
                        <p><strong>This link will expire in 24 hours.</strong></p>
                        
                        <hr>
                        
                        <p>If you didn't create an account with WENMOON, please ignore this email.</p>
                    </div>
                </div>
            </body>
            </html>
        `;
        
        return this.sendEmail(user.email, subject, html);
    }
    
    /**
     * Send password reset email
     */
    async sendPasswordResetEmail(user, resetToken) {
        const resetUrl = `${process.env.FRONTEND_URL}/reset-password/${resetToken}`;
        const subject = 'Reset your WENMOON password';
        const html = `
            <!DOCTYPE html>
            <html>
            <head>
                <style>
                    body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
                    .container { max-width: 600px; margin: 0 auto; padding: 20px; }
                    .header { background: linear-gradient(135deg, #7c3aed 0%, #06b6d4 100%); color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; }
                    .content { background: #f9f9f9; padding: 30px; border-radius: 0 0 10px 10px; }
                    .button { display: inline-block; background: #dc3545; color: white; padding: 12px 24px; text-decoration: none; border-radius: 5px; font-weight: bold; }
                    .warning { background: #fff3cd; border: 1px solid #ffc107; padding: 15px; border-radius: 5px; margin: 20px 0; }
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header">
                        <h1>🔑 Password Reset</h1>
                        <p>WENMOON Airdrop Platform</p>
                    </div>
                    <div class="content">
                        <h2>Hello ${user.name}!</h2>
                        <p>We received a request to reset your password for your WENMOON account.</p>
                        
                        <p>
                            <a href="${resetUrl}" class="button">Reset Password</a>
                        </p>
                        
                        <p>Or copy and paste this link in your browser:</p>
                        <p><code>${resetUrl}</code></p>
                        
                        <div class="warning">
                            <p><strong>⚠️ Security Notice:</strong></p>
                            <p>If you didn't request this password reset, please ignore this email.</p>
                            <p>This link will expire in 1 hour for security reasons.</p>
                        </div>
                        
                        <hr>
                        
                        <p>For security, this request was received from IP: ${user.lastLoginIP || 'Unknown'}</p>
                    </div>
                </div>
            </body>
            </html>
        `;
        
        return this.sendEmail(user.email, subject, html);
    }
    
    /**
     * Send task completion notification
     */
    async sendTaskCompletionEmail(user, task, pointsEarned) {
        const subject = `🎉 Task Completed: ${task.title}`;
        const html = `
            <!DOCTYPE html>
            <html>
            <head>
                <style>
                    body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
                    .container { max-width: 600px; margin: 0 auto; padding: 20px; }
                    .header { background: linear-gradient(135deg, #7c3aed 0%, #06b6d4 100%); color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; }
                    .content { background: #f9f9f9; padding: 30px; border-radius: 0 0 10px 10px; }
                    .points-badge { background: #fbbf24; color: #1f2937; padding: 10px 20px; border-radius: 20px; display: inline-block; font-weight: bold; font-size: 1.2em; }
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header">
                        <h1>🎯 Task Completed!</h1>
                        <p>WENMOON Airdrop Platform</p>
                    </div>
                    <div class="content">
                        <h2>Great job, ${user.name}!</h2>
                        <p>You've successfully completed the task: <strong>${task.title}</strong></p>
                        
                        <div style="text-align: center; margin: 30px 0;">
                            <div class="points-badge">
                                +${pointsEarned} Moon Points
                            </div>
                        </div>
                        
                        <h3>Your Progress</h3>
                        <ul>
                            <li><strong>Total Moon Points:</strong> ${user.moonPoints}</li>
                            <li><strong>Tasks Completed Today:</strong> ${user.tasksCompletedToday}/${user.dailyTaskLimit}</li>
                            <li><strong>Rank:</strong> ${user.rank || 'Calculating...'}</li>
                        </ul>
                        
                        <p>Keep completing tasks to increase your share of the 300M WEN token airdrop!</p>
                        
                        <p>
                            <a href="${process.env.FRONTEND_URL}/tasks" style="display: inline-block; background: #7c3aed; color: white; padding: 12px 24px; text-decoration: none; border-radius: 5px; font-weight: bold;">
                                Complete More Tasks
                            </a>
                        </p>
                        
                        <hr>
                        
                        <p><small>You're receiving this email because you completed a task on WENMOON. If this wasn't you, please contact support immediately.</small></p>
                    </div>
                </div>
            </body>
            </html>
        `;
        
        return this.sendEmail(user.email, subject, html);
    }
    
    /**
     * Send security alert
     */
    async sendSecurityAlert(user, alertType, details = {}) {
        const subject = `⚠️ Security Alert: ${alertType}`;
        const html = `
            <!DOCTYPE html>
            <html>
            <head>
                <style>
                    body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
                    .container { max-width: 600px; margin: 0 auto; padding: 20px; }
                    .header { background: linear-gradient(135deg, #ef4444 0%, #dc2626 100%); color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; }
                    .content { background: #f9f9f9; padding: 30px; border-radius: 0 0 10px 10px; }
                    .alert-box { background: #fee2e2; border: 1px solid #ef4444; padding: 20px; border-radius: 5px; margin: 20px 0; }
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header">
                        <h1>🚨 Security Alert</h1>
                        <p>WENMOON Airdrop Platform</p>
                    </div>
                    <div class="content">
                        <h2>Hello ${user.name},</h2>
                        
                        <div class="alert-box">
                            <h3>${this.getAlertTitle(alertType)}</h3>
                            <p>${this.getAlertDescription(alertType, details)}</p>
                        </div>
                        
                        <h3>Details:</h3>
                        <ul>
                            <li><strong>Time:</strong> ${new Date().toLocaleString()}</li>
                            <li><strong>IP Address:</strong> ${details.ip || 'Unknown'}</li>
                            <li><strong>Location:</strong> ${details.location || 'Unknown'}</li>
                            <li><strong>Device:</strong> ${details.device || 'Unknown'}</li>
                        </ul>
                        
                        <p><strong>If this was you:</strong> You can ignore this alert.</p>
                        <p><strong>If this wasn't you:</strong> Please secure your account immediately:</p>
                        <ol>
                            <li>Change your password</li>
                            <li>Review your account activity</li>
                            <li>Contact support if needed</li>
                        </ol>
                        
                        <p>
                            <a href="${process.env.FRONTEND_URL}/security" style="display: inline-block; background: #ef4444; color: white; padding: 12px 24px; text-decoration: none; border-radius: 5px; font-weight: bold;">
                                Review Account Security
                            </a>
                        </p>
                        
                        <hr>
                        
                        <p><small>This is an automated security alert from WENMOON. Please do not reply to this email.</small></p>
                    </div>
                </div>
            </body>
            </html>
        `;
        
        return this.sendEmail(user.email, subject, html);
    }
    
    /**
     * Send admin alert
     */
    async sendAdminAlert(alertType, details = {}) {
        const adminEmail = process.env.ADMIN_EMAIL;
        if (!adminEmail) {
            logger.error('Admin email not configured');
            return { sent: false, error: 'Admin email not configured' };
        }
        
        const subject = `👑 ADMIN: ${alertType}`;
        const html = `
            <!DOCTYPE html>
            <html>
            <head>
                <style>
                    body { font-family: 'Courier New', monospace; line-height: 1.6; color: #333; }
                    .container { max-width: 800px; margin: 0 auto; padding: 20px; }
                    .header { background: #1f2937; color: white; padding: 20px; border-radius: 5px; }
                    .content { background: #f3f4f6; padding: 20px; border-radius: 0 0 5px 5px; border: 1px solid #d1d5db; }
                    pre { background: #1f2937; color: #10b981; padding: 15px; border-radius: 5px; overflow: auto; }
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header">
                        <h1>🔔 ${alertType}</h1>
                        <p>WENMOON Admin Alert - ${new Date().toISOString()}</p>
                    </div>
                    <div class="content">
                        <h2>Alert Details</h2>
                        <pre>${JSON.stringify(details, null, 2)}</pre>
                        
                        <h3>System Status</h3>
                        <ul>
                            <li><strong>Environment:</strong> ${process.env.NODE_ENV}</li>
                            <li><strong>Time:</strong> ${new Date().toISOString()}</li>
                            <li><strong>Alert ID:</strong> ${crypto.randomBytes(4).toString('hex')}</li>
                        </ul>
                        
                        <hr>
                        
                        <p><small>This is an automated admin alert from the WENMOON backend system.</small></p>
                    </div>
                </div>
            </body>
            </html>
        `;
        
        return this.sendEmail(adminEmail, subject, html);
    }
    
    /**
     * Helper: Convert HTML to plain text
     */
    htmlToText(html) {
        return html
            .replace(/<[^>]*>/g, ' ') // Remove HTML tags
            .replace(/\s+/g, ' ') // Collapse whitespace
            .trim();
    }
    
    /**
     * Helper: Get alert title
     */
    getAlertTitle(alertType) {
        const titles = {
            'new_device': 'New Device Login',
            'unusual_location': 'Unusual Location Detected',
            'multiple_failed_logins': 'Multiple Failed Login Attempts',
            'suspicious_activity': 'Suspicious Activity Detected',
            'account_locked': 'Account Temporarily Locked'
        };
        
        return titles[alertType] || 'Security Alert';
    }
    
    /**
     * Helper: Get alert description
     */
    getAlertDescription(alertType, details) {
        const descriptions = {
            'new_device': `A new device was used to access your account from ${details.location || 'an unknown location'}.`,
            'unusual_location': `Your account was accessed from ${details.location || 'an unusual location'} that doesn't match your usual pattern.`,
            'multiple_failed_logins': 'Multiple failed login attempts were detected on your account.',
            'suspicious_activity': 'Suspicious activity was detected on your account that may indicate unauthorized access.',
            'account_locked': 'Your account has been temporarily locked due to security concerns.'
        };
        
        return descriptions[alertType] || 'A security event was detected on your account.';
    }
    
    /**
     * Get email statistics
     */
    async getStats() {
        // This would typically query your email logs database
        // For now, return basic info
        
        return {
            enabled: this.enabled,
            smtpConfigured: !!this.transporter,
            fromEmail: this.fromEmail,
            fromName: this.fromName
        };
    }
}

module.exports = new EmailService();
