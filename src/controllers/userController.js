const User = require('../models/User');
const Task = require('../models/Task');
const IPLog = require('../models/IPLog');
const SecurityLog = require('../models/SecurityLog');
const logger = require('../utils/logger');
const fraudDetection = require('../services/fraudDetection');
const { getIPInfo } = require('../services/ipService');

// Get user profile
const getProfile = async (req, res) => {
    try {
        const user = await User.findById(req.userId)
            .select('-password -twoFactorSecret -verificationToken')
            .populate('completedTasks.taskId', 'title points category')
            .populate('referrals.userId', 'name avatar')
            .populate('referredBy', 'name avatar');
        
        if (!user) {
            return res.status(404).json({
                status: 'error',
                message: 'User not found'
            });
        }
        
        res.status(200).json({
            status: 'success',
            data: { user }
        });
    } catch (error) {
        logger.error('Get profile error:', error);
        res.status(500).json({
            status: 'error',
            message: 'An error occurred'
        });
    }
};

// Update user profile
const updateProfile = async (req, res) => {
    try {
        const { name, avatar } = req.body;
        
        const user = await User.findById(req.userId);
        if (!user) {
            return res.status(404).json({
                status: 'error',
                message: 'User not found'
            });
        }
        
        // Update fields
        if (name) user.name = name;
        if (avatar) user.avatar = avatar;
        
        await user.save();
        
        // Remove sensitive data
        user.password = undefined;
        user.twoFactorSecret = undefined;
        user.verificationToken = undefined;
        
        res.status(200).json({
            status: 'success',
            data: { user }
        });
    } catch (error) {
        logger.error('Update profile error:', error);
        res.status(500).json({
            status: 'error',
            message: 'An error occurred'
        });
    }
};

// Connect wallet
const connectWallet = async (req, res) => {
    try {
        const { walletAddress, signature } = req.body;
        
        // Validate wallet address
        if (!/^0x[a-fA-F0-9]{40}$/.test(walletAddress)) {
            return res.status(400).json({
                status: 'error',
                message: 'Invalid Ethereum address'
            });
        }
        
        // Check if wallet is already connected to another account
        const existingUser = await User.findOne({ 
            walletAddress,
            _id: { $ne: req.userId }
        });
        
        if (existingUser) {
            return res.status(400).json({
                status: 'error',
                message: 'Wallet already connected to another account'
            });
        }
        
        const user = await User.findById(req.userId);
        if (!user) {
            return res.status(404).json({
                status: 'error',
                message: 'User not found'
            });
        }
        
        // In production, verify the signature here
        // For now, we'll trust the client
        
        user.walletAddress = walletAddress;
        user.walletConnectedAt = new Date();
        
        // Give bonus points for wallet connection
        if (!user.walletAddress) {
            await user.addPoints(80, 'wallet_connection');
        }
        
        await user.save();
        
        // Log wallet connection
        await SecurityLog.create({
            userId: user._id,
            type: 'wallet_connected',
            severity: 'info',
            details: { walletAddress }
        });
        
        // Update IP log
        await IPLog.create({
            ipAddress: req.clientIP,
            userId: user._id,
            action: 'wallet_connect',
            userAgent: req.useragent?.source,
            riskScore: user.riskScore
        });
        
        res.status(200).json({
            status: 'success',
            data: {
                walletAddress: user.walletAddress,
                connectedAt: user.walletConnectedAt,
                bonusPoints: 80
            }
        });
    } catch (error) {
        logger.error('Connect wallet error:', error);
        res.status(500).json({
            status: 'error',
            message: 'An error occurred'
        });
    }
};

// Get referral information
const getReferralInfo = async (req, res) => {
    try {
        const user = await User.findById(req.userId)
            .populate('referrals.userId', 'name avatar moonPoints createdAt')
            .populate('referredBy', 'name avatar');
        
        if (!user) {
            return res.status(404).json({
                status: 'error',
                message: 'User not found'
            });
        }
        
        const referralStats = {
            code: user.referralCode,
            totalReferrals: user.referralCount,
            totalPoints: user.referrals.reduce((sum, ref) => sum + (ref.pointsEarned || 0), 0),
            referrals: user.referrals,
            referredBy: user.referredBy,
            referralLink: `${process.env.FRONTEND_URL}/ref/${user.referralCode}`
        };
        
        res.status(200).json({
            status: 'success',
            data: referralStats
        });
    } catch (error) {
        logger.error('Get referral info error:', error);
        res.status(500).json({
            status: 'error',
            message: 'An error occurred'
        });
    }
};

// Process referral
const processReferral = async (req, res) => {
    try {
        const { referralCode } = req.body;
        
        const user = await User.findById(req.userId);
        if (!user) {
            return res.status(404).json({
                status: 'error',
                message: 'User not found'
            });
        }
        
        // Check if user already used a referral
        if (user.referredBy) {
            return res.status(400).json({
                status: 'error',
                message: 'Referral already used'
            });
        }
        
        // Find referrer
        const referrer = await User.findOne({ referralCode });
        if (!referrer) {
            return res.status(404).json({
                status: 'error',
                message: 'Invalid referral code'
            });
        }
        
        // Check if referring self
        if (referrer._id.toString() === user._id.toString()) {
            return res.status(400).json({
                status: 'error',
                message: 'Cannot use your own referral code'
            });
        }
        
        // Update user with referrer
        user.referredBy = referrer._id;
        await user.save();
        
        // Update referrer's referrals
        referrer.referrals.push({
            userId: user._id,
            pointsEarned: 100,
            referredAt: new Date()
        });
        referrer.referralCount += 1;
        
        // Give referral points to referrer
        await referrer.addPoints(100, 'referral');
        
        await referrer.save();
        
        // Give bonus points to new user
        await user.addPoints(50, 'referral_signup');
        
        res.status(200).json({
            status: 'success',
            data: {
                referrer: {
                    name: referrer.name,
                    avatar: referrer.avatar
                },
                pointsEarned: {
                    user: 50,
                    referrer: 100
                }
            }
        });
    } catch (error) {
        logger.error('Process referral error:', error);
        res.status(500).json({
            status: 'error',
            message: 'An error occurred'
        });
    }
};

// Get user stats
const getUserStats = async (req, res) => {
    try {
        const user = await User.findById(req.userId);
        if (!user) {
            return res.status(404).json({
                status: 'error',
                message: 'User not found'
            });
        }
        
        // Get task completion stats
        const taskStats = {
            totalCompleted: user.completedTasks.length,
            completedToday: user.tasksCompletedToday,
            dailyLimit: user.dailyTaskLimit,
            pointsToday: user.pointsHistory
                .filter(ph => {
                    const today = new Date();
                    const phDate = new Date(ph.timestamp);
                    return phDate.toDateString() === today.toDateString();
                })
                .reduce((sum, ph) => sum + ph.points, 0)
        };
        
        // Get session stats
        const sessionStats = {
            totalLogins: user.totalLogins,
            totalSessions: user.totalSessions,
            lastLogin: user.lastLogin,
            lastActivity: user.lastActivity
        };
        
        // Get security stats
        const securityStats = {
            riskScore: user.riskScore,
            riskLevel: fraudDetection.getRiskLevel(user.riskScore),
            flags: user.flags.length,
            uniqueIPs: user.ipHistory.length,
            uniqueDevices: user.deviceHistory.length
        };
        
        res.status(200).json({
            status: 'success',
            data: {
                user: {
                    name: user.name,
                    avatar: user.avatar,
                    moonPoints: user.moonPoints,
                    totalPointsEarned: user.totalPointsEarned,
                    walletConnected: !!user.walletAddress,
                    accountAge: Date.now() - user.createdAt
                },
                taskStats,
                sessionStats,
                securityStats
            }
        });
    } catch (error) {
        logger.error('Get user stats error:', error);
        res.status(500).json({
            status: 'error',
            message: 'An error occurred'
        });
    }
};

// Get leaderboard
const getLeaderboard = async (req, res) => {
    try {
        const { limit = 100, page = 1 } = req.query;
        const skip = (page - 1) * limit;
        
        const users = await User.find({ status: 'active' })
            .sort({ moonPoints: -1 })
            .skip(skip)
            .limit(parseInt(limit))
            .select('name avatar moonPoints referralCode createdAt')
            .lean();
        
        // Get user's rank
        const userRank = await User.countDocuments({
            status: 'active',
            moonPoints: { $gt: req.user?.moonPoints || 0 }
        }) + 1;
        
        res.status(200).json({
            status: 'success',
            data: {
                leaderboard: users,
                currentUser: {
                    rank: userRank,
                    points: req.user?.moonPoints || 0
                },
                pagination: {
                    page: parseInt(page),
                    limit: parseInt(limit),
                    total: await User.countDocuments({ status: 'active' })
                }
            }
        });
    } catch (error) {
        logger.error('Get leaderboard error:', error);
        res.status(500).json({
            status: 'error',
            message: 'An error occurred'
        });
    }
};

// Delete account
const deleteAccount = async (req, res) => {
    try {
        const { reason, password } = req.body;
        
        const user = await User.findById(req.userId).select('+password');
        if (!user) {
            return res.status(404).json({
                status: 'error',
                message: 'User not found'
            });
        }
        
        // Verify password
        const isPasswordValid = await user.comparePassword(password);
        if (!isPasswordValid) {
            return res.status(401).json({
                status: 'error',
                message: 'Invalid password'
            });
        }
        
        // Soft delete - mark as deleted
        user.status = 'deleted';
        user.email = `deleted_${Date.now()}_${user.email}`;
        user.telegramId = null;
        user.googleId = null;
        user.walletAddress = null;
        await user.save();
        
        // Log account deletion
        await SecurityLog.create({
            userId: user._id,
            type: 'account_deleted',
            severity: 'info',
            details: { reason }
        });
        
        res.status(200).json({
            status: 'success',
            message: 'Account deleted successfully'
        });
    } catch (error) {
        logger.error('Delete account error:', error);
        res.status(500).json({
            status: 'error',
            message: 'An error occurred'
        });
    }
};

module.exports = {
    getProfile,
    updateProfile,
    connectWallet,
    getReferralInfo,
    processReferral,
    getUserStats,
    getLeaderboard,
    deleteAccount
};
