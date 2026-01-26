const mongoose = require('mongoose');

const IPLogSchema = new mongoose.Schema({
    ipAddress: {
        type: String,
        required: true,
        index: true
    },
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User'
    },
    action: {
        type: String,
        required: true,
        enum: ['signup', 'login', 'task_completion', 'wallet_connect', 'api_request']
    },
    userAgent: String,
    country: String,
    city: String,
    isp: String,
    vpn: Boolean,
    proxy: Boolean,
    timestamp: {
        type: Date,
        default: Date.now,
        index: true,
        expires: '30d' // Auto-delete after 30 days
    },
    riskScore: {
        type: Number,
        default: 0,
        min: 0,
        max: 100
    },
    isBlocked: {
        type: Boolean,
        default: false
    },
    blockReason: String,
    blockExpires: Date
}, {
    timestamps: true
});

// Index for faster queries
IPLogSchema.index({ ipAddress: 1, timestamp: -1 });
IPLogSchema.index({ userId: 1, timestamp: -1 });
IPLogSchema.index({ isBlocked: 1, blockExpires: 1 });

// Static method to check IP limit
IPLogSchema.statics.checkIPLimit = async function(ipAddress, maxUsers = 5) {
    const twentyFourHoursAgo = new Date(Date.now() - 24 * 60 * 60 * 1000);
    
    const userCount = await this.distinct('userId', {
        ipAddress,
        action: 'signup',
        timestamp: { $gte: twentyFourHoursAgo },
        isBlocked: false
    }).then(users => users.length);

    return {
        allowed: userCount < maxUsers,
        currentCount: userCount,
        maxAllowed: maxUsers
    };
};

// Static method to get IP statistics
IPLogSchema.statics.getIPStats = async function(ipAddress, hours = 24) {
    const timeAgo = new Date(Date.now() - hours * 60 * 60 * 1000);
    
    const stats = await this.aggregate([
        {
            $match: {
                ipAddress,
                timestamp: { $gte: timeAgo }
            }
        },
        {
            $group: {
                _id: '$action',
                count: { $sum: 1 },
                lastTimestamp: { $max: '$timestamp' }
            }
        },
        {
            $project: {
                action: '$_id',
                count: 1,
                lastTimestamp: 1,
                _id: 0
            }
        }
    ]);

    return stats;
};

const IPLog = mongoose.model('IPLog', IPLogSchema);

module.exports = IPLog;
