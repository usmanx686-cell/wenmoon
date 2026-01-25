const { DataTypes } = require('sequelize');
const { sequelize } = require('../config/database');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');

const User = sequelize.define('User', {
  id: {
    type: DataTypes.INTEGER,
    primaryKey: true,
    autoIncrement: true
  },
  email: {
    type: DataTypes.STRING(255),
    allowNull: false,
    unique: true,
    validate: {
      isEmail: true
    }
  },
  username: {
    type: DataTypes.STRING(100),
    unique: true,
    allowNull: true
  },
  password_hash: {
    type: DataTypes.STRING(255),
    allowNull: true // Can be null for social logins
  },
  wallet_address: {
    type: DataTypes.STRING(255),
    validate: {
      isEthereumAddress(value) {
        if (value && !/^0x[a-fA-F0-9]{40}$/.test(value)) {
          throw new Error('Invalid Ethereum address');
        }
      }
    }
  },
  referral_code: {
    type: DataTypes.STRING(50),
    unique: true,
    allowNull: false
  },
  referred_by: {
    type: DataTypes.STRING(50)
  },
  moon_points: {
    type: DataTypes.INTEGER,
    defaultValue: 0,
    validate: {
      min: 0
    }
  },
  total_points_earned: {
    type: DataTypes.INTEGER,
    defaultValue: 0,
    validate: {
      min: 0
    }
  },
  email_verified: {
    type: DataTypes.BOOLEAN,
    defaultValue: false
  },
  telegram_id: {
    type: DataTypes.STRING(100),
    unique: true,
    allowNull: true
  },
  google_id: {
    type: DataTypes.STRING(100),
    unique: true,
    allowNull: true
  },
  ip_address: {
    type: DataTypes.STRING(45) // IPv6 max length
  },
  last_login: {
    type: DataTypes.DATE
  },
  is_active: {
    type: DataTypes.BOOLEAN,
    defaultValue: true
  },
  is_admin: {
    type: DataTypes.BOOLEAN,
    defaultValue: false
  },
  profile_image: {
    type: DataTypes.STRING(500)
  },
  twitter_handle: {
    type: DataTypes.STRING(100)
  },
  discord_id: {
    type: DataTypes.STRING(100)
  },
  telegram_username: {
    type: DataTypes.STRING(100)
  }
}, {
  tableName: 'users',
  timestamps: true,
  underscored: true,
  hooks: {
    beforeCreate: async (user) => {
      // Hash password if provided
      if (user.password_hash) {
        const salt = await bcrypt.genSalt(10);
        user.password_hash = await bcrypt.hash(user.password_hash, salt);
      }
      
      // Generate unique referral code
      if (!user.referral_code) {
        let code;
        let isUnique = false;
        
        while (!isUnique) {
          code = crypto.randomBytes(4).toString('hex').toUpperCase();
          const existingUser = await User.findOne({ where: { referral_code: code } });
          if (!existingUser) {
            isUnique = true;
          }
        }
        
        user.referral_code = code;
      }
      
      // Generate username from email if not provided
      if (!user.username && user.email) {
        const baseUsername = user.email.split('@')[0];
        let username = baseUsername;
        let counter = 1;
        
        // Ensure username is unique
        while (true) {
          const existingUser = await User.findOne({ where: { username } });
          if (!existingUser) {
            break;
          }
          username = `${baseUsername}${counter}`;
          counter++;
        }
        
        user.username = username;
      }
    },
    
    beforeUpdate: async (user) => {
      // Hash password if it's being changed
      if (user.changed('password_hash') && user.password_hash) {
        const salt = await bcrypt.genSalt(10);
        user.password_hash = await bcrypt.hash(user.password_hash, salt);
      }
    }
  }
});

// Instance methods
User.prototype.comparePassword = async function(candidatePassword) {
  if (!this.password_hash) {
    return false;
  }
  return await bcrypt.compare(candidatePassword, this.password_hash);
};

User.prototype.generateAuthToken = function() {
  const jwt = require('jsonwebtoken');
  return jwt.sign(
    { userId: this.id },
    process.env.JWT_SECRET,
    { expiresIn: process.env.JWT_EXPIRE || '7d' }
  );
};

User.prototype.generateRefreshToken = function() {
  const jwt = require('jsonwebtoken');
  return jwt.sign(
    { userId: this.id, type: 'refresh' },
    process.env.JWT_REFRESH_SECRET,
    { expiresIn: process.env.JWT_REFRESH_EXPIRE || '30d' }
  );
};

User.prototype.toJSON = function() {
  const values = Object.assign({}, this.get());
  
  // Remove sensitive fields
  delete values.password_hash;
  delete values.google_id;
  delete values.telegram_id;
  delete values.ip_address;
  delete values.created_at;
  delete values.updated_at;
  
  return values;
};

// Static methods
User.findByEmail = async function(email) {
  return await this.findOne({ where: { email } });
};

User.findByReferralCode = async function(referralCode) {
  return await this.findOne({ where: { referral_code: referralCode } });
};

User.findByWalletAddress = async function(walletAddress) {
  return await this.findOne({ 
    where: { 
      wallet_address: sequelize.where(
        sequelize.fn('LOWER', sequelize.col('wallet_address')),
        walletAddress.toLowerCase()
      )
    }
  });
};

// Class methods for statistics
User.getTotalUsers = async function() {
  return await this.count();
};

User.getActiveUsers = async function() {
  return await this.count({ where: { is_active: true } });
};

User.getTopUsersByPoints = async function(limit = 10) {
  return await this.findAll({
    attributes: ['id', 'username', 'email', 'moon_points', 'total_points_earned'],
    order: [['moon_points', 'DESC']],
    limit: limit
  });
};

module.exports = User;
