const { User, WalletConnection, ActivityLog } = require('../models');
const Web3 = require('web3');
const logger = require('../utils/logger');

class WalletController {
  // Connect wallet
  async connectWallet(req, res) {
    try {
      const { wallet_address, signature, message, network = 'Ethereum' } = req.body;
      const userId = req.user.id;
      const ip = req.clientIp;

      // Validate Ethereum address
      if (!Web3.utils.isAddress(wallet_address)) {
        return res.status(400).json({
          success: false,
          message: 'Invalid Ethereum address'
        });
      }

      // Verify signature (basic implementation)
      if (signature && message) {
        const web3 = new Web3();
        const recoveredAddress = web3.eth.accounts.recover(message, signature);
        
        if (recoveredAddress.toLowerCase() !== wallet_address.toLowerCase()) {
          return res.status(400).json({
            success: false,
            message: 'Signature verification failed'
          });
        }
      }

      // Check if wallet already connected to another account
      const existingConnection = await WalletConnection.findOne({
        where: { wallet_address: wallet_address.toLowerCase() }
      });

      if (existingConnection && existingConnection.user_id !== userId) {
        return res.status(400).json({
          success: false,
          message: 'Wallet already connected to another account'
        });
      }

      // Get user
      const user = await User.findByPk(userId);

      // Check if user already has this wallet
      const userWallet = await WalletConnection.findOne({
        where: {
          user_id: userId,
          wallet_address: wallet_address.toLowerCase()
        }
      });

      if (userWallet) {
        return res.status(400).json({
          success: false,
          message: 'Wallet already connected'
        });
      }

      // Create wallet connection
      await WalletConnection.create({
        user_id: userId,
        wallet_address: wallet_address.toLowerCase(),
        wallet_type: 'EVM',
        network,
        is_primary: true
      });

      // Update user's primary wallet
      await user.update({
        wallet_address: wallet_address.toLowerCase()
      });

      // Award points for wallet connection (if not already awarded)
      const taskAwarded = await this.awardWalletTaskPoints(userId);
      
      // Log activity
      await ActivityLog.create({
        user_id: userId,
        action: 'wallet_connected',
        details: {
          wallet_address: wallet_address.toLowerCase(),
          network,
          ip,
          task_awarded: taskAwarded
        },
        ip_address: ip
      });

      res.json({
        success: true,
        message: 'Wallet connected successfully',
        data: {
          wallet_address: wallet_address.toLowerCase(),
          network,
          points_awarded: taskAwarded ? 80 : 0
        }
      });

    } catch (error) {
      logger.error('Wallet connection error:', error);
      res.status(500).json({
        success: false,
        message: 'Failed to connect wallet'
      });
    }
  }

  // Get user's wallets
  async getUserWallets(req, res) {
    try {
      const wallets = await WalletConnection.findAll({
        where: { user_id: req.user.id },
        attributes: ['id', 'wallet_address', 'wallet_type', 'network', 'connected_at', 'is_primary']
      });

      res.json({
        success: true,
        data: wallets
      });
    } catch (error) {
      logger.error('Get wallets error:', error);
      res.status(500).json({
        success: false,
        message: 'Failed to fetch wallets'
      });
    }
  }

  // Verify wallet ownership
  async verifyWallet(req, res) {
    try {
      const { wallet_address, signature, message } = req.body;
      
      const web3 = new Web3();
      const recoveredAddress = web3.eth.accounts.recover(message, signature);
      
      const isValid = recoveredAddress.toLowerCase() === wallet_address.toLowerCase();
      
      res.json({
        success: true,
        data: {
          verified: isValid,
          wallet_address: wallet_address.toLowerCase(),
          recovered_address: recoveredAddress.toLowerCase()
        }
      });

    } catch (error) {
      logger.error('Wallet verification error:', error);
      res.status(500).json({
        success: false,
        message: 'Wallet verification failed'
      });
    }
  }

  // Get wallet transactions (mock for now)
  async getWalletTransactions(req, res) {
    try {
      const { wallet_address } = req.params;
      
      // In production, integrate with blockchain explorer API
      const mockTransactions = [
        {
          hash: '0x123...abc',
          from: wallet_address,
          to: '0x789...def',
          value: '0.1 ETH',
          timestamp: new Date().toISOString(),
          status: 'confirmed'
        }
      ];

      res.json({
        success: true,
        data: {
          wallet_address,
          transactions: mockTransactions,
          total_transactions: mockTransactions.length
        }
      });

    } catch (error) {
      logger.error('Get transactions error:', error);
      res.status(500).json({
        success: false,
        message: 'Failed to fetch transactions'
      });
    }
  }

  // Helper: Award wallet connection task points
  async awardWalletTaskPoints(userId) {
    try {
      const user = await User.findByPk(userId);
      
      // Check if already completed wallet task
      const walletTaskCompleted = await require('../models').UserTask.findOne({
        where: {
          user_id: userId,
          task_id: 'wallet_connect'
        }
      });

      if (!walletTaskCompleted) {
        // Award points
        await user.update({
          moon_points: user.moon_points + 80,
          total_points_earned: user.total_points_earned + 80
        });

        // Create task completion record
        await require('../models').UserTask.create({
          user_id: userId,
          task_id: 'wallet_connect',
          points_awarded: 80,
          metadata: { type: 'wallet_connection' }
        });

        return true;
      }

      return false;
    } catch (error) {
      logger.error('Award wallet points error:', error);
      return false;
    }
  }
}

module.exports = new WalletController();
