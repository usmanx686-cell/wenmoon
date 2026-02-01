# WENMOON Airdrop Platform Backend

A secure, scalable backend for the WENMOON community-powered airdrop platform with advanced anti-bot protection and IP limiting features.

## Features

### 🛡️ Security Features
- **IP Limiting**: Maximum 5 users per IP address
- **Advanced Bot Detection**: Multiple layers of bot detection and prevention
- **CAPTCHA Integration**: hCaptcha/Google reCAPTCHA support
- **Rate Limiting**: Multi-tier rate limiting per endpoint
- **Fraud Detection**: Real-time scoring and behavioral analysis
- **Device Fingerprinting**: Unique device identification
- **VPN/Proxy Detection**: Integration with IP intelligence services

### 📊 Core Features
- User authentication (Email, Google, Telegram)
- Task management and completion system
- Moon Points earning and tracking
- Referral system with bonus points
- Wallet connection (Web3 integration)
- Admin dashboard with monitoring tools
- Real-time security alerts

### 🚀 Performance Features
- Redis caching for frequently accessed data
- Database connection pooling
- Request/response compression
- Efficient indexing and query optimization

## Tech Stack

- **Runtime**: Node.js 18+
- **Framework**: Express.js
- **Database**: MongoDB with Mongoose ODM
- **Cache**: Redis
- **Authentication**: JWT with refresh tokens
- **Security**: Helmet, CORS, rate limiting, input sanitization
- **Logging**: Winston with file rotation
- **Email**: Nodemailer with templates

## Getting Started

### Prerequisites

- Node.js 18 or higher
- MongoDB 5.0 or higher
- Redis 6.0 or higher
- npm or yarn

### Installation

1. **Clone the repository**
```bash
git clone https://github.com/yourusername/wenmoon-backend.git
cd wenmoon-backend
