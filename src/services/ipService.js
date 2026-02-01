const axios = require('axios');
const geoip = require('geoip-lite');
const NodeCache = require('node-cache');
const logger = require('../utils/logger');

// Cache for IP info (5 minutes TTL)
const ipCache = new NodeCache({ stdTTL: 300, checkperiod: 60 });

// List of VPN/Proxy detection services (you'll need API keys)
const VPN_DETECTION_SERVICES = {
    // Free tier available
    IPHUB: process.env.IPHUB_API_KEY ? 
        `http://v2.api.iphub.info/ip/${ip}` : null,
    
    // Commercial service
    IPQUALITY: process.env.IPQUALITY_API_KEY ?
        `https://ipqualityscore.com/api/json/ip/${process.env.IPQUALITY_API_KEY}/${ip}` : null,
    
    // Free service with limitations
    IPAPI: `http://ip-api.com/json/${ip}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,query,proxy,hosting`
};

/**
 * Get comprehensive IP information
 */
const getIPInfo = async (ip) => {
    try {
        // Check cache first
        const cached = ipCache.get(ip);
        if (cached) {
            return cached;
        }
        
        // Basic geolocation using geoip-lite
        const geo = geoip.lookup(ip) || {};
        
        // Default response structure
        const ipInfo = {
            ip,
            country: geo.country || '',
            countryCode: geo.country || '',
            region: geo.region || '',
            regionName: '',
            city: geo.city || '',
            zip: '',
            lat: geo.ll?.[0] || 0,
            lon: geo.ll?.[1] || 0,
            timezone: geo.timezone || '',
            isp: '',
            org: '',
            as: '',
            vpn: false,
            proxy: false,
            hosting: false,
            tor: false
        };
        
        // Try to get more detailed info from ip-api (free)
        try {
            const response = await axios.get(`http://ip-api.com/json/${ip}?fields=66842623`, {
                timeout: 3000
            });
            
            if (response.data && response.data.status === 'success') {
                ipInfo.country = response.data.country || ipInfo.country;
                ipInfo.countryCode = response.data.countryCode || ipInfo.countryCode;
                ipInfo.region = response.data.region || ipInfo.region;
                ipInfo.regionName = response.data.regionName || ipInfo.regionName;
                ipInfo.city = response.data.city || ipInfo.city;
                ipInfo.zip = response.data.zip || ipInfo.zip;
                ipInfo.lat = response.data.lat || ipInfo.lat;
                ipInfo.lon = response.data.lon || ipInfo.lon;
                ipInfo.timezone = response.data.timezone || ipInfo.timezone;
                ipInfo.isp = response.data.isp || ipInfo.isp;
                ipInfo.org = response.data.org || ipInfo.org;
                ipInfo.as = response.data.as || ipInfo.as;
                
                // Check for proxy/hosting from ip-api
                ipInfo.proxy = response.data.proxy || false;
                ipInfo.hosting = response.data.hosting || false;
            }
        } catch (error) {
            logger.debug(`IP-API request failed for ${ip}:`, error.message);
        }
        
        // Check VPN using additional services if API keys are available
        if (process.env.IPHUB_API_KEY) {
            try {
                const iphubResponse = await axios.get(
                    `http://v2.api.iphub.info/ip/${ip}`,
                    {
                        headers: { 'X-Key': process.env.IPHUB_API_KEY },
                        timeout: 3000
                    }
                );
                
                if (iphubResponse.data && iphubResponse.data.block === 1) {
                    ipInfo.vpn = true;
                    ipInfo.proxy = true;
                }
            } catch (error) {
                logger.debug(`IPHub request failed for ${ip}:`, error.message);
            }
        }
        
        // Check for TOR nodes
        if (await isTorNode(ip)) {
            ipInfo.tor = true;
            ipInfo.vpn = true;
            ipInfo.proxy = true;
        }
        
        // Check for data center/hosting IP ranges
        if (isHostingIP(ip)) {
            ipInfo.hosting = true;
        }
        
        // Cache the result
        ipCache.set(ip, ipInfo);
        
        return ipInfo;
        
    } catch (error) {
        logger.error('Error getting IP info:', error);
        
        // Return minimal info on error
        return {
            ip,
            country: '',
            countryCode: '',
            region: '',
            regionName: '',
            city: '',
            zip: '',
            lat: 0,
            lon: 0,
            timezone: '',
            isp: '',
            org: '',
            as: '',
            vpn: false,
            proxy: false,
            hosting: false,
            tor: false
        };
    }
};

/**
 * Check if IP is a TOR node
 * Note: This is a simplified check. In production, use a TOR exit node list.
 */
const isTorNode = async (ip) => {
    // This would check against a list of known TOR exit nodes
    // For now, return false (implement properly in production)
    return false;
};

/**
 * Check if IP belongs to a hosting/data center
 */
const isHostingIP = (ip) => {
    // Known hosting provider IP ranges (simplified)
    const hostingRanges = [
        // AWS
        '3.0.0.0/9', '52.0.0.0/10', '54.0.0.0/10',
        // Google Cloud
        '8.34.0.0/19', '8.35.0.0/19', '23.236.0.0/19',
        // Azure
        '13.64.0.0/11', '20.0.0.0/10', '40.64.0.0/10',
        // Digital Ocean
        '138.197.0.0/16', '159.203.0.0/16', '167.99.0.0/16',
        // Linode
        '45.33.0.0/16', '45.56.0.0/16', '66.228.0.0/16'
    ];
    
    return hostingRanges.some(range => ipInRange(ip, range));
};

/**
 * Helper function to check if IP is in CIDR range
 */
function ipInRange(ip, range) {
    const [rangeIP, prefix] = range.split('/');
    if (!prefix) return ip === rangeIP;
    
    const mask = ~((1 << (32 - parseInt(prefix))) - 1);
    const ipNum = ipToNumber(ip);
    const rangeIPNum = ipToNumber(rangeIP);
    
    return (ipNum & mask) === (rangeIPNum & mask);
}

function ipToNumber(ip) {
    return ip.split('.').reduce((acc, octet) => (acc << 8) + parseInt(octet, 10), 0) >>> 0;
}

/**
 * Get IP reputation score
 */
const getIPReputation = async (ip) => {
    const ipInfo = await getIPInfo(ip);
    
    let reputationScore = 100; // Start with perfect score
    
    // Deduct points for suspicious indicators
    if (ipInfo.vpn || ipInfo.proxy) reputationScore -= 40;
    if (ipInfo.tor) reputationScore -= 60;
    if (ipInfo.hosting) reputationScore -= 20;
    
    // Country-based scoring (customize based on your target market)
    const highRiskCountries = ['RU', 'CN', 'UA', 'TR', 'VN', 'BR', 'IN'];
    if (highRiskCountries.includes(ipInfo.countryCode)) {
        reputationScore -= 15;
    }
    
    // Ensure score is between 0-100
    return Math.max(0, Math.min(100, reputationScore));
};

/**
 * Batch process IPs (for admin/analytics)
 */
const batchProcessIPs = async (ips) => {
    const results = [];
    
    for (const ip of ips) {
        try {
            const info = await getIPInfo(ip);
            const reputation = await getIPReputation(ip);
            results.push({ ip, ...info, reputation });
        } catch (error) {
            results.push({ ip, error: error.message });
        }
    }
    
    return results;
};

/**
 * Clear IP cache
 */
const clearCache = () => {
    ipCache.flushAll();
    logger.info('IP cache cleared');
};

module.exports = {
    getIPInfo,
    getIPReputation,
    batchProcessIPs,
    clearCache,
    isHostingIP,
    ipInRange
};
