/**
 * Threat Intelligence Service
 * 
 * Comprehensive threat intelligence aggregation from multiple sources:
 * - Open Source Threat Intelligence (OSINT)
 * - Microsoft Sentinel
 * - Reddit subreddits (r/cybersecurity, r/malware, etc.)
 * - Black hat/White hat security communities
 * - Commercial threat intelligence feeds
 * - IoC databases and reputation services
 */
const { logger } = require('../../utils/logger');
const cacheService = require('../cache/cacheService');
const axios = require('axios');
const config = require('../../config');

class ThreatIntelligenceService {
  constructor() {
    this.sources = {
      openSource: {
        virusTotal: { enabled: true, apiKey: config.VIRUS_TOTAL_API_KEY },
        abuseIPDB: { enabled: true, apiKey: config.ABUSE_IPDB_API_KEY },
        otx: { enabled: true, apiKey: config.OTX_API_KEY },
        hybridAnalysis: { enabled: true, apiKey: config.HYBRID_ANALYSIS_API_KEY },
        urlVoid: { enabled: true, apiKey: config.URL_VOID_API_KEY },
        threatCrowd: { enabled: true, apiKey: null },
        shodan: { enabled: true, apiKey: config.SHODAN_API_KEY }
      },
      commercial: {
        recordedFuture: { enabled: false, apiKey: config.RECORDED_FUTURE_API_KEY },
        threatConnect: { enabled: false, apiKey: config.THREAT_CONNECT_API_KEY },
        crowdStrike: { enabled: false, apiKey: config.CROWDSTRIKE_API_KEY }
      },
      social: {
        reddit: { enabled: true, subreddits: ['cybersecurity', 'malware', 'netsec', 'AskNetsec', 'blackhat'] },
        twitter: { enabled: true, accounts: ['@malware_traffic', '@URLVoid', '@abuse_ch'] },
        telegram: { enabled: true, channels: ['@malware_traffic', '@cyberthreat'] }
      },
      microsoft: {
        sentinel: { enabled: true },
        defender: { enabled: true },
        graph: { enabled: true }
      }
    };

    this.confidenceWeights = {
      virusTotal: 0.9,
      abuseIPDB: 0.8,
      otx: 0.7,
      hybridAnalysis: 0.9,
      sentinel: 0.95,
      recordedFuture: 0.95,
      crowdStrike: 0.9,
      reddit: 0.4,
      twitter: 0.3,
      telegram: 0.3
    };

    this.cacheTimeout = 3600; // 1 hour cache
  }

  /**
   * Analyze indicators of compromise across all sources
   * @param {Array} indicators - List of IOCs to analyze
   * @returns {Promise<Object>} Threat intelligence analysis
   */
  async analyzeIndicators(indicators) {
    logger.info('Analyzing indicators across threat intelligence sources', { 
      indicatorCount: indicators.length 
    });

    try {
      const results = await Promise.allSettled(
        indicators.map(indicator => this.analyzeIndicator(indicator))
      );

      const analysisResults = results.map((result, index) => ({
        indicator: indicators[index],
        success: result.status === 'fulfilled',
        data: result.status === 'fulfilled' ? result.value : null,
        error: result.status === 'rejected' ? result.reason.message : null
      }));

      const summary = this.summarizeAnalysis(analysisResults);

      return {
        indicators: analysisResults,
        summary,
        timestamp: new Date(),
        sources: Object.keys(this.sources).reduce((acc, category) => ({
          ...acc,
          [category]: Object.keys(this.sources[category]).filter(source => 
            this.sources[category][source].enabled
          )
        }), {})
      };

    } catch (error) {
      logger.error('Failed to analyze indicators', { error: error.message });
      throw error;
    }
  }

  /**
   * Analyze single indicator
   * @param {string} indicator - IOC to analyze
   * @returns {Promise<Object>} Indicator analysis
   * @private
   */
  async analyzeIndicator(indicator) {
    const cacheKey = `threat_intel:${indicator}`;
    
    // Check cache first
    const cached = await cacheService.get(cacheKey);
    if (cached) {
      logger.debug('Using cached threat intelligence', { indicator });
      return cached;
    }

    const indicatorType = this.detectIndicatorType(indicator);
    logger.debug('Analyzing indicator', { indicator, type: indicatorType });

    const sourceResults = await Promise.allSettled([
      this.checkVirusTotal(indicator, indicatorType),
      this.checkAbuseIPDB(indicator, indicatorType),
      this.checkOTX(indicator, indicatorType),
      this.checkHybridAnalysis(indicator, indicatorType),
      this.checkThreatCrowd(indicator, indicatorType),
      this.checkShodan(indicator, indicatorType),
      this.checkRedditMentions(indicator),
      this.checkTwitterMentions(indicator),
      this.checkSentinelThreatIntel(indicator)
    ]);

    const analysis = {
      indicator,
      type: indicatorType,
      sources: this.processSourceResults(sourceResults),
      overallScore: 0,
      confidence: 'unknown',
      threatTypes: [],
      isMalicious: false,
      categories: [],
      firstSeen: null,
      lastSeen: null,
      reputation: 'unknown'
    };

    // Calculate overall threat score and confidence
    analysis.overallScore = this.calculateThreatScore(analysis.sources);
    analysis.confidence = this.calculateConfidence(analysis.sources);
    analysis.isMalicious = analysis.overallScore > 50;
    analysis.reputation = this.determineReputation(analysis.overallScore);
    analysis.threatTypes = this.extractThreatTypes(analysis.sources);
    analysis.categories = this.extractCategories(analysis.sources);

    // Cache the result
    await cacheService.set(cacheKey, analysis, this.cacheTimeout);

    return analysis;
  }

  /**
   * Check IP reputation with multiple sources
   * @param {string} ip - IP address to check
   * @returns {Promise<Object>} IP reputation data
   */
  async checkIpReputation(ip) {
    logger.debug('Checking IP reputation', { ip });

    try {
      const [virusTotal, abuseIPDB, otx, shodan] = await Promise.allSettled([
        this.checkVirusTotal(ip, 'ip'),
        this.checkAbuseIPDB(ip, 'ip'),
        this.checkOTX(ip, 'ip'),
        this.checkShodan(ip, 'ip')
      ]);

      const sources = this.processSourceResults([virusTotal, abuseIPDB, otx, shodan]);
      const threatScore = this.calculateThreatScore(sources);
      
      return {
        ip,
        isMalicious: threatScore > 50,
        threatScore,
        confidence: this.calculateConfidence(sources),
        categories: this.extractCategories(sources),
        sources: sources.filter(s => s.success),
        lastChecked: new Date()
      };

    } catch (error) {
      logger.error('Failed to check IP reputation', { ip, error: error.message });
      throw error;
    }
  }

  /**
   * Check VirusTotal for indicator
   * @param {string} indicator - IOC to check
   * @param {string} type - Indicator type
   * @returns {Promise<Object>} VirusTotal result
   * @private
   */
  async checkVirusTotal(indicator, type) {
    if (!this.sources.openSource.virusTotal.enabled || !this.sources.openSource.virusTotal.apiKey) {
      return { source: 'virusTotal', success: false, error: 'API key not configured' };
    }

    try {
      logger.debug('Checking VirusTotal', { indicator, type });
      
      // Mock implementation - replace with actual VirusTotal API calls
      const mockResult = {
        source: 'virusTotal',
        success: true,
        data: {
          positives: Math.floor(Math.random() * 5),
          total: 70,
          scan_date: new Date(),
          permalink: `https://virustotal.com/gui/${type}/${indicator}`,
          scans: {},
          response_code: 1
        },
        confidence: this.confidenceWeights.virusTotal,
        categories: ['malware']
      };

      return mockResult;

    } catch (error) {
      logger.warn('VirusTotal check failed', { indicator, error: error.message });
      return { source: 'virusTotal', success: false, error: error.message };
    }
  }

  /**
   * Check AbuseIPDB for IP reputation
   * @param {string} indicator - IOC to check
   * @param {string} type - Indicator type
   * @returns {Promise<Object>} AbuseIPDB result
   * @private
   */
  async checkAbuseIPDB(indicator, type) {
    if (type !== 'ip' || !this.sources.openSource.abuseIPDB.enabled) {
      return { source: 'abuseIPDB', success: false, error: 'Not applicable for this indicator type' };
    }

    try {
      logger.debug('Checking AbuseIPDB', { indicator });
      
      // Mock implementation - replace with actual AbuseIPDB API calls
      const mockResult = {
        source: 'abuseIPDB',
        success: true,
        data: {
          abuseConfidenceScore: Math.floor(Math.random() * 100),
          countryCode: 'US',
          isWhitelisted: false,
          totalReports: Math.floor(Math.random() * 10),
          numDistinctUsers: Math.floor(Math.random() * 5),
          lastReportedAt: new Date()
        },
        confidence: this.confidenceWeights.abuseIPDB,
        categories: ['abuse']
      };

      return mockResult;

    } catch (error) {
      logger.warn('AbuseIPDB check failed', { indicator, error: error.message });
      return { source: 'abuseIPDB', success: false, error: error.message };
    }
  }

  /**
   * Check AlienVault OTX for indicator
   * @param {string} indicator - IOC to check
   * @param {string} type - Indicator type
   * @returns {Promise<Object>} OTX result
   * @private
   */
  async checkOTX(indicator, type) {
    if (!this.sources.openSource.otx.enabled) {
      return { source: 'otx', success: false, error: 'OTX not enabled' };
    }

    try {
      logger.debug('Checking OTX', { indicator, type });
      
      // Mock implementation - replace with actual OTX API calls
      const mockResult = {
        source: 'otx',
        success: true,
        data: {
          pulse_info: {
            count: Math.floor(Math.random() * 3),
            pulses: []
          },
          malware: {
            count: Math.floor(Math.random() * 2),
            data: []
          },
          reputation: Math.floor(Math.random() * 5)
        },
        confidence: this.confidenceWeights.otx,
        categories: ['malware', 'botnet']
      };

      return mockResult;

    } catch (error) {
      logger.warn('OTX check failed', { indicator, error: error.message });
      return { source: 'otx', success: false, error: error.message };
    }
  }

  /**
   * Check Hybrid Analysis for file/URL analysis
   * @param {string} indicator - IOC to check
   * @param {string} type - Indicator type
   * @returns {Promise<Object>} Hybrid Analysis result
   * @private
   */
  async checkHybridAnalysis(indicator, type) {
    if (!['hash', 'url'].includes(type) || !this.sources.openSource.hybridAnalysis.enabled) {
      return { source: 'hybridAnalysis', success: false, error: 'Not applicable for this indicator type' };
    }

    try {
      logger.debug('Checking Hybrid Analysis', { indicator, type });
      
      // Mock implementation - replace with actual Hybrid Analysis API calls
      const mockResult = {
        source: 'hybridAnalysis',
        success: true,
        data: {
          verdict: ['malicious', 'suspicious', 'clean'][Math.floor(Math.random() * 3)],
          threat_score: Math.floor(Math.random() * 100),
          analysis_start_time: new Date(),
          environment_id: 100,
          job_id: `${Date.now()}`
        },
        confidence: this.confidenceWeights.hybridAnalysis,
        categories: ['malware', 'trojan']
      };

      return mockResult;

    } catch (error) {
      logger.warn('Hybrid Analysis check failed', { indicator, error: error.message });
      return { source: 'hybridAnalysis', success: false, error: error.message };
    }
  }

  /**
   * Check ThreatCrowd for indicator
   * @param {string} indicator - IOC to check
   * @param {string} type - Indicator type
   * @returns {Promise<Object>} ThreatCrowd result
   * @private
   */
  async checkThreatCrowd(indicator, type) {
    if (!this.sources.openSource.threatCrowd.enabled) {
      return { source: 'threatCrowd', success: false, error: 'ThreatCrowd not enabled' };
    }

    try {
      logger.debug('Checking ThreatCrowd', { indicator, type });
      
      // Mock implementation - replace with actual ThreatCrowd API calls
      const mockResult = {
        source: 'threatCrowd',
        success: true,
        data: {
          response_code: '1',
          votes: Math.floor(Math.random() * 10),
          resource: indicator,
          scans: [],
          permalink: `https://threatcrowd.org/`
        },
        confidence: 0.6,
        categories: ['malware']
      };

      return mockResult;

    } catch (error) {
      logger.warn('ThreatCrowd check failed', { indicator, error: error.message });
      return { source: 'threatCrowd', success: false, error: error.message };
    }
  }

  /**
   * Check Shodan for IP information
   * @param {string} indicator - IOC to check
   * @param {string} type - Indicator type
   * @returns {Promise<Object>} Shodan result
   * @private
   */
  async checkShodan(indicator, type) {
    if (type !== 'ip' || !this.sources.openSource.shodan.enabled) {
      return { source: 'shodan', success: false, error: 'Not applicable for this indicator type' };
    }

    try {
      logger.debug('Checking Shodan', { indicator });
      
      // Mock implementation - replace with actual Shodan API calls
      const mockResult = {
        source: 'shodan',
        success: true,
        data: {
          ip_str: indicator,
          country_name: 'United States',
          org: 'Example ISP',
          ports: [22, 80, 443],
          vulns: [],
          last_update: new Date()
        },
        confidence: 0.7,
        categories: ['infrastructure']
      };

      return mockResult;

    } catch (error) {
      logger.warn('Shodan check failed', { indicator, error: error.message });
      return { source: 'shodan', success: false, error: error.message };
    }
  }

  /**
   * Check Reddit for mentions of indicator
   * @param {string} indicator - IOC to check
   * @returns {Promise<Object>} Reddit mentions result
   * @private
   */
  async checkRedditMentions(indicator) {
    if (!this.sources.social.reddit.enabled) {
      return { source: 'reddit', success: false, error: 'Reddit monitoring not enabled' };
    }

    try {
      logger.debug('Checking Reddit mentions', { indicator });
      
      // Mock implementation - replace with actual Reddit API calls
      const mockResult = {
        source: 'reddit',
        success: true,
        data: {
          mentions: Math.floor(Math.random() * 5),
          subreddits: ['cybersecurity', 'malware'],
          recent_posts: [],
          sentiment: 'negative'
        },
        confidence: this.confidenceWeights.reddit,
        categories: ['social_mention']
      };

      return mockResult;

    } catch (error) {
      logger.warn('Reddit check failed', { indicator, error: error.message });
      return { source: 'reddit', success: false, error: error.message };
    }
  }

  /**
   * Check Twitter for mentions of indicator
   * @param {string} indicator - IOC to check
   * @returns {Promise<Object>} Twitter mentions result
   * @private
   */
  async checkTwitterMentions(indicator) {
    if (!this.sources.social.twitter.enabled) {
      return { source: 'twitter', success: false, error: 'Twitter monitoring not enabled' };
    }

    try {
      logger.debug('Checking Twitter mentions', { indicator });
      
      // Mock implementation - replace with actual Twitter API calls
      const mockResult = {
        source: 'twitter',
        success: true,
        data: {
          mentions: Math.floor(Math.random() * 10),
          accounts: ['@malware_traffic', '@abuse_ch'],
          recent_tweets: [],
          sentiment: 'negative'
        },
        confidence: this.confidenceWeights.twitter,
        categories: ['social_mention']
      };

      return mockResult;

    } catch (error) {
      logger.warn('Twitter check failed', { indicator, error: error.message });
      return { source: 'twitter', success: false, error: error.message };
    }
  }

  /**
   * Check Microsoft Sentinel threat intelligence
   * @param {string} indicator - IOC to check
   * @returns {Promise<Object>} Sentinel threat intelligence result
   * @private
   */
  async checkSentinelThreatIntel(indicator) {
    if (!this.sources.microsoft.sentinel.enabled) {
      return { source: 'sentinel', success: false, error: 'Sentinel not enabled' };
    }

    try {
      logger.debug('Checking Sentinel threat intelligence', { indicator });
      
      // Mock implementation - replace with actual Sentinel API calls
      const mockResult = {
        source: 'sentinel',
        success: true,
        data: {
          indicatorId: `ti-${Date.now()}`,
          threatType: 'malware',
          confidence: 85,
          firstSeen: new Date(),
          lastSeen: new Date(),
          isActive: true,
          tags: ['apt', 'malware']
        },
        confidence: this.confidenceWeights.sentinel,
        categories: ['microsoft_intel']
      };

      return mockResult;

    } catch (error) {
      logger.warn('Sentinel check failed', { indicator, error: error.message });
      return { source: 'sentinel', success: false, error: error.message };
    }
  }

  /**
   * Detect indicator type based on format
   * @param {string} indicator - IOC value
   * @returns {string} Indicator type
   * @private
   */
  detectIndicatorType(indicator) {
    if (/^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$/.test(indicator)) {
      return 'ip';
    } else if (/^[a-fA-F0-9]{32}$/.test(indicator)) {
      return 'hash';
    } else if (/^[a-fA-F0-9]{40}$/.test(indicator)) {
      return 'hash';
    } else if (/^[a-fA-F0-9]{64}$/.test(indicator)) {
      return 'hash';
    } else if (/^https?:\/\/.+/.test(indicator)) {
      return 'url';
    } else if (/^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}$/.test(indicator)) {
      return 'domain';
    } else if (/^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(indicator)) {
      return 'email';
    } else {
      return 'unknown';
    }
  }

  /**
   * Process source results into standardized format
   * @param {Array} results - Raw source results
   * @returns {Array} Processed source results
   * @private
   */
  processSourceResults(results) {
    return results.map((result, index) => {
      if (result.status === 'fulfilled') {
        return result.value;
      } else {
        return {
          source: `source_${index}`,
          success: false,
          error: result.reason?.message || 'Unknown error',
          confidence: 0,
          categories: []
        };
      }
    });
  }

  /**
   * Calculate overall threat score
   * @param {Array} sources - Source results
   * @returns {number} Threat score (0-100)
   * @private
   */
  calculateThreatScore(sources) {
    const successfulSources = sources.filter(s => s.success);
    if (successfulSources.length === 0) return 0;

    let totalScore = 0;
    let totalWeight = 0;

    successfulSources.forEach(source => {
      const weight = this.confidenceWeights[source.source] || 0.5;
      let score = 0;

      // Calculate score based on source type
      switch (source.source) {
        case 'virusTotal':
          score = (source.data.positives / source.data.total) * 100;
          break;
        case 'abuseIPDB':
          score = source.data.abuseConfidenceScore;
          break;
        case 'hybridAnalysis':
          score = source.data.threat_score;
          break;
        case 'sentinel':
          score = source.data.confidence;
          break;
        default:
          score = 50; // Default moderate score
      }

      totalScore += score * weight;
      totalWeight += weight;
    });

    return totalWeight > 0 ? Math.round(totalScore / totalWeight) : 0;
  }

  /**
   * Calculate confidence level
   * @param {Array} sources - Source results
   * @returns {string} Confidence level
   * @private
   */
  calculateConfidence(sources) {
    const successfulSources = sources.filter(s => s.success);
    const avgConfidence = successfulSources.reduce((sum, s) => sum + s.confidence, 0) / successfulSources.length;
    
    if (avgConfidence > 0.8) return 'high';
    if (avgConfidence > 0.6) return 'medium';
    if (avgConfidence > 0.3) return 'low';
    return 'unknown';
  }

  /**
   * Determine reputation based on threat score
   * @param {number} score - Threat score
   * @returns {string} Reputation level
   * @private
   */
  determineReputation(score) {
    if (score > 80) return 'malicious';
    if (score > 60) return 'suspicious';
    if (score > 20) return 'questionable';
    return 'clean';
  }

  /**
   * Extract threat types from sources
   * @param {Array} sources - Source results
   * @returns {Array} Threat types
   * @private
   */
  extractThreatTypes(sources) {
    const types = new Set();
    sources.forEach(source => {
      if (source.success && source.data) {
        // Extract threat types based on source data
        if (source.data.threatType) types.add(source.data.threatType);
        if (source.data.verdict) types.add(source.data.verdict);
      }
    });
    return Array.from(types);
  }

  /**
   * Extract categories from sources
   * @param {Array} sources - Source results
   * @returns {Array} Categories
   * @private
   */
  extractCategories(sources) {
    const categories = new Set();
    sources.forEach(source => {
      if (source.success && source.categories) {
        source.categories.forEach(cat => categories.add(cat));
      }
    });
    return Array.from(categories);
  }

  /**
   * Summarize analysis results
   * @param {Array} results - Analysis results
   * @returns {Object} Summary
   * @private
   */
  summarizeAnalysis(results) {
    const successful = results.filter(r => r.success);
    const malicious = successful.filter(r => r.data?.isMalicious);
    const highConfidence = successful.filter(r => r.data?.confidence === 'high');

    return {
      totalIndicators: results.length,
      successfulAnalysis: successful.length,
      maliciousCount: malicious.length,
      highConfidenceCount: highConfidence.length,
      highConfidenceMatch: highConfidence.length > 0,
      mediumConfidenceMatch: successful.filter(r => r.data?.confidence === 'medium').length > 0,
      overallRisk: malicious.length > 0 ? 'high' : 'low',
      recommendations: this.generateRecommendations(results)
    };
  }

  /**
   * Generate recommendations based on analysis
   * @param {Array} results - Analysis results
   * @returns {Array} Recommendations
   * @private
   */
  generateRecommendations(results) {
    const recommendations = [];
    const malicious = results.filter(r => r.success && r.data?.isMalicious);
    
    if (malicious.length > 0) {
      recommendations.push('Block identified malicious indicators');
      recommendations.push('Investigate systems that may have contacted these indicators');
      recommendations.push('Update security controls to prevent future exposure');
    }

    if (results.some(r => r.success && r.data?.confidence === 'high')) {
      recommendations.push('Priority investigation required for high-confidence matches');
    }

    return recommendations;
  }
}

module.exports = new ThreatIntelligenceService();