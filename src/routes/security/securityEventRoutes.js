/**
 * Security Event Management API Routes
 * 
 * Provides REST endpoints for the comprehensive security event management system
 * including event processing, threat intelligence, and security dashboard.
 */
const express = require('express');
const router = express.Router();
const securityEventManager = require('../../services/security/securityEventManager');
const threatIntelligenceService = require('../../services/security/threatIntelligenceService');
const soarService = require('../../services/security/soarService');
const microsoftSecurityService = require('../../services/security/microsoftSecurityService');
const { logger } = require('../../utils/logger');

/**
 * POST /api/security/events
 * Process a security event
 */
router.post('/events', async (req, res) => {
  try {
    const event = req.body;
    
    // Validate required fields
    if (!event.id || !event.type || !event.severity) {
      return res.status(400).json({
        error: 'Missing required fields: id, type, severity'
      });
    }

    const result = await securityEventManager.processSecurityEvent(event);
    
    res.status(201).json({
      success: true,
      data: result
    });

  } catch (error) {
    logger.error('Failed to process security event', { error: error.message });
    res.status(500).json({
      error: 'Failed to process security event',
      message: error.message
    });
  }
});

/**
 * GET /api/security/dashboard/:tenantId
 * Get security dashboard data
 */
router.get('/dashboard/:tenantId', async (req, res) => {
  try {
    const { tenantId } = req.params;
    const dashboard = await securityEventManager.getSecurityDashboard(tenantId);
    
    res.json({
      success: true,
      data: dashboard
    });

  } catch (error) {
    logger.error('Failed to get security dashboard', { error: error.message });
    res.status(500).json({
      error: 'Failed to get security dashboard',
      message: error.message
    });
  }
});

/**
 * POST /api/security/threat-intelligence/analyze
 * Analyze indicators of compromise
 */
router.post('/threat-intelligence/analyze', async (req, res) => {
  try {
    const { indicators } = req.body;
    
    if (!indicators || !Array.isArray(indicators)) {
      return res.status(400).json({
        error: 'indicators array is required'
      });
    }

    const analysis = await threatIntelligenceService.analyzeIndicators(indicators);
    
    res.json({
      success: true,
      data: analysis
    });

  } catch (error) {
    logger.error('Failed to analyze indicators', { error: error.message });
    res.status(500).json({
      error: 'Failed to analyze indicators',
      message: error.message
    });
  }
});

/**
 * GET /api/security/threat-intelligence/ip/:ip
 * Check IP reputation
 */
router.get('/threat-intelligence/ip/:ip', async (req, res) => {
  try {
    const { ip } = req.params;
    const reputation = await threatIntelligenceService.checkIpReputation(ip);
    
    res.json({
      success: true,
      data: reputation
    });

  } catch (error) {
    logger.error('Failed to check IP reputation', { error: error.message });
    res.status(500).json({
      error: 'Failed to check IP reputation',
      message: error.message
    });
  }
});

/**
 * POST /api/security/actions/execute
 * Execute security action
 */
router.post('/actions/execute', async (req, res) => {
  try {
    const { actionType, parameters } = req.body;
    
    if (!actionType) {
      return res.status(400).json({
        error: 'actionType is required'
      });
    }

    const result = await soarService.executeAction(actionType, parameters);
    
    res.json({
      success: true,
      data: result
    });

  } catch (error) {
    logger.error('Failed to execute security action', { error: error.message });
    res.status(500).json({
      error: 'Failed to execute security action',
      message: error.message
    });
  }
});

/**
 * GET /api/security/actions/active
 * Get active security actions
 */
router.get('/actions/active', async (req, res) => {
  try {
    const activeActions = soarService.getActiveActions();
    
    res.json({
      success: true,
      data: activeActions
    });

  } catch (error) {
    logger.error('Failed to get active actions', { error: error.message });
    res.status(500).json({
      error: 'Failed to get active actions',
      message: error.message
    });
  }
});

/**
 * GET /api/security/actions/history
 * Get action execution history
 */
router.get('/actions/history', async (req, res) => {
  try {
    const { limit = 100 } = req.query;
    const history = soarService.getActionHistory(parseInt(limit));
    
    res.json({
      success: true,
      data: history
    });

  } catch (error) {
    logger.error('Failed to get action history', { error: error.message });
    res.status(500).json({
      error: 'Failed to get action history',
      message: error.message
    });
  }
});

/**
 * POST /api/security/microsoft/isolate-device
 * Isolate device using Microsoft Defender
 */
router.post('/microsoft/isolate-device', async (req, res) => {
  try {
    const { deviceId, isolationType = 'full' } = req.body;
    
    if (!deviceId) {
      return res.status(400).json({
        error: 'deviceId is required'
      });
    }

    const result = await microsoftSecurityService.isolateDevice(deviceId, isolationType);
    
    res.json({
      success: true,
      data: result
    });

  } catch (error) {
    logger.error('Failed to isolate device', { error: error.message });
    res.status(500).json({
      error: 'Failed to isolate device',
      message: error.message
    });
  }
});

/**
 * POST /api/security/microsoft/release-device
 * Release device from isolation
 */
router.post('/microsoft/release-device', async (req, res) => {
  try {
    const { deviceId } = req.body;
    
    if (!deviceId) {
      return res.status(400).json({
        error: 'deviceId is required'
      });
    }

    const result = await microsoftSecurityService.releaseDevice(deviceId);
    
    res.json({
      success: true,
      data: result
    });

  } catch (error) {
    logger.error('Failed to release device', { error: error.message });
    res.status(500).json({
      error: 'Failed to release device',
      message: error.message
    });
  }
});

/**
 * POST /api/security/microsoft/disable-account
 * Disable user account
 */
router.post('/microsoft/disable-account', async (req, res) => {
  try {
    const { userId } = req.body;
    
    if (!userId) {
      return res.status(400).json({
        error: 'userId is required'
      });
    }

    const result = await microsoftSecurityService.disableUserAccount(userId);
    
    res.json({
      success: true,
      data: result
    });

  } catch (error) {
    logger.error('Failed to disable account', { error: error.message });
    res.status(500).json({
      error: 'Failed to disable account',
      message: error.message
    });
  }
});

/**
 * POST /api/security/microsoft/enable-account
 * Enable user account
 */
router.post('/microsoft/enable-account', async (req, res) => {
  try {
    const { userId } = req.body;
    
    if (!userId) {
      return res.status(400).json({
        error: 'userId is required'
      });
    }

    const result = await microsoftSecurityService.enableUserAccount(userId);
    
    res.json({
      success: true,
      data: result
    });

  } catch (error) {
    logger.error('Failed to enable account', { error: error.message });
    res.status(500).json({
      error: 'Failed to enable account',
      message: error.message
    });
  }
});

/**
 * POST /api/security/microsoft/revoke-sessions
 * Revoke user sessions
 */
router.post('/microsoft/revoke-sessions', async (req, res) => {
  try {
    const { userId } = req.body;
    
    if (!userId) {
      return res.status(400).json({
        error: 'userId is required'
      });
    }

    const result = await microsoftSecurityService.revokeUserSessions(userId);
    
    res.json({
      success: true,
      data: result
    });

  } catch (error) {
    logger.error('Failed to revoke sessions', { error: error.message });
    res.status(500).json({
      error: 'Failed to revoke sessions',
      message: error.message
    });
  }
});

/**
 * GET /api/security/microsoft/device/:deviceId
 * Get device information
 */
router.get('/microsoft/device/:deviceId', async (req, res) => {
  try {
    const { deviceId } = req.params;
    const deviceInfo = await microsoftSecurityService.getDeviceInfo(deviceId);
    
    res.json({
      success: true,
      data: deviceInfo
    });

  } catch (error) {
    logger.error('Failed to get device info', { error: error.message });
    res.status(500).json({
      error: 'Failed to get device info',
      message: error.message
    });
  }
});

/**
 * GET /api/security/microsoft/user/:userId
 * Get user information
 */
router.get('/microsoft/user/:userId', async (req, res) => {
  try {
    const { userId } = req.params;
    const userInfo = await microsoftSecurityService.getUserInfo(userId);
    
    res.json({
      success: true,
      data: userInfo
    });

  } catch (error) {
    logger.error('Failed to get user info', { error: error.message });
    res.status(500).json({
      error: 'Failed to get user info',
      message: error.message
    });
  }
});

module.exports = router;