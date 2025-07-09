/**
 * Security Event Management Service
 * 
 * Comprehensive security event handling with automated triage, investigation,
 * and remediation capabilities integrated with Microsoft security ecosystem.
 */
const { logger } = require('../../utils/logger');
const cacheService = require('../cache/cacheService');
const microsoftSecurityService = require('./microsoftSecurityService');
const threatIntelligenceService = require('./threatIntelligenceService');
const soarService = require('./soarService');
const spyCloudService = require('./spyCloudService');
const config = require('../../config');

// Event severities and priorities
const EVENT_SEVERITY = {
  CRITICAL: 'critical',
  HIGH: 'high',
  MEDIUM: 'medium',
  LOW: 'low',
  INFO: 'info'
};

const EVENT_STATUS = {
  NEW: 'new',
  TRIAGED: 'triaged',
  INVESTIGATING: 'investigating',
  REMEDIATING: 'remediating',
  RESOLVED: 'resolved',
  CLOSED: 'closed',
  FALSE_POSITIVE: 'false_positive'
};

const INVESTIGATION_CONFIDENCE = {
  HIGH: 'high',
  MEDIUM: 'medium',
  LOW: 'low',
  UNKNOWN: 'unknown'
};

class SecurityEventManager {
  constructor() {
    this.eventQueue = [];
    this.activeInvestigations = new Map();
    this.remediationPlaybooks = new Map();
    this.triageRules = [];
    this.initializeTriageRules();
    this.initializeRemediationPlaybooks();
  }

  /**
   * Initialize automated triage rules
   * @private
   */
  initializeTriageRules() {
    this.triageRules = [
      // Critical events - immediate response required
      {
        id: 'malware_detected',
        priority: 1,
        conditions: {
          eventType: ['malware_detection', 'virus_detected'],
          severity: [EVENT_SEVERITY.CRITICAL, EVENT_SEVERITY.HIGH]
        },
        actions: ['isolate_endpoint', 'escalate_to_soc', 'auto_remediate'],
        autoRemediate: true,
        escalationLevel: 'immediate'
      },
      {
        id: 'ransomware_indicators',
        priority: 1,
        conditions: {
          eventType: ['file_encryption', 'mass_file_deletion', 'ransom_note'],
          indicators: ['entropy_spike', 'file_extension_change']
        },
        actions: ['isolate_endpoint', 'backup_verification', 'incident_response'],
        autoRemediate: true,
        escalationLevel: 'immediate'
      },
      // High priority events
      {
        id: 'suspicious_authentication',
        priority: 2,
        conditions: {
          eventType: ['impossible_travel', 'brute_force', 'credential_stuffing'],
          severity: [EVENT_SEVERITY.HIGH, EVENT_SEVERITY.MEDIUM]
        },
        actions: ['disable_account', 'require_mfa', 'notify_user'],
        autoRemediate: true,
        escalationLevel: 'high'
      },
      {
        id: 'privilege_escalation',
        priority: 2,
        conditions: {
          eventType: ['privilege_escalation', 'admin_rights_granted'],
          context: ['unexpected', 'suspicious']
        },
        actions: ['revoke_privileges', 'investigate_source', 'audit_permissions'],
        autoRemediate: false,
        escalationLevel: 'high'
      },
      // Medium priority events
      {
        id: 'network_anomaly',
        priority: 3,
        conditions: {
          eventType: ['unusual_traffic', 'port_scan', 'dns_tunneling'],
          severity: [EVENT_SEVERITY.MEDIUM]
        },
        actions: ['network_analysis', 'traffic_monitoring', 'firewall_update'],
        autoRemediate: true,
        escalationLevel: 'medium'
      },
      // Low priority events
      {
        id: 'policy_violation',
        priority: 4,
        conditions: {
          eventType: ['policy_violation', 'compliance_deviation'],
          severity: [EVENT_SEVERITY.LOW, EVENT_SEVERITY.INFO]
        },
        actions: ['policy_enforcement', 'user_notification', 'compliance_report'],
        autoRemediate: true,
        escalationLevel: 'low'
      }
    ];
  }

  /**
   * Initialize automated remediation playbooks
   * @private
   */
  initializeRemediationPlaybooks() {
    this.remediationPlaybooks.set('isolate_endpoint', {
      name: 'Endpoint Isolation',
      description: 'Isolate compromised endpoint from network',
      steps: [
        { action: 'defender_isolate_device', params: { isolation_type: 'full' } },
        { action: 'update_firewall_rules', params: { block_device: true } },
        { action: 'notify_administrators', params: { urgency: 'high' } }
      ],
      rollbackSteps: [
        { action: 'defender_release_device', params: {} },
        { action: 'restore_firewall_rules', params: {} }
      ],
      successCriteria: ['device_isolated', 'network_blocked'],
      timeoutMinutes: 5
    });

    this.remediationPlaybooks.set('disable_account', {
      name: 'Account Suspension',
      description: 'Disable compromised user account',
      steps: [
        { action: 'azure_ad_disable_account', params: {} },
        { action: 'revoke_active_sessions', params: {} },
        { action: 'notify_user_manager', params: {} }
      ],
      rollbackSteps: [
        { action: 'azure_ad_enable_account', params: {} }
      ],
      successCriteria: ['account_disabled', 'sessions_revoked'],
      timeoutMinutes: 3
    });

    this.remediationPlaybooks.set('network_analysis', {
      name: 'Network Traffic Analysis',
      description: 'Analyze suspicious network activity',
      steps: [
        { action: 'capture_network_traffic', params: { duration: 300 } },
        { action: 'analyze_traffic_patterns', params: {} },
        { action: 'check_threat_intelligence', params: {} },
        { action: 'update_security_rules', params: {} }
      ],
      rollbackSteps: [],
      successCriteria: ['traffic_analyzed', 'rules_updated'],
      timeoutMinutes: 15
    });

    this.remediationPlaybooks.set('policy_enforcement', {
      name: 'Policy Enforcement',
      description: 'Enforce security policy violations',
      steps: [
        { action: 'apply_policy_correction', params: {} },
        { action: 'update_compliance_status', params: {} },
        { action: 'schedule_policy_review', params: {} }
      ],
      rollbackSteps: [],
      successCriteria: ['policy_applied', 'compliance_updated'],
      timeoutMinutes: 10
    });
  }

  /**
   * Process incoming security event
   * @param {Object} event - Security event data
   * @returns {Promise<Object>} Processing result
   */
  async processSecurityEvent(event) {
    logger.info('Processing security event', { 
      eventId: event.id, 
      eventType: event.type,
      severity: event.severity 
    });

    try {
      // Enrich event with additional data
      const enrichedEvent = await this.enrichEvent(event);

      // Perform automated triage
      const triageResult = await this.triageEvent(enrichedEvent);

      // Start investigation if required
      if (triageResult.requiresInvestigation) {
        await this.startInvestigation(enrichedEvent, triageResult);
      }

      // Execute automated remediation if applicable
      if (triageResult.autoRemediate && triageResult.remediationActions.length > 0) {
        await this.executeAutomaticRemediation(enrichedEvent, triageResult.remediationActions);
      }

      // Update event status and store
      enrichedEvent.status = triageResult.autoRemediate ? EVENT_STATUS.REMEDIATING : EVENT_STATUS.TRIAGED;
      enrichedEvent.triageResult = triageResult;
      enrichedEvent.processedAt = new Date();

      await this.storeEvent(enrichedEvent);

      return {
        success: true,
        eventId: enrichedEvent.id,
        status: enrichedEvent.status,
        triageResult,
        actions: triageResult.remediationActions
      };

    } catch (error) {
      logger.error('Security event processing failed', {
        error: error.message,
        eventId: event.id,
        stack: error.stack
      });

      throw error;
    }
  }

  /**
   * Enrich security event with contextual data
   * @param {Object} event - Raw security event
   * @returns {Promise<Object>} Enriched event
   * @private
   */
  async enrichEvent(event) {
    const enrichedEvent = { ...event };

    try {
      // Add threat intelligence context
      if (event.indicators) {
        enrichedEvent.threatIntelligence = await threatIntelligenceService.analyzeIndicators(event.indicators);
      }

      // Add device/user context
      if (event.deviceId) {
        enrichedEvent.deviceContext = await this.getDeviceContext(event.deviceId);
      }

      if (event.userId) {
        enrichedEvent.userContext = await this.getUserContext(event.userId);
      }

      // Add network context
      if (event.sourceIp) {
        enrichedEvent.networkContext = await this.getNetworkContext(event.sourceIp);
      }

      // Add historical context
      enrichedEvent.historicalContext = await this.getHistoricalContext(event);

      // Calculate risk score
      enrichedEvent.riskScore = this.calculateRiskScore(enrichedEvent);

      logger.debug('Event enriched successfully', { 
        eventId: event.id,
        riskScore: enrichedEvent.riskScore 
      });

      return enrichedEvent;

    } catch (error) {
      logger.warn('Event enrichment failed, proceeding with basic event', {
        eventId: event.id,
        error: error.message
      });
      return enrichedEvent;
    }
  }

  /**
   * Perform automated triage of security event
   * @param {Object} event - Enriched security event
   * @returns {Promise<Object>} Triage result
   * @private
   */
  async triageEvent(event) {
    logger.debug('Starting event triage', { eventId: event.id });

    const triageResult = {
      eventId: event.id,
      priority: 5, // Default lowest priority
      matchedRules: [],
      remediationActions: [],
      requiresInvestigation: false,
      autoRemediate: false,
      escalationLevel: 'none',
      confidence: INVESTIGATION_CONFIDENCE.UNKNOWN,
      reasoning: []
    };

    // Apply triage rules
    for (const rule of this.triageRules) {
      if (this.evaluateTriageRule(rule, event)) {
        triageResult.matchedRules.push(rule.id);
        
        if (rule.priority < triageResult.priority) {
          triageResult.priority = rule.priority;
          triageResult.escalationLevel = rule.escalationLevel;
          triageResult.autoRemediate = rule.autoRemediate;
          triageResult.remediationActions = rule.actions;
        }

        triageResult.reasoning.push(`Matched rule: ${rule.id}`);
      }
    }

    // Risk-based triage adjustments
    if (event.riskScore > 80) {
      triageResult.priority = Math.min(triageResult.priority, 2);
      triageResult.requiresInvestigation = true;
      triageResult.reasoning.push('High risk score detected');
    }

    // Threat intelligence influence
    if (event.threatIntelligence?.highConfidenceMatch) {
      triageResult.priority = Math.min(triageResult.priority, 1);
      triageResult.confidence = INVESTIGATION_CONFIDENCE.HIGH;
      triageResult.reasoning.push('High confidence threat intelligence match');
    }

    // Set investigation requirement
    triageResult.requiresInvestigation = triageResult.priority <= 3 || event.riskScore > 60;

    logger.info('Event triage completed', {
      eventId: event.id,
      priority: triageResult.priority,
      autoRemediate: triageResult.autoRemediate,
      escalationLevel: triageResult.escalationLevel
    });

    return triageResult;
  }

  /**
   * Evaluate if event matches triage rule
   * @param {Object} rule - Triage rule
   * @param {Object} event - Security event
   * @returns {boolean} Rule match result
   * @private
   */
  evaluateTriageRule(rule, event) {
    const conditions = rule.conditions;

    // Check event type
    if (conditions.eventType && !conditions.eventType.includes(event.type)) {
      return false;
    }

    // Check severity
    if (conditions.severity && !conditions.severity.includes(event.severity)) {
      return false;
    }

    // Check indicators
    if (conditions.indicators && event.indicators) {
      const hasIndicator = conditions.indicators.some(indicator => 
        event.indicators.includes(indicator)
      );
      if (!hasIndicator) return false;
    }

    // Check context
    if (conditions.context && event.context) {
      const hasContext = conditions.context.some(ctx => 
        event.context.includes(ctx)
      );
      if (!hasContext) return false;
    }

    return true;
  }

  /**
   * Start automated investigation
   * @param {Object} event - Security event
   * @param {Object} triageResult - Triage result
   * @returns {Promise<Object>} Investigation result
   * @private
   */
  async startInvestigation(event, triageResult) {
    const investigationId = `inv_${event.id}_${Date.now()}`;
    
    logger.info('Starting security investigation', {
      investigationId,
      eventId: event.id,
      priority: triageResult.priority
    });

    const investigation = {
      id: investigationId,
      eventId: event.id,
      startTime: new Date(),
      status: 'active',
      priority: triageResult.priority,
      investigationSteps: [],
      findings: [],
      evidence: [],
      timeline: []
    };

    // Store active investigation
    this.activeInvestigations.set(investigationId, investigation);

    try {
      // Execute investigation playbook
      await this.executeInvestigationPlaybook(investigation, event);

      return investigation;

    } catch (error) {
      logger.error('Investigation failed', {
        investigationId,
        error: error.message
      });

      investigation.status = 'failed';
      investigation.error = error.message;
      investigation.endTime = new Date();

      throw error;
    }
  }

  /**
   * Execute investigation playbook
   * @param {Object} investigation - Investigation object
   * @param {Object} event - Security event
   * @private
   */
  async executeInvestigationPlaybook(investigation, event) {
    const playbook = this.getInvestigationPlaybook(event.type, event.severity);

    for (const step of playbook.steps) {
      try {
        investigation.investigationSteps.push({
          step: step.name,
          startTime: new Date(),
          status: 'running'
        });

        const stepResult = await this.executeInvestigationStep(step, event, investigation);
        
        const currentStep = investigation.investigationSteps[investigation.investigationSteps.length - 1];
        currentStep.status = 'completed';
        currentStep.endTime = new Date();
        currentStep.result = stepResult;

        if (stepResult.findings) {
          investigation.findings.push(...stepResult.findings);
        }

        if (stepResult.evidence) {
          investigation.evidence.push(...stepResult.evidence);
        }

      } catch (error) {
        const currentStep = investigation.investigationSteps[investigation.investigationSteps.length - 1];
        currentStep.status = 'failed';
        currentStep.error = error.message;
        currentStep.endTime = new Date();

        logger.warn('Investigation step failed', {
          investigationId: investigation.id,
          step: step.name,
          error: error.message
        });
      }
    }

    // Analyze investigation results
    investigation.conclusion = this.analyzeInvestigationResults(investigation);
    investigation.status = 'completed';
    investigation.endTime = new Date();

    logger.info('Investigation completed', {
      investigationId: investigation.id,
      conclusion: investigation.conclusion,
      findingsCount: investigation.findings.length
    });
  }

  /**
   * Execute automatic remediation
   * @param {Object} event - Security event
   * @param {Array} actions - Remediation actions
   * @returns {Promise<Object>} Remediation result
   * @private
   */
  async executeAutomaticRemediation(event, actions) {
    const remediationId = `rem_${event.id}_${Date.now()}`;
    
    logger.info('Starting automatic remediation', {
      remediationId,
      eventId: event.id,
      actions
    });

    const remediation = {
      id: remediationId,
      eventId: event.id,
      startTime: new Date(),
      status: 'running',
      actions: [],
      success: false,
      rollbackRequired: false
    };

    try {
      for (const actionName of actions) {
        const playbook = this.remediationPlaybooks.get(actionName);
        if (!playbook) {
          logger.warn('Remediation playbook not found', { actionName });
          continue;
        }

        const actionResult = await this.executeRemediationPlaybook(playbook, event);
        
        remediation.actions.push({
          name: actionName,
          playbook: playbook.name,
          result: actionResult,
          timestamp: new Date()
        });

        if (!actionResult.success && playbook.rollbackSteps.length > 0) {
          remediation.rollbackRequired = true;
          break;
        }
      }

      remediation.success = remediation.actions.every(action => action.result.success);
      remediation.status = remediation.success ? 'completed' : 'failed';
      remediation.endTime = new Date();

      // Execute rollback if required
      if (remediation.rollbackRequired) {
        await this.executeRollback(remediation);
      }

      logger.info('Automatic remediation completed', {
        remediationId,
        success: remediation.success,
        actionsExecuted: remediation.actions.length
      });

      return remediation;

    } catch (error) {
      logger.error('Automatic remediation failed', {
        remediationId,
        error: error.message
      });

      remediation.status = 'failed';
      remediation.error = error.message;
      remediation.endTime = new Date();

      throw error;
    }
  }

  /**
   * Execute remediation playbook
   * @param {Object} playbook - Remediation playbook
   * @param {Object} event - Security event
   * @returns {Promise<Object>} Execution result
   * @private
   */
  async executeRemediationPlaybook(playbook, event) {
    logger.debug('Executing remediation playbook', { 
      playbookName: playbook.name,
      eventId: event.id 
    });

    const result = {
      playbookName: playbook.name,
      success: false,
      steps: [],
      error: null
    };

    try {
      for (const step of playbook.steps) {
        const stepResult = await soarService.executeAction(step.action, {
          ...step.params,
          event,
          context: { playbook: playbook.name }
        });

        result.steps.push({
          action: step.action,
          success: stepResult.success,
          result: stepResult.result,
          timestamp: new Date()
        });

        if (!stepResult.success) {
          result.error = stepResult.error;
          break;
        }
      }

      result.success = result.steps.every(step => step.success);

      return result;

    } catch (error) {
      result.error = error.message;
      logger.error('Remediation playbook execution failed', {
        playbookName: playbook.name,
        error: error.message
      });

      throw error;
    }
  }

  /**
   * Get investigation playbook based on event type and severity
   * @param {string} eventType - Event type
   * @param {string} severity - Event severity
   * @returns {Object} Investigation playbook
   * @private
   */
  getInvestigationPlaybook(eventType, severity) {
    // Dynamic playbook generation based on event characteristics
    const baseSteps = [
      { name: 'gather_basic_info', action: 'collect_event_metadata' },
      { name: 'check_threat_intelligence', action: 'query_threat_feeds' },
      { name: 'analyze_user_behavior', action: 'behavioral_analysis' },
      { name: 'check_historical_patterns', action: 'pattern_analysis' }
    ];

    const severitySteps = {
      [EVENT_SEVERITY.CRITICAL]: [
        { name: 'immediate_containment_check', action: 'verify_containment' },
        { name: 'impact_assessment', action: 'assess_blast_radius' },
        { name: 'stakeholder_notification', action: 'notify_executives' }
      ],
      [EVENT_SEVERITY.HIGH]: [
        { name: 'containment_evaluation', action: 'evaluate_containment' },
        { name: 'impact_assessment', action: 'assess_impact' }
      ]
    };

    const typeSteps = {
      'malware_detection': [
        { name: 'malware_analysis', action: 'analyze_malware_sample' },
        { name: 'infection_vector_analysis', action: 'trace_infection_path' }
      ],
      'suspicious_authentication': [
        { name: 'authentication_analysis', action: 'analyze_auth_patterns' },
        { name: 'account_compromise_check', action: 'check_account_status' }
      ]
    };

    return {
      name: `Investigation_${eventType}_${severity}`,
      steps: [
        ...baseSteps,
        ...(severitySteps[severity] || []),
        ...(typeSteps[eventType] || [])
      ]
    };
  }

  /**
   * Calculate risk score for event
   * @param {Object} event - Enriched event
   * @returns {number} Risk score (0-100)
   * @private
   */
  calculateRiskScore(event) {
    let score = 0;

    // Base severity score
    const severityScores = {
      [EVENT_SEVERITY.CRITICAL]: 40,
      [EVENT_SEVERITY.HIGH]: 30,
      [EVENT_SEVERITY.MEDIUM]: 20,
      [EVENT_SEVERITY.LOW]: 10,
      [EVENT_SEVERITY.INFO]: 5
    };
    score += severityScores[event.severity] || 0;

    // Threat intelligence boost
    if (event.threatIntelligence?.highConfidenceMatch) {
      score += 25;
    } else if (event.threatIntelligence?.mediumConfidenceMatch) {
      score += 15;
    }

    // User context influence
    if (event.userContext?.isPrivileged) {
      score += 15;
    }
    if (event.userContext?.hasRecentSuspiciousActivity) {
      score += 10;
    }

    // Device context influence
    if (event.deviceContext?.isManaged === false) {
      score += 10;
    }
    if (event.deviceContext?.hasKnownVulnerabilities) {
      score += 10;
    }

    // Network context influence
    if (event.networkContext?.isFromKnownBadIp) {
      score += 20;
    }
    if (event.networkContext?.isFromUnusualLocation) {
      score += 5;
    }

    // Cap at 100
    return Math.min(score, 100);
  }

  /**
   * Get device context for enrichment
   * @param {string} deviceId - Device ID
   * @returns {Promise<Object>} Device context
   * @private
   */
  async getDeviceContext(deviceId) {
    try {
      // This would integrate with Microsoft Defender for Endpoint
      const deviceInfo = await microsoftSecurityService.getDeviceInfo(deviceId);
      
      return {
        isManaged: deviceInfo.isManaged,
        complianceState: deviceInfo.complianceState,
        riskLevel: deviceInfo.riskLevel,
        hasKnownVulnerabilities: deviceInfo.vulnerabilityCount > 0,
        lastSeen: deviceInfo.lastSeen,
        deviceType: deviceInfo.deviceType,
        operatingSystem: deviceInfo.operatingSystem
      };
    } catch (error) {
      logger.warn('Failed to get device context', { deviceId, error: error.message });
      return {};
    }
  }

  /**
   * Get user context for enrichment
   * @param {string} userId - User ID
   * @returns {Promise<Object>} User context
   * @private
   */
  async getUserContext(userId) {
    try {
      // This would integrate with Azure AD and other Microsoft security tools
      const userInfo = await microsoftSecurityService.getUserInfo(userId);
      
      return {
        isPrivileged: userInfo.isPrivileged,
        riskState: userInfo.riskState,
        hasRecentSuspiciousActivity: userInfo.hasRecentSuspiciousActivity,
        department: userInfo.department,
        lastSignIn: userInfo.lastSignIn,
        signInRiskLevel: userInfo.signInRiskLevel,
        userRiskLevel: userInfo.userRiskLevel
      };
    } catch (error) {
      logger.warn('Failed to get user context', { userId, error: error.message });
      return {};
    }
  }

  /**
   * Get network context for enrichment
   * @param {string} sourceIp - Source IP address
   * @returns {Promise<Object>} Network context
   * @private
   */
  async getNetworkContext(sourceIp) {
    try {
      const [threatIntel, geoLocation] = await Promise.all([
        threatIntelligenceService.checkIpReputation(sourceIp),
        this.getIpGeolocation(sourceIp)
      ]);
      
      return {
        isFromKnownBadIp: threatIntel.isMalicious,
        threatCategories: threatIntel.categories,
        isFromUnusualLocation: geoLocation.isUnusual,
        country: geoLocation.country,
        region: geoLocation.region,
        isp: geoLocation.isp,
        isVpn: geoLocation.isVpn,
        isTor: geoLocation.isTor
      };
    } catch (error) {
      logger.warn('Failed to get network context', { sourceIp, error: error.message });
      return {};
    }
  }

  /**
   * Get historical context for event
   * @param {Object} event - Security event
   * @returns {Promise<Object>} Historical context
   * @private
   */
  async getHistoricalContext(event) {
    try {
      // Check for similar events in the past
      const similarEvents = await this.findSimilarEvents(event, 30); // Last 30 days
      
      return {
        similarEventCount: similarEvents.length,
        lastSimilarEvent: similarEvents[0]?.timestamp || null,
        isRepeatedPattern: similarEvents.length > 2,
        escalationTrend: this.calculateEscalationTrend(similarEvents)
      };
    } catch (error) {
      logger.warn('Failed to get historical context', { eventId: event.id, error: error.message });
      return {};
    }
  }

  /**
   * Store security event
   * @param {Object} event - Processed security event
   * @private
   */
  async storeEvent(event) {
    try {
      // Store in cache for quick access
      await cacheService.set(`security:event:${event.id}`, event, 24 * 60 * 60); // 24 hours

      // Store in database (implementation would depend on your database choice)
      // await database.securityEvents.insert(event);

      logger.debug('Security event stored', { eventId: event.id });
    } catch (error) {
      logger.error('Failed to store security event', { 
        eventId: event.id, 
        error: error.message 
      });
    }
  }

  /**
   * Get real-time security dashboard data
   * @param {string} tenantId - Tenant ID
   * @returns {Promise<Object>} Dashboard data
   */
  async getSecurityDashboard(tenantId) {
    try {
      const [events, investigations, remediations, threatLevel] = await Promise.all([
        this.getRecentEvents(tenantId, 24), // Last 24 hours
        this.getActiveInvestigations(tenantId),
        this.getRecentRemediations(tenantId, 24),
        this.calculateThreatLevel(tenantId)
      ]);

      return {
        tenantId,
        lastUpdated: new Date(),
        summary: {
          totalEvents: events.length,
          criticalEvents: events.filter(e => e.severity === EVENT_SEVERITY.CRITICAL).length,
          activeInvestigations: investigations.length,
          autoRemediations: remediations.filter(r => r.automated).length,
          currentThreatLevel: threatLevel
        },
        events: events.slice(0, 10), // Top 10 recent events
        investigations: investigations.slice(0, 5), // Top 5 active investigations
        remediations: remediations.slice(0, 10), // Recent remediations
        metrics: {
          meanTimeToDetection: this.calculateMTTD(events),
          meanTimeToResponse: this.calculateMTTR(events),
          autoRemediationRate: this.calculateAutoRemediationRate(events)
        }
      };
    } catch (error) {
      logger.error('Failed to get security dashboard data', { 
        tenantId, 
        error: error.message 
      });
      throw error;
    }
  }

  // Helper methods for dashboard calculations
  calculateMTTD(events) {
    // Calculate Mean Time To Detection
    return '2.3 minutes'; // Placeholder
  }

  calculateMTTR(events) {
    // Calculate Mean Time To Response
    return '4.7 minutes'; // Placeholder
  }

  calculateAutoRemediationRate(events) {
    const autoRemediated = events.filter(e => 
      e.triageResult?.autoRemediate && e.status === EVENT_STATUS.RESOLVED
    ).length;
    return events.length > 0 ? Math.round((autoRemediated / events.length) * 100) : 0;
  }

  // Additional helper methods would be implemented here...
  async getRecentEvents(tenantId, hours) {
    // Implementation for fetching recent events
    return [];
  }

  async getActiveInvestigations(tenantId) {
    // Implementation for fetching active investigations
    return [];
  }

  async getRecentRemediations(tenantId, hours) {
    // Implementation for fetching recent remediations
    return [];
  }

  async calculateThreatLevel(tenantId) {
    // Implementation for calculating current threat level
    return 'MEDIUM';
  }

  async findSimilarEvents(event, days) {
    // Implementation for finding similar historical events
    return [];
  }

  calculateEscalationTrend(events) {
    // Implementation for calculating escalation trend
    return 'stable';
  }

  async executeInvestigationStep(step, event, investigation) {
    // Implementation for executing investigation steps
    return { findings: [], evidence: [] };
  }

  analyzeInvestigationResults(investigation) {
    // Implementation for analyzing investigation results
    return {
      verdict: 'confirmed_threat',
      confidence: INVESTIGATION_CONFIDENCE.HIGH,
      recommendation: 'immediate_containment'
    };
  }

  async executeRollback(remediation) {
    // Implementation for executing rollback procedures
    logger.info('Executing remediation rollback', { remediationId: remediation.id });
  }

  async getIpGeolocation(ip) {
    // Implementation for IP geolocation lookup
    return {
      country: 'Unknown',
      region: 'Unknown',
      isUnusual: false,
      isp: 'Unknown',
      isVpn: false,
      isTor: false
    };
  }
}

module.exports = new SecurityEventManager();