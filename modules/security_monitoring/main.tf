terraform {
  required_version = ">= 1.9.0"
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.0"
    }
    azapi = {
      source  = "Azure/azapi"
      version = "~> 2.4.0"
    }
  }
}

locals {
  tags = merge(
    try(var.global_settings.tags, {}),
    try(var.security_monitoring.tags, {}),
    {
      module = "security_monitoring"
    }
  )
}

# Log Analytics Workspace for Security Monitoring
resource "azurerm_log_analytics_workspace" "security_workspace" {
  name                = "${var.security_monitoring.name}-workspace"
  location            = var.location
  resource_group_name = var.resource_group_name
  sku                 = "PerGB2018"
  retention_in_days   = var.security_monitoring.log_retention_days
  
  tags = local.tags
}

# Security Center Workspace
resource "azurerm_security_center_workspace" "security_center" {
  scope        = "/subscriptions/${data.azurerm_client_config.current.subscription_id}"
  workspace_id = azurerm_log_analytics_workspace.security_workspace.id
}

# Application Insights for DevCenter Monitoring
resource "azurerm_application_insights" "devcenter_insights" {
  name                = "${var.security_monitoring.name}-insights"
  location            = var.location
  resource_group_name = var.resource_group_name
  workspace_id        = azurerm_log_analytics_workspace.security_workspace.id
  application_type    = "web"
  
  tags = local.tags
}

# DevCenter Diagnostic Settings
resource "azurerm_monitor_diagnostic_setting" "devcenter_diagnostics" {
  name                       = "${var.security_monitoring.name}-devcenter-diagnostics"
  target_resource_id         = var.devcenter_id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.security_workspace.id

  dynamic "enabled_log" {
    for_each = var.security_monitoring.devcenter_log_categories
    content {
      category = enabled_log.value
    }
  }

  metric {
    category = "AllMetrics"
    enabled  = true
  }

  depends_on = [azurerm_log_analytics_workspace.security_workspace]
}

# Security Alerts for DevBox Operations
resource "azurerm_monitor_action_group" "security_alerts" {
  name                = "${var.security_monitoring.name}-security-alerts"
  resource_group_name = var.resource_group_name
  short_name          = "sec-alerts"

  dynamic "email_receiver" {
    for_each = var.security_monitoring.alert_email_addresses
    content {
      name          = "email-${email_receiver.key}"
      email_address = email_receiver.value
    }
  }

  webhook_receiver {
    name        = "security-webhook"
    service_uri = var.security_monitoring.webhook_uri
  }

  tags = local.tags
}

# Query Rule for Failed DevBox Provisioning
resource "azurerm_monitor_scheduled_query_rules_alert_v2" "failed_devbox_provisioning" {
  name                = "${var.security_monitoring.name}-failed-devbox-provisioning"
  resource_group_name = var.resource_group_name
  location            = var.location
  
  evaluation_frequency = "PT5M"
  window_duration     = "PT10M"
  scopes              = [azurerm_log_analytics_workspace.security_workspace.id]
  severity            = 2
  
  criteria {
    query = <<-QUERY
      AzureDiagnostics
      | where Category == "DevBoxOperations"
      | where ResultType == "Failed"
      | where TimeGenerated > ago(10m)
      | summarize count() by bin(TimeGenerated, 5m)
      | where count_ > 3
    QUERY
    
    time_aggregation_method = "Count"
    threshold              = 3
    operator               = "GreaterThan"
  }
  
  action {
    action_groups = [azurerm_monitor_action_group.security_alerts.id]
  }
  
  description = "Alert when DevBox provisioning failures exceed threshold"
  enabled     = true
  
  tags = local.tags
}

# Query Rule for Unusual DevBox Access Patterns
resource "azurerm_monitor_scheduled_query_rules_alert_v2" "unusual_devbox_access" {
  name                = "${var.security_monitoring.name}-unusual-devbox-access"
  resource_group_name = var.resource_group_name
  location            = var.location
  
  evaluation_frequency = "PT15M"
  window_duration     = "PT30M"
  scopes              = [azurerm_log_analytics_workspace.security_workspace.id]
  severity            = 3
  
  criteria {
    query = <<-QUERY
      AzureDiagnostics
      | where Category == "DevBoxOperations"
      | where OperationName == "DevBoxConnect"
      | where TimeGenerated > ago(30m)
      | summarize ConnectionCount = count() by UserPrincipalName, bin(TimeGenerated, 15m)
      | where ConnectionCount > 10
    QUERY
    
    time_aggregation_method = "Count"
    threshold              = 1
    operator               = "GreaterThan"
  }
  
  action {
    action_groups = [azurerm_monitor_action_group.security_alerts.id]
  }
  
  description = "Alert on unusual DevBox access patterns"
  enabled     = true
  
  tags = local.tags
}

# Windows 365 Security Monitoring
resource "azurerm_monitor_scheduled_query_rules_alert_v2" "windows365_security_events" {
  name                = "${var.security_monitoring.name}-windows365-security"
  resource_group_name = var.resource_group_name
  location            = var.location
  
  evaluation_frequency = "PT5M"
  window_duration     = "PT15M"
  scopes              = [azurerm_log_analytics_workspace.security_workspace.id]
  severity            = 2
  
  criteria {
    query = <<-QUERY
      SecurityEvent
      | where Computer contains "W365"
      | where EventID in (4625, 4648, 4649, 4771, 4776)
      | where TimeGenerated > ago(15m)
      | summarize FailedAttempts = count() by Computer, Account, bin(TimeGenerated, 5m)
      | where FailedAttempts > 5
    QUERY
    
    time_aggregation_method = "Count"
    threshold              = 1
    operator               = "GreaterThan"
  }
  
  action {
    action_groups = [azurerm_monitor_action_group.security_alerts.id]
  }
  
  description = "Alert on Windows 365 security events"
  enabled     = true
  
  tags = local.tags
}

# AVD Security Monitoring
resource "azurerm_monitor_scheduled_query_rules_alert_v2" "avd_session_anomalies" {
  name                = "${var.security_monitoring.name}-avd-session-anomalies"
  resource_group_name = var.resource_group_name
  location            = var.location
  
  evaluation_frequency = "PT10M"
  window_duration     = "PT30M"
  scopes              = [azurerm_log_analytics_workspace.security_workspace.id]
  severity            = 3
  
  criteria {
    query = <<-QUERY
      WVDConnections
      | where TimeGenerated > ago(30m)
      | where State == "Connected"
      | summarize SessionCount = count() by UserName, bin(TimeGenerated, 10m)
      | where SessionCount > 5
    QUERY
    
    time_aggregation_method = "Count"
    threshold              = 1
    operator               = "GreaterThan"
  }
  
  action {
    action_groups = [azurerm_monitor_action_group.security_alerts.id]
  }
  
  description = "Alert on AVD session anomalies"
  enabled     = true
  
  tags = local.tags
}

# Security Dashboard
resource "azurerm_portal_dashboard" "security_dashboard" {
  name                = "${var.security_monitoring.name}-security-dashboard"
  resource_group_name = var.resource_group_name
  location            = var.location
  
  dashboard_properties = jsonencode({
    lenses = {
      "0" = {
        order = 0
        parts = {
          "0" = {
            position = {
              x = 0
              y = 0
              rowSpan = 4
              colSpan = 6
            }
            metadata = {
              inputs = [
                {
                  name = "resourceTypeMode"
                  isOptional = true
                }
              ]
              type = "Extension/HubsExtension/PartType/MonitorChartPart"
              settings = {
                content = {
                  options = {
                    chart = {
                      metrics = [
                        {
                          resourceMetadata = {
                            id = var.devcenter_id
                          }
                          name = "DevBoxProvisioningSuccessRate"
                          aggregationType = 4
                          namespace = "Microsoft.DevCenter/devcenters"
                          metricVisualization = {
                            displayName = "DevBox Provisioning Success Rate"
                          }
                        }
                      ]
                      title = "DevBox Security Metrics"
                      titleKind = 1
                      visualization = {
                        chartType = 2
                        legendVisualization = {
                          isVisible = true
                          position = 2
                          hideSubtitle = false
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
    metadata = {
      model = {
        timeRange = {
          value = {
            relative = {
              duration = 24
              timeUnit = 1
            }
          }
          type = "MsPortalFx.Composition.Configuration.ValueTypes.TimeRange"
        }
        filterLocale = {
          value = "en-us"
        }
      }
    }
  })
  
  tags = local.tags
}

# Key Vault for Security Secrets
resource "azurerm_key_vault" "security_vault" {
  name                = "${var.security_monitoring.name}-kv"
  location            = var.location
  resource_group_name = var.resource_group_name
  tenant_id           = data.azurerm_client_config.current.tenant_id
  sku_name            = "standard"
  
  enabled_for_disk_encryption     = true
  enabled_for_deployment          = true
  enabled_for_template_deployment = true
  purge_protection_enabled        = true
  soft_delete_retention_days      = 90
  
  network_acls {
    default_action = "Deny"
    bypass         = "AzureServices"
    
    ip_rules = var.security_monitoring.key_vault_allowed_ips
  }
  
  tags = local.tags
}

# Key Vault Access Policy for Security Monitoring
resource "azurerm_key_vault_access_policy" "security_monitoring_policy" {
  key_vault_id = azurerm_key_vault.security_vault.id
  tenant_id    = data.azurerm_client_config.current.tenant_id
  object_id    = var.security_monitoring.monitoring_service_principal_id
  
  secret_permissions = [
    "Get",
    "List",
    "Set",
    "Delete",
    "Purge",
    "Recover"
  ]
  
  certificate_permissions = [
    "Get",
    "List",
    "Create",
    "Delete",
    "Purge",
    "Recover"
  ]
  
  key_permissions = [
    "Get",
    "List",
    "Create",
    "Delete",
    "Purge",
    "Recover",
    "Sign",
    "Verify"
  ]
}

# Security Automation Account
resource "azurerm_automation_account" "security_automation" {
  name                = "${var.security_monitoring.name}-automation"
  location            = var.location
  resource_group_name = var.resource_group_name
  sku_name            = "Basic"
  
  identity {
    type = "SystemAssigned"
  }
  
  tags = local.tags
}

# Security Runbook for Incident Response
resource "azurerm_automation_runbook" "security_incident_response" {
  name                    = "SecurityIncidentResponse"
  location                = var.location
  resource_group_name     = var.resource_group_name
  automation_account_name = azurerm_automation_account.security_automation.name
  log_verbose             = true
  log_progress            = true
  runbook_type            = "PowerShell"
  
  content = <<-CONTENT
    param(
        [Parameter(Mandatory=$true)]
        [string]$AlertName,
        
        [Parameter(Mandatory=$true)]
        [string]$ResourceId,
        
        [Parameter(Mandatory=$true)]
        [string]$Severity
    )
    
    Write-Output "Security incident detected: $AlertName"
    Write-Output "Resource: $ResourceId"
    Write-Output "Severity: $Severity"
    
    # Connect to Azure using managed identity
    Connect-AzAccount -Identity
    
    # Implement incident response logic
    switch ($Severity) {
        "Critical" {
            Write-Output "Executing critical incident response procedures"
            # Disable compromised resources
            # Send immediate notifications
            # Trigger disaster recovery procedures
        }
        "High" {
            Write-Output "Executing high severity incident response procedures"
            # Isolate affected resources
            # Increase monitoring
            # Notify security team
        }
        "Medium" {
            Write-Output "Executing medium severity incident response procedures"
            # Log incident
            # Schedule review
        }
        default {
            Write-Output "Executing default incident response procedures"
            # Log incident
        }
    }
  CONTENT
  
  tags = local.tags
}

data "azurerm_client_config" "current" {}

# Outputs
output "log_analytics_workspace_id" {
  description = "The ID of the Log Analytics workspace"
  value       = azurerm_log_analytics_workspace.security_workspace.id
}

output "security_dashboard_id" {
  description = "The ID of the security dashboard"
  value       = azurerm_portal_dashboard.security_dashboard.id
}

output "key_vault_id" {
  description = "The ID of the security Key Vault"
  value       = azurerm_key_vault.security_vault.id
}

output "automation_account_id" {
  description = "The ID of the security automation account"
  value       = azurerm_automation_account.security_automation.id
}