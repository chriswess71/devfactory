variable "global_settings" {
  description = "Global settings object"
  type = object({
    prefixes      = optional(list(string))
    random_length = optional(number)
    passthrough   = optional(bool)
    use_slug      = optional(bool)
    tags          = optional(map(string), {})
  })
}

variable "location" {
  description = "The location/region where the security monitoring resources are created"
  type        = string
}

variable "resource_group_name" {
  description = "The name of the resource group in which to create the security monitoring resources"
  type        = string
}

variable "devcenter_id" {
  description = "The ID of the DevCenter to monitor"
  type        = string
}

variable "security_monitoring" {
  description = "Configuration object for security monitoring"
  type = object({
    name                              = string
    log_retention_days               = optional(number, 90)
    monitoring_service_principal_id  = string
    webhook_uri                      = optional(string, "")
    key_vault_allowed_ips           = optional(list(string), [])
    
    # Alert configuration
    alert_email_addresses = optional(map(string), {})
    
    # Log categories to monitor
    devcenter_log_categories = optional(list(string), [
      "AuditLogs",
      "DevBoxOperations",
      "ProjectOperations",
      "EnvironmentOperations"
    ])
    
    tags = optional(map(string), {})
  })
  
  validation {
    condition     = can(regex("^[a-zA-Z0-9][a-zA-Z0-9-_]*[a-zA-Z0-9]$", var.security_monitoring.name)) && length(var.security_monitoring.name) >= 3 && length(var.security_monitoring.name) <= 20
    error_message = "Security monitoring name must be between 3 and 20 characters long and can contain alphanumeric characters, hyphens, and underscores."
  }
  
  validation {
    condition     = var.security_monitoring.log_retention_days >= 30 && var.security_monitoring.log_retention_days <= 730
    error_message = "Log retention days must be between 30 and 730 days."
  }
}