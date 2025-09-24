variable "global_settings" {
  description = "Global settings object"
  type = object({
    prefixes      = optional(list(string))
    random_length = optional(number)
    passthrough   = optional(bool)
    use_slug      = optional(bool)
    tags          = optional(map(string))
  })
}

variable "resource_groups" {
  description = "Resource groups configuration objects"
  type = map(object({
    name   = string
    region = string
    tags   = optional(map(string), {})
  }))
  default = {}
}

variable "dev_centers" {
  description = "Dev Centers configuration objects"
  type = map(object({
    name         = string
    display_name = optional(string)
    resource_group = object({
      key = string
    })
    identity = optional(object({
      type         = string
      identity_ids = optional(list(string))
    }))
    dev_box_provisioning_settings = optional(object({
      install_azure_monitor_agent_enable_installation = optional(string)
    }))
    encryption = optional(object({
      customer_managed_key_encryption = optional(object({
        key_encryption_key_identity = optional(object({
          identity_type                      = optional(string)
          delegated_identity_client_id       = optional(string)
          user_assigned_identity_resource_id = optional(string)
        }))
        key_encryption_key_url = optional(string)
      }))
    }))
    network_settings = optional(object({
      microsoft_hosted_network_enable_status = optional(string)
    }))
    project_catalog_settings = optional(object({
      catalog_item_sync_enable_status = optional(string)
    }))
    tags = optional(map(string), {})
  }))
  default = {}
}

#tflint-ignore: terraform_unused_declarations
variable "dev_center_galleries" {
  description = "Dev Center Galleries configuration objects"
  type = map(object({
    name          = string
    dev_center_id = optional(string)
    dev_center = optional(object({
      key = string
    }))
    resource_group_name = optional(string)
    resource_group = optional(object({
      key = string
    }))
    gallery_resource_id = string
    shared_gallery = optional(object({
      key = string
    }))
    tags = optional(map(string), {})
  }))
  default = {}
}

# tflint-ignore: terraform_unused_declarations
variable "dev_center_dev_box_definitions" {
  description = "Dev Center Dev Box Definitions configuration objects"
  type = map(object({
    name = string
    dev_center = object({
      key = string
    })
    resource_group = object({
      key = string
    })
    image_reference_id = string
    sku_name           = string
    hibernate_support = optional(object({
      enabled = optional(bool, false)
    }))
    tags = optional(map(string), {})
  }))
  default = {}
}

variable "dev_center_projects" {
  description = "Dev Center Projects configuration objects"
  type = map(object({
    name          = string
    dev_center_id = optional(string)
    dev_center = optional(object({
      key = string
    }))
    resource_group_name = optional(string)
    resource_group = optional(object({
      key = string
    }))
    resource_group_id          = optional(string)
    region                     = optional(string)
    description                = optional(string)
    display_name               = optional(string)
    maximum_dev_boxes_per_user = optional(number)
    dev_box_definition_names   = optional(list(string), [])

    # Managed Identity configuration
    identity = optional(object({
      type         = string # "None", "SystemAssigned", "UserAssigned", "SystemAssigned, UserAssigned"
      identity_ids = optional(list(string), [])
      }), {
      type = "SystemAssigned"
    })

    # Azure AI Services Settings
    azure_ai_services_settings = optional(object({
      azure_ai_services_mode = optional(string, "Disabled") # "AutoDeploy", "Disabled"
    }))

    # Catalog Settings
    catalog_settings = optional(object({
      catalog_item_sync_types = optional(list(string), []) # "EnvironmentDefinition", "ImageDefinition"
    }))

    # Customization Settings
    customization_settings = optional(object({
      user_customizations_enable_status = optional(string, "Disabled") # "Enabled", "Disabled"
      identities = optional(list(object({
        identity_resource_id = optional(string)
        identity_type        = optional(string) # "systemAssignedIdentity", "userAssignedIdentity"
      })), [])
    }))

    # Dev Box Auto Delete Settings
    dev_box_auto_delete_settings = optional(object({
      delete_mode        = optional(string, "Manual") # "Auto", "Manual"
      grace_period       = optional(string)           # ISO8601 duration format PT[n]H[n]M[n]S
      inactive_threshold = optional(string)           # ISO8601 duration format PT[n]H[n]M[n]S
    }))

    # Serverless GPU Sessions Settings
    serverless_gpu_sessions_settings = optional(object({
      max_concurrent_sessions_per_project = optional(number)
      serverless_gpu_sessions_mode        = optional(string, "Disabled") # "AutoDeploy", "Disabled"
    }))

    # Workspace Storage Settings
    workspace_storage_settings = optional(object({
      workspace_storage_mode = optional(string, "Disabled") # "AutoDeploy", "Disabled"
    }))

    tags = optional(map(string), {})
  }))
  default = {}
}

variable "dev_center_catalogs" {
  description = "Dev Center Catalogs configuration objects"
  type = map(object({
    name          = string
    dev_center_id = optional(string)
    dev_center = optional(object({
      key = string
    }))

    # GitHub catalog configuration
    github = optional(object({
      branch            = string
      uri               = string
      path              = optional(string)
      secret_identifier = optional(string)
    }))

    # Azure DevOps Git catalog configuration
    ado_git = optional(object({
      branch            = string
      uri               = string
      path              = optional(string)
      secret_identifier = optional(string)
    }))

    # Sync type: Manual or Scheduled
    sync_type = optional(string)

    # Resource-specific tags (separate from infrastructure tags)
    resource_tags = optional(map(string))

    tags = optional(map(string), {})
  }))
  default = {}

  validation {
    condition = alltrue([
      for k, v in var.dev_center_catalogs : (
        (try(v.github, null) != null && try(v.ado_git, null) == null) ||
        (try(v.github, null) == null && try(v.ado_git, null) != null)
      )
    ])
    error_message = "Each catalog must specify exactly one of 'github' or 'ado_git', but not both."
  }

  validation {
    condition = alltrue([
      for k, v in var.dev_center_catalogs :
      try(v.sync_type, null) == null ? true : contains(["Manual", "Scheduled"], v.sync_type)
    ])
    error_message = "sync_type must be either 'Manual' or 'Scheduled'."
  }
}

variable "dev_center_environment_types" {
  description = "Dev Center Environment Types configuration objects"
  type = map(object({
    name          = string
    display_name  = optional(string)
    dev_center_id = optional(string)
    dev_center = optional(object({
      key = string
    }))
    tags = optional(map(string), {})
  }))
  default = {}
}

# tflint-ignore: terraform_unused_declarations
variable "dev_center_project_environment_types" {
  description = "Dev Center Project Environment Types configuration objects"
  type = map(object({
    name       = string
    project_id = optional(string)
    project = optional(object({
      key = string
    }))
    environment_type_id = optional(string)
    environment_type = optional(object({
      key = string
    }))
    tags = optional(map(string), {})
  }))
  default = {}
}

# tflint-ignore: terraform_unused_declarations
variable "dev_center_network_connections" {
  description = "Dev Center Network Connections configuration objects"
  type = map(object({
    name          = string
    dev_center_id = optional(string)
    dev_center = optional(object({
      key = string
    }))
    network_connection_resource_id = string
    subnet_resource_id             = string
    domain_join = optional(object({
      domain_name               = string
      domain_password_secret_id = optional(string)
      domain_username           = string
      organizational_unit_path  = optional(string)
    }))
    tags = optional(map(string), {})
  }))
  default = {}
}

# tflint-ignore: terraform_unused_declarations
variable "shared_image_galleries" {
  description = "Shared Image Galleries configuration objects"
  type = map(object({
    name                = string
    description         = optional(string)
    location            = optional(string)
    resource_group_name = optional(string)
    resource_group = optional(object({
      key = string
    }))
    sharing = optional(object({
      permission = string
    }))
    tags = optional(map(string), {})
  }))
  default = {}
}

# ============================================================================
# DevFactory Variables Configuration
# Azure DevCenter Development Platform Variables
# ============================================================================

# ============================================================================
# CORE ENVIRONMENT CONFIGURATION
# ============================================================================

variable "environment" {
  description = "Environment name (dev, staging, prod)"
  type        = string
  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "Environment must be one of: dev, staging, prod."
  }
}

variable "location" {
  description = "Azure region for resources"
  type        = string
  default     = "East US"
}

variable "location_short" {
  description = "Short code for Azure region (e.g., eus for East US)"
  type        = string
  default     = "eus"
}

variable "organization_prefix" {
  description = "Organization prefix for resource naming (CAF standard)"
  type        = string
  default     = "wis"
}

variable "instance_id" {
  description = "Instance identifier for resource naming"
  type        = string
  default     = "001"
}

# ============================================================================
# CAF TAGGING AND GOVERNANCE
# ============================================================================

variable "project_name" {
  description = "Project name for tagging"
  type        = string
  default     = "DevFactory Platform"
}

variable "resource_owner" {
  description = "Resource owner for tagging"
  type        = string
  default     = "DevOps Team"
}

variable "cost_center" {
  description = "Cost center for billing allocation"
  type        = string
  default     = "IT-002"
}

variable "business_unit" {
  description = "Business unit responsible for the resource"
  type        = string
  default     = "Technology"
}

variable "criticality" {
  description = "Business criticality level"
  type        = string
  default     = "High"
  validation {
    condition     = contains(["Low", "Medium", "High", "Critical"], var.criticality)
    error_message = "Criticality must be one of: Low, Medium, High, Critical."
  }
}

variable "data_classification" {
  description = "Data classification level"
  type        = string
  default     = "Internal"
  validation {
    condition     = contains(["Public", "Internal", "Confidential", "Restricted"], var.data_classification)
    error_message = "Data classification must be one of: Public, Internal, Confidential, Restricted."
  }
}

variable "additional_tags" {
  description = "Additional tags to apply to resources"
  type        = map(string)
  default     = {}
}

# ============================================================================
# DEVCENTER CONFIGURATION
# ============================================================================

variable "devcenter_public_access_enabled" {
  description = "Enable public network access for DevCenter"
  type        = bool
  default     = false
}

# ============================================================================
# CATALOG CONFIGURATION
# ============================================================================

variable "catalog_repo_url" {
  description = "URL of the main catalog repository"
  type        = string
  default     = "https://github.com/Azure/deployment-environments.git"
}

variable "catalog_repo_branch" {
  description = "Branch of the main catalog repository"
  type        = string
  default     = "main"
}

variable "catalog_repo_path" {
  description = "Path within the main catalog repository"
  type        = string
  default     = "."
}

variable "cloudnova_catalog_repo_url" {
  description = "URL of the CloudNova-specific catalog repository"
  type        = string
  default     = "https://github.com/cloudnova/deployment-templates.git"
}

variable "cloudnova_catalog_repo_branch" {
  description = "Branch of the CloudNova catalog repository"
  type        = string
  default     = "main"
}

variable "cloudnova_catalog_repo_path" {
  description = "Path within the CloudNova catalog repository"
  type        = string
  default     = "./environments"
}

# ============================================================================
# DEVBOX CONFIGURATION
# ============================================================================

variable "web_devbox_sku" {
  description = "SKU for web development DevBoxes"
  type        = string
  default     = "general_i_8c32gb256ssd_v2"
  validation {
    condition = can(regex("^(general_i_[0-9]+c[0-9]+gb[0-9]+ssd_v[0-9]+|general_a_[0-9]+c[0-9]+gb[0-9]+ssd_v[0-9]+)$", var.web_devbox_sku))
    error_message = "DevBox SKU must be in valid format, e.g., general_i_8c32gb256ssd_v2."
  }
}

variable "data_devbox_sku" {
  description = "SKU for data science development DevBoxes"
  type        = string
  default     = "general_i_16c64gb512ssd_v2"
  validation {
    condition = can(regex("^(general_i_[0-9]+c[0-9]+gb[0-9]+ssd_v[0-9]+|general_a_[0-9]+c[0-9]+gb[0-9]+ssd_v[0-9]+)$", var.data_devbox_sku))
    error_message = "DevBox SKU must be in valid format, e.g., general_i_16c64gb512ssd_v2."
  }
}

variable "mobile_devbox_sku" {
  description = "SKU for mobile development DevBoxes"
  type        = string
  default     = "general_i_8c32gb256ssd_v2"
  validation {
    condition = can(regex("^(general_i_[0-9]+c[0-9]+gb[0-9]+ssd_v[0-9]+|general_a_[0-9]+c[0-9]+gb[0-9]+ssd_v[0-9]+)$", var.mobile_devbox_sku))
    error_message = "DevBox SKU must be in valid format, e.g., general_i_8c32gb256ssd_v2."
  }
}

variable "max_dev_boxes_per_user" {
  description = "Maximum number of dev boxes per user"
  type        = number
  default     = 3
  validation {
    condition     = var.max_dev_boxes_per_user >= 1 && var.max_dev_boxes_per_user <= 10
    error_message = "Max dev boxes per user must be between 1 and 10."
  }
}

variable "auto_shutdown_grace_period" {
  description = "Grace period in minutes before auto-shutdown"
  type        = number
  default     = 60
  validation {
    condition     = var.auto_shutdown_grace_period >= 0 && var.auto_shutdown_grace_period <= 480
    error_message = "Auto-shutdown grace period must be between 0 and 480 minutes."
  }
}

# ============================================================================
# COST OPTIMIZATION
# ============================================================================

variable "enable_dev_box_hibernation" {
  description = "Enable hibernation for DevBoxes to optimize costs"
  type        = bool
  default     = true
}

variable "dev_box_idle_timeout_minutes" {
  description = "Idle timeout in minutes before DevBox hibernation"
  type        = number
  default     = 120
  validation {
    condition     = var.dev_box_idle_timeout_minutes >= 60 && var.dev_box_idle_timeout_minutes <= 1440
    error_message = "Idle timeout must be between 60 and 1440 minutes (24 hours)."
  }
}

# ============================================================================
# NETWORKING CONFIGURATION
# ============================================================================

variable "enable_dev_box_network_isolation" {
  description = "Enable network isolation for DevBoxes"
  type        = bool
  default     = true
}

variable "allowed_dev_box_network_ranges" {
  description = "Allowed network ranges for DevBox access"
  type        = list(string)
  default     = []
}

# ============================================================================
# SECURITY CONFIGURATION
# ============================================================================

variable "enable_dev_box_just_in_time_access" {
  description = "Enable just-in-time access for DevBoxes"
  type        = bool
  default     = true
}

variable "dev_box_access_duration_hours" {
  description = "Duration in hours for just-in-time access"
  type        = number
  default     = 8
  validation {
    condition     = var.dev_box_access_duration_hours >= 1 && var.dev_box_access_duration_hours <= 24
    error_message = "Access duration must be between 1 and 24 hours."
  }
}

variable "enable_dev_box_conditional_access" {
  description = "Enable conditional access policies for DevBoxes"
  type        = bool
  default     = true
}

# ============================================================================
# MONITORING AND ANALYTICS
# ============================================================================

variable "enable_dev_box_monitoring" {
  description = "Enable monitoring and analytics for DevBoxes"
  type        = bool
  default     = true
}

variable "dev_box_monitoring_retention_days" {
  description = "Retention period for DevBox monitoring data in days"
  type        = number
  default     = 90
  validation {
    condition     = var.dev_box_monitoring_retention_days >= 30 && var.dev_box_monitoring_retention_days <= 365
    error_message = "Monitoring retention must be between 30 and 365 days."
  }
}

# ============================================================================
# INTEGRATION CONFIGURATION
# ============================================================================

variable "github_organization" {
  description = "GitHub organization for repository integration"
  type        = string
  default     = "cloudnova"
}

variable "azure_devops_organization" {
  description = "Azure DevOps organization for integration"
  type        = string
  default     = "cloudnova-devops"
}

variable "enable_github_integration" {
  description = "Enable GitHub integration for DevCenter"
  type        = bool
  default     = true
}

variable "enable_azdo_integration" {
  description = "Enable Azure DevOps integration for DevCenter"
  type        = bool
  default     = true
}

# ============================================================================
# DISASTER RECOVERY
# ============================================================================

variable "enable_dev_center_backup" {
  description = "Enable backup for DevCenter configuration"
  type        = bool
  default     = true
}

variable "dev_center_backup_retention_days" {
  description = "Retention period for DevCenter backups in days"
  type        = number
  default     = 30
  validation {
    condition     = var.dev_center_backup_retention_days >= 7 && var.dev_center_backup_retention_days <= 365
    error_message = "Backup retention must be between 7 and 365 days."
  }
}

# ============================================================================
# COMPLIANCE AND GOVERNANCE
# ============================================================================

variable "enable_dev_box_compliance_scanning" {
  description = "Enable compliance scanning for DevBoxes"
  type        = bool
  default     = true
}

variable "required_dev_box_policies" {
  description = "List of required policy definitions for DevBoxes"
  type        = list(string)
  default = [
    "Require encryption at rest",
    "Require approved VM extensions only",
    "Enforce resource tagging",
    "Require network security groups"
  ]
}

variable "enable_dev_box_vulnerability_scanning" {
  description = "Enable vulnerability scanning for DevBox images"
  type        = bool
  default     = true
}

# ============================================================================
# DEVELOPMENT WORKFLOW CONFIGURATION
# ============================================================================

variable "default_dev_box_user_role" {
  description = "Default role for DevBox users"
  type        = string
  default     = "DevCenter Dev Box User"
  validation {
    condition = contains([
      "DevCenter Dev Box User",
      "DevCenter Project Admin",
      "DevCenter Environment Admin"
    ], var.default_dev_box_user_role)
    error_message = "Default user role must be a valid DevCenter role."
  }
}

variable "enable_dev_box_auto_provisioning" {
  description = "Enable automatic provisioning of DevBoxes"
  type        = bool
  default     = false
}

variable "dev_box_provisioning_schedule" {
  description = "Schedule for automatic DevBox provisioning (cron format)"
  type        = string
  default     = "0 8 * * MON"
}

# ============================================================================
# CUSTOM IMAGE CONFIGURATION
# ============================================================================

variable "enable_custom_dev_box_images" {
  description = "Enable custom DevBox images"
  type        = bool
  default     = true
}

variable "custom_image_gallery_name" {
  description = "Name of the shared image gallery for custom DevBox images"
  type        = string
  default     = "cloudnova-devbox-gallery"
}

variable "enable_image_versioning" {
  description = "Enable versioning for custom DevBox images"
  type        = bool
  default     = true
}
