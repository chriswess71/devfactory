# ============================================================================
# DevFactory Infrastructure Outputs
# Azure DevCenter Platform Outputs
# ============================================================================

# ============================================================================
# CORE DEVCENTER OUTPUTS
# ============================================================================

output "dev_center" {
  description = "DevCenter resource information"
  value = {
    id                = module.dev_center.id
    name              = module.dev_center.name
    resource_group_name = module.devfactory_resource_group.name
    location          = var.location
    identity          = module.dev_center.identity
  }
}

output "dev_center_id" {
  description = "ID of the DevCenter"
  value       = module.dev_center.id
}

output "dev_center_name" {
  description = "Name of the DevCenter"
  value       = module.dev_center.name
}

output "dev_center_uri" {
  description = "URI of the DevCenter"
  value       = module.dev_center.dev_center_uri
}

# ============================================================================
# RESOURCE GROUP OUTPUTS
# ============================================================================

output "resource_group" {
  description = "DevFactory resource group information"
  value = {
    id       = module.devfactory_resource_group.id
    name     = module.devfactory_resource_group.name
    location = module.devfactory_resource_group.location
  }
}

# ============================================================================
# DEVCENTER PROJECTS OUTPUTS
# ============================================================================

output "dev_center_projects" {
  description = "DevCenter projects information"
  value = {
    cloudnova_platform = {
      id                = module.dev_center_project_cloudnova.id
      name              = module.dev_center_project_cloudnova.name
      description       = "CloudNova platform development project"
      dev_center_id     = module.dev_center.id
    }
    cloudnova_frontend = {
      id                = module.dev_center_project_frontend.id
      name              = module.dev_center_project_frontend.name
      description       = "CloudNova frontend development project"
      dev_center_id     = module.dev_center.id
    }
    cloudnova_backend = {
      id                = module.dev_center_project_backend.id
      name              = module.dev_center_project_backend.name
      description       = "CloudNova backend development project"
      dev_center_id     = module.dev_center.id
    }
    cloudnova_infrastructure = {
      id                = module.dev_center_project_infrastructure.id
      name              = module.dev_center_project_infrastructure.name
      description       = "CloudNova infrastructure and DevOps project"
      dev_center_id     = module.dev_center.id
    }
  }
  sensitive = true
}

# ============================================================================
# CATALOGS OUTPUTS
# ============================================================================

output "dev_center_catalogs" {
  description = "DevCenter catalogs information"
  value = {
    main_catalog = {
      id            = module.dev_center_catalog_main.id
      name          = module.dev_center_catalog_main.name
      dev_center_id = module.dev_center.id
      repo_url      = var.catalog_repo_url
      repo_branch   = var.catalog_repo_branch
    }
    cloudnova_catalog = {
      id            = module.dev_center_catalog_cloudnova.id
      name          = module.dev_center_catalog_cloudnova.name
      dev_center_id = module.dev_center.id
      repo_url      = var.cloudnova_catalog_repo_url
      repo_branch   = var.cloudnova_catalog_repo_branch
    }
  }
}

# ============================================================================
# ENVIRONMENT TYPES OUTPUTS
# ============================================================================

output "environment_types" {
  description = "DevCenter environment types information"
  value = {
    development = {
      id            = module.dev_environment_type.id
      name          = module.dev_environment_type.name
      dev_center_id = module.dev_center.id
    }
    staging = {
      id            = module.staging_environment_type.id
      name          = module.staging_environment_type.name
      dev_center_id = module.dev_center.id
    }
    production = {
      id            = module.production_environment_type.id
      name          = module.production_environment_type.name
      dev_center_id = module.dev_center.id
    }
  }
}

# ============================================================================
# DEVBOX DEFINITIONS OUTPUTS
# ============================================================================

output "dev_box_definitions" {
  description = "DevBox definitions information"
  value = {
    web_development = {
      id            = module.dev_box_definition_web.id
      name          = module.dev_box_definition_web.name
      dev_center_id = module.dev_center.id
      sku_name      = var.web_devbox_sku
      image_reference = {
        publisher = "microsoftvisualstudio"
        offer     = "visualstudioplustools"
        sku       = "vs-2022-ent-general-win11-m365-gen2"
      }
    }
    data_development = {
      id            = module.dev_box_definition_data.id
      name          = module.dev_box_definition_data.name
      dev_center_id = module.dev_center.id
      sku_name      = var.data_devbox_sku
      image_reference = {
        publisher = "microsoft-dsvm"
        offer     = "dsvm-win-2022"
        sku       = "winserver-2022"
      }
    }
    mobile_development = {
      id            = module.dev_box_definition_mobile.id
      name          = module.dev_box_definition_mobile.name
      dev_center_id = module.dev_center.id
      sku_name      = var.mobile_devbox_sku
      image_reference = {
        publisher = "microsoftvisualstudio"
        offer     = "visualstudioplustools"
        sku       = "vs-2022-ent-general-win11-m365-gen2"
      }
    }
  }
}

# ============================================================================
# DEVBOX POOLS OUTPUTS
# ============================================================================

output "dev_box_pools" {
  description = "DevBox pools information"
  value = {
    web_dev_pool = {
      id                      = azurerm_dev_center_dev_box_pool.web_dev_pool.id
      name                    = azurerm_dev_center_dev_box_pool.web_dev_pool.name
      dev_center_project_id   = module.dev_center_project_frontend.id
      dev_box_definition_name = module.dev_box_definition_web.name
    }
    backend_dev_pool = {
      id                      = azurerm_dev_center_dev_box_pool.backend_dev_pool.id
      name                    = azurerm_dev_center_dev_box_pool.backend_dev_pool.name
      dev_center_project_id   = module.dev_center_project_backend.id
      dev_box_definition_name = module.dev_box_definition_web.name
    }
    data_dev_pool = {
      id                      = azurerm_dev_center_dev_box_pool.data_dev_pool.id
      name                    = azurerm_dev_center_dev_box_pool.data_dev_pool.name
      dev_center_project_id   = module.dev_center_project_infrastructure.id
      dev_box_definition_name = module.dev_box_definition_data.name
    }
  }
}

# ============================================================================
# PROJECT ENVIRONMENT TYPE ASSOCIATIONS OUTPUTS
# ============================================================================

output "project_environment_associations" {
  description = "Project environment type associations"
  value = {
    cloudnova_dev = {
      id                    = azurerm_dev_center_project_environment_type.cloudnova_dev.id
      dev_center_project_id = module.dev_center_project_cloudnova.id
      environment_type_name = module.dev_environment_type.name
      status               = "Enabled"
    }
    cloudnova_staging = {
      id                    = azurerm_dev_center_project_environment_type.cloudnova_staging.id
      dev_center_project_id = module.dev_center_project_cloudnova.id
      environment_type_name = module.staging_environment_type.name
      status               = var.environment == "prod" || var.environment == "staging" ? "Enabled" : "Disabled"
    }
    cloudnova_production = {
      id                    = azurerm_dev_center_project_environment_type.cloudnova_production.id
      dev_center_project_id = module.dev_center_project_cloudnova.id
      environment_type_name = module.production_environment_type.name
      status               = var.environment == "prod" ? "Enabled" : "Disabled"
    }
  }
}

# ============================================================================
# CONFIGURATION SUMMARY OUTPUTS
# ============================================================================

output "dev_center_configuration" {
  description = "DevCenter configuration summary"
  value = {
    environment                   = var.environment
    location                     = var.location
    public_network_access_enabled = var.devcenter_public_access_enabled
    max_dev_boxes_per_user       = var.max_dev_boxes_per_user
    auto_shutdown_grace_period   = var.auto_shutdown_grace_period
    github_integration_enabled   = var.enable_github_integration
    azdo_integration_enabled     = var.enable_azdo_integration
    monitoring_enabled           = var.enable_dev_box_monitoring
    compliance_scanning_enabled  = var.enable_dev_box_compliance_scanning
  }
}

# ============================================================================
# COST OPTIMIZATION OUTPUTS
# ============================================================================

output "cost_optimization_settings" {
  description = "Cost optimization settings for DevCenter"
  value = {
    hibernation_enabled        = var.enable_dev_box_hibernation
    idle_timeout_minutes      = var.dev_box_idle_timeout_minutes
    auto_provisioning_enabled = var.enable_dev_box_auto_provisioning
    provisioning_schedule     = var.dev_box_provisioning_schedule
    backup_retention_days     = var.dev_center_backup_retention_days
  }
}

# ============================================================================
# SECURITY CONFIGURATION OUTPUTS
# ============================================================================

output "security_configuration" {
  description = "Security configuration for DevCenter"
  value = {
    network_isolation_enabled      = var.enable_dev_box_network_isolation
    just_in_time_access_enabled   = var.enable_dev_box_just_in_time_access
    access_duration_hours         = var.dev_box_access_duration_hours
    conditional_access_enabled    = var.enable_dev_box_conditional_access
    vulnerability_scanning_enabled = var.enable_dev_box_vulnerability_scanning
    required_policies             = var.required_dev_box_policies
  }
}

# ============================================================================
# INTEGRATION ENDPOINTS OUTPUTS
# ============================================================================

output "integration_endpoints" {
  description = "Integration endpoints and URLs"
  value = {
    dev_center_portal_url = "https://devportal.microsoft.com/"
    dev_center_api_url    = "https://management.azure.com/subscriptions/${data.azurerm_subscription.current.subscription_id}/resourceGroups/${module.devfactory_resource_group.name}/providers/Microsoft.DevCenter/devcenters/${module.dev_center.name}"
    github_organization   = var.github_organization
    azdo_organization     = var.azure_devops_organization
  }
}

# ============================================================================
# DEPLOYMENT INFORMATION OUTPUTS
# ============================================================================

output "deployment_information" {
  description = "Deployment information and metadata"
  value = {
    deployment_timestamp = timestamp()
    terraform_workspace  = terraform.workspace
    environment         = var.environment
    organization_prefix = var.organization_prefix
    tags               = local.common_tags
    naming_convention  = local.naming_convention
  }
}

# ============================================================================
# CONNECTION INFORMATION OUTPUTS
# ============================================================================

output "connection_information" {
  description = "Information for connecting to DevCenter resources"
  value = {
    dev_center_name = module.dev_center.name
    resource_group  = module.devfactory_resource_group.name
    subscription_id = data.azurerm_subscription.current.subscription_id
    project_urls = {
      cloudnova_platform     = "https://devportal.microsoft.com/projects/${module.dev_center_project_cloudnova.name}"
      cloudnova_frontend     = "https://devportal.microsoft.com/projects/${module.dev_center_project_frontend.name}"
      cloudnova_backend      = "https://devportal.microsoft.com/projects/${module.dev_center_project_backend.name}"
      cloudnova_infrastructure = "https://devportal.microsoft.com/projects/${module.dev_center_project_infrastructure.name}"
    }
  }
}

# ============================================================================
# MONITORING AND ANALYTICS OUTPUTS
# ============================================================================

output "monitoring_configuration" {
  description = "Monitoring and analytics configuration"
  value = {
    monitoring_enabled           = var.enable_dev_box_monitoring
    monitoring_retention_days    = var.dev_box_monitoring_retention_days
    compliance_scanning_enabled  = var.enable_dev_box_compliance_scanning
    vulnerability_scanning_enabled = var.enable_dev_box_vulnerability_scanning
    backup_enabled              = var.enable_dev_center_backup
    backup_retention_days       = var.dev_center_backup_retention_days
  }
}

# ============================================================================
# CUSTOM IMAGES CONFIGURATION OUTPUTS
# ============================================================================

output "custom_images_configuration" {
  description = "Custom images configuration"
  value = {
    custom_images_enabled    = var.enable_custom_dev_box_images
    image_gallery_name      = var.custom_image_gallery_name
    image_versioning_enabled = var.enable_image_versioning
  }
}

# ============================================================================
# OPERATIONAL INFORMATION OUTPUTS
# ============================================================================

output "operational_information" {
  description = "Operational information for DevCenter management"
  value = {
    resource_count = {
      dev_centers               = 1
      projects                 = 4
      catalogs                 = 2
      environment_types        = 3
      dev_box_definitions      = 3
      dev_box_pools           = 3
      environment_associations = 3
    }
    management_commands = {
      list_projects    = "az devcenter admin project list --dev-center-name ${module.dev_center.name} --resource-group ${module.devfactory_resource_group.name}"
      list_dev_boxes   = "az devcenter admin dev-box-definition list --dev-center-name ${module.dev_center.name} --resource-group ${module.devfactory_resource_group.name}"
      list_catalogs    = "az devcenter admin catalog list --dev-center-name ${module.dev_center.name} --resource-group ${module.devfactory_resource_group.name}"
    }
  }
} 