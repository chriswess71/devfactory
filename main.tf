# ============================================================================
# DevFactory Infrastructure Configuration
# Azure DevCenter and Development Environment Management
# ============================================================================

terraform {
  required_version = ">= 1.5.0"
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.80.0"
    }
    azuread = {
      source  = "hashicorp/azuread"
      version = "~> 2.41.0"
    }
  }

  backend "azurerm" {
    # Backend configuration provided via init command
  }
}

# Configure providers
provider "azurerm" {
  features {
    resource_group {
      prevent_deletion_if_contains_resources = false
    }
  }
}

provider "azuread" {}

# ============================================================================
# LOCAL VALUES AND NAMING CONVENTIONS
# ============================================================================

locals {
  # CAF Naming Convention
  naming_convention = {
    prefix = var.organization_prefix
    environment = var.environment
    location_short = var.location_short
    instance = var.instance_id
  }

  # Common tags following CAF standards
  common_tags = merge(var.additional_tags, {
    Environment      = var.environment
    Owner           = var.resource_owner
    CostCenter      = var.cost_center
    Project         = var.project_name
    ApplicationName = "DevFactory"
    BusinessUnit    = var.business_unit
    Criticality     = var.criticality
    DataClass       = var.data_classification
    ManagedBy       = "Terraform"
    DeployedBy      = "GitHub-Actions"
    CreatedDate     = formatdate("YYYY-MM-DD", timestamp())
    Architecture    = "devops-platform"
    Framework       = "CAF"
    Purpose         = "development-infrastructure"
  })

  # Resource naming
  resource_names = {
    resource_group = "rg-${local.naming_convention.prefix}-devfactory-${local.naming_convention.environment}-${local.naming_convention.location_short}-${local.naming_convention.instance}"
    dev_center    = "dc-${local.naming_convention.prefix}-${local.naming_convention.environment}-${local.naming_convention.location_short}-${local.naming_convention.instance}"
  }
}

# ============================================================================
# RESOURCE GROUP FOR DEVFACTORY
# ============================================================================

module "devfactory_resource_group" {
  source = "./modules/resource_group"

  name     = local.resource_names.resource_group
  location = var.location
  tags     = local.common_tags
}

# ============================================================================
# AZURE DEVCENTER
# ============================================================================

module "dev_center" {
  source = "./modules/dev_center"

  name                = local.resource_names.dev_center
  resource_group_name = module.devfactory_resource_group.name
  location           = var.location

  # DevCenter Configuration
  identity_type = "SystemAssigned"
  
  # Security and compliance
  public_network_access_enabled = var.devcenter_public_access_enabled
  
  tags = local.common_tags

  depends_on = [module.devfactory_resource_group]
}

# ============================================================================
# DEVCENTER CATALOGS
# ============================================================================

module "dev_center_catalog_main" {
  source = "./modules/dev_center_catalog"

  name           = "catalog-main"
  dev_center_id  = module.dev_center.id
  
  # GitHub repository configuration for templates
  repo_url    = var.catalog_repo_url
  repo_branch = var.catalog_repo_branch
  repo_path   = var.catalog_repo_path

  tags = local.common_tags

  depends_on = [module.dev_center]
}

module "dev_center_catalog_cloudnova" {
  source = "./modules/dev_center_catalog"

  name           = "catalog-cloudnova"
  dev_center_id  = module.dev_center.id
  
  # CloudNova specific templates
  repo_url    = var.cloudnova_catalog_repo_url
  repo_branch = var.cloudnova_catalog_repo_branch
  repo_path   = var.cloudnova_catalog_repo_path

  tags = local.common_tags

  depends_on = [module.dev_center]
}

# ============================================================================
# DEVCENTER ENVIRONMENT TYPES
# ============================================================================

module "dev_environment_type" {
  source = "./modules/dev_center_environment_type"

  name           = "development"
  dev_center_id  = module.dev_center.id
  
  tags = local.common_tags

  depends_on = [module.dev_center]
}

module "staging_environment_type" {
  source = "./modules/dev_center_environment_type"

  name           = "staging"
  dev_center_id  = module.dev_center.id
  
  tags = local.common_tags

  depends_on = [module.dev_center]
}

module "production_environment_type" {
  source = "./modules/dev_center_environment_type"

  name           = "production"
  dev_center_id  = module.dev_center.id
  
  tags = local.common_tags

  depends_on = [module.dev_center]
}

# ============================================================================
# DEVBOX DEFINITIONS
# ============================================================================

module "dev_box_definition_web" {
  source = "./modules/dev_center_dev_box_definition"

  name                = "web-development"
  dev_center_id       = module.dev_center.id
  location           = var.location
  
  # VM Configuration
  image_reference = {
    publisher = "microsoftvisualstudio"
    offer     = "visualstudioplustools"
    sku       = "vs-2022-ent-general-win11-m365-gen2"
    version   = "latest"
  }
  
  sku_name = var.web_devbox_sku
  
  # Storage configuration
  os_disk_type = "Premium_LRS"

  tags = local.common_tags

  depends_on = [module.dev_center]
}

module "dev_box_definition_data" {
  source = "./modules/dev_center_dev_box_definition"

  name                = "data-development"
  dev_center_id       = module.dev_center.id
  location           = var.location
  
  # VM Configuration for data science workloads
  image_reference = {
    publisher = "microsoft-dsvm"
    offer     = "dsvm-win-2022"
    sku       = "winserver-2022"
    version   = "latest"
  }
  
  sku_name = var.data_devbox_sku
  
  # Storage configuration
  os_disk_type = "Premium_LRS"

  tags = local.common_tags

  depends_on = [module.dev_center]
}

module "dev_box_definition_mobile" {
  source = "./modules/dev_center_dev_box_definition"

  name                = "mobile-development"
  dev_center_id       = module.dev_center.id
  location           = var.location
  
  # VM Configuration for mobile development
  image_reference = {
    publisher = "microsoftvisualstudio"
    offer     = "visualstudioplustools"
    sku       = "vs-2022-ent-general-win11-m365-gen2"
    version   = "latest"
  }
  
  sku_name = var.mobile_devbox_sku
  
  # Storage configuration
  os_disk_type = "Premium_LRS"

  tags = local.common_tags

  depends_on = [module.dev_center]
}

# ============================================================================
# DEVCENTER PROJECTS
# ============================================================================

module "dev_center_project_cloudnova" {
  source = "./modules/dev_center_project"

  name           = "cloudnova-platform"
  dev_center_id  = module.dev_center.id
  
  description = "CloudNova platform development project"
  max_dev_boxes_per_user = var.max_dev_boxes_per_user
  
  tags = local.common_tags

  depends_on = [module.dev_center]
}

module "dev_center_project_frontend" {
  source = "./modules/dev_center_project"

  name           = "cloudnova-frontend"
  dev_center_id  = module.dev_center.id
  
  description = "CloudNova frontend development project"
  max_dev_boxes_per_user = var.max_dev_boxes_per_user
  
  tags = local.common_tags

  depends_on = [module.dev_center]
}

module "dev_center_project_backend" {
  source = "./modules/dev_center_project"

  name           = "cloudnova-backend"
  dev_center_id  = module.dev_center.id
  
  description = "CloudNova backend development project"
  max_dev_boxes_per_user = var.max_dev_boxes_per_user
  
  tags = local.common_tags

  depends_on = [module.dev_center]
}

module "dev_center_project_infrastructure" {
  source = "./modules/dev_center_project"

  name           = "cloudnova-infrastructure"
  dev_center_id  = module.dev_center.id
  
  description = "CloudNova infrastructure and DevOps project"
  max_dev_boxes_per_user = var.max_dev_boxes_per_user
  
  tags = local.common_tags

  depends_on = [module.dev_center]
}

module "dev_center_project_test" {
  source = "./modules/dev_center_project"

  name           = "cloudnova-test"
  dev_center_id  = module.dev_center.id
  
  description = "CloudNova testing project"
  max_dev_boxes_per_user = var.max_dev_boxes_per_user
  
  tags = local.common_tags

  depends_on = [module.dev_center]
}

# ============================================================================
# PROJECT ENVIRONMENT TYPE ASSOCIATIONS
# ============================================================================

# Associate environment types with projects
resource "azurerm_dev_center_project_environment_type" "cloudnova_dev" {
  dev_center_project_id = module.dev_center_project_cloudnova.id
  environment_type_name = module.dev_environment_type.name
  location             = var.location

  identity {
    type = "SystemAssigned"
  }

  deployment_target_id = data.azurerm_subscription.current.id
  status              = "Enabled"

  tags = local.common_tags
}

resource "azurerm_dev_center_project_environment_type" "cloudnova_staging" {
  dev_center_project_id = module.dev_center_project_cloudnova.id
  environment_type_name = module.staging_environment_type.name
  location             = var.location

  identity {
    type = "SystemAssigned"
  }

  deployment_target_id = data.azurerm_subscription.current.id
  status              = var.environment == "prod" || var.environment == "staging" ? "Enabled" : "Disabled"

  tags = local.common_tags
}

resource "azurerm_dev_center_project_environment_type" "cloudnova_production" {
  dev_center_project_id = module.dev_center_project_cloudnova.id
  environment_type_name = module.production_environment_type.name
  location             = var.location

  identity {
    type = "SystemAssigned"
  }

  deployment_target_id = data.azurerm_subscription.current.id
  status              = var.environment == "prod" ? "Enabled" : "Disabled"

  tags = local.common_tags
}

# ============================================================================
# DEV BOX POOLS
# ============================================================================

resource "azurerm_dev_center_dev_box_pool" "web_dev_pool" {
  name                         = "web-dev-pool"
  dev_center_project_id        = module.dev_center_project_frontend.id
  location                    = var.location
  dev_box_definition_name     = module.dev_box_definition_web.name
  
  # Auto-shutdown configuration
  local_administrator_enabled = true
  stop_on_disconnect {
    status               = "Enabled"
    grace_period_minutes = var.auto_shutdown_grace_period
  }

  tags = local.common_tags
}

resource "azurerm_dev_center_dev_box_pool" "backend_dev_pool" {
  name                         = "backend-dev-pool"
  dev_center_project_id        = module.dev_center_project_backend.id
  location                    = var.location
  dev_box_definition_name     = module.dev_box_definition_web.name
  
  # Auto-shutdown configuration
  local_administrator_enabled = true
  stop_on_disconnect {
    status               = "Enabled"
    grace_period_minutes = var.auto_shutdown_grace_period
  }

  tags = local.common_tags
}

resource "azurerm_dev_center_dev_box_pool" "data_dev_pool" {
  name                         = "data-dev-pool"
  dev_center_project_id        = module.dev_center_project_infrastructure.id
  location                    = var.location
  dev_box_definition_name     = module.dev_box_definition_data.name
  
  # Auto-shutdown configuration
  local_administrator_enabled = true
  stop_on_disconnect {
    status               = "Enabled"
    grace_period_minutes = var.auto_shutdown_grace_period
  }

  tags = local.common_tags
}

# ============================================================================
# DATA SOURCES
# ============================================================================

data "azurerm_subscription" "current" {}

data "azurerm_client_config" "current" {} 