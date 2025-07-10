// Enhanced security configuration for DevFactory
// This example demonstrates best practices for secure DevCenter deployment

global_settings = {
  prefixes      = ["secure", "dev"]
  random_length = 4
  passthrough   = false
  use_slug      = true
  tags = {
    environment     = "production"
    owner          = "SecurityTeam"
    project        = "DevFactory"
    compliance     = "SOC2"
    backup_policy  = "required"
    monitoring     = "enabled"
    encryption     = "cmk"
  }
}

resource_groups = {
  main = {
    name   = "devfactory-secure-demo"
    region = "eastus"
    tags = {
      environment = "production"
      workload    = "secure-devcenter"
      tier        = "critical"
    }
  }
  
  security = {
    name   = "devfactory-security-resources"
    region = "eastus"
    tags = {
      environment = "production"
      workload    = "security-infrastructure"
      tier        = "critical"
    }
  }
}

# Enhanced DevCenter with comprehensive security features
dev_centers = {
  secure_devcenter = {
    name         = "secure-devcenter"
    display_name = "Secure DevFactory Center"
    
    # Managed Identity Configuration
    identity = {
      type = "UserAssigned"
      identity_ids = [
        "/subscriptions/$(ARM_SUBSCRIPTION_ID)/resourceGroups/devfactory-security-resources/providers/Microsoft.ManagedIdentity/userAssignedIdentities/devcenter-identity"
      ]
    }
    
    # Customer-Managed Key Encryption
    encryption = {
      customer_managed_key_encryption = {
        key_encryption_key_identity = {
          identity_type = "userAssignedIdentity"
          user_assigned_identity_resource_id = "/subscriptions/$(ARM_SUBSCRIPTION_ID)/resourceGroups/devfactory-security-resources/providers/Microsoft.ManagedIdentity/userAssignedIdentities/cmk-identity"
        }
        key_encryption_key_url = "https://devfactory-keyvault.vault.azure.net/keys/devcenter-cmk/latest"
      }
    }
    
    # DevBox Provisioning Settings with Enhanced Security
    dev_box_provisioning_settings = {
      install_azure_monitor_agent_enable_installation = "Enabled"
    }
    
    # Network Security Settings
    network_settings = {
      microsoft_hosted_network_enable_status = "Enabled"
    }
    
    # Project Catalog Security Settings
    project_catalog_settings = {
      catalog_item_sync_enable_status = "Enabled"
    }
    
    resource_group = {
      key = "main"
    }
    region = "eastus"
    
    tags = {
      security_level = "high"
      compliance     = "required"
      monitoring     = "comprehensive"
    }
  }
}

# Secure DevCenter Projects with Enhanced Security Features
dev_center_projects = {
  secure_devbox_project = {
    name         = "secure-devbox-project"
    display_name = "Secure DevBox Development Environment"
    description  = "Secure development environment with enhanced security controls"
    
    # Multi-identity configuration for enhanced security
    identity = {
      type = "SystemAssigned, UserAssigned"
      identity_ids = [
        "/subscriptions/$(ARM_SUBSCRIPTION_ID)/resourceGroups/devfactory-security-resources/providers/Microsoft.ManagedIdentity/userAssignedIdentities/project-identity"
      ]
    }
    
    # Security-focused DevBox settings
    maximum_dev_boxes_per_user = 2
    
    # Azure AI Services - Disabled for security
    azure_ai_services_settings = {
      azure_ai_services_mode = "Disabled"
    }
    
    # Catalog Security Settings
    catalog_settings = {
      catalog_item_sync_types = ["EnvironmentDefinition", "ImageDefinition"]
    }
    
    # Customization Security Settings
    customization_settings = {
      user_customizations_enable_status = "Enabled"
      identities = [
        {
          identity_resource_id = "/subscriptions/$(ARM_SUBSCRIPTION_ID)/resourceGroups/devfactory-security-resources/providers/Microsoft.ManagedIdentity/userAssignedIdentities/customization-identity"
          identity_type        = "userAssignedIdentity"
        }
      ]
    }
    
    # Auto-delete for security and cost optimization
    dev_box_auto_delete_settings = {
      delete_mode        = "Auto"
      grace_period       = "PT4H"   # 4 hours grace period
      inactive_threshold = "PT8H"   # 8 hours inactive threshold
    }
    
    # GPU Sessions - Disabled for security
    serverless_gpu_sessions_settings = {
      max_concurrent_sessions_per_project = 0
      serverless_gpu_sessions_mode        = "Disabled"
    }
    
    # Workspace Storage Security
    workspace_storage_settings = {
      workspace_storage_mode = "Disabled"  # Use secure external storage
    }
    
    dev_center = {
      key = "secure_devcenter"
    }
    resource_group = {
      key = "main"
    }
    
    tags = {
      security_profile = "hardened"
      auto_delete     = "enabled"
      compliance      = "required"
      backup_required = "true"
    }
  }
  
  windows365_project = {
    name         = "windows365-secure-project"
    display_name = "Windows 365 Secure Cloud PC Environment"
    description  = "Secure Windows 365 Cloud PC environment with enhanced security"
    
    identity = {
      type = "UserAssigned"
      identity_ids = [
        "/subscriptions/$(ARM_SUBSCRIPTION_ID)/resourceGroups/devfactory-security-resources/providers/Microsoft.ManagedIdentity/userAssignedIdentities/windows365-identity"
      ]
    }
    
    maximum_dev_boxes_per_user = 1
    
    # Enhanced security settings for Windows 365
    azure_ai_services_settings = {
      azure_ai_services_mode = "Disabled"
    }
    
    catalog_settings = {
      catalog_item_sync_types = ["EnvironmentDefinition"]
    }
    
    # Strict customization controls
    customization_settings = {
      user_customizations_enable_status = "Disabled"
    }
    
    # Aggressive auto-delete for Cloud PCs
    dev_box_auto_delete_settings = {
      delete_mode        = "Auto"
      grace_period       = "PT2H"   # 2 hours grace period
      inactive_threshold = "PT4H"   # 4 hours inactive threshold
    }
    
    dev_center = {
      key = "secure_devcenter"
    }
    resource_group = {
      key = "main"
    }
    
    tags = {
      platform        = "windows365"
      security_level  = "maximum"
      compliance      = "strict"
      data_residency  = "required"
    }
  }
  
  avd_project = {
    name         = "avd-secure-project"
    display_name = "Azure Virtual Desktop Secure Environment"
    description  = "Secure AVD environment with enhanced security controls"
    
    identity = {
      type = "SystemAssigned"
    }
    
    maximum_dev_boxes_per_user = 3
    
    # AI Services configuration for AVD
    azure_ai_services_settings = {
      azure_ai_services_mode = "AutoDeploy"  # Enabled for development scenarios
    }
    
    catalog_settings = {
      catalog_item_sync_types = ["EnvironmentDefinition", "ImageDefinition"]
    }
    
    # AVD-specific customization settings
    customization_settings = {
      user_customizations_enable_status = "Enabled"
      identities = [
        {
          identity_resource_id = "/subscriptions/$(ARM_SUBSCRIPTION_ID)/resourceGroups/devfactory-security-resources/providers/Microsoft.ManagedIdentity/userAssignedIdentities/avd-identity"
          identity_type        = "userAssignedIdentity"
        }
      ]
    }
    
    # Moderate auto-delete for AVD
    dev_box_auto_delete_settings = {
      delete_mode        = "Auto"
      grace_period       = "PT8H"   # 8 hours grace period
      inactive_threshold = "PT24H"  # 24 hours inactive threshold
    }
    
    # GPU support for AVD workloads
    serverless_gpu_sessions_settings = {
      max_concurrent_sessions_per_project = 5
      serverless_gpu_sessions_mode        = "AutoDeploy"
    }
    
    # Workspace storage for AVD
    workspace_storage_settings = {
      workspace_storage_mode = "AutoDeploy"
    }
    
    dev_center = {
      key = "secure_devcenter"
    }
    resource_group = {
      key = "main"
    }
    
    tags = {
      platform       = "avd"
      gpu_enabled    = "true"
      session_type   = "multi-session"
      fslogix        = "enabled"
      backup_policy  = "comprehensive"
    }
  }
}

# DevBox Definitions with Security Hardening
dev_box_definitions = {
  secure_devbox_win11 = {
    name         = "secure-win11-devbox"
    display_name = "Secure Windows 11 DevBox"
    
    image_reference = {
      id = "/subscriptions/$(ARM_SUBSCRIPTION_ID)/resourceGroups/devfactory-images/providers/Microsoft.Compute/galleries/devfactory_gallery/images/secure-win11-image/versions/latest"
    }
    
    sku = {
      name = "general_i_8c32gb256ssd_v2"
    }
    
    # Hibernate support for security
    hibernate_support = "Enabled"
    
    dev_center = {
      key = "secure_devcenter"
    }
    
    tags = {
      os_type        = "windows11"
      security_level = "hardened"
      compliance     = "required"
      encryption     = "enabled"
    }
  }
  
  secure_devbox_win365 = {
    name         = "secure-win365-cloudpc"
    display_name = "Secure Windows 365 Cloud PC"
    
    image_reference = {
      id = "/subscriptions/$(ARM_SUBSCRIPTION_ID)/resourceGroups/devfactory-images/providers/Microsoft.Compute/galleries/devfactory_gallery/images/secure-win365-image/versions/latest"
    }
    
    sku = {
      name = "general_i_4c16gb128ssd_v2"
    }
    
    hibernate_support = "Enabled"
    
    dev_center = {
      key = "secure_devcenter"
    }
    
    tags = {
      platform       = "windows365"
      security_level = "maximum"
      compliance     = "strict"
      backup_policy  = "required"
    }
  }
  
  secure_devbox_avd = {
    name         = "secure-avd-sessionhost"
    display_name = "Secure AVD Session Host"
    
    image_reference = {
      id = "/subscriptions/$(ARM_SUBSCRIPTION_ID)/resourceGroups/devfactory-images/providers/Microsoft.Compute/galleries/devfactory_gallery/images/secure-avd-image/versions/latest"
    }
    
    sku = {
      name = "general_i_16c64gb512ssd_v2"
    }
    
    hibernate_support = "Disabled"  # AVD session hosts typically don't hibernate
    
    dev_center = {
      key = "secure_devcenter"
    }
    
    tags = {
      platform       = "avd"
      session_type   = "multi-session"
      gpu_support    = "enabled"
      fslogix        = "enabled"
      security_level = "high"
    }
  }
}

# Environment Types with Security Configurations
dev_center_environment_types = {
  secure_dev_environment = {
    name         = "secure-dev"
    display_name = "Secure Development Environment"
    
    # Deployment identity for secure deployments
    deployment_target_id = "/subscriptions/$(ARM_SUBSCRIPTION_ID)"
    
    dev_center = {
      key = "secure_devcenter"
    }
    
    tags = {
      environment_type = "development"
      security_level   = "high"
      compliance       = "required"
      network_isolated = "true"
    }
  }
  
  secure_prod_environment = {
    name         = "secure-prod"
    display_name = "Secure Production Environment"
    
    deployment_target_id = "/subscriptions/$(ARM_SUBSCRIPTION_ID)"
    
    dev_center = {
      key = "secure_devcenter"
    }
    
    tags = {
      environment_type = "production"
      security_level   = "maximum"
      compliance       = "strict"
      network_isolated = "true"
      audit_logging    = "comprehensive"
    }
  }
}

# Security and Compliance Tags
tags = {
  security_classification = "confidential"
  compliance_framework    = "SOC2-TypeII"
  data_residency         = "required"
  audit_logging          = "enabled"
  backup_policy          = "required"
  disaster_recovery      = "enabled"
  network_security       = "enhanced"
  encryption_at_rest     = "cmk"
  encryption_in_transit  = "required"
  access_control         = "rbac"
  monitoring_level       = "comprehensive"
  incident_response      = "automated"
}