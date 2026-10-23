packer {
  required_plugins {
    azure = {
      version = ">= 2.0.0"
      source  = "github.com/hashicorp/azure"
    }
  }
}

# Leave default out! Packer will read this safely from GitHub Secrets at runtime.
variable "subscription_id" {
  type      = string
  sensitive = true
}

variable "vm_size" {
  type    = string
  default = "Standard_D2as_v7"
}

variable "resource_group_name" {
  type    = string
  default = "rg-devsecops-lab"
}

source "azure-arm" "windows2022" {
  use_azure_cli_auth = true
  subscription_id    = var.subscription_id

  managed_image_resource_group_name = var.resource_group_name
  managed_image_name                = "win2022-cis-gold-v1"
  location                          = "italynorth"

  os_type         = "Windows"
  image_publisher = "MicrosoftWindowsServer"
  image_offer     = "WindowsServer"
  image_sku       = "2022-datacenter-g2"

  communicator   = "winrm"
  winrm_use_ssl  = true
  winrm_insecure = true
  winrm_timeout  = "15m"
  winrm_username = "packer"

  vm_size = var.vm_size
}

build {
  sources = ["source.azure-arm.windows2022"]

  # 1. Run the Enterprise Hardening Script
  provisioner "powershell" {
    script = "./scripts/CIShardening.ps1"
  }

  # 2. Reboot VM so RunAsPPL, Schannel, and feature removals take effect
  provisioner "windows-restart" {
    restart_timeout = "10m"
  }

  # 3. Run the Compliance Validation Script (Aborts build if any check fails)
  provisioner "powershell" {
    script = "./scripts/Test-CisCompliance.ps1"
  }

  # 4. Generalize OS via Sysprep so Azure can capture the Golden Image
  provisioner "powershell" {
    inline = [
      "& $env:SystemRoot\\System32\\Sysprep\\sysprep.exe /oobe /generalize /quit /quiet",
      "while($true) { $process = Get-Process sysprep -ErrorAction SilentlyContinue; if (!$process) { break; } Start-Sleep -s 5 }"
    ]
  }
}