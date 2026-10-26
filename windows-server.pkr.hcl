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
  default = "Standard_DS1_v2"
}

variable "resource_group_name" {
  type    = string
  default = "rg-devsecops-lab"
}

# Which controls to apply from controls/catalog.json
variable "os" {
  type    = string
  default = "ws2022"

  validation {
    condition     = contains(["ws2022"], var.os)
    error_message = "The os must be one the catalog has been tested on: ws2022."
  }
}

variable "cis_level" {
  type    = number
  default = 1

  validation {
    condition     = contains([1, 2], var.cis_level)
    error_message = "The cis_level must be 1 or 2."
  }
}

locals {
  # Marketplace image for each OS the catalog supports
  image_skus = {
    ws2022 = "2022-datacenter-g2"
  }
  baseline_args = "-Os ${var.os} -Level ${var.cis_level} -Platform azure"
}

source "azure-arm" "windows2022" {
  use_azure_cli_auth = true
  subscription_id    = var.subscription_id

  managed_image_resource_group_name = var.resource_group_name
  managed_image_name                = "win2022-cis-gold-v1"
  location                          = "belgiumcentral"

  os_type         = "Windows"
  image_publisher = "MicrosoftWindowsServer"
  image_offer     = "WindowsServer"
  image_sku       = local.image_skus[var.os]

  communicator   = "winrm"
  winrm_use_ssl  = true
  winrm_insecure = true
  winrm_timeout  = "15m"
  winrm_username = "packer"

  vm_size = var.vm_size
}

build {
  sources = ["source.azure-arm.windows2022"]

  # 1. Upload the baseline engine, controls catalog and entry script to C:\cis
  provisioner "powershell" {
    inline = ["New-Item -Path C:\\cis -ItemType Directory -Force | Out-Null"]
  }

  provisioner "file" {
    sources     = ["./engine", "./controls", "./scripts"]
    destination = "C:\\cis\\"
  }

  # 2. Apply the selected controls
  provisioner "powershell" {
    inline = ["& C:\\cis\\scripts\\Invoke-CisBaseline.ps1 -Mode Apply ${local.baseline_args}"]
  }

  # 3. Reboot VM so RunAsPPL, Schannel, and feature removals take effect
  provisioner "windows-restart" {
    restart_timeout = "10m"
  }

  # 4. Test every selected control and save the results. -ReportOnly keeps the build going
  #    so the results can be downloaded even when controls fail; step 6 enforces the result.
  provisioner "powershell" {
    inline = ["& C:\\cis\\scripts\\Invoke-CisBaseline.ps1 -Mode Test ${local.baseline_args} -ResultsPath C:\\cis\\results.json -ReportOnly"]
  }

  # 5. Bring the results back to the runner as build evidence
  provisioner "file" {
    direction   = "download"
    source      = "C:\\cis\\results.json"
    destination = "artifacts/compliance-results.json"
  }

  # 6. Compliance gate: abort before Sysprep if any control failed, so the image is never captured
  provisioner "powershell" {
    inline = [
      "$Report = Get-Content C:\\cis\\results.json -Raw | ConvertFrom-Json",
      "if ($Report.failed -gt 0) { Write-Host ('Compliance gate: ' + $Report.failed + ' control(s) failed'); exit 1 }",
      "Write-Host ('Compliance gate: all ' + $Report.passed + ' controls passed')"
    ]
  }

  # 7. Generalize OS via Sysprep so Azure can capture the Golden Image
  provisioner "powershell" {
    inline = [
      "& $env:SystemRoot\\System32\\Sysprep\\sysprep.exe /oobe /generalize /quit /quiet",
      "while($true) { $process = Get-Process sysprep -ErrorAction SilentlyContinue; if (!$process) { break; } Start-Sleep -s 5 }"
    ]
  }
}