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
    condition     = contains(["ws2019", "ws2022", "ws2025"], var.os)
    error_message = "The os must be ws2019, ws2022 or ws2025."
  }
}

# ms = member server image. dc = throwaway test: promote a lab domain controller, apply and
# test the DC profile, then delete everything without capturing an image (DCs can't be sysprepped).
variable "role" {
  type    = string
  default = "ms"

  validation {
    condition     = contains(["ms", "dc"], var.role)
    error_message = "The role must be ms (member server) or dc (domain controller)."
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
    ws2019 = "2019-datacenter-gensecond"
    ws2022 = "2022-datacenter-g2"
    ws2025 = "2025-datacenter-g2"
  }
  baseline_args = "-Os ${var.os} -Role ${var.role} -Level ${var.cis_level} -Platform azure"
}

source "azure-arm" "windows" {
  use_azure_cli_auth = true
  subscription_id    = var.subscription_id

  # One image per OS and level, e.g. cis-ws2022-ms-l1, so builds don't overwrite each other
  managed_image_resource_group_name = var.resource_group_name
  managed_image_name                = "cis-${var.os}-ms-l${var.cis_level}"
  location                          = "belgiumcentral"
  skip_create_image                 = var.role == "dc"

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
  sources = ["source.azure-arm.windows"]

  # 1. Upload the baseline engine, controls catalog and entry script to C:\cis
  provisioner "powershell" {
    inline = ["New-Item -Path C:\\cis -ItemType Directory -Force | Out-Null"]
  }

  provisioner "file" {
    sources     = ["./engine", "./controls", "./scripts"]
    destination = "C:\\cis\\"
  }

  # 2. DC test builds only: promote the VM to the first DC of a throwaway lab forest.
  #    The DSRM password is random and never leaves the VM, which is deleted after the build.
  provisioner "powershell" {
    inline = [
      "if ('${var.role}' -ne 'dc') { Write-Host 'Member server build: no domain controller promotion'; exit 0 }",
      "Install-WindowsFeature AD-Domain-Services -IncludeManagementTools | Out-Null",
      "$Dsrm = ConvertTo-SecureString ([guid]::NewGuid().ToString() + 'Aa1!') -AsPlainText -Force",
      "Install-ADDSForest -DomainName 'lab.example.internal' -DomainNetbiosName 'LAB' -SafeModeAdministratorPassword $Dsrm -InstallDns -NoRebootOnCompletion -Force | Out-Null",
      "Write-Host 'Promoted to domain controller of lab.example.internal; restarting to finish'"
    ]
  }

  # 3. Restart to finish DC promotion (slow on small VMs). Member server builds just restart quickly.
  provisioner "windows-restart" {
    restart_timeout = "30m"
  }

  # 4. Apply the selected controls
  provisioner "powershell" {
    inline = ["& C:\\cis\\scripts\\Invoke-CisBaseline.ps1 -Mode Apply ${local.baseline_args}"]
  }

  # 5. Reboot VM so RunAsPPL, Schannel, and feature removals take effect
  provisioner "windows-restart" {
    restart_timeout = "10m"
  }

  # 6. Test every selected control and save the results. -ReportOnly keeps the build going
  #    so the results can be downloaded even when controls fail; step 8 enforces the result.
  provisioner "powershell" {
    inline = ["& C:\\cis\\scripts\\Invoke-CisBaseline.ps1 -Mode Test ${local.baseline_args} -ResultsPath C:\\cis\\results.json -ReportOnly"]
  }

  # 7. Bring the results back to the runner as build evidence
  provisioner "file" {
    direction   = "download"
    source      = "C:\\cis\\results.json"
    destination = "artifacts/compliance-results.json"
  }

  # 8. Compliance gate: abort before Sysprep if any control failed, so the image is never captured
  provisioner "powershell" {
    inline = [
      "$Report = Get-Content C:\\cis\\results.json -Raw | ConvertFrom-Json",
      "if ($Report.failed -gt 0) { Write-Host ('Compliance gate: ' + $Report.failed + ' control(s) failed'); exit 1 }",
      "Write-Host ('Compliance gate: all ' + $Report.passed + ' controls passed')"
    ]
  }

  # 9. Generalize OS via Sysprep so Azure can capture the Golden Image (member servers only)
  provisioner "powershell" {
    inline = [
      "if ('${var.role}' -eq 'dc') { Write-Host 'DC test build: no Sysprep or image capture'; exit 0 }",
      "& $env:SystemRoot\\System32\\Sysprep\\sysprep.exe /oobe /generalize /quit /quiet",
      "while($true) { $process = Get-Process sysprep -ErrorAction SilentlyContinue; if (!$process) { break; } Start-Sleep -s 5 }"
    ]
  }
}