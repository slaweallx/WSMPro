# Windows Güvenlik Yöneticisi Pro
# Bu script Windows Defender ve Windows Güvenlik ayarlarýný yönetmenizi saðlar
# Oluþturan: [Tarih: 11.05.2025]
# Powered by Slaweally (Megabre.com)

# Administrator yetkisiyle çalýþtýrýlýp çalýþtýrýlmadýðýný kontrol et
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "Bu script yönetici haklarýyla çalýþtýrýlmalýdýr! Lütfen PowerShell'i yönetici olarak çalýþtýrýn." -ForegroundColor Red
    Write-Host "PowerShell'i yönetici olarak çalýþtýrdýktan sonra þu komutu kullanabilirsiniz:" -ForegroundColor Yellow
    Write-Host "Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force" -ForegroundColor Yellow
    Start-Sleep -Seconds 5
    exit
}

# Form oluþturmak için gereken assembly'leri yükle
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# Dil ayarlarý - Türkçe ve Ýngilizce dil desteði
$global:CurrentLanguage = "TR" # Varsayýlan dil: Türkçe

$global:Translations = @{}
$global:Translations["TR"] = @{
    "FormTitle" = "Windows Güvenlik Yöneticisi Pro"
    "WindowsDefender" = "Windows Defender"
    "WindowsFirewall" = "Windows Güvenlik Duvarý"
    "MaxSecurity" = "Maksimum Güvenlik"
    "AdvancedSettings" = "Geliþmiþ Ayarlar"
    "EnableDefender" = "Defender'ý Etkinleþtir"
    "DisableDefender" = "Defender'ý Devre Dýþý Býrak"
    "EnableFirewall" = "Güvenlik Duvarýný Etkinleþtir"
    "DisableFirewall" = "Güvenlik Duvarýný Devre Dýþý Býrak"
    "EnableMaxSecurity" = "Maksimum Güvenliði Etkinleþtir"
    "QuickScan" = "Hýzlý Tarama Baþlat"
    "UpdateDefinitions" = "Virüs Ýmzalarýný Güncelle"
    "OpenWindowsSecurity" = "Windows Güvenlik Merkezi'ni Aç"
    "OpenFirewallSettings" = "Güvenlik Duvarý Ayarlarýný Aç"
    "Status" = "Durum"
    "Ready" = "Hazýr. Lütfen bir iþlem seçin."
    "SecurityStatus" = "Güvenlik Durumu"
    "DefenderStatus" = "Windows Defender Durumu:"
    "FirewallStatus" = "Windows Güvenlik Duvarý Durumu:"
    "Active" = "Aktif"
    "Inactive" = "Devre Dýþý"
    "SecuritySettingsTab" = "Güvenlik Ayarlarý"
    "FirewallTab" = "Güvenlik Duvarý"
    "AdvancedTab" = "Geliþmiþ Ayarlar"
    "AboutTab" = "Hakkýnda"
    "RealTimeProtection" = "Gerçek Zamanlý Koruma"
    "BehaviorMonitoring" = "Davranýþ Ýzleme"
    "DownloadProtection" = "Ýndirilen Dosya Korumasý"
    "NetworkProtection" = "Að Saldýrýsý Korumasý"
    "AutomaticUpdates" = "Otomatik Güncellemeler"
    "SmartScreen" = "SmartScreen Filtresi"
    "UAC" = "Kullanýcý Hesabý Denetimi (UAC)"
    "DEP" = "Veri Yürütme Engelleme (DEP)"
    "DomainFirewall" = "Etki Alaný Profili (Ýþ aðlarý)"
    "PrivateFirewall" = "Özel Profil (Ev aðlarý)"
    "PublicFirewall" = "Genel Profil (Halka açýk aðlar)"
    "BlockInbound" = "Tüm Gelen Baðlantýlarý Engelle (Önerilen)"
    "AllowInbound" = "Gelen Baðlantýlara Ýzin Ver (Daha Az Güvenli)"
    "FirewallRuleName" = "Kural Adý:"
    "PortNumber" = "Baðlantý Noktasý:"
    "Protocol" = "Protokol:"
    "OpenPort" = "Baðlantý Noktasýný Aç"
    "ClosePort" = "Baðlantý Noktasýný Kapat"
    "SettingNotFound" = "Bilinmeyen ayar:"
    "FirewallInfo" = "Güvenlik Duvarý (Firewall), bilgisayarýnýzý að üzerinden gelen yetkisiz eriþimlere karþý korur.`n`nProfiller:`n- Etki Alaný: Ýþ aðlarýnda kullanýlýr.`n- Özel: Ev aðlarýnda kullanýlýr.`n- Genel: Kafeler, havaalanlarý gibi halka açýk aðlarda kullanýlýr.`n`nEylemler:`n- Gelen baðlantýlarý engelle: Tüm gelen baðlantýlarý reddeder.`n- Gelen baðlantýlara izin ver: Kurallara uyan baðlantýlara izin verir.`n`nBaðlantý Noktalarý:`nBelirli bir hizmet için baðlantý noktasý açmak, o hizmete uzaktan eriþim saðlar. Ancak gereksiz açýk baðlantý noktalarý güvenlik riski oluþturabilir.`n`nYaygýn Baðlantý Noktalarý:`n- 80: HTTP (Web)`n- 443: HTTPS (Güvenli Web)`n- 3389: Uzak Masaüstü`n- 25, 587: SMTP (E-posta)`n- 110, 995: POP3 (E-posta)`n- 143, 993: IMAP (E-posta)"
    "AboutInfo" = "Windows Güvenlik Yöneticisi Pro`n`nSürüm: 1.0`nTarih: 11.05.2025`n`nBu araç, Windows'un yerleþik güvenlik özelliklerini kolayca yönetmenizi saðlar. Windows Defender ve Windows Güvenlik Duvarý gibi önemli güvenlik bileþenlerini tek týklamayla kontrol edebilirsiniz.`n`nWindows'un yerleþik güvenlik özellikleri, çoðu kullanýcý için ek bir antivirüs yazýlýmýna gerek kalmadan yeterli koruma saðlar. Bu araç sayesinde bu güvenlik özelliklerini maksimum seviyeye çýkarabilirsiniz.`n`nPowered by Slaweally (Megabre.com)"
    "MaxSecurityEnabled" = "Maksimum güvenlik ayarlarý etkinleþtirildi."
    "SomeSettingsFailed" = "Bazý ayarlar uygulanýrken sorun oluþtu:"
    "DefenderEnabled" = "Windows Defender baþarýyla etkinleþtirildi."
    "DefenderDisabled" = "Windows Defender devre dýþý býrakýldý."
    "FirewallEnabled" = "Windows Güvenlik Duvarý baþarýyla etkinleþtirildi."
    "FirewallDisabled" = "Windows Güvenlik Duvarý devre dýþý býrakýldý."
    "ScanCompleted" = "Güvenlik taramasý tamamlandý."
    "ScanFailed" = "Güvenlik taramasý baþlatýlamadý:"
    "UpdateCompleted" = "Ýmza güncellemesi tamamlandý."
    "UpdateFailed" = "Ýmza güncellemesi baþlatýlamadý:"
    "DefenderAppNotFound" = "Windows Defender uygulamasý bulunamadý. Windows Güvenlik uygulamasý açýlýyor."
    "EnterRuleName" = "Lütfen bir kural adý girin."
    "EnterValidPort" = "Lütfen geçerli bir baðlantý noktasý numarasý girin."
    "PortOpened" = "Baðlantý noktasý {0} ({1}) baþarýyla açýldý."
    "PortOpenFailed" = "Baðlantý noktasý açýlamadý."
    "RuleRemoved" = "'{0}' kuralý baþarýyla kaldýrýldý."
    "RuleRemoveFailed" = "Baðlantý noktasý kuralý kaldýrýlamadý."
    "Error" = "Hata"
    "Info" = "Bilgi"
    "Warning" = "Uyarý"
    "Success" = "Ýþlem Tamamlandý"
    "WarningTitle" = "Dikkat!"
    "SecurityLevel" = "Güvenlik Seviyesi:"
    "High" = "Yüksek"
    "Medium" = "Orta"
    "Low" = "Düþük"
}

$global:Translations["EN"] = @{
    "FormTitle" = "Windows Security Manager Pro"
    "WindowsDefender" = "Windows Defender"
    "WindowsFirewall" = "Windows Firewall"
    "MaxSecurity" = "Maximum Security"
    "AdvancedSettings" = "Advanced Settings"
    "EnableDefender" = "Enable Defender"
    "DisableDefender" = "Disable Defender"
    "EnableFirewall" = "Enable Firewall"
    "DisableFirewall" = "Disable Firewall"
    "EnableMaxSecurity" = "Enable Maximum Security"
    "QuickScan" = "Start Quick Scan"
    "UpdateDefinitions" = "Update Virus Definitions"
    "OpenWindowsSecurity" = "Open Windows Security Center"
    "OpenFirewallSettings" = "Open Firewall Settings"
    "Status" = "Status"
    "Ready" = "Ready. Please select an operation."
    "SecurityStatus" = "Security Status"
    "DefenderStatus" = "Windows Defender Status:"
    "FirewallStatus" = "Windows Firewall Status:"
    "Active" = "Active"
    "Inactive" = "Inactive"
    "SecuritySettingsTab" = "Security Settings"
    "FirewallTab" = "Firewall"
    "AdvancedTab" = "Advanced Settings"
    "AboutTab" = "About"
    "RealTimeProtection" = "Real-time Protection"
    "BehaviorMonitoring" = "Behavior Monitoring"
    "DownloadProtection" = "Downloaded File Protection"
    "NetworkProtection" = "Network Attack Protection"
    "AutomaticUpdates" = "Automatic Updates"
    "SmartScreen" = "SmartScreen Filter"
    "UAC" = "User Account Control (UAC)"
    "DEP" = "Data Execution Prevention (DEP)"
    "DomainFirewall" = "Domain Profile (Business networks)"
    "PrivateFirewall" = "Private Profile (Home networks)"
    "PublicFirewall" = "Public Profile (Public networks)"
    "BlockInbound" = "Block All Incoming Connections (Recommended)"
    "AllowInbound" = "Allow Incoming Connections (Less Secure)"
    "FirewallRuleName" = "Rule Name:"
    "PortNumber" = "Port Number:"
    "Protocol" = "Protocol:"
    "OpenPort" = "Open Port"
    "ClosePort" = "Close Port"
    "SettingNotFound" = "Unknown setting:"
    "FirewallInfo" = "Firewall protects your computer from unauthorized access via the network.`n`nProfiles:`n- Domain: Used in business networks.`n- Private: Used in home networks.`n- Public: Used in public places like cafes, airports.`n`nActions:`n- Block incoming connections: Rejects all incoming connections.`n- Allow incoming connections: Allows connections matching the rules.`n`nPorts:`nOpening a port for a specific service allows remote access to that service. However, unnecessarily open ports can create security risks.`n`nCommon Ports:`n- 80: HTTP (Web)`n- 443: HTTPS (Secure Web)`n- 3389: Remote Desktop`n- 25, 587: SMTP (Email)`n- 110, 995: POP3 (Email)`n- 143, 993: IMAP (Email)"
    "AboutInfo" = "Windows Security Manager Pro`n`nVersion: 1.0`nDate: 05/11/2025`n`nThis tool allows you to easily manage the built-in security features of Windows. You can control important security components like Windows Defender and Windows Firewall with just one click.`n`nThe built-in security features of Windows provide sufficient protection for most users without the need for additional antivirus software. With this tool, you can maximize these security features.`n`nPowered by Slaweally (Megabre.com)"
    "MaxSecurityEnabled" = "Maximum security settings have been enabled."
    "SomeSettingsFailed" = "Some settings could not be applied:"
    "DefenderEnabled" = "Windows Defender has been successfully enabled."
    "DefenderDisabled" = "Windows Defender has been disabled."
    "FirewallEnabled" = "Windows Firewall has been successfully enabled."
    "FirewallDisabled" = "Windows Firewall has been disabled."
    "ScanCompleted" = "Security scan completed."
    "ScanFailed" = "Could not start security scan:"
    "UpdateCompleted" = "Signature update completed."
    "UpdateFailed" = "Could not start signature update:"
    "DefenderAppNotFound" = "Windows Defender application not found. Opening Windows Security application."
    "EnterRuleName" = "Please enter a rule name."
    "EnterValidPort" = "Please enter a valid port number."
    "PortOpened" = "Port {0} ({1}) has been successfully opened."
    "PortOpenFailed" = "Could not open port."
    "RuleRemoved" = "Rule '{0}' has been successfully removed."
    "RuleRemoveFailed" = "Could not remove port rule."
    "Error" = "Error"
    "Info" = "Information"
    "Warning" = "Warning"
    "Success" = "Operation Completed"
    "WarningTitle" = "Warning!"
    "SecurityLevel" = "Security Level:"
    "High" = "High"
    "Medium" = "Medium"
    "Low" = "Low"
	
}

# Çeviriyi al
function Get-Translation {
    param (
        [string]$Key
    )
    
    return $global:Translations[$global:CurrentLanguage][$Key]
}

# Dil deðiþtirme fonksiyonu
function Set-Language {
    param (
        [string]$Language
    )
    
    $global:CurrentLanguage = $Language
    Update-UILanguage
}

# Windows Defender servislerini kontrol et ve baþlat
function Ensure-WindowsDefenderServices {
    $defenderServices = @(
        "WinDefend", # Windows Defender Service
        "WdNisSvc", # Windows Defender Network Inspection Service
        "SecurityHealthService" # Windows Security Health Service
    )
    
    $result = $true
    
    foreach ($service in $defenderServices) {
        try {
            $serviceStatus = Get-Service -Name $service -ErrorAction SilentlyContinue
            
            if ($serviceStatus -and $serviceStatus.Status -ne "Running") {
                Write-Host "Windows Defender servisi '$service' çalýþmýyor. Baþlatýlýyor..." -ForegroundColor Yellow
                Start-Service -Name $service -ErrorAction SilentlyContinue
                $serviceStatus = Get-Service -Name $service -ErrorAction SilentlyContinue
                
                if ($serviceStatus.Status -ne "Running") {
                    Write-Host "Windows Defender servisi '$service' baþlatýlamadý." -ForegroundColor Red
                    $result = $false
                }
            }
            elseif (-not $serviceStatus) {
                Write-Host "Windows Defender servisi '$service' bulunamadý." -ForegroundColor Red
                $result = $false
            }
        }
        catch {
            Write-Host "Windows Defender servisleri kontrol edilirken hata oluþtu: $_" -ForegroundColor Red
            $result = $false
        }
    }
    
    # WMI servisini kontrol et
    try {
        $wmiStatus = Get-Service -Name "Winmgmt" -ErrorAction SilentlyContinue
        
        if ($wmiStatus -and $wmiStatus.Status -ne "Running") {
            Write-Host "WMI servisi çalýþmýyor. Baþlatýlýyor..." -ForegroundColor Yellow
            Start-Service -Name "Winmgmt" -ErrorAction SilentlyContinue
            $wmiStatus = Get-Service -Name "Winmgmt" -ErrorAction SilentlyContinue
            
            if ($wmiStatus.Status -ne "Running") {
                Write-Host "WMI servisi baþlatýlamadý." -ForegroundColor Red
                $result = $false
            }
        }
    }
    catch {
        Write-Host "WMI servisi kontrol edilirken hata oluþtu: $_" -ForegroundColor Red
        $result = $false
    }
    
    return $result
}

# Windows Defender durumunu Registry üzerinden kontrol et ve ayarla
function Set-WindowsDefenderRegistry {
    param (
        [string]$Setting,
        [bool]$Enabled
    )
    
    # Registry yollarý
    $defenderRegPaths = @{
        "RealTimeProtection" = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"
        "BehaviorMonitoring" = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"
        "IoavProtection" = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"
        "GeneralProtection" = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender"
    }
    
    # Registry deðerleri
    $defenderRegValues = @{
        "RealTimeProtection" = "DisableRealtimeMonitoring"
        "BehaviorMonitoring" = "DisableBehaviorMonitoring"
        "IoavProtection" = "DisableIOAVProtection"
        "GeneralProtection" = "DisableAntiSpyware"
    }
    
    try {
        switch ($Setting) {
            "RealTimeProtection" {
                $regPath = $defenderRegPaths["RealTimeProtection"]
                $regValue = $defenderRegValues["RealTimeProtection"]
                
                if (-not (Test-Path $regPath)) {
                    New-Item -Path $regPath -Force | Out-Null
                }
                
                Set-ItemProperty -Path $regPath -Name $regValue -Value ([int](-not $Enabled)) -Type DWord
            }
            "BehaviorMonitoring" {
                $regPath = $defenderRegPaths["BehaviorMonitoring"]
                $regValue = $defenderRegValues["BehaviorMonitoring"]
                
                if (-not (Test-Path $regPath)) {
                    New-Item -Path $regPath -Force | Out-Null
                }
                
                Set-ItemProperty -Path $regPath -Name $regValue -Value ([int](-not $Enabled)) -Type DWord
            }
            "IoavProtection" {
                $regPath = $defenderRegPaths["IoavProtection"]
                $regValue = $defenderRegValues["IoavProtection"]
                
                if (-not (Test-Path $regPath)) {
                    New-Item -Path $regPath -Force | Out-Null
                }
                
                Set-ItemProperty -Path $regPath -Name $regValue -Value ([int](-not $Enabled)) -Type DWord
            }
            "AntivirusProtection" {
                $regPath = $defenderRegPaths["GeneralProtection"]
                $regValue = $defenderRegValues["GeneralProtection"]
                
                if (-not (Test-Path $regPath)) {
                    New-Item -Path $regPath -Force | Out-Null
                }
                
                Set-ItemProperty -Path $regPath -Name $regValue -Value ([int](-not $Enabled)) -Type DWord
            }
        }
        
        return $true
    }
    catch {
        Write-Host "Registry ayarlarý yapýlýrken hata oluþtu: $_" -ForegroundColor Red
        return $false
    }
}

# Windows Defender durumunu kontrol etme
function Get-WindowsDefenderStatus {
    try {
        # Ensure-WindowsDefenderServices fonksiyonunu çaðýr
        $servicesOK = Ensure-WindowsDefenderServices
        
        if (-not $servicesOK) {
            # Registry'den durum okumayý dene
            return Get-WindowsDefenderStatusFromRegistry
        }
        
        $defenderStatus = Get-MpComputerStatus -ErrorAction SilentlyContinue
        
        if ($defenderStatus) {
            $settings = @{
                "RealTimeProtection" = $defenderStatus.RealTimeProtectionEnabled
                "BehaviorMonitoring" = $defenderStatus.BehaviorMonitoringEnabled
                "AntivirusEnabled" = $defenderStatus.AntivirusEnabled
                "AntispywareEnabled" = $defenderStatus.AntispywareEnabled
                "IoavProtection" = $defenderStatus.IoavProtectionEnabled
                "NIS" = $defenderStatus.NISEnabled
            }
            
            return $settings
        }
        else {
            # Get-MpComputerStatus çalýþmazsa, registry'den kontrol et
            return Get-WindowsDefenderStatusFromRegistry
        }
    }
    catch {
        Write-Host "Windows Defender durumu alýnamadý: $_" -ForegroundColor Red
        return Get-WindowsDefenderStatusFromRegistry
    }
}

# Registry'den Windows Defender durumunu oku
function Get-WindowsDefenderStatusFromRegistry {
    $settings = @{
        "RealTimeProtection" = $true
        "BehaviorMonitoring" = $true
        "AntivirusEnabled" = $true
        "AntispywareEnabled" = $true
        "IoavProtection" = $true
        "NIS" = $true
    }
    
    # Registry yollarý ve deðerleri
    $paths = @{
        "RealTimeProtection" = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"
        "BehaviorMonitoring" = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"
        "IoavProtection" = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"
        "GeneralProtection" = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender"
    }
    
    $values = @{
        "RealTimeProtection" = "DisableRealtimeMonitoring"
        "BehaviorMonitoring" = "DisableBehaviorMonitoring"
        "IoavProtection" = "DisableIOAVProtection"
        "GeneralProtection" = "DisableAntiSpyware"
    }
    
    # RealTimeProtection kontrolü
    try {
        if (Test-Path $paths["RealTimeProtection"]) {
            $rtpValue = Get-ItemProperty -Path $paths["RealTimeProtection"] -Name $values["RealTimeProtection"] -ErrorAction SilentlyContinue
            if ($rtpValue -ne $null -and $rtpValue.$($values["RealTimeProtection"]) -eq 1) {
                $settings["RealTimeProtection"] = $false
            }
        }
    }
    catch { }
    
    # BehaviorMonitoring kontrolü
    try {
        if (Test-Path $paths["BehaviorMonitoring"]) {
            $bmValue = Get-ItemProperty -Path $paths["BehaviorMonitoring"] -Name $values["BehaviorMonitoring"] -ErrorAction SilentlyContinue
            if ($bmValue -ne $null -and $bmValue.$($values["BehaviorMonitoring"]) -eq 1) {
                $settings["BehaviorMonitoring"] = $false
            }
        }
    }
    catch { }
    
    # IoavProtection kontrolü
    try {
        if (Test-Path $paths["IoavProtection"]) {
            $ioavValue = Get-ItemProperty -Path $paths["IoavProtection"] -Name $values["IoavProtection"] -ErrorAction SilentlyContinue
            if ($ioavValue -ne $null -and $ioavValue.$($values["IoavProtection"]) -eq 1) {
                $settings["IoavProtection"] = $false
            }
        }
    }
    catch { }
    
    # AntivirusEnabled ve AntispywareEnabled kontrolü
    try {
        if (Test-Path $paths["GeneralProtection"]) {
            $gpValue = Get-ItemProperty -Path $paths["GeneralProtection"] -Name $values["GeneralProtection"] -ErrorAction SilentlyContinue
            if ($gpValue -ne $null -and $gpValue.$($values["GeneralProtection"]) -eq 1) {
                $settings["AntivirusEnabled"] = $false
                $settings["AntispywareEnabled"] = $false
            }
        }
    }
    catch { }
    
    return $settings
}

# Windows Defender durumunu tek seferde aç/kapat
function Set-WindowsDefenderState {
    param (
        [bool]$Enabled
    )
    
    $success = $true
    $errors = @()
    
    # Windows Defender genel durumu ayarla
    try {
        # PowerShell komutu ile dene
        Set-MpPreference -DisableRealtimeMonitoring $(-not $Enabled) -ErrorAction SilentlyContinue
        Set-MpPreference -DisableBehaviorMonitoring $(-not $Enabled) -ErrorAction SilentlyContinue
        Set-MpPreference -DisableIOAVProtection $(-not $Enabled) -ErrorAction SilentlyContinue
        Set-MpPreference -DisableIntrusionPreventionSystem $(-not $Enabled) -ErrorAction SilentlyContinue
    }
    catch {
        # Registry ile dene
        if (-not (Set-WindowsDefenderRegistry -Setting "RealTimeProtection" -Enabled $Enabled)) {
            $success = $false
            $errors += "Gerçek Zamanlý Koruma ayarlanamadý."
        }
        
        if (-not (Set-WindowsDefenderRegistry -Setting "BehaviorMonitoring" -Enabled $Enabled)) {
            $success = $false
            $errors += "Davranýþ Ýzleme ayarlanamadý."
        }
        
        if (-not (Set-WindowsDefenderRegistry -Setting "IoavProtection" -Enabled $Enabled)) {
            $success = $false
            $errors += "Ýndirilen Dosya Korumasý ayarlanamadý."
        }
        
        if (-not (Set-WindowsDefenderRegistry -Setting "AntivirusProtection" -Enabled $Enabled)) {
            $success = $false
            $errors += "Antivirüs Korumasý ayarlanamadý."
        }
    }
    
    # Defender servislerini ayarla
    $defenderServices = @(
        "WinDefend", # Windows Defender Service
        "WdNisSvc", # Windows Defender Network Inspection Service
        "SecurityHealthService" # Windows Security Health Service
    )
    
    foreach ($service in $defenderServices) {
        try {
            $serviceStatus = Get-Service -Name $service -ErrorAction SilentlyContinue
            
            if ($serviceStatus) {
                if ($Enabled) {
                    if ($serviceStatus.Status -ne "Running") {
                        Start-Service -Name $service -ErrorAction SilentlyContinue
                    }
                    Set-Service -Name $service -StartupType Automatic -ErrorAction SilentlyContinue
                }
                else {
                    if ($serviceStatus.Status -eq "Running") {
                        Stop-Service -Name $service -Force -ErrorAction SilentlyContinue
                    }
                    Set-Service -Name $service -StartupType Disabled -ErrorAction SilentlyContinue
                }
            }
        }
        catch {
            $success = $false
            $errors += "Servis '$service' ayarlanamadý: $_"
        }
    }
    
    # SmartScreen ayarý
    try {
        if ($Enabled) {
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "SmartScreenEnabled" -Value "RequireAdmin" -Type String -ErrorAction SilentlyContinue
        }
        else {
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "SmartScreenEnabled" -Value "Off" -Type String -ErrorAction SilentlyContinue
        }
    }
    catch {
        $success = $false
        $errors += "SmartScreen ayarlanamadý: $_"
    }
    
    # Sonucu döndür
    if ($success) {
        if ($Enabled) {
            return @{
                Success = $true
                Message = $(Get-Translation "DefenderEnabled")
            }
        }
        else {
            return @{
                Success = $true
                Message = $(Get-Translation "DefenderDisabled")
            }
        }
    }
    else {
        return @{
            Success = $false
            Message = $(Get-Translation "SomeSettingsFailed") + "`n" + ($errors -join "`n")
        }
    }
}

# Güvenlik Duvarýný tek seferde aç/kapat
function Set-FirewallState {
    param (
        [bool]$Enabled
    )
    
    $success = $true
    $errors = @()
    
    # Tüm profiller için güvenlik duvarýný aç/kapat
    try {
        if ($Enabled) {
            netsh advfirewall set allprofiles state on | Out-Null
        }
        else {
            netsh advfirewall set allprofiles state off | Out-Null
        }
    }
    catch {
        $success = $false
        $errors += "Güvenlik duvarý durumu deðiþtirilemedi: $_"
    }
    
    # Güvenlik duvarý servisi durumunu ayarla
    try {
        $firewallService = Get-Service -Name "MpsSvc" -ErrorAction SilentlyContinue # Windows Defender Firewall Service
        
        if ($firewallService) {
            if ($Enabled) {
                if ($firewallService.Status -ne "Running") {
                    Start-Service -Name "MpsSvc" -ErrorAction SilentlyContinue
                }
                Set-Service -Name "MpsSvc" -StartupType Automatic -ErrorAction SilentlyContinue
            }
            else {
                if ($firewallService.Status -eq "Running") {
                    Stop-Service -Name "MpsSvc" -Force -ErrorAction SilentlyContinue
                }
                Set-Service -Name "MpsSvc" -StartupType Disabled -ErrorAction SilentlyContinue
            }
        }
    }
    catch {
        $success = $false
        $errors += "Güvenlik duvarý servisi ayarlanamadý: $_"
    }
    
    # Sonucu döndür
    if ($success) {
        if ($Enabled) {
            return @{
                Success = $true
                Message = $(Get-Translation "FirewallEnabled")
            }
        }
        else {
            return @{
                Success = $true
                Message = $(Get-Translation "FirewallDisabled")
            }
        }
    }
    else {
        return @{
            Success = $false
            Message = $(Get-Translation "SomeSettingsFailed") + "`n" + ($errors -join "`n")
        }
    }
}

# Tüm güvenlik ayarlarýný alma
function Get-SecuritySettings {
    $settings = @{}
    
    # Windows Defender durumunu al
    $defenderSettings = Get-WindowsDefenderStatus
    if ($defenderSettings) {
        foreach ($key in $defenderSettings.Keys) {
            $settings[$key] = $defenderSettings[$key]
        }
    }
    
    # Windows Güvenlik Duvarý durumunu kontrol et
    try {
        # Direkt netsh komutlarýyla durum kontrolü
        $domainFirewall = (netsh advfirewall show domain | Select-String "State") -match "ON"
        $privateFirewall = (netsh advfirewall show private | Select-String "State") -match "ON"
        $publicFirewall = (netsh advfirewall show public | Select-String "State") -match "ON"
        
        $settings["FirewallDomain"] = $domainFirewall
        $settings["FirewallPrivate"] = $privateFirewall
        $settings["FirewallPublic"] = $publicFirewall
        
        # Genel güvenlik duvarý durumu
        $settings["FirewallEnabled"] = ($domainFirewall -or $privateFirewall -or $publicFirewall)
    }
    catch {
        Write-Host "Güvenlik Duvarý durumu alýnamadý: $_" -ForegroundColor Red
        $settings["FirewallDomain"] = $false
        $settings["FirewallPrivate"] = $false
        $settings["FirewallPublic"] = $false
        $settings["FirewallEnabled"] = $false
    }
    
    # Windows Update ayarlarýný kontrol et
    try {
        # Windows Update servisini kontrol et
        $wuService = Get-Service -Name "wuauserv" -ErrorAction SilentlyContinue
        $settings["AutomaticUpdates"] = ($wuService.StartType -ne "Disabled")
        
        # Registry'den otomatik güncelleme ayarlarýný kontrol et
        $auPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update"
        if (Test-Path $auPath) {
            $auOptions = (Get-ItemProperty -Path $auPath -Name "AUOptions" -ErrorAction SilentlyContinue).AUOptions
            if ($auOptions -ne $null) {
                $settings["AutomaticUpdates"] = ($auOptions -eq 4)
            }
        }
    }
    catch {
        Write-Host "Windows Update durumu alýnamadý: $_" -ForegroundColor Red
        $settings["AutomaticUpdates"] = $false
    }
    
    # SmartScreen durumunu kontrol et
    try {
        $smartScreen = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "SmartScreenEnabled" -ErrorAction SilentlyContinue).SmartScreenEnabled
        $settings["SmartScreen"] = if ($smartScreen -eq "RequireAdmin" -or $smartScreen -eq "Warn") { $true } else { $false }
    }
    catch {
        Write-Host "SmartScreen durumu alýnamadý: $_" -ForegroundColor Red
        $settings["SmartScreen"] = $false
    }
    
    # UAC durumunu kontrol et
    try {
        $uacLevel = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -ErrorAction SilentlyContinue).ConsentPromptBehaviorAdmin
        $settings["UAC"] = if ($uacLevel -ge 1) { $true } else { $false }
    }
    catch {
        Write-Host "UAC durumu alýnamadý: $_" -ForegroundColor Red
        $settings["UAC"] = $false
    }
    
    # DEP durumu kontrolü (wmic ile)
    try {
        $depStatus = (wmic OS Get DataExecutionPrevention_SupportPolicy | Select-String -Pattern "\d+").Matches[0].Value
        $settings["DEP"] = if ($depStatus -gt 0) { $true } else { $false }
    }
    catch {
        Write-Host "DEP durumu alýnamadý: $_" -ForegroundColor Red
        $settings["DEP"] = $false
    }
    
    # Güvenlik seviyesini hesapla
    $securityLevel = "Low"
    $criticalSettings = @("RealTimeProtection", "FirewallEnabled", "SmartScreen", "UAC")
    $essentialSettings = @("BehaviorMonitoring", "IoavProtection", "AutomaticUpdates", "DEP")
    
    $criticalCount = ($criticalSettings | Where-Object { $settings[$_] -eq $true }).Count
    $essentialCount = ($essentialSettings | Where-Object { $settings[$_] -eq $true }).Count
    
    if ($criticalCount -eq $criticalSettings.Count -and $essentialCount -ge 3) {
        $securityLevel = "High"
    }
    elseif ($criticalCount -ge 3 -and $essentialCount -ge 2) {
        $securityLevel = "Medium"
    }
    
    $settings["SecurityLevel"] = $securityLevel
    
    return $settings
}

# Güvenlik ayarlarýný deðiþtirme
function Set-SecuritySetting {
    param (
        [string]$Setting,
        [bool]$Enabled
    )
    
    $success = $false
    
    switch ($Setting) {
        # Windows Defender ayarlarý
        "RealTimeProtection" {
            # Önce PowerShell komutunu dene
            try {
                Set-MpPreference -DisableRealtimeMonitoring $(-not $Enabled) -ErrorAction SilentlyContinue
                $success = $true
            }
            catch {
                Write-Host "Set-MpPreference komutu çalýþtýrýlamadý. Registry ile ayarlama deneniyor..." -ForegroundColor Yellow
                $success = Set-WindowsDefenderRegistry -Setting "RealTimeProtection" -Enabled $Enabled
            }
        }
        "BehaviorMonitoring" {
            try {
                Set-MpPreference -DisableBehaviorMonitoring $(-not $Enabled) -ErrorAction SilentlyContinue
                $success = $true
            }
            catch {
                Write-Host "Set-MpPreference komutu çalýþtýrýlamadý. Registry ile ayarlama deneniyor..." -ForegroundColor Yellow
                $success = Set-WindowsDefenderRegistry -Setting "BehaviorMonitoring" -Enabled $Enabled
            }
        }
        "IoavProtection" {
            try {
                Set-MpPreference -DisableIOAVProtection $(-not $Enabled) -ErrorAction SilentlyContinue
                $success = $true
            }
            catch {
                Write-Host "Set-MpPreference komutu çalýþtýrýlamadý. Registry ile ayarlama deneniyor..." -ForegroundColor Yellow
                $success = Set-WindowsDefenderRegistry -Setting "IoavProtection" -Enabled $Enabled
            }
        }
        "NIS" {
            try {
                Set-MpPreference -DisableIntrusionPreventionSystem $(-not $Enabled) -ErrorAction SilentlyContinue
                $success = $true
            }
            catch {
                Write-Host "Set-MpPreference komutu çalýþtýrýlamadý." -ForegroundColor Yellow
            }
        }
        
        # Güvenlik Duvarý ayarlarý
        "FirewallDomain" {
            try {
                if ($Enabled) {
                    netsh advfirewall set domainprofile state on | Out-Null
                }
                else {
                    netsh advfirewall set domainprofile state off | Out-Null
                }
                $success = $true
            }
            catch {
                Write-Host "Güvenlik duvarý deðiþtirilemedi: $_" -ForegroundColor Red
            }
        }
        "FirewallPrivate" {
            try {
                if ($Enabled) {
                    netsh advfirewall set privateprofile state on | Out-Null
                }
                else {
                    netsh advfirewall set privateprofile state off | Out-Null
                }
                $success = $true
            }
            catch {
                Write-Host "Güvenlik duvarý deðiþtirilemedi: $_" -ForegroundColor Red
            }
        }
        "FirewallPublic" {
            try {
                if ($Enabled) {
                    netsh advfirewall set publicprofile state on | Out-Null
                }
                else {
                    netsh advfirewall set publicprofile state off | Out-Null
                }
                $success = $true
            }
            catch {
                Write-Host "Güvenlik duvarý deðiþtirilemedi: $_" -ForegroundColor Red
            }
        }
        
        # Windows Update ayarlarý
        "AutomaticUpdates" {
            try {
                if ($Enabled) {
                    # Windows Update servisini etkinleþtir
                    Set-Service -Name "wuauserv" -StartupType Automatic -ErrorAction SilentlyContinue
                    Start-Service -Name "wuauserv" -ErrorAction SilentlyContinue
                    
                    # Registry ayarlarýný güncelle
                    $auPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update"
                    if (Test-Path $auPath) {
                        Set-ItemProperty -Path $auPath -Name "AUOptions" -Value 4 -Type DWord -ErrorAction SilentlyContinue
                    }
                }
                else {
                    # Windows Update servisini devre dýþý býrak
                    Stop-Service -Name "wuauserv" -Force -ErrorAction SilentlyContinue
                    Set-Service -Name "wuauserv" -StartupType Disabled -ErrorAction SilentlyContinue
                    
                    # Registry ayarlarýný güncelle
                    $auPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update"
                    if (Test-Path $auPath) {
                        Set-ItemProperty -Path $auPath -Name "AUOptions" -Value 1 -Type DWord -ErrorAction SilentlyContinue
                    }
                }
                $success = $true
            }
            catch {
                Write-Host "Windows Update ayarlarý deðiþtirilemedi: $_" -ForegroundColor Red
            }
        }
        
        # SmartScreen ayarlarý
        "SmartScreen" {
            try {
                if ($Enabled) {
                    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "SmartScreenEnabled" -Value "RequireAdmin" -Type String -ErrorAction SilentlyContinue
                }
                else {
                    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "SmartScreenEnabled" -Value "Off" -Type String -ErrorAction SilentlyContinue
                }
                $success = $true
            }
            catch {
                Write-Host "SmartScreen ayarlarý deðiþtirilemedi: $_" -ForegroundColor Red
            }
        }
        
        # UAC ayarlarý
        "UAC" {
            try {
                if ($Enabled) {
                    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Value 2 -Type DWord -ErrorAction SilentlyContinue
                    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 1 -Type DWord -ErrorAction SilentlyContinue
                }
                else {
                    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Value 0 -Type DWord -ErrorAction SilentlyContinue
                    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 0 -Type DWord -ErrorAction SilentlyContinue
                }
                $success = $true
            }
            catch {
                Write-Host "UAC ayarlarý deðiþtirilemedi: $_" -ForegroundColor Red
            }
        }
        
        # DEP ayarlarý (bcdedit ile)
        "DEP" {
            try {
                if ($Enabled) {
                    bcdedit /set nx AlwaysOn | Out-Null
                }
                else {
                    bcdedit /set nx AlwaysOff | Out-Null
                }
                $success = $true
            }
            catch {
                Write-Host "DEP ayarlarý deðiþtirilemedi: $_" -ForegroundColor Red
            }
        }
        
        default {
            Write-Host $(Get-Translation "SettingNotFound") + " $Setting" -ForegroundColor Red
        }
    }
    
    return $success
}

# Güvenlik taramasý baþlat
function Run-SecurityScan {
    try {
        # MpCmdRun.exe'nin varlýðýný kontrol et
        $mpCmdRunPath = "C:\Program Files\Windows Defender\MpCmdRun.exe"
        if (Test-Path $mpCmdRunPath) {
            Start-Process -FilePath $mpCmdRunPath -ArgumentList "-Scan -ScanType 1" -Wait
            [System.Windows.Forms.MessageBox]::Show($(Get-Translation "ScanCompleted"), $(Get-Translation "Success"), [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
        }
        else {
            # Windows Security uygulamasýný aç
            Start-Process "ms-settings:windowsdefender-protection" -ErrorAction SilentlyContinue
            [System.Windows.Forms.MessageBox]::Show($(Get-Translation "DefenderAppNotFound"), $(Get-Translation "Info"), [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
        }
    }
    catch {
        [System.Windows.Forms.MessageBox]::Show($(Get-Translation "ScanFailed") + " $_", $(Get-Translation "Error"), [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
    }
}

# Ýmza güncellemesi
function Update-Definitions {
    try {
        # MpCmdRun.exe'nin varlýðýný kontrol et
        $mpCmdRunPath = "C:\Program Files\Windows Defender\MpCmdRun.exe"
        if (Test-Path $mpCmdRunPath) {
            Start-Process -FilePath $mpCmdRunPath -ArgumentList "-SignatureUpdate" -Wait
            [System.Windows.Forms.MessageBox]::Show($(Get-Translation "UpdateCompleted"), $(Get-Translation "Success"), [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
        }
        else {
            # Windows Security uygulamasýný aç
            Start-Process "ms-settings:windowsdefender-protection" -ErrorAction SilentlyContinue
            [System.Windows.Forms.MessageBox]::Show($(Get-Translation "DefenderAppNotFound"), $(Get-Translation "Info"), [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
        }
    }
    catch {
        [System.Windows.Forms.MessageBox]::Show($(Get-Translation "UpdateFailed") + " $_", $(Get-Translation "Error"), [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
    }
}

# Güvenlik Duvarý için Baðlantý Noktasý Ayarlarý
function Configure-FirewallPort {
    param (
        [string]$Name,
        [int]$Port,
        [string]$Protocol = "TCP",
        [bool]$Enabled
    )
    
    try {
        if ($Enabled) {
            # Baðlantý noktasýný aç
            netsh advfirewall firewall add rule name="$Name" dir=in action=allow protocol=$Protocol localport=$Port | Out-Null
            return $true
        }
        else {
            # Baðlantý noktasýný kapat
            netsh advfirewall firewall delete rule name="$Name" | Out-Null
            return $true
        }
    }
    catch {
        Write-Host "Güvenlik Duvarý baðlantý noktasý yapýlandýrýlamadý: $_" -ForegroundColor Red
        return $false
    }
}

# Tüm güvenlik ayarlarýný optimize et
function Optimize-SecuritySettings {
    $errors = @()
    
    # Windows Defender Ayarlarý
    if (-not (Set-SecuritySetting -Setting "RealTimeProtection" -Enabled $true)) {
        $errors += "Gerçek Zamanlý Koruma etkinleþtirilemedi."
    }
    
    if (-not (Set-SecuritySetting -Setting "BehaviorMonitoring" -Enabled $true)) {
        $errors += "Davranýþ Ýzleme etkinleþtirilemedi."
    }
    
    if (-not (Set-SecuritySetting -Setting "IoavProtection" -Enabled $true)) {
        $errors += "Ýndirilen Dosya Korumasý etkinleþtirilemedi."
    }
    
    if (-not (Set-SecuritySetting -Setting "NIS" -Enabled $true)) {
        $errors += "Að Saldýrýsý Korumasý etkinleþtirilemedi."
    }
    
    # Güvenlik Duvarý Ayarlarý
    if (-not (Set-SecuritySetting -Setting "FirewallDomain" -Enabled $true)) {
        $errors += "Etki Alaný Güvenlik Duvarý etkinleþtirilemedi."
    }
    
    if (-not (Set-SecuritySetting -Setting "FirewallPrivate" -Enabled $true)) {
        $errors += "Özel Að Güvenlik Duvarý etkinleþtirilemedi."
    }
    
    if (-not (Set-SecuritySetting -Setting "FirewallPublic" -Enabled $true)) {
        $errors += "Genel Að Güvenlik Duvarý etkinleþtirilemedi."
    }
    
    # Güvenlik duvarý eylemini ayarla
    try {
        netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound | Out-Null
    }
    catch {
        $errors += "Güvenlik duvarý eylemi ayarlanamadý."
    }
    
    # Diðer Ayarlar
    if (-not (Set-SecuritySetting -Setting "AutomaticUpdates" -Enabled $true)) {
        $errors += "Otomatik Güncellemeler etkinleþtirilemedi."
    }
    
    if (-not (Set-SecuritySetting -Setting "SmartScreen" -Enabled $true)) {
        $errors += "SmartScreen Filtresi etkinleþtirilemedi."
    }
    
    if (-not (Set-SecuritySetting -Setting "UAC" -Enabled $true)) {
        $errors += "Kullanýcý Hesabý Denetimi (UAC) etkinleþtirilemedi."
    }
    
    if (-not (Set-SecuritySetting -Setting "DEP" -Enabled $true)) {
        $errors += "Veri Yürütme Engelleme (DEP) etkinleþtirilemedi."
    }
    
    # Kullanýcýya sonuç bildir
    if ($errors.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show($(Get-Translation "MaxSecurityEnabled"), $(Get-Translation "Success"), [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
        return $true
    }
    else {
        $errorMessage = $(Get-Translation "SomeSettingsFailed") + "`n`n" + ($errors -join "`n")
        [System.Windows.Forms.MessageBox]::Show($errorMessage, $(Get-Translation "Warning"), [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
        return $false
    }
}

# Windows Güvenlik Merkezi'ni Aç
function Open-WindowsSecurityCenter {
    try {
        Start-Process "windowsdefender:" -ErrorAction SilentlyContinue
    }
    catch {
        # Alternatif olarak ayarlar sayfasýný aç
        Start-Process "ms-settings:windowsdefender" -ErrorAction SilentlyContinue
    }
}

# Güvenlik Duvarý Ayarlarýný Aç
function Open-FirewallSettings {
    try {
        Start-Process "firewall.cpl" -ErrorAction SilentlyContinue
    }
    catch {
        # Alternatif olarak ayarlar sayfasýný aç
        Start-Process "ms-settings:windowsdefender-firewall" -ErrorAction SilentlyContinue
    }
}

#region UI Oluþturma

# Form oluþtur
$form = New-Object System.Windows.Forms.Form
$form.Text = $(Get-Translation "FormTitle")
$form.Size = New-Object System.Drawing.Size(950, 700)
$form.StartPosition = "CenterScreen"
$form.BackColor = [System.Drawing.Color]::White
$form.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedDialog
$form.MaximizeBox = $false

# Form ikonu
$iconBase64 = "iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAYAAABzenr0AAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsMAAA7DAcdvqGQAAAMDSURBVFhH7ZZdSFNhGMf/57gzp9vcRR/QReuil4sKCqKLLoKgqIsoCukuqLtAr4S6CCQoyItEqIsiIkG6COlCuhDCiShJiqKVaYVmwtTNj23OHc/pPduZc85Zwi7qIvzBw/u+z/u8z//5OGfnSK8fuKbwn5A1p/4JXQGFrKwseDwepKen/zlfXLY2aWQyGfh8Pt3WkQUEAoEVD+h0OvX0c6emppCamqr7dGQBAVluhYSEhJji1kF5eTkmJiZ0n064AvLz81FUVKSvlmdiYgIFBQW6T4dXgNFohCRJfxXAF2A1j8mTICYmJuLIkSP48+8QFSDJUVRU1GpgaGgIBw4cgMPhQFJSEtrb25Gbm4srV65genpa97Oab9q0CdevX8eBQ5X4/W0Cn8c9aG5uxoULFzA6OqqHWrF//35cuXoNXxUzXrzqg8lkwtWrV3Hv3j34/X49KhzuJ8Dj8eDq5XO4+7AV7skA6s9exLlzZ7B//35kZ2frXlYKCwvR2NiIhw9a8P7jcERsRUUFampqcPjwYUiSRPdEPyzjXsGHZ68C3O/0qRrWPe5j9+/fp2iVzs5Odv78eTY6OsoCgQBrbW1ljY2NbGZmRrv39tUTduLUGdbV1cVisRgMsnPnzrHu7m5tdnd3s7KyMnbo0CF25MgR/iThFcDpf9vD/G4bc40ZNdvn8zG73c7m5uZYMBhkDocjasDHd6/YsWPHmMvl0nxCLpcrzOf1svHxcTY8PMw8Ho8WGw0+oSmgxQfV53I6tOufP3+ytrY2NjQ0xJxOp2ZbrVYWCoVY56tn7MSJ46y/v1+z83KMzO12M5vNxgYGBpjFYmGzs7NafDT4HYgqQG3GwsICm5ycZDMzM8ztdrPFxUXm9/u1eyaTiX369J61d3SwbCnAAv45ZrfbmdFoZH19fay8vJy1tLSwkpIStnnzZpaRkaHFRoNfwQrfgkAgEPEt4KgFBx2FVpK6FHJ+H8xmc9TiiQW/ghU+Ai0CQUREyO/7u1+ERBXw/cdPJKdlaRZfxftE/uXbKMomt2ZHg1dA3NGcNQ14+QtI04EnymxiNgAAAABJRU5ErkJggg=="
$iconBytes = [Convert]::FromBase64String($iconBase64)
$memoryStream = New-Object System.IO.MemoryStream($iconBytes, 0, $iconBytes.Length)
$formIcon = [System.Drawing.Icon]::FromHandle(([System.Drawing.Bitmap]::FromStream($memoryStream)).GetHIcon())
$form.Icon = $formIcon

# Font ve renkler tanýmla
$fontRegular = New-Object System.Drawing.Font("Segoe UI", 9)
$fontBold = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
$fontTitle = New-Object System.Drawing.Font("Segoe UI", 14, [System.Drawing.FontStyle]::Bold)
$fontSubTitle = New-Object System.Drawing.Font("Segoe UI", 12, [System.Drawing.FontStyle]::Bold)
$fontSection = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
$fontButtonLarge = New-Object System.Drawing.Font("Segoe UI", 11, [System.Drawing.FontStyle]::Bold)
$fontButtonMedium = New-Object System.Drawing.Font("Segoe UI", 10)
$fontStatus = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Italic)

$colorPrimary = [System.Drawing.Color]::FromArgb(0, 120, 212)
$colorSuccess = [System.Drawing.Color]::FromArgb(16, 124, 16)
$colorWarning = [System.Drawing.Color]::FromArgb(197, 17, 40)
$colorAccent = [System.Drawing.Color]::FromArgb(14, 99, 156)
$colorGray = [System.Drawing.Color]::FromArgb(120, 120, 120)
$colorLightGray = [System.Drawing.Color]::FromArgb(240, 240, 240)

# Tab Control oluþtur
$tabControl = New-Object System.Windows.Forms.TabControl
$tabControl.Location = New-Object System.Drawing.Point(20, 120)
$tabControl.Size = New-Object System.Drawing.Size(910, 530)
$tabControl.SelectedIndex = 0
$form.Controls.Add($tabControl)

# Tab Sayfalarý
$tabMain = New-Object System.Windows.Forms.TabPage
$tabMain.Text = $(Get-Translation "SecuritySettingsTab")
$tabControl.Controls.Add($tabMain)

$tabFirewall = New-Object System.Windows.Forms.TabPage
$tabFirewall.Text = $(Get-Translation "FirewallTab")
$tabControl.Controls.Add($tabFirewall)

$tabAdvanced = New-Object System.Windows.Forms.TabPage
$tabAdvanced.Text = $(Get-Translation "AdvancedTab")
$tabControl.Controls.Add($tabAdvanced)

$tabAbout = New-Object System.Windows.Forms.TabPage
$tabAbout.Text = $(Get-Translation "AboutTab")
$tabControl.Controls.Add($tabAbout)

# Dil deðiþtirme butonu - Sað üst köþe
$btnLanguage = New-Object System.Windows.Forms.Button
$btnLanguage.Location = New-Object System.Drawing.Point(850, 20)
$btnLanguage.Size = New-Object System.Drawing.Size(80, 30)
$btnLanguage.Text = "English"
$btnLanguage.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$btnLanguage.BackColor = $colorPrimary
$btnLanguage.ForeColor = [System.Drawing.Color]::White
$btnLanguage.FlatAppearance.BorderSize = 0
$btnLanguage.Cursor = [System.Windows.Forms.Cursors]::Hand
$btnLanguage.Add_Click({
    if ($global:CurrentLanguage -eq "TR") {
        Set-Language -Language "EN"
        $btnLanguage.Text = "Türkçe"
    }
    else {
        Set-Language -Language "TR"
        $btnLanguage.Text = "English"
    }
})
$form.Controls.Add($btnLanguage)

# Powered by etiketi - Sað üst köþe
$lblPoweredBy = New-Object System.Windows.Forms.Label
$lblPoweredBy.Location = New-Object System.Drawing.Point(690, 25)
$lblPoweredBy.Size = New-Object System.Drawing.Size(150, 30)
$lblPoweredBy.Text = "Powered by Slaweally (Megabre.com)"
$lblPoweredBy.Font = $fontRegular
$lblPoweredBy.ForeColor = $colorGray
$lblPoweredBy.TextAlign = [System.Drawing.ContentAlignment]::MiddleRight
$form.Controls.Add($lblPoweredBy)

# Baþlýk
$lblTitle = New-Object System.Windows.Forms.Label
$lblTitle.Location = New-Object System.Drawing.Point(20, 20)
$lblTitle.Size = New-Object System.Drawing.Size(650, 30)
$lblTitle.Text = $(Get-Translation "FormTitle")
$lblTitle.Font = $fontTitle
$lblTitle.ForeColor = $colorPrimary
$form.Controls.Add($lblTitle)

# Alt baþlýk
$lblSubtitle = New-Object System.Windows.Forms.Label
$lblSubtitle.Location = New-Object System.Drawing.Point(23, 50)
$lblSubtitle.Size = New-Object System.Drawing.Size(600, 25)
$lblSubtitle.Text = $(Get-Translation "SecurityStatus")
$lblSubtitle.Font = $fontSubTitle
$lblSubtitle.ForeColor = $colorAccent
$form.Controls.Add($lblSubtitle)

# Güvenlik Seviyesi
$lblSecurityLevel = New-Object System.Windows.Forms.Label
$lblSecurityLevel.Location = New-Object System.Drawing.Point(25, 75)
$lblSecurityLevel.Size = New-Object System.Drawing.Size(150, 20)
$lblSecurityLevel.Text = $(Get-Translation "SecurityLevel")
$lblSecurityLevel.Font = $fontSection
$form.Controls.Add($lblSecurityLevel)

# Güvenlik Seviyesi Deðeri
$lblSecurityLevelValue = New-Object System.Windows.Forms.Label
$lblSecurityLevelValue.Location = New-Object System.Drawing.Point(175, 75)
$lblSecurityLevelValue.Size = New-Object System.Drawing.Size(100, 20)
$lblSecurityLevelValue.Text = $(Get-Translation "High")
$lblSecurityLevelValue.Font = $fontSection
$lblSecurityLevelValue.ForeColor = $colorSuccess
$form.Controls.Add($lblSecurityLevelValue)

# Defender Durumu
$lblDefenderStatus = New-Object System.Windows.Forms.Label
$lblDefenderStatus.Location = New-Object System.Drawing.Point(290, 75)
$lblDefenderStatus.Size = New-Object System.Drawing.Size(200, 20)
$lblDefenderStatus.Text = $(Get-Translation "DefenderStatus")
$lblDefenderStatus.Font = $fontSection
$form.Controls.Add($lblDefenderStatus)

# Defender Durumu Deðeri
$lblDefenderStatusValue = New-Object System.Windows.Forms.Label
$lblDefenderStatusValue.Location = New-Object System.Drawing.Point(490, 75)
$lblDefenderStatusValue.Size = New-Object System.Drawing.Size(100, 20)
$lblDefenderStatusValue.Text = $(Get-Translation "Active")
$lblDefenderStatusValue.Font = $fontSection
$lblDefenderStatusValue.ForeColor = $colorSuccess
$form.Controls.Add($lblDefenderStatusValue)

# Güvenlik Duvarý Durumu
$lblFirewallStatus = New-Object System.Windows.Forms.Label
$lblFirewallStatus.Location = New-Object System.Drawing.Point(600, 75)
$lblFirewallStatus.Size = New-Object System.Drawing.Size(200, 20)
$lblFirewallStatus.Text = $(Get-Translation "FirewallStatus")
$lblFirewallStatus.Font = $fontSection
$form.Controls.Add($lblFirewallStatus)

# Güvenlik Duvarý Durumu Deðeri
$lblFirewallStatusValue = New-Object System.Windows.Forms.Label
$lblFirewallStatusValue.Location = New-Object System.Drawing.Point(800, 75)
$lblFirewallStatusValue.Size = New-Object System.Drawing.Size(100, 20)
$lblFirewallStatusValue.Text = $(Get-Translation "Active")
$lblFirewallStatusValue.Font = $fontSection
$lblFirewallStatusValue.ForeColor = $colorSuccess
$form.Controls.Add($lblFirewallStatusValue)

# Ana Sekme içeriði oluþtur

# Defender Paneli
$pnlDefender = New-Object System.Windows.Forms.Panel
$pnlDefender.Location = New-Object System.Drawing.Point(20, 20)
$pnlDefender.Size = New-Object System.Drawing.Size(420, 230)
$pnlDefender.BorderStyle = [System.Windows.Forms.BorderStyle]::FixedSingle
$pnlDefender.BackColor = $colorLightGray
$tabMain.Controls.Add($pnlDefender)

# Defender Baþlýk
$lblDefenderTitle = New-Object System.Windows.Forms.Label
$lblDefenderTitle.Location = New-Object System.Drawing.Point(10, 10)
$lblDefenderTitle.Size = New-Object System.Drawing.Size(400, 30)
$lblDefenderTitle.Text = $(Get-Translation "WindowsDefender")
$lblDefenderTitle.Font = $fontSubTitle
$lblDefenderTitle.ForeColor = $colorPrimary
$pnlDefender.Controls.Add($lblDefenderTitle)

# Defender Etkinleþtir Düðmesi
$btnEnableDefender = New-Object System.Windows.Forms.Button
$btnEnableDefender.Location = New-Object System.Drawing.Point(20, 60)
$btnEnableDefender.Size = New-Object System.Drawing.Size(380, 60)
$btnEnableDefender.Text = $(Get-Translation "EnableDefender")
$btnEnableDefender.Font = $fontButtonLarge
$btnEnableDefender.BackColor = $colorSuccess
$btnEnableDefender.ForeColor = [System.Drawing.Color]::White
$btnEnableDefender.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$btnEnableDefender.FlatAppearance.BorderSize = 0
$btnEnableDefender.Cursor = [System.Windows.Forms.Cursors]::Hand
$btnEnableDefender.Add_Click({
    $result = Set-WindowsDefenderState -Enabled $true
    if ($result.Success) {
        [System.Windows.Forms.MessageBox]::Show($result.Message, $(Get-Translation "Success"), [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
    }
    else {
        [System.Windows.Forms.MessageBox]::Show($result.Message, $(Get-Translation "Warning"), [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
    }
    RefreshControls
})
$pnlDefender.Controls.Add($btnEnableDefender)

# Defender Devre Dýþý Býrak Düðmesi
$btnDisableDefender = New-Object System.Windows.Forms.Button
$btnDisableDefender.Location = New-Object System.Drawing.Point(20, 130)
$btnDisableDefender.Size = New-Object System.Drawing.Size(380, 40)
$btnDisableDefender.Text = $(Get-Translation "DisableDefender")
$btnDisableDefender.Font = $fontButtonMedium
$btnDisableDefender.BackColor = $colorWarning
$btnDisableDefender.ForeColor = [System.Drawing.Color]::White
$btnDisableDefender.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$btnDisableDefender.FlatAppearance.BorderSize = 0
$btnDisableDefender.Cursor = [System.Windows.Forms.Cursors]::Hand
$btnDisableDefender.Add_Click({
    $result = Set-WindowsDefenderState -Enabled $false
    if ($result.Success) {
        [System.Windows.Forms.MessageBox]::Show($result.Message, $(Get-Translation "Success"), [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
    }
    else {
        [System.Windows.Forms.MessageBox]::Show($result.Message, $(Get-Translation "Warning"), [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
    }
    RefreshControls
})
$pnlDefender.Controls.Add($btnDisableDefender)

# Hýzlý Tarama Baþlat Düðmesi
$btnQuickScan = New-Object System.Windows.Forms.Button
$btnQuickScan.Location = New-Object System.Drawing.Point(20, 180)
$btnQuickScan.Size = New-Object System.Drawing.Size(185, 40)
$btnQuickScan.Text = $(Get-Translation "QuickScan")
$btnQuickScan.Font = $fontButtonMedium
$btnQuickScan.BackColor = $colorPrimary
$btnQuickScan.ForeColor = [System.Drawing.Color]::White
$btnQuickScan.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$btnQuickScan.FlatAppearance.BorderSize = 0
$btnQuickScan.Cursor = [System.Windows.Forms.Cursors]::Hand
$btnQuickScan.Add_Click({
    Run-SecurityScan
})
$pnlDefender.Controls.Add($btnQuickScan)

# Ýmza Güncelle Düðmesi
$btnUpdateDefinitions = New-Object System.Windows.Forms.Button
$btnUpdateDefinitions.Location = New-Object System.Drawing.Point(215, 180)
$btnUpdateDefinitions.Size = New-Object System.Drawing.Size(185, 40)
$btnUpdateDefinitions.Text = $(Get-Translation "UpdateDefinitions")
$btnUpdateDefinitions.Font = $fontButtonMedium
$btnUpdateDefinitions.BackColor = $colorPrimary
$btnUpdateDefinitions.ForeColor = [System.Drawing.Color]::White
$btnUpdateDefinitions.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$btnUpdateDefinitions.FlatAppearance.BorderSize = 0
$btnUpdateDefinitions.Cursor = [System.Windows.Forms.Cursors]::Hand
$btnUpdateDefinitions.Add_Click({
    Update-Definitions
})
$pnlDefender.Controls.Add($btnUpdateDefinitions)

# Güvenlik Duvarý Paneli
$pnlFirewall = New-Object System.Windows.Forms.Panel
$pnlFirewall.Location = New-Object System.Drawing.Point(450, 20)
$pnlFirewall.Size = New-Object System.Drawing.Size(420, 230)
$pnlFirewall.BorderStyle = [System.Windows.Forms.BorderStyle]::FixedSingle
$pnlFirewall.BackColor = $colorLightGray
$tabMain.Controls.Add($pnlFirewall)

# Güvenlik Duvarý Baþlýk
$lblFirewallTitle = New-Object System.Windows.Forms.Label
$lblFirewallTitle.Location = New-Object System.Drawing.Point(10, 10)
$lblFirewallTitle.Size = New-Object System.Drawing.Size(400, 30)
$lblFirewallTitle.Text = $(Get-Translation "WindowsFirewall")
$lblFirewallTitle.Font = $fontSubTitle
$lblFirewallTitle.ForeColor = $colorPrimary
$pnlFirewall.Controls.Add($lblFirewallTitle)

# Güvenlik Duvarý Etkinleþtir Düðmesi
$btnEnableFirewall = New-Object System.Windows.Forms.Button
$btnEnableFirewall.Location = New-Object System.Drawing.Point(20, 60)
$btnEnableFirewall.Size = New-Object System.Drawing.Size(380, 60)
$btnEnableFirewall.Text = $(Get-Translation "EnableFirewall")
$btnEnableFirewall.Font = $fontButtonLarge
$btnEnableFirewall.BackColor = $colorSuccess
$btnEnableFirewall.ForeColor = [System.Drawing.Color]::White
$btnEnableFirewall.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$btnEnableFirewall.FlatAppearance.BorderSize = 0
$btnEnableFirewall.Cursor = [System.Windows.Forms.Cursors]::Hand
$btnEnableFirewall.Add_Click({
    $result = Set-FirewallState -Enabled $true
    if ($result.Success) {
        [System.Windows.Forms.MessageBox]::Show($result.Message, $(Get-Translation "Success"), [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
    }
    else {
        [System.Windows.Forms.MessageBox]::Show($result.Message, $(Get-Translation "Warning"), [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
    }
    RefreshControls
})
$pnlFirewall.Controls.Add($btnEnableFirewall)

# Güvenlik Duvarý Devre Dýþý Býrak Düðmesi
$btnDisableFirewall = New-Object System.Windows.Forms.Button
$btnDisableFirewall.Location = New-Object System.Drawing.Point(20, 130)
$btnDisableFirewall.Size = New-Object System.Drawing.Size(380, 40)
$btnDisableFirewall.Text = $(Get-Translation "DisableFirewall")
$btnDisableFirewall.Font = $fontButtonMedium
$btnDisableFirewall.BackColor = $colorWarning
$btnDisableFirewall.ForeColor = [System.Drawing.Color]::White
$btnDisableFirewall.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$btnDisableFirewall.FlatAppearance.BorderSize = 0
$btnDisableFirewall.Cursor = [System.Windows.Forms.Cursors]::Hand
$btnDisableFirewall.Add_Click({
    $result = Set-FirewallState -Enabled $false
    if ($result.Success) {
        [System.Windows.Forms.MessageBox]::Show($result.Message, $(Get-Translation "Success"), [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
    }
    else {
        [System.Windows.Forms.MessageBox]::Show($result.Message, $(Get-Translation "Warning"), [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
    }
    RefreshControls
})
$pnlFirewall.Controls.Add($btnDisableFirewall)

# Windows Güvenlik Merkezi'ni Aç Düðmesi
$btnOpenSecurityCenter = New-Object System.Windows.Forms.Button
$btnOpenSecurityCenter.Location = New-Object System.Drawing.Point(20, 180)
$btnOpenSecurityCenter.Size = New-Object System.Drawing.Size(185, 40)
$btnOpenSecurityCenter.Text = $(Get-Translation "OpenWindowsSecurity")
$btnOpenSecurityCenter.Font = $fontButtonMedium
$btnOpenSecurityCenter.BackColor = $colorPrimary
$btnOpenSecurityCenter.ForeColor = [System.Drawing.Color]::White
$btnOpenSecurityCenter.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$btnOpenSecurityCenter.FlatAppearance.BorderSize = 0
$btnOpenSecurityCenter.Cursor = [System.Windows.Forms.Cursors]::Hand
$btnOpenSecurityCenter.Add_Click({
    Open-WindowsSecurityCenter
})
$pnlFirewall.Controls.Add($btnOpenSecurityCenter)

# Güvenlik Duvarý Ayarlarýný Aç Düðmesi
$btnOpenFirewallSettings = New-Object System.Windows.Forms.Button
$btnOpenFirewallSettings.Location = New-Object System.Drawing.Point(215, 180)
$btnOpenFirewallSettings.Size = New-Object System.Drawing.Size(185, 40)
$btnOpenFirewallSettings.Text = $(Get-Translation "OpenFirewallSettings")
$btnOpenFirewallSettings.Font = $fontButtonMedium
$btnOpenFirewallSettings.BackColor = $colorPrimary
$btnOpenFirewallSettings.ForeColor = [System.Drawing.Color]::White
$btnOpenFirewallSettings.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$btnOpenFirewallSettings.FlatAppearance.BorderSize = 0
$btnOpenFirewallSettings.Cursor = [System.Windows.Forms.Cursors]::Hand
$btnOpenFirewallSettings.Add_Click({
    Open-FirewallSettings
})
$pnlFirewall.Controls.Add($btnOpenFirewallSettings)

# Maksimum Güvenlik Paneli
$pnlMaxSecurity = New-Object System.Windows.Forms.Panel
$pnlMaxSecurity.Location = New-Object System.Drawing.Point(20, 270)
$pnlMaxSecurity.Size = New-Object System.Drawing.Size(850, 200)
$pnlMaxSecurity.BorderStyle = [System.Windows.Forms.BorderStyle]::FixedSingle
$pnlMaxSecurity.BackColor = $colorLightGray
$tabMain.Controls.Add($pnlMaxSecurity)

# Maksimum Güvenlik Baþlýk
$lblMaxSecurityTitle = New-Object System.Windows.Forms.Label
$lblMaxSecurityTitle.Location = New-Object System.Drawing.Point(10, 10)
$lblMaxSecurityTitle.Size = New-Object System.Drawing.Size(830, 30)
$lblMaxSecurityTitle.Text = $(Get-Translation "MaxSecurity")
$lblMaxSecurityTitle.Font = $fontSubTitle
$lblMaxSecurityTitle.ForeColor = $colorPrimary
$pnlMaxSecurity.Controls.Add($lblMaxSecurityTitle)

# Maksimum Güvenlik Aç Düðmesi
$btnEnableMaxSecurity = New-Object System.Windows.Forms.Button
$btnEnableMaxSecurity.Location = New-Object System.Drawing.Point(20, 60)
$btnEnableMaxSecurity.Size = New-Object System.Drawing.Size(810, 100)
$btnEnableMaxSecurity.Text = $(Get-Translation "EnableMaxSecurity")
$btnEnableMaxSecurity.Font = New-Object System.Drawing.Font("Segoe UI", 14, [System.Drawing.FontStyle]::Bold)
$btnEnableMaxSecurity.BackColor = $colorSuccess
$btnEnableMaxSecurity.ForeColor = [System.Drawing.Color]::White
$btnEnableMaxSecurity.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$btnEnableMaxSecurity.FlatAppearance.BorderSize = 0
$btnEnableMaxSecurity.Cursor = [System.Windows.Forms.Cursors]::Hand
$btnEnableMaxSecurity.Add_Click({
    $success = Optimize-SecuritySettings
    RefreshControls
})
$pnlMaxSecurity.Controls.Add($btnEnableMaxSecurity)

# Geliþmiþ Ayarlar sekmesi içeriði

# Ayarlar grubu
$gbAdvancedSettings = New-Object System.Windows.Forms.GroupBox
$gbAdvancedSettings.Location = New-Object System.Drawing.Point(20, 20)
$gbAdvancedSettings.Size = New-Object System.Drawing.Size(370, 450)
$gbAdvancedSettings.Text = $(Get-Translation "AdvancedSettings")
$gbAdvancedSettings.Font = $fontBold
$tabAdvanced.Controls.Add($gbAdvancedSettings)

# Durum ve Açýklama grubu
$gbAdvancedInfo = New-Object System.Windows.Forms.GroupBox
$gbAdvancedInfo.Location = New-Object System.Drawing.Point(410, 20)
$gbAdvancedInfo.Size = New-Object System.Drawing.Size(470, 270)
$gbAdvancedInfo.Text = $(Get-Translation "AdvancedSettings")
$gbAdvancedInfo.Font = $fontBold
$tabAdvanced.Controls.Add($gbAdvancedInfo)

# Açýklama alaný
$txtAdvancedInfo = New-Object System.Windows.Forms.RichTextBox
$txtAdvancedInfo.Location = New-Object System.Drawing.Point(10, 20)
$txtAdvancedInfo.Size = New-Object System.Drawing.Size(450, 240)
$txtAdvancedInfo.Font = $fontRegular
$txtAdvancedInfo.ReadOnly = $true
$txtAdvancedInfo.BackColor = [System.Drawing.Color]::White
$txtAdvancedInfo.BorderStyle = [System.Windows.Forms.BorderStyle]::None
$gbAdvancedInfo.Controls.Add($txtAdvancedInfo)

# Geliþmiþ Açýklama alaný
$txtInfoAdvanced = $txtAdvancedInfo

# Güvenlik Duvarý Sekmesi Ýçeriði

# Güvenlik duvarý profilleri
$gbFirewallProfiles = New-Object System.Windows.Forms.GroupBox
$gbFirewallProfiles.Location = New-Object System.Drawing.Point(20, 20)
$gbFirewallProfiles.Size = New-Object System.Drawing.Size(400, 150)
$gbFirewallProfiles.Text = $(Get-Translation "WindowsFirewall")
$gbFirewallProfiles.Font = $fontBold
$tabFirewall.Controls.Add($gbFirewallProfiles)

# Güvenlik duvarý eylem kontrolü
$gbFirewallAction = New-Object System.Windows.Forms.GroupBox
$gbFirewallAction.Location = New-Object System.Drawing.Point(20, 180)
$gbFirewallAction.Size = New-Object System.Drawing.Size(400, 150)
$gbFirewallAction.Text = $(Get-Translation "AdvancedSettings")
$gbFirewallAction.Font = $fontBold
$tabFirewall.Controls.Add($gbFirewallAction)

# Baðlantý noktasý açma
$gbFirewallPorts = New-Object System.Windows.Forms.GroupBox
$gbFirewallPorts.Location = New-Object System.Drawing.Point(20, 340)
$gbFirewallPorts.Size = New-Object System.Drawing.Size(400, 200)
$gbFirewallPorts.Text = $(Get-Translation "PortNumber")
$gbFirewallPorts.Font = $fontBold
$tabFirewall.Controls.Add($gbFirewallPorts)

# Güvenlik duvarý bilgileri
$gbFirewallInfo = New-Object System.Windows.Forms.GroupBox
$gbFirewallInfo.Location = New-Object System.Drawing.Point(440, 20)
$gbFirewallInfo.Size = New-Object System.Drawing.Size(440, 520)
$gbFirewallInfo.Text = $(Get-Translation "FirewallTab")
$gbFirewallInfo.Font = $fontBold
$tabFirewall.Controls.Add($gbFirewallInfo)

# Güvenlik duvarý bilgi kutusu
$txtFirewallInfo = New-Object System.Windows.Forms.RichTextBox
$txtFirewallInfo.Location = New-Object System.Drawing.Point(10, 20)
$txtFirewallInfo.Size = New-Object System.Drawing.Size(420, 490)
$txtFirewallInfo.Font = $fontRegular
$txtFirewallInfo.ReadOnly = $true
$txtFirewallInfo.BackColor = [System.Drawing.Color]::White
$txtFirewallInfo.BorderStyle = [System.Windows.Forms.BorderStyle]::None
$txtFirewallInfo.Text = $(Get-Translation "FirewallInfo")
$gbFirewallInfo.Controls.Add($txtFirewallInfo)

# Profil onay kutularý
$cbDomainProfile = New-Object System.Windows.Forms.CheckBox
$cbDomainProfile.Location = New-Object System.Drawing.Point(20, 30)
$cbDomainProfile.Size = New-Object System.Drawing.Size(360, 30)
$cbDomainProfile.Text = $(Get-Translation "DomainFirewall")
$cbDomainProfile.Name = "FirewallDomain"
$cbDomainProfile.Font = $fontRegular
$cbDomainProfile.Add_Click({
    Set-SecuritySetting -Setting "FirewallDomain" -Enabled $this.Checked
    RefreshControls
})
$gbFirewallProfiles.Controls.Add($cbDomainProfile)

$cbPrivateProfile = New-Object System.Windows.Forms.CheckBox
$cbPrivateProfile.Location = New-Object System.Drawing.Point(20, 60)
$cbPrivateProfile.Size = New-Object System.Drawing.Size(360, 30)
$cbPrivateProfile.Text = $(Get-Translation "PrivateFirewall")
$cbPrivateProfile.Name = "FirewallPrivate"
$cbPrivateProfile.Font = $fontRegular
$cbPrivateProfile.Add_Click({
    Set-SecuritySetting -Setting "FirewallPrivate" -Enabled $this.Checked
    RefreshControls
})
$gbFirewallProfiles.Controls.Add($cbPrivateProfile)

$cbPublicProfile = New-Object System.Windows.Forms.CheckBox
$cbPublicProfile.Location = New-Object System.Drawing.Point(20, 90)
$cbPublicProfile.Size = New-Object System.Drawing.Size(360, 30)
$cbPublicProfile.Text = $(Get-Translation "PublicFirewall")
$cbPublicProfile.Name = "FirewallPublic"
$cbPublicProfile.Font = $fontRegular
$cbPublicProfile.Add_Click({
    Set-SecuritySetting -Setting "FirewallPublic" -Enabled $this.Checked
    RefreshControls
})
$gbFirewallProfiles.Controls.Add($cbPublicProfile)

# Firewall eylem radyo düðmeleri
$rbBlockInbound = New-Object System.Windows.Forms.RadioButton
$rbBlockInbound.Location = New-Object System.Drawing.Point(20, 30)
$rbBlockInbound.Size = New-Object System.Drawing.Size(360, 30)
$rbBlockInbound.Text = $(Get-Translation "BlockInbound")
$rbBlockInbound.Font = $fontRegular
$rbBlockInbound.Checked = $true
$rbBlockInbound.Add_Click({
    try {
        netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound | Out-Null
        [System.Windows.Forms.MessageBox]::Show("Tüm profiller için gelen baðlantýlar engellendi.", $(Get-Translation "Success"), [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
    }
    catch {
        [System.Windows.Forms.MessageBox]::Show("Güvenlik duvarý ayarlarý deðiþtirilemedi: $_", $(Get-Translation "Error"), [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
    }
})
$gbFirewallAction.Controls.Add($rbBlockInbound)

$rbAllowInbound = New-Object System.Windows.Forms.RadioButton
$rbAllowInbound.Location = New-Object System.Drawing.Point(20, 60)
$rbAllowInbound.Size = New-Object System.Drawing.Size(360, 30)
$rbAllowInbound.Text = $(Get-Translation "AllowInbound")
$rbAllowInbound.Font = $fontRegular
$rbAllowInbound.Add_Click({
    try {
        netsh advfirewall set allprofiles firewallpolicy allowinbound,allowoutbound | Out-Null
        [System.Windows.Forms.MessageBox]::Show("Tüm profiller için gelen baðlantýlara izin verildi. Bu daha az güvenlidir.", $(Get-Translation "WarningTitle"), [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
    }
    catch {
        [System.Windows.Forms.MessageBox]::Show("Güvenlik duvarý ayarlarý deðiþtirilemedi: $_", $(Get-Translation "Error"), [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
    }
})
$gbFirewallAction.Controls.Add($rbAllowInbound)

# Firewall Policy durumunu kontrol et
try {
    $firewallPolicy = (netsh advfirewall show allprofiles | Select-String "Inbound connections") -match "Block"
    $rbBlockInbound.Checked = $firewallPolicy
    $rbAllowInbound.Checked = -not $firewallPolicy
}
catch { }

# Port açma/kapama kontrolleri
$lblPortName = New-Object System.Windows.Forms.Label
$lblPortName.Location = New-Object System.Drawing.Point(20, 30)
$lblPortName.Size = New-Object System.Drawing.Size(120, 20)
$lblPortName.Text = $(Get-Translation "FirewallRuleName")
$lblPortName.Font = $fontRegular
$gbFirewallPorts.Controls.Add($lblPortName)

$txtPortName = New-Object System.Windows.Forms.TextBox
$txtPortName.Location = New-Object System.Drawing.Point(150, 30)
$txtPortName.Size = New-Object System.Drawing.Size(230, 20)
$txtPortName.Font = $fontRegular
$gbFirewallPorts.Controls.Add($txtPortName)

$lblPortNumber = New-Object System.Windows.Forms.Label
$lblPortNumber.Location = New-Object System.Drawing.Point(20, 60)
$lblPortNumber.Size = New-Object System.Drawing.Size(120, 20)
$lblPortNumber.Text = $(Get-Translation "PortNumber")
$lblPortNumber.Font = $fontRegular
$gbFirewallPorts.Controls.Add($lblPortNumber)

$txtPortNumber = New-Object System.Windows.Forms.TextBox
$txtPortNumber.Location = New-Object System.Drawing.Point(150, 60)
$txtPortNumber.Size = New-Object System.Drawing.Size(230, 20)
$txtPortNumber.Font = $fontRegular
$gbFirewallPorts.Controls.Add($txtPortNumber)

$lblProtocol = New-Object System.Windows.Forms.Label
$lblProtocol.Location = New-Object System.Drawing.Point(20, 90)
$lblProtocol.Size = New-Object System.Drawing.Size(120, 20)
$lblProtocol.Text = $(Get-Translation "Protocol")
$lblProtocol.Font = $fontRegular
$gbFirewallPorts.Controls.Add($lblProtocol)

$cbProtocol = New-Object System.Windows.Forms.ComboBox
$cbProtocol.Location = New-Object System.Drawing.Point(150, 90)
$cbProtocol.Size = New-Object System.Drawing.Size(230, 20)
$cbProtocol.Font = $fontRegular
$cbProtocol.DropDownStyle = [System.Windows.Forms.ComboBoxStyle]::DropDownList
$cbProtocol.Items.Add("TCP")
$cbProtocol.Items.Add("UDP")
$cbProtocol.SelectedIndex = 0
$gbFirewallPorts.Controls.Add($cbProtocol)

$btnOpenPort = New-Object System.Windows.Forms.Button
$btnOpenPort.Location = New-Object System.Drawing.Point(20, 130)
$btnOpenPort.Size = New-Object System.Drawing.Size(180, 40)
$btnOpenPort.Text = $(Get-Translation "OpenPort")
$btnOpenPort.Font = $fontRegular
$btnOpenPort.BackColor = $colorPrimary
$btnOpenPort.ForeColor = [System.Drawing.Color]::White
$btnOpenPort.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$btnOpenPort.FlatAppearance.BorderSize = 0
$btnOpenPort.Cursor = [System.Windows.Forms.Cursors]::Hand
$btnOpenPort.Add_Click({
    $portName = $txtPortName.Text.Trim()
    $portNumber = $txtPortNumber.Text.Trim()
    $protocol = $cbProtocol.SelectedItem.ToString()
    
    if ([string]::IsNullOrEmpty($portName)) {
        [System.Windows.Forms.MessageBox]::Show($(Get-Translation "EnterRuleName"), $(Get-Translation "Error"), [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
        return
    }
    
    if ([string]::IsNullOrEmpty($portNumber) -or -not [int]::TryParse($portNumber, [ref]$null)) {
        [System.Windows.Forms.MessageBox]::Show($(Get-Translation "EnterValidPort"), $(Get-Translation "Error"), [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
        return
    }
    
    $success = Configure-FirewallPort -Name $portName -Port ([int]$portNumber) -Protocol $protocol -Enabled $true
    
    if ($success) {
        [System.Windows.Forms.MessageBox]::Show($([string]::Format($(Get-Translation "PortOpened"), $portNumber, $protocol)), $(Get-Translation "Success"), [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
    }
    else {
        [System.Windows.Forms.MessageBox]::Show($(Get-Translation "PortOpenFailed"), $(Get-Translation "Error"), [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
    }
})
$gbFirewallPorts.Controls.Add($btnOpenPort)

$btnClosePort = New-Object System.Windows.Forms.Button
$btnClosePort.Location = New-Object System.Drawing.Point(210, 130)
$btnClosePort.Size = New-Object System.Drawing.Size(170, 40)
$btnClosePort.Text = $(Get-Translation "ClosePort")
$btnClosePort.Font = $fontRegular
$btnClosePort.BackColor = $colorWarning
$btnClosePort.ForeColor = [System.Drawing.Color]::White
$btnClosePort.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$btnClosePort.FlatAppearance.BorderSize = 0
$btnClosePort.Cursor = [System.Windows.Forms.Cursors]::Hand
$btnClosePort.Add_Click({
    $portName = $txtPortName.Text.Trim()
    
    if ([string]::IsNullOrEmpty($portName)) {
        [System.Windows.Forms.MessageBox]::Show($(Get-Translation "EnterRuleName"), $(Get-Translation "Error"), [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
        return
    }
    
    $success = Configure-FirewallPort -Name $portName -Port 0 -Protocol "TCP" -Enabled $false
    
    if ($success) {
        [System.Windows.Forms.MessageBox]::Show($([string]::Format($(Get-Translation "RuleRemoved"), $portName)), $(Get-Translation "Success"), [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
    }
    else {
        [System.Windows.Forms.MessageBox]::Show($(Get-Translation "RuleRemoveFailed"), $(Get-Translation "Error"), [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
    }
})
$gbFirewallPorts.Controls.Add($btnClosePort)

# Hakkýnda sekmesi içeriði
$txtAbout = New-Object System.Windows.Forms.RichTextBox
$txtAbout.Location = New-Object System.Drawing.Point(20, 20)
$txtAbout.Size = New-Object System.Drawing.Size(870, 480)
$txtAbout.Font = $fontRegular
$txtAbout.ReadOnly = $true
$txtAbout.BackColor = [System.Drawing.Color]::White
$txtAbout.Text = $(Get-Translation "AboutInfo")
$tabAbout.Controls.Add($txtAbout)

# Ayar açýklamalarý
$settingDescriptions = @{
    "RealTimeProtection" = $(Get-Translation "RealTimeProtection")
    "BehaviorMonitoring" = $(Get-Translation "BehaviorMonitoring")
    "IoavProtection" = $(Get-Translation "DownloadProtection")
    "NIS" = $(Get-Translation "NetworkProtection")
    "FirewallDomain" = $(Get-Translation "DomainFirewall")
    "FirewallPrivate" = $(Get-Translation "PrivateFirewall")
    "FirewallPublic" = $(Get-Translation "PublicFirewall")
    "AutomaticUpdates" = $(Get-Translation "AutomaticUpdates")
    "SmartScreen" = $(Get-Translation "SmartScreen")
    "UAC" = $(Get-Translation "UAC")
    "DEP" = $(Get-Translation "DEP")
}

# Checkbox'larýn iþlevi için gereken deðiþkenler
$checkboxes = @{}
$yPosition = 30
$checkBoxWidth = 350
$checkBoxHeight = 30
$margin = 5

function Update-UILanguage {
    # Form baþlýðý
    $form.Text = $(Get-Translation "FormTitle")
    
    # Ana baþlýklar
    $lblTitle.Text = $(Get-Translation "FormTitle")
    $lblSubtitle.Text = $(Get-Translation "SecurityStatus")
    $lblSecurityLevel.Text = $(Get-Translation "SecurityLevel")
    
    # Güvenlik seviyesini çevir
    $currentSecurityLevel = $lblSecurityLevelValue.Text
    if ($currentSecurityLevel -eq "Yüksek" -or $currentSecurityLevel -eq "High") {
        $lblSecurityLevelValue.Text = $(Get-Translation "High")
    }
    elseif ($currentSecurityLevel -eq "Orta" -or $currentSecurityLevel -eq "Medium") {
        $lblSecurityLevelValue.Text = $(Get-Translation "Medium")
    }
    else {
        $lblSecurityLevelValue.Text = $(Get-Translation "Low")
    }
    
    # Durum etiketleri
    $lblDefenderStatus.Text = $(Get-Translation "DefenderStatus")
    $lblFirewallStatus.Text = $(Get-Translation "FirewallStatus")
    
    # Durum deðerlerini çevir
    $currentDefenderStatus = $lblDefenderStatusValue.Text
    if ($currentDefenderStatus -eq "Aktif" -or $currentDefenderStatus -eq "Active") {
        $lblDefenderStatusValue.Text = $(Get-Translation "Active")
    }
    else {
        $lblDefenderStatusValue.Text = $(Get-Translation "Inactive")
    }
    
    $currentFirewallStatus = $lblFirewallStatusValue.Text
    if ($currentFirewallStatus -eq "Aktif" -or $currentFirewallStatus -eq "Active") {
        $lblFirewallStatusValue.Text = $(Get-Translation "Active")
    }
    else {
        $lblFirewallStatusValue.Text = $(Get-Translation "Inactive")
    }
    
    # Sekme baþlýklarý
    $tabMain.Text = $(Get-Translation "SecuritySettingsTab")
    $tabFirewall.Text = $(Get-Translation "FirewallTab")
    $tabAdvanced.Text = $(Get-Translation "AdvancedTab")
    $tabAbout.Text = $(Get-Translation "AboutTab")
    
    # Ana panel baþlýklarý
    $lblDefenderTitle.Text = $(Get-Translation "WindowsDefender")
    $lblFirewallTitle.Text = $(Get-Translation "WindowsFirewall")
    $lblMaxSecurityTitle.Text = $(Get-Translation "MaxSecurity")
    
    # Düðme metinleri
    $btnEnableDefender.Text = $(Get-Translation "EnableDefender")
    $btnDisableDefender.Text = $(Get-Translation "DisableDefender")
    $btnQuickScan.Text = $(Get-Translation "QuickScan")
    $btnUpdateDefinitions.Text = $(Get-Translation "UpdateDefinitions")
    
    $btnEnableFirewall.Text = $(Get-Translation "EnableFirewall")
    $btnDisableFirewall.Text = $(Get-Translation "DisableFirewall")
    $btnOpenSecurityCenter.Text = $(Get-Translation "OpenWindowsSecurity")
    $btnOpenFirewallSettings.Text = $(Get-Translation "OpenFirewallSettings")
    
    $btnEnableMaxSecurity.Text = $(Get-Translation "EnableMaxSecurity")
    
    # Güvenlik Duvarý sekmesi
    $gbFirewallProfiles.Text = $(Get-Translation "WindowsFirewall")
    $gbFirewallAction.Text = $(Get-Translation "AdvancedSettings")
    $gbFirewallPorts.Text = $(Get-Translation "PortNumber")
    $gbFirewallInfo.Text = $(Get-Translation "FirewallTab")
    
    $cbDomainProfile.Text = $(Get-Translation "DomainFirewall")
    $cbPrivateProfile.Text = $(Get-Translation "PrivateFirewall")
    $cbPublicProfile.Text = $(Get-Translation "PublicFirewall")
    
    $rbBlockInbound.Text = $(Get-Translation "BlockInbound")
    $rbAllowInbound.Text = $(Get-Translation "AllowInbound")
    
    $lblPortName.Text = $(Get-Translation "FirewallRuleName")
    $lblPortNumber.Text = $(Get-Translation "PortNumber")
    $lblProtocol.Text = $(Get-Translation "Protocol")
    
    $btnOpenPort.Text = $(Get-Translation "OpenPort")
    $btnClosePort.Text = $(Get-Translation "ClosePort")
    
    # Bilgi metinleri
    $txtFirewallInfo.Text = $(Get-Translation "FirewallInfo")
    $txtAbout.Text = $(Get-Translation "AboutInfo")
    
    # Geliþmiþ ayarlar
    $gbAdvancedSettings.Text = $(Get-Translation "AdvancedSettings")
    $gbAdvancedInfo.Text = $(Get-Translation "AdvancedSettings")
    
    # Checkbox açýklamalarýný güncelle
    $settingDescriptions["RealTimeProtection"] = $(Get-Translation "RealTimeProtection")
    $settingDescriptions["BehaviorMonitoring"] = $(Get-Translation "BehaviorMonitoring")
    $settingDescriptions["IoavProtection"] = $(Get-Translation "DownloadProtection")
    $settingDescriptions["NIS"] = $(Get-Translation "NetworkProtection")
    $settingDescriptions["FirewallDomain"] = $(Get-Translation "DomainFirewall")
    $settingDescriptions["FirewallPrivate"] = $(Get-Translation "PrivateFirewall")
    $settingDescriptions["FirewallPublic"] = $(Get-Translation "PublicFirewall")
    $settingDescriptions["AutomaticUpdates"] = $(Get-Translation "AutomaticUpdates")
    $settingDescriptions["SmartScreen"] = $(Get-Translation "SmartScreen")
    $settingDescriptions["UAC"] = $(Get-Translation "UAC")
    $settingDescriptions["DEP"] = $(Get-Translation "DEP")
}

function RefreshControls {
    $settings = Get-SecuritySettings
    
    # Defender durumu kontrolü
    $defenderEnabled = ($settings.ContainsKey("RealTimeProtection") -and $settings["RealTimeProtection"])
    $lblDefenderStatusValue.Text = if ($defenderEnabled) { $(Get-Translation "Active") } else { $(Get-Translation "Inactive") }
    $lblDefenderStatusValue.ForeColor = if ($defenderEnabled) { $colorSuccess } else { $colorWarning }
    
    # Güvenlik Duvarý durumu kontrolü
    $firewallEnabled = ($settings.ContainsKey("FirewallEnabled") -and $settings["FirewallEnabled"])
    $lblFirewallStatusValue.Text = if ($firewallEnabled) { $(Get-Translation "Active") } else { $(Get-Translation "Inactive") }
    $lblFirewallStatusValue.ForeColor = if ($firewallEnabled) { $colorSuccess } else { $colorWarning }
    
    # Güvenlik seviyesi kontrolü
    if ($settings.ContainsKey("SecurityLevel")) {
        $securityLevel = $settings["SecurityLevel"]
        if ($securityLevel -eq "High") {
            $lblSecurityLevelValue.Text = $(Get-Translation "High")
            $lblSecurityLevelValue.ForeColor = $colorSuccess
        }
        elseif ($securityLevel -eq "Medium") {
            $lblSecurityLevelValue.Text = $(Get-Translation "Medium")
            $lblSecurityLevelValue.ForeColor = $colorAccent
        }
        else {
            $lblSecurityLevelValue.Text = $(Get-Translation "Low")
            $lblSecurityLevelValue.ForeColor = $colorWarning
        }
    }
    
    foreach ($key in $checkboxes.Keys) {
        if ($settings.ContainsKey($key)) {
            $checkboxes[$key].Checked = $settings[$key]
            
            # Durum rengini güncelle
            if ($settings[$key]) {
                $checkboxes[$key].ForeColor = $colorSuccess
            }
            else {
                $checkboxes[$key].ForeColor = $colorWarning
            }
        }
    }
    
    # Firewall profil kontrollerini güncelle
    if ($settings.ContainsKey("FirewallDomain")) {
        $cbDomainProfile.Checked = $settings["FirewallDomain"]
        $cbDomainProfile.ForeColor = if ($settings["FirewallDomain"]) { $colorSuccess } else { $colorWarning }
    }
    
    if ($settings.ContainsKey("FirewallPrivate")) {
        $cbPrivateProfile.Checked = $settings["FirewallPrivate"]
        $cbPrivateProfile.ForeColor = if ($settings["FirewallPrivate"]) { $colorSuccess } else { $colorWarning }
    }
    
    if ($settings.ContainsKey("FirewallPublic")) {
        $cbPublicProfile.Checked = $settings["FirewallPublic"]
        $cbPublicProfile.ForeColor = if ($settings["FirewallPublic"]) { $colorSuccess } else { $colorWarning }
    }
}

# Geliþmiþ ayarlar için Checkbox'lar oluþtur
$settingLabels = @{
    "RealTimeProtection" = $(Get-Translation "RealTimeProtection")
    "BehaviorMonitoring" = $(Get-Translation "BehaviorMonitoring")
    "IoavProtection" = $(Get-Translation "DownloadProtection")
    "NIS" = $(Get-Translation "NetworkProtection")
    "AutomaticUpdates" = $(Get-Translation "AutomaticUpdates")
    "SmartScreen" = $(Get-Translation "SmartScreen")
    "UAC" = $(Get-Translation "UAC")
    "DEP" = $(Get-Translation "DEP")
}

foreach ($setting in $settingLabels.Keys) {
    $checkbox = New-Object System.Windows.Forms.CheckBox
    $checkbox.Location = New-Object System.Drawing.Point(20, $yPosition)
    $checkbox.Size = New-Object System.Drawing.Size($checkBoxWidth, $checkBoxHeight)
    $checkbox.Text = $settingLabels[$setting]
    $checkbox.Name = $setting
    $checkbox.Font = $fontRegular
    $checkbox.Cursor = [System.Windows.Forms.Cursors]::Hand
    
    # Týklama olayý
    $checkbox.Add_Click({
        $settingName = $this.Name
        Set-SecuritySetting -Setting $settingName -Enabled $this.Checked
        RefreshControls
    })
    
    # Fare üzerinde iken açýklama göster
    $checkbox.Add_MouseHover({
        $settingName = $this.Name
        if ($settingDescriptions.ContainsKey($settingName)) {
            $txtInfoAdvanced.Text = $settingDescriptions[$settingName]
        }
    })
    
    $gbAdvancedSettings.Controls.Add($checkbox)
    $checkboxes[$setting] = $checkbox
    $yPosition += $checkBoxHeight + $margin
}

# Durum bilgisi
$lblStatus = New-Object System.Windows.Forms.Label
$lblStatus.Location = New-Object System.Drawing.Point(20, 660)
$lblStatus.Size = New-Object System.Drawing.Size(910, 20)
$lblStatus.Text = $(Get-Translation "Ready")
$lblStatus.Font = $fontStatus
$form.Controls.Add($lblStatus)

#endregion

# Form yüklendiðinde ayarlarý oku
$form.Add_Shown({
    # Windows Defender servislerini kontrol et
    Ensure-WindowsDefenderServices
    
    # Kontrolleri güncelle
    RefreshControls
})

# Formu göster
[void]$form.ShowDialog()