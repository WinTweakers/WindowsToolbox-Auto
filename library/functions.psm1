#functions
    
    #general functions
    $version = "1.0.0-beta.3"
    $build = (Get-CimInstance Win32_OperatingSystem).version
    $winver= (Get-WmiObject -class Win32_OperatingSystem).Caption
    
    
    function setup {
        if ($winver -like "*Windows 11*") {
            $winver = '11'
        } elseif ($winver -like "*Windows 10*") {
            $winver = '10'
        }
    }
    function Exit {
        stop-process -id $PID
    }
    
    function Restart {
        Restart-Computer
    }
    
    function Info {
        Write-Output "Windows Toolbox $version"
        Write-Output "Windows build $build"
        Write-Output ""
        Write-Output ""
        Write-Output "Please read before using WindowsToolbox"
        Write-Output "- None of the scripts have configs (for now), you have to edit them to your liking beforehand."
        Write-Output "- Only Windows 10 is supported, however support for Windows 11 is comming soonTM"
        Write-Output "- There is no undo (for now), all scripts are provided AS-IS and you use them at your own risk"
        Write-Output "- Navigation: Use the arrow keys to navigate, Enter to select and Esc to go back"
        Write-Output ""
        Write-Output "Stuff that breaks core functions (very unlikely to be fixed cuz this is Windows we're talking about)"
        Write-Output "- Disable ShellExperienceHost"
        Write-Output "- Disable SearchUI"
        Write-Output ""
        Write-Output "Stuff that breaks Windows 11 (will be fixed ofc):"
        Write-Output "- Disabling telemetry (if using insider)"
        Write-Output ""
        Write-Output ""
        Read-Host "Press Enter to continue"
    }
    
    #TakeOwn functions
    function Takeown-Registry($key) {
        # TODO does not work for all root keys yet
        switch ($key.split('\')[0]) {
            "HKEY_CLASSES_ROOT" {
                $reg = [Microsoft.Win32.Registry]::ClassesRoot
                $key = $key.substring(18)
            }
            "HKEY_CURRENT_USER" {
                $reg = [Microsoft.Win32.Registry]::CurrentUser
                $key = $key.substring(18)
            }
            "HKEY_LOCAL_MACHINE" {
                $reg = [Microsoft.Win32.Registry]::LocalMachine
                $key = $key.substring(19)
            }
        }
    
        # get administraor group
        $admins = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-544")
        $admins = $admins.Translate([System.Security.Principal.NTAccount])
    
        # set owner
        $key = $reg.OpenSubKey($key, "ReadWriteSubTree", "TakeOwnership")
        $acl = $key.GetAccessControl()
        $acl.SetOwner($admins)
        $key.SetAccessControl($acl)
    
        # set FullControl
        $acl = $key.GetAccessControl()
        $rule = New-Object System.Security.AccessControl.RegistryAccessRule($admins, "FullControl", "Allow")
        $acl.SetAccessRule($rule)
        $key.SetAccessControl($acl)
    }

    function Takeown-File($path) {
        takeown.exe /A /F $path
        $acl = Get-Acl $path
    
        # get administraor group
        $admins = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-544")
        $admins = $admins.Translate([System.Security.Principal.NTAccount])
    
        # add NT Authority\SYSTEM
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($admins, "FullControl", "None", "None", "Allow")
        $acl.AddAccessRule($rule)
    
        Set-Acl -Path $path -AclObject $acl
    }

    function Takeown-Folder($path) {
        Takeown-File $path
        foreach ($item in Get-ChildItem $path) {
            if (Test-Path $item -PathType Container) {
                Takeown-Folder $item.FullName
            } else {
                Takeown-File $item.FullName
            }
        }
    }

    function Elevate-Privileges {
        param($Privilege)
        $Definition = @"
        using System;
        using System.Runtime.InteropServices;
        public class AdjPriv {
            [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
                internal static extern bool AdjustTokenPrivileges(IntPtr htok, bool disall, ref TokPriv1Luid newst, int len, IntPtr prev, IntPtr rele);
            [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
                internal static extern bool OpenProcessToken(IntPtr h, int acc, ref IntPtr phtok);
            [DllImport("advapi32.dll", SetLastError = true)]
                internal static extern bool LookupPrivilegeValue(string host, string name, ref long pluid);
            [StructLayout(LayoutKind.Sequential, Pack = 1)]
                internal struct TokPriv1Luid {
                    public int Count;
                    public long Luid;
                    public int Attr;
                }
            internal const int SE_PRIVILEGE_ENABLED = 0x00000002;
            internal const int TOKEN_QUERY = 0x00000008;
            internal const int TOKEN_ADJUST_PRIVILEGES = 0x00000020;
            public static bool EnablePrivilege(long processHandle, string privilege) {
                bool retVal;
                TokPriv1Luid tp;
                IntPtr hproc = new IntPtr(processHandle);
                IntPtr htok = IntPtr.Zero;
                retVal = OpenProcessToken(hproc, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ref htok);
                tp.Count = 1;
                tp.Luid = 0;
                tp.Attr = SE_PRIVILEGE_ENABLED;
                retVal = LookupPrivilegeValue(null, privilege, ref tp.Luid);
                retVal = AdjustTokenPrivileges(htok, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
                return retVal;
            }
        }
"@
        $ProcessHandle = (Get-Process -id $pid).Handle
        $type = Add-Type $definition -PassThru
        $type[0]::EnablePrivilege($processHandle, $Privilege)
    }


    #WinCore functions
    function New-FolderForced {
        [CmdletBinding(SupportsShouldProcess = $true)]
        param (
            [Parameter(Position = 0, Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
            [string]
            $Path
        )
    
        process {
            if (-not (Test-Path $Path)) {
                Write-Verbose "-- Creating full path to:  $Path"
                New-Item -Path $Path -ItemType Directory -Force
            }
        }
    }
    
    function InstallChoco {
        $testchoco = powershell choco -v
        if(-not($testchoco)){
            Write-Output "Seems Chocolatey is not installed, installing now"
            Set-ExecutionPolicy Bypass -Scope Process -Force; Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
            choco feature enable -n allowGlobalConfirmation
        }
        else{
            choco feature enable -n allowGlobalConfirmation
            Write-Output "Chocolatey Version $testchoco is already installed"
        }
    }
    
    function InstallWSL {
        Write-Output "Installing Linux Subsystem..."
        Get-WindowsOptionalFeature -Online | Where-Object { $_.FeatureName -eq "Microsoft-Windows-Subsystem-Linux" } | Enable-WindowsOptionalFeature -Online -NoRestart -WarningAction SilentlyContinue | Out-Null
    }
    
    function InstallHyperV {
        Write-Output "Installing Hyper-V..."
        if ((Get-CimInstance -Class "Win32_OperatingSystem").ProductType -eq 1) {
            Get-WindowsOptionalFeature -Online | Where-Object { $_.FeatureName -eq "Microsoft-Hyper-V-All" } | Enable-WindowsOptionalFeature -Online -NoRestart -WarningAction SilentlyContinue | Out-Null
        } else {
            Install-WindowsFeature -Name "Hyper-V" -IncludeManagementTools -WarningAction SilentlyContinue | Out-Null
        }
    }
    


    #Privacy functions
    function Disable-Telemetry {
        Write-Output "Disabling telemetry via Group Policies"
        New-FolderForced -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" "AllowTelemetry" 0
    
        # Entries related to Akamai have been reported to cause issues with Widevine
        # DRM.
    
        Write-Output "Adding telemetry domains to hosts file"
        $hosts_file = "$env:systemroot\System32\drivers\etc\hosts"
        $domains = @(
            "184-86-53-99.deploy.static.akamaitechnologies.com"
            "a-0001.a-msedge.net"
            "a-0002.a-msedge.net"
            "a-0003.a-msedge.net"
            "a-0004.a-msedge.net"
            "a-0005.a-msedge.net"
            "a-0006.a-msedge.net"
            "a-0007.a-msedge.net"
            "a-0008.a-msedge.net"
            "a-0009.a-msedge.net"
            "a1621.g.akamai.net"
            "a1856.g2.akamai.net"
            "a1961.g.akamai.net"
            #"a248.e.akamai.net"            # makes iTunes download button disappear (#43)
            "a978.i6g1.akamai.net"
            "a.ads1.msn.com"
            "a.ads2.msads.net"
            "a.ads2.msn.com"
            "ac3.msn.com"
            "ad.doubleclick.net"
            "adnexus.net"
            "adnxs.com"
            "ads1.msads.net"
            "ads1.msn.com"
            "ads.msn.com"
            "aidps.atdmt.com"
            "aka-cdn-ns.adtech.de"
            "a-msedge.net"
            "any.edge.bing.com"
            "a.rad.msn.com"
            "az361816.vo.msecnd.net"
            "az512334.vo.msecnd.net"
            "b.ads1.msn.com"
            "b.ads2.msads.net"
            "bingads.microsoft.com"
            "b.rad.msn.com"
            "bs.serving-sys.com"
            "c.atdmt.com"
            "cdn.atdmt.com"
            "cds26.ams9.msecn.net"
            "choice.microsoft.com"
            "choice.microsoft.com.nsatc.net"
            "compatexchange.cloudapp.net"
            "corpext.msitadfs.glbdns2.microsoft.com"
            "corp.sts.microsoft.com"
            "cs1.wpc.v0cdn.net"
            "db3aqu.atdmt.com"
            "df.telemetry.microsoft.com"
            "diagnostics.support.microsoft.com"
            "e2835.dspb.akamaiedge.net"
            "e7341.g.akamaiedge.net"
            "e7502.ce.akamaiedge.net"
            "e8218.ce.akamaiedge.net"
            "ec.atdmt.com"
            "fe2.update.microsoft.com.akadns.net"
            "feedback.microsoft-hohm.com"
            "feedback.search.microsoft.com"
            "feedback.windows.com"
            "flex.msn.com"
            "g.msn.com"
            "h1.msn.com"
            "h2.msn.com"
            "hostedocsp.globalsign.com"
            "i1.services.social.microsoft.com"
            "i1.services.social.microsoft.com.nsatc.net"
            #"ipv6.msftncsi.com"                    # Issues may arise where Windows 10 thinks it doesn't have internet
            #"ipv6.msftncsi.com.edgesuite.net"      # Issues may arise where Windows 10 thinks it doesn't have internet
            "lb1.www.ms.akadns.net"
            "live.rads.msn.com"
            "m.adnxs.com"
            "msedge.net"
            #"msftncsi.com"
            "msnbot-65-55-108-23.search.msn.com"
            "msntest.serving-sys.com"
            "oca.telemetry.microsoft.com"
            "oca.telemetry.microsoft.com.nsatc.net"
            "onesettings-db5.metron.live.nsatc.net"
            "pre.footprintpredict.com"
            "preview.msn.com"
            "rad.live.com"
            "rad.msn.com"
            "redir.metaservices.microsoft.com"
            "reports.wes.df.telemetry.microsoft.com"
            "schemas.microsoft.akadns.net"
            "secure.adnxs.com"
            "secure.flashtalking.com"
            "services.wes.df.telemetry.microsoft.com"
            "settings-sandbox.data.microsoft.com"
            #"settings-win.data.microsoft.com"       # may cause issues with Windows Updates
            "sls.update.microsoft.com.akadns.net"
            #"sls.update.microsoft.com.nsatc.net"    # may cause issues with Windows Updates
            "sqm.df.telemetry.microsoft.com"
            "sqm.telemetry.microsoft.com"
            "sqm.telemetry.microsoft.com.nsatc.net"
            "ssw.live.com"
            "static.2mdn.net"
            "statsfe1.ws.microsoft.com"
            "statsfe2.update.microsoft.com.akadns.net"
            "statsfe2.ws.microsoft.com"
            "survey.watson.microsoft.com"
            "telecommand.telemetry.microsoft.com"
            "telecommand.telemetry.microsoft.com.nsatc.net"
            "telemetry.appex.bing.net"
            "telemetry.microsoft.com"
            "telemetry.urs.microsoft.com"
            "vortex-bn2.metron.live.com.nsatc.net"
            "vortex-cy2.metron.live.com.nsatc.net"
            "vortex.data.microsoft.com"
            "vortex-sandbox.data.microsoft.com"
            "vortex-win.data.microsoft.com"
            "cy2.vortex.data.microsoft.com.akadns.net"
            "watson.live.com"
            "watson.microsoft.com"
            "watson.ppe.telemetry.microsoft.com"
            "watson.telemetry.microsoft.com"
            "watson.telemetry.microsoft.com.nsatc.net"
            "wes.df.telemetry.microsoft.com"
            "win10.ipv6.microsoft.com"
            "www.bingads.microsoft.com"
            "www.go.microsoft.akadns.net"
            #"www.msftncsi.com"                         # Issues may arise where Windows 10 thinks it doesn't have internet
            "client.wns.windows.com"
            #"wdcp.microsoft.com"                       # may cause issues with Windows Defender Cloud-based protection
            #"dns.msftncsi.com"                         # This causes Windows to think it doesn't have internet
            #"storeedgefd.dsx.mp.microsoft.com"         # breaks Windows Store
            "wdcpalt.microsoft.com"
            "settings-ssl.xboxlive.com"
            "settings-ssl.xboxlive.com-c.edgekey.net"
            "settings-ssl.xboxlive.com-c.edgekey.net.globalredir.akadns.net"
            "e87.dspb.akamaidege.net"
            "insiderservice.microsoft.com"
            "insiderservice.trafficmanager.net"
            "e3843.g.akamaiedge.net"
            "flightingserviceweurope.cloudapp.net"
            #"sls.update.microsoft.com"                 # may cause issues with Windows Updates
            "static.ads-twitter.com"                    # may cause issues with Twitter login
            "www-google-analytics.l.google.com"
            "p.static.ads-twitter.com"                  # may cause issues with Twitter login
            "hubspot.net.edge.net"
            "e9483.a.akamaiedge.net"
    
            #"www.google-analytics.com"
            #"padgead2.googlesyndication.com"
            #"mirror1.malwaredomains.com"
            #"mirror.cedia.org.ec"
            "stats.g.doubleclick.net"
            "stats.l.doubleclick.net"
            "adservice.google.de"
            "adservice.google.com"
            "googleads.g.doubleclick.net"
            "pagead46.l.doubleclick.net"
            "hubspot.net.edgekey.net"
            "insiderppe.cloudapp.net"                   # Feedback-Hub
            "livetileedge.dsx.mp.microsoft.com"
    
            # extra
            "fe2.update.microsoft.com.akadns.net"
            "s0.2mdn.net"
            "statsfe2.update.microsoft.com.akadns.net"
            "survey.watson.microsoft.com"
            "view.atdmt.com"
            "watson.microsoft.com"
            "watson.ppe.telemetry.microsoft.com"
            "watson.telemetry.microsoft.com"
            "watson.telemetry.microsoft.com.nsatc.net"
            "wes.df.telemetry.microsoft.com"
            "m.hotmail.com"
    
            # can cause issues with Skype (#79) or other services (#171)
            "apps.skype.com"
            "c.msn.com"
            # "login.live.com"                  # prevents login to outlook and other live apps
            "pricelist.skype.com"
            "s.gateway.messenger.live.com"
            "ui.skype.com"
        )
        Write-Output "" | Out-File -Encoding ASCII -Append $hosts_file
        foreach ($domain in $domains) {
            if (-Not (Select-String -Path $hosts_file -Pattern $domain)) {
                Write-Output "0.0.0.0 $domain" | Out-File -Append $hosts_file
            }
        }
    
        Write-Output "Adding telemetry ips to firewall"
        $ips = @(
            "134.170.30.202"
            "137.116.81.24"
            "157.56.106.189"
            "184.86.53.99"
            "2.22.61.43"
            "2.22.61.66"
            "204.79.197.200"
            "23.218.212.69"
            "65.39.117.230"
            "65.52.108.33"   # Causes problems with Microsoft Store
            "65.55.108.23"
            "64.4.54.254"
        )
        Remove-NetFirewallRule -DisplayName "Block Telemetry IPs" -ErrorAction SilentlyContinue
        New-NetFirewallRule -DisplayName "Block Telemetry IPs" -Direction Outbound `
            -Action Block -RemoteAddress ([string[]]$ips)
    }
    
    function PrivacyFixSettings {
        #   Description:
        # This script will try to fix many of the privacy settings for the user. This
        # is work in progress!
    
        Import-Module -DisableNameChecking $PSScriptRoot\..\lib\New-FolderForced.psm1
        Import-Module -DisableNameChecking $PSScriptRoot\..\lib\take-own.psm1
    
        Write-Output "Elevating priviledges for this process"
        do {} until (Elevate-Privileges SeTakeOwnershipPrivilege)
    
        Write-Output "Defuse Windows search settings"
        Set-WindowsSearchSetting -EnableWebResultsSetting $false
    
        Write-Output "Set general privacy options"
        # "Let websites provide locally relevant content by accessing my language list"
        Set-ItemProperty -Path "HKCU:\Control Panel\International\User Profile" "HttpAcceptLanguageOptOut" 1
        # Locaton aware printing (changes default based on connected network)
        New-FolderForced -Path "HKCU:\Printers\Defaults"
        Set-ItemProperty -Path "HKCU:\Printers\Defaults" "NetID" "{00000000-0000-0000-0000-000000000000}"
        # "Send Microsoft info about how I write to help us improve typing and writing in the future"
        New-FolderForced -Path "HKCU:\SOFTWARE\Microsoft\Input\TIPC"
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Input\TIPC" "Enabled" 0
        # "Let apps use my advertising ID for experiencess across apps"
        New-FolderForced -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo"
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" "Enabled" 0
        # "Turn on SmartScreen Filter to check web content"
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" "EnableWebContentEvaluation" 0
    
        Write-Output "Disable synchronisation of settings"
        # These only apply if you log on using Microsoft account
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync" "BackupPolicy" 0x3c
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync" "DeviceMetadataUploaded" 0
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync" "PriorLogons" 1
        $groups = @(
            "Accessibility"
            "AppSync"
            "BrowserSettings"
            "Credentials"
            "DesktopTheme"
            "Language"
            "PackageState"
            "Personalization"
            "StartLayout"
            "Windows"
        )
        foreach ($group in $groups) {
            New-FolderForced -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\$group"
            Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\$group" "Enabled" 0
        }
    
        Write-Output "Set privacy policy accepted state to 0"
        # Prevents sending speech, inking and typing samples to MS (so Cortana
        # can learn to recognise you)
        New-FolderForced -Path "HKCU:\SOFTWARE\Microsoft\Personalization\Settings"
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Personalization\Settings" "AcceptedPrivacyPolicy" 0
    
        Write-Output "Do not scan contact informations"
        # Prevents sending contacts to MS (so Cortana can compare speech etc samples)
        New-FolderForced -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore"
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" "HarvestContacts" 0
    
        Write-Output "Inking and typing settings"
        # Handwriting recognition personalization
        New-FolderForced -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization"
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" "RestrictImplicitInkCollection" 1
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" "RestrictImplicitTextCollection" 1
    
        Write-Output "Microsoft Edge settings"
        New-FolderForced -Path "HKCU:\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\Main"
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\Main" "DoNotTrack" 1
        New-FolderForced -Path "HKCU:\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\User\Default\SearchScopes"
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\User\Default\SearchScopes" "ShowSearchSuggestionsGlobal" 0
        New-FolderForced -Path "HKCU:\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\FlipAhead"
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\FlipAhead" "FPEnabled" 0
        New-FolderForced -Path "HKCU:\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\PhishingFilter"
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\PhishingFilter" "EnabledV9" 0
    
        Write-Output "Disable background access of default apps"
        foreach ($key in (Get-ChildItem "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications")) {
            Set-ItemProperty -Path ("HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\" + $key.PSChildName) "Disabled" 1
        }
    
        Write-Output "Denying device access"
        # Disable sharing information with unpaired devices
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\LooselyCoupled" "Type" "LooselyCoupled"
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\LooselyCoupled" "Value" "Deny"
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\LooselyCoupled" "InitialAppValue" "Unspecified"
        foreach ($key in (Get-ChildItem "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global")) {
            if ($key.PSChildName -EQ "LooselyCoupled") {
                continue
            }
            Set-ItemProperty -Path ("HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\" + $key.PSChildName) "Type" "InterfaceClass"
            Set-ItemProperty -Path ("HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\" + $key.PSChildName) "Value" "Deny"
            Set-ItemProperty -Path ("HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\" + $key.PSChildName) "InitialAppValue" "Unspecified"
        }
    
        Write-Output "Disable location sensor"
        New-FolderForced -Path "HKCU:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Permissions\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}"
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Permissions\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" "SensorPermissionState" 0
    
        Write-Output "Disable submission of Windows Defender findings (w/ elevated privileges)"
        Takeown-Registry("HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Spynet")
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender\Spynet" "SpyNetReporting" 0       # write-protected even after takeown ?!
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender\Spynet" "SubmitSamplesConsent" 0
    
        # The following section can cause problems with network / internet connectivity
        # in generel. See the corresponding issue:
        # https://github.com/W4RH4WK/Debloat-Windows-10/issues/270
        #Write-Output "Do not share wifi networks"
        #$user = New-Object System.Security.Principal.NTAccount($env:UserName)
        #$sid = $user.Translate([System.Security.Principal.SecurityIdentifier]).value
        #New-FolderForced -Path ("HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\features\" + $sid)
        #Set-ItemProperty -Path ("HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\features\" + $sid) "FeatureStates" 0x33c
        #Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\features" "WiFiSenseCredShared" 0
        #Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\features" "WiFiSenseOpen" 0    
    }
    
    Function DisableAppSuggestions {
        Elevate-Privileges
        Write-Output "Disabling Application suggestions..."
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "ContentDeliveryAllowed" -Type DWord -Value 0
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "OemPreInstalledAppsEnabled" -Type DWord -Value 0
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEnabled" -Type DWord -Value 0
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEverEnabled" -Type DWord -Value 0
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SilentInstalledAppsEnabled" -Type DWord -Value 0
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-310093Enabled" -Type DWord -Value 0
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-314559Enabled" -Type DWord -Value 0
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338387Enabled" -Type DWord -Value 0
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338388Enabled" -Type DWord -Value 0
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338389Enabled" -Type DWord -Value 0
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338393Enabled" -Type DWord -Value 0
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353694Enabled" -Type DWord -Value 0
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353696Enabled" -Type DWord -Value 0
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353698Enabled" -Type DWord -Value 0
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SystemPaneSuggestionsEnabled" -Type DWord -Value 0
        If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement")) {
            New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement" -Force | Out-Null
        }
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement" -Name "ScoobeSystemSettingEnabled" -Type DWord -Value 0
        If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace")) {
            New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace" -Force | Out-Null
        }
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace" -Name "AllowSuggestedAppsInWindowsInkWorkspace" -Type DWord -Value 0
        # Empty placeholder tile collection in registry cache and restart Start Menu process to reload the cache
        If ([System.Environment]::OSVersion.Version.Build -ge 17134) {
            $key = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\CloudStore\Store\Cache\DefaultAccount\*windows.data.placeholdertilecollection\Current"
            Set-ItemProperty -Path $key.PSPath -Name "Data" -Type Binary -Value $key.Data[0..15]
            Stop-Process -Name "ShellExperienceHost" -Force -ErrorAction SilentlyContinue
            Write-Output "done"
        }
    }
    
    function DisableTailoredExperiences {
        Write-Output "Disabling Tailored Experiences..."
        If (!(Test-Path "HKCU:\Software\Policies\Microsoft\Windows\CloudContent")) {
            New-Item -Path "HKCU:\Software\Policies\Microsoft\Windows\CloudContent" -Force | Out-Null
        }
        Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\CloudContent" -Name "DisableTailoredExperiencesWithDiagnosticData" -Type DWord -Value 1
    }
    
    function DisableAdvertisingID {
        Write-Output "Disabling Advertising ID..."
        If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo")) {
            New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" | Out-Null
        }
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" -Name "DisabledByGroupPolicy" -Type DWord -Value 1
        Write-Output "done"
    }


    #Debloat functions
    function DisableWindowsDefender {

        Write-Output "Elevating priviledges for this process"
        do {} until (Elevate-Privileges SeTakeOwnershipPrivilege)
        
        $tasks = @(
            "\Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenance"
            "\Microsoft\Windows\Windows Defender\Windows Defender Cleanup"
            "\Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan"
            "\Microsoft\Windows\Windows Defender\Windows Defender Verification"
        )
        
        foreach ($task in $tasks) {
            $parts = $task.split('\')
            $name = $parts[-1]
            $path = $parts[0..($parts.length-2)] -join '\'
    
            Write-Output "Trying to disable scheduled task $name"
            Disable-ScheduledTask -TaskName "$name" -TaskPath "$path"
        }
        
        Write-Output "Disabling Windows Defender via Group Policies"
        New-FolderForced -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows Defender"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows Defender" "DisableAntiSpyware" 1
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows Defender" "DisableRoutinelyTakingAction" 1
        New-FolderForced -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows Defender\Real-Time Protection"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows Defender\Real-Time Protection" "DisableRealtimeMonitoring" 1
        
        Write-Output "Disabling Windows Defender Services"
        Takeown-Registry("HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WinDefend")
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WinDefend" "Start" 4
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WinDefend" "AutorunsDisabled" 3
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WdNisSvc" "Start" 4
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WdNisSvc" "AutorunsDisabled" 3
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Sense" "Start" 4
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Sense" "AutorunsDisabled" 3
        
        Write-Output "Removing Windows Defender context menu item"
        Set-Item "HKLM:\SOFTWARE\Classes\CLSID\{09A47860-11B0-4DA5-AFA5-26D86198A780}\InprocServer32" ""
        
        Write-Output "Removing Windows Defender GUI / tray from autorun"
        Remove-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" "WindowsDefender" -ea 0
    }
    
    function RemoveDefaultApps {
        # Add "#" (without quotes) in front of a package to prevent it from being removed.
        # So "Microsoft.SomeBloatware" becomes #"Microsoft.SomeBloatware"
    
        $apps = @(
            #"Microsoft.549981C3F5F10" # Cortana
            "Microsoft.3DBuilder"
            #"Microsoft.Appconnector"
            #"Microsoft.BingFinance"
            #"Microsoft.BingNews"
            #"Microsoft.BingSports"
            #"Microsoft.BingTranslator"
            "Microsoft.BingWeather"
            #"Microsoft.FreshPaint"
            "Microsoft.GamingServices"
            "Microsoft.Microsoft3DViewer"
            "Microsoft.MicrosoftOfficeHub"
            "Microsoft.MicrosoftPowerBIForWindows"
            "Microsoft.MicrosoftSolitaireCollection"
            #"Microsoft.MicrosoftStickyNotes"
            "Microsoft.MinecraftUWP"
            "Microsoft.NetworkSpeedTest"
            "Microsoft.Office.OneNote"
            "Microsoft.People"
            "Microsoft.Print3D"
            "Microsoft.SkypeApp"
            "Microsoft.Wallet" #wtf when did ms have a wallet app
            #"Microsoft.Windows.Photos"
            "Microsoft.WindowsAlarms"
            #"Microsoft.WindowsCalculator"
            "Microsoft.WindowsCamera"
            "microsoft.windowscommunicationsapps"
            "Microsoft.WindowsMaps"
            "Microsoft.WindowsPhone"
            "Microsoft.WindowsSoundRecorder"
            #"Microsoft.WindowsStore"   # can't be re-installed
            "Microsoft.Xbox.TCUI"
            "Microsoft.XboxApp"
            "Microsoft.XboxGameOverlay"
            "Microsoft.XboxGamingOverlay"
            "Microsoft.XboxSpeechToTextOverlay"
            "Microsoft.YourPhone"
            "Microsoft.ZuneMusic"
            "Microsoft.ZuneVideo"
    
            # Threshold 2 apps
            "Microsoft.CommsPhone"
            "Microsoft.ConnectivityStore"
            "Microsoft.GetHelp"
            "Microsoft.Getstarted"
            "Microsoft.Messaging"
            "Microsoft.Office.Sway"
            "Microsoft.OneConnect"
            "Microsoft.WindowsFeedbackHub"
    
            # Creators Update apps
            "Microsoft.Microsoft3DViewer"
            #"Microsoft.MSPaint"
    
            # Redstone apps
            "Microsoft.BingFoodAndDrink"
            "Microsoft.BingHealthAndFitness"
            "Microsoft.BingTravel"
            "Microsoft.WindowsReadingList"
    
            # Redstone 5 apps
            "Microsoft.MixedReality.Portal"
            "Microsoft.ScreenSketch"
            "Microsoft.XboxGamingOverlay"
            "Microsoft.YourPhone"
    
            # non-Microsoft
            "2FE3CB00.PicsArt-PhotoStudio"
            "46928bounde.EclipseManager"
            "4DF9E0F8.Netflix"
            "613EBCEA.PolarrPhotoEditorAcademicEdition"
            "6Wunderkinder.Wunderlist"
            "7EE7776C.LinkedInforWindows"
            "89006A2E.AutodeskSketchBook"
            "9E2F88E3.Twitter"
            "A278AB0D.DisneyMagicKingdoms"
            "A278AB0D.MarchofEmpires"
            "ActiproSoftwareLLC.562882FEEB491" # next one is for the Code Writer from Actipro Software LLC
            "CAF9E577.Plex"  
            "ClearChannelRadioDigital.iHeartRadio"
            "D52A8D61.FarmVille2CountryEscape"
            "D5EA27B7.Duolingo-LearnLanguagesforFree"
            "DB6EA5DB.CyberLinkMediaSuiteEssentials"
            "DolbyLaboratories.DolbyAccess"
            "DolbyLaboratories.DolbyAccess"
            "Drawboard.DrawboardPDF"
            "Facebook.Facebook"
            "Fitbit.FitbitCoach"
            "Flipboard.Flipboard"
            "GAMELOFTSA.Asphalt8Airborne"
            "KeeperSecurityInc.Keeper"
            "NORDCURRENT.COOKINGFEVER"
            "PandoraMediaInc.29680B314EFC2"
            "Playtika.CaesarsSlotsFreeCasino"
            "ShazamEntertainmentLtd.Shazam"
            "SlingTVLLC.SlingTV"
            "SpotifyAB.SpotifyMusic"
            "TheNewYorkTimes.NYTCrossword"
            "ThumbmunkeysLtd.PhototasticCollage"
            "TuneIn.TuneInRadio"
            "WinZipComputing.WinZipUniversal"
            "XINGAG.XING"
            "flaregamesGmbH.RoyalRevolt2"
            "king.com.*"
            "king.com.BubbleWitch3Saga"
            "king.com.CandyCrushSaga"
            "king.com.CandyCrushSodaSaga"
    
            # Apps which cannot be removed using Remove-AppxPackage
            #"Microsoft.BioEnrollment"
            #"Microsoft.MicrosoftEdge"
            #"Microsoft.Windows.Cortana"
            #"Microsoft.WindowsFeedback"
            #"Microsoft.XboxGameCallableUI"
            #"Microsoft.XboxIdentityProvider"
            #"Windows.ContactSupport"
    
            # apps which other apps depend on
            "Microsoft.Advertising.Xaml"
        )
    
        Write-Output "Elevating privileges for this process"
        do {} until (Elevate-Privileges SeTakeOwnershipPrivilege)
    
        Write-Output "Uninstalling default apps"
    
        foreach ($app in $apps) {
            Write-Output "Trying to remove $app"
    
            Get-AppxPackage -Name $app -AllUsers | Remove-AppxPackage -AllUsers
    
            Get-AppXProvisionedPackage -Online |
                Where-Object DisplayName -EQ $app |
                Remove-AppxProvisionedPackage -Online
        }
    
        # Prevents Apps from re-installing
        $cdm = @(
            "ContentDeliveryAllowed"
            "FeatureManagementEnabled"
            "OemPreInstalledAppsEnabled"
            "PreInstalledAppsEnabled"
            "PreInstalledAppsEverEnabled"
            "SilentInstalledAppsEnabled"
            "SubscribedContent-314559Enabled"
            "SubscribedContent-338387Enabled"
            "SubscribedContent-338388Enabled"
            "SubscribedContent-338389Enabled"
            "SubscribedContent-338393Enabled"
            "SubscribedContentEnabled"
            "SystemPaneSuggestionsEnabled"
        )
    
        New-FolderForced -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
        foreach ($key in $cdm) {
            Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" $key 0
        }
    
        New-FolderForced -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" "AutoDownload" 2
    
        # Prevents "Suggested Applications" returning
        New-FolderForced -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" "DisableWindowsConsumerFeatures" 1
    }
    
    function RemoveOneDrive {
        Write-Output "Killing OneDrive process"
        taskkill.exe /F /IM "OneDrive.exe"
        taskkill.exe /F /IM "explorer.exe"
        
        Write-Output "Removing OneDrive"
        if (Test-Path "$env:systemroot\System32\OneDriveSetup.exe") {
            & "$env:systemroot\System32\OneDriveSetup.exe" /uninstall
        }
        if (Test-Path "$env:systemroot\SysWOW64\OneDriveSetup.exe") {
            & "$env:systemroot\SysWOW64\OneDriveSetup.exe" /uninstall
        }
        
        Write-Output "Removing OneDrive leftovers"
        Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "$env:localappdata\Microsoft\OneDrive"
        Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "$env:programdata\Microsoft OneDrive"
        Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "$env:systemdrive\OneDriveTemp"
        # check if directory is empty before removing:
        If ((Get-ChildItem "$env:userprofile\OneDrive" -Recurse | Measure-Object).Count -eq 0) {
            Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "$env:userprofile\OneDrive"
        }
        
        Write-Output "Disable OneDrive via Group Policies"
        New-FolderForced -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\OneDrive"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\OneDrive" "DisableFileSyncNGSC" 1
        
        Write-Output "Remove Onedrive from explorer sidebar"
        New-PSDrive -PSProvider "Registry" -Root "HKEY_CLASSES_ROOT" -Name "HKCR"
        mkdir -Force "HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}"
        Set-ItemProperty -Path "HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" "System.IsPinnedToNameSpaceTree" 0
        mkdir -Force "HKCR:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}"
        Set-ItemProperty -Path "HKCR:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" "System.IsPinnedToNameSpaceTree" 0
        Remove-PSDrive "HKCR"
        
        Write-Output "Removing run hook for new users"
        reg load "hku\Default" "C:\Users\Default\NTUSER.DAT"
        reg delete "HKEY_USERS\Default\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "OneDriveSetup" /f
        reg unload "hku\Default"
        
        Write-Output "Removing startmenu entry"
        Remove-Item -Force -ErrorAction SilentlyContinue "$env:userprofile\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\OneDrive.lnk"
        
        Write-Output "Removing scheduled task"
        Get-ScheduledTask -TaskPath '\' -TaskName 'OneDrive*' -ea SilentlyContinue | Unregister-ScheduledTask -Confirm:$false
        
        Write-Output "Restarting explorer"
        Start-Process "explorer.exe"
        
        Write-Output "Waiting for explorer to complete loading"
        Start-Sleep 10
        
        Write-Output "Removing additional OneDrive leftovers"
        foreach ($item in (Get-ChildItem "$env:WinDir\WinSxS\*onedrive*")) {
            Takeown-Folder $item.FullName
            Remove-Item -Recurse -Force $item.FullName
        }
    }
    
    function OptimizeUpdates {
        Write-Output "Disabling automatic download and installation of Windows updates"
        New-FolderForced -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\WindowsUpdate\AU"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\WindowsUpdate\AU" "NoAutoUpdate" 0
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\WindowsUpdate\AU" "AUOptions" 2
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\WindowsUpdate\AU" "ScheduledInstallDay" 0
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\WindowsUpdate\AU" "ScheduledInstallTime" 3
        
        Write-Output "Disable seeding of updates to other computers via Group Policies"
        New-FolderForced -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" "DODownloadMode" 0
        
        #echo "Disabling automatic driver update"
        #sp "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" "SearchOrderConfig" 0
        
        $objSID = New-Object System.Security.Principal.SecurityIdentifier "S-1-1-0"
        $EveryOne = $objSID.Translate( [System.Security.Principal.NTAccount]).Value
        
        
        Write-Output "Disable 'Updates are available' message"
        
        takeown /F "$env:WinDIR\System32\MusNotification.exe"
        icacls "$env:WinDIR\System32\MusNotification.exe" /deny "$($EveryOne):(X)"
        takeown /F "$env:WinDIR\System32\MusNotificationUx.exe"
        icacls "$env:WinDIR\System32\MusNotificationUx.exe" /deny "$($EveryOne):(X)"
    }
    
    function DisableServices {
        $services = @(
            "diagnosticshub.standardcollector.service" # Microsoft (R) Diagnostics Hub Standard Collector Service
            "DiagTrack"                                # Diagnostics Tracking Service
            "dmwappushservice"                         # WAP Push Message Routing Service (see known issues)
            "lfsvc"                                    # Geolocation Service
            "MapsBroker"                               # Downloaded Maps Manager
            "NetTcpPortSharing"                        # Net.Tcp Port Sharing Service
            "RemoteAccess"                             # Routing and Remote Access
            "RemoteRegistry"                           # Remote Registry
            "SharedAccess"                             # Internet Connection Sharing (ICS)
            "TrkWks"                                   # Distributed Link Tracking Client
            "WbioSrvc"                                 # Windows Biometric Service (required for Fingerprint reader / facial detection)
            #"WlanSvc"                                 # WLAN AutoConfig
            "WMPNetworkSvc"                            # Windows Media Player Network Sharing Service
            #"wscsvc"                                  # Windows Security Center Service
            #"WSearch"                                 # Windows Search
            "XblAuthManager"                           # Xbox Live Auth Manager
            "XblGameSave"                              # Xbox Live Game Save Service
            "XboxNetApiSvc"                            # Xbox Live Networking Service
            "ndu"                                      # Windows Network Data Usage Monitor
            # Services which cannot be disabled
            #"WdNisSvc"
        )
        foreach ($service in $services) {
            Write-Output "Trying to disable $service"
            Get-Service -Name $service | Set-Service -StartupType Disabled
        }
        Read-Host "Press Enter To Continue"
    }
    
    function DisableCortana {
        Write-Output "Disabling Cortana..."
        If (!(Test-Path "HKCU:\Software\Microsoft\Personalization\Settings")) {
            New-Item -Path "HKCU:\Software\Microsoft\Personalization\Settings" -Force | Out-Null
        }
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Personalization\Settings" -Name "AcceptedPrivacyPolicy" -Type DWord -Value 0
        If (!(Test-Path "HKCU:\Software\Microsoft\InputPersonalization\TrainedDataStore")) {
            New-Item -Path "HKCU:\Software\Microsoft\InputPersonalization\TrainedDataStore" -Force | Out-Null
        }
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\InputPersonalization" -Name "RestrictImplicitTextCollection" -Type DWord -Value 1
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\InputPersonalization" -Name "RestrictImplicitInkCollection" -Type DWord -Value 1
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\InputPersonalization\TrainedDataStore" -Name "HarvestContacts" -Type DWord -Value 0
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowCortanaButton" -Type DWord -Value 0
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Experience\AllowCortana" -Name "Value" -Type DWord -Value 0
        If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search")) {
            New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Force | Out-Null
        }
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana" -Type DWord -Value 0
        If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization")) {
            New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization" -Force | Out-Null
        }
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization" -Name "AllowInputPersonalization" -Type DWord -Value 0
        Get-AppxPackage "Microsoft.549981C3F5F10" | Remove-AppxPackage
        Write-Output "done"
    }
    
    function RemoveIE {
        Write-Output "Uninstalling Internet Explorer..."
        Get-WindowsOptionalFeature -Online | Where-Object { $_.FeatureName -like "Internet-Explorer-Optional*" } | Disable-WindowsOptionalFeature -Online -NoRestart -WarningAction SilentlyContinue | Out-Null
        Get-WindowsCapability -Online | Where-Object { $_.Name -like "Browser.InternetExplorer*" } | Remove-WindowsCapability -Online | Out-Null
        Write-Output "done"
    }


    #Tweaks
    function DarkMode {
        if((Test-Path -LiteralPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize") -ne $true) {  New-Item "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -force -ea SilentlyContinue };
        if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize") -ne $true) {  New-Item "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -force -ea SilentlyContinue };
        New-ItemProperty -LiteralPath 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize' -Name 'AppsUseLightTheme' -Value 0 -PropertyType DWord -Force -ea SilentlyContinue;
        New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize' -Name 'AppsUseLightTheme' -Value 0 -PropertyType DWord -Force -ea SilentlyContinue;
    }
    
    function RAM {
        if((Test-Path -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Control") -ne $true) {  New-Item "HKLM:\SYSTEM\CurrentControlSet\Control" -force -ea SilentlyContinue };
        if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile") -ne $true) {  New-Item "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -force -ea SilentlyContinue };
        if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks") -ne $true) {  New-Item "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks" -force -ea SilentlyContinue };
        if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio") -ne $true) {  New-Item "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio" -force -ea SilentlyContinue };
        if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Capture") -ne $true) {  New-Item "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Capture" -force -ea SilentlyContinue };
    }
    
    function DisablePrefetchPrelaunch {
        Disable-MMAgent -ApplicationPreLaunch
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v EnablePrefetcher /t REG_DWORD /d "0" /f
        reg add "HKLM\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main" /v AllowPrelaunch /t REG_DWORD /d "0" /f
        
    }
    
    function DisableEdgePrelaunch {
        if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main") -ne $true) {  New-Item "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main" -force -ea SilentlyContinue };
        if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\TabPreloader") -ne $true) {  New-Item "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\TabPreloader" -force -ea SilentlyContinue };
        New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main' -Name 'AllowPrelaunch' -Value 0 -PropertyType DWord -Force -ea SilentlyContinue;
        New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\TabPreloader' -Name 'AllowTabPreloading' -Value 0 -PropertyType DWord -Force -ea SilentlyContinue;
    }
    
    function EnablePhotoViewer {
        Write-Output "Enabling Photo Viewer"
        if((Test-Path -LiteralPath "HKCU:\Software\Classes\.jpg") -ne $true) {  New-Item "HKCU:\Software\Classes\.jpg" -force -ea SilentlyContinue };
        if((Test-Path -LiteralPath "HKCU:\Software\Classes\.jpeg") -ne $true) {  New-Item "HKCU:\Software\Classes\.jpeg" -force -ea SilentlyContinue };
        if((Test-Path -LiteralPath "HKCU:\Software\Classes\.gif") -ne $true) {  New-Item "HKCU:\Software\Classes\.gif" -force -ea SilentlyContinue };
        if((Test-Path -LiteralPath "HKCU:\Software\Classes\.png") -ne $true) {  New-Item "HKCU:\Software\Classes\.png" -force -ea SilentlyContinue };
        if((Test-Path -LiteralPath "HKCU:\Software\Classes\.bmp") -ne $true) {  New-Item "HKCU:\Software\Classes\.bmp" -force -ea SilentlyContinue };
        if((Test-Path -LiteralPath "HKCU:\Software\Classes\.tiff") -ne $true) {  New-Item "HKCU:\Software\Classes\.tiff" -force -ea SilentlyContinue };
        if((Test-Path -LiteralPath "HKCU:\Software\Classes\.ico") -ne $true) {  New-Item "HKCU:\Software\Classes\.ico" -force -ea SilentlyContinue };
        New-ItemProperty -LiteralPath 'HKCU:\Software\Classes\.jpg' -Name '(default)' -Value 'PhotoViewer.FileAssoc.Tiff' -PropertyType String -Force -ea SilentlyContinue;
        New-ItemProperty -LiteralPath 'HKCU:\Software\Classes\.jpeg' -Name '(default)' -Value 'PhotoViewer.FileAssoc.Tiff' -PropertyType String -Force -ea SilentlyContinue;
        New-ItemProperty -LiteralPath 'HKCU:\Software\Classes\.gif' -Name '(default)' -Value 'PhotoViewer.FileAssoc.Tiff' -PropertyType String -Force -ea SilentlyContinue;
        New-ItemProperty -LiteralPath 'HKCU:\Software\Classes\.png' -Name '(default)' -Value 'PhotoViewer.FileAssoc.Tiff' -PropertyType String -Force -ea SilentlyContinue;
        New-ItemProperty -LiteralPath 'HKCU:\Software\Classes\.bmp' -Name '(default)' -Value 'PhotoViewer.FileAssoc.Tiff' -PropertyType String -Force -ea SilentlyContinue;
        New-ItemProperty -LiteralPath 'HKCU:\Software\Classes\.tiff' -Name '(default)' -Value 'PhotoViewer.FileAssoc.Tiff' -PropertyType String -Force -ea SilentlyContinue;
        New-ItemProperty -LiteralPath 'HKCU:\Software\Classes\.ico' -Name '(default)' -Value 'PhotoViewer.FileAssoc.Tiff' -PropertyType String -Force -ea SilentlyContinue;
        Write-Output "Done"
    }
    
    function UseUTC {
        if((Test-Path -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Control\TimeZoneInformation") -ne $true) {  New-Item "HKLM:\SYSTEM\CurrentControlSet\Control\TimeZoneInformation" -force -ea SilentlyContinue };
        New-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\TimeZoneInformation' -Name 'RealTimeIsUniversal' -Value 1 -PropertyType DWord -Force -ea SilentlyContinue;
        Write-Output "Done"
    }
    
    function DisableShellExperienceHost {
        #This will somewhat break internet connectivity, Explorer, WSL, etc
        Write-Output "Disabling ShellExperienceHost"
        taskkill.exe /F /IM ShellExperienceHost.exe
        Move-Item -Path "%windir%\SystemApps\ShellExperienceHost_cw5n1h2txyewy" -Destination "%windir%\SystemApps\ShellExperienceHost_cw5n1h2txyewy.bak" 
        Write-Output "Done"
    }
    
    function DisableSearchUI {
        Write-Output "Disabling SearchUI"
        taskkill.exe /F /IM SearchUI.exe
        Move-Item -Path "%windir%\SystemApps\Microsoft.Windows.Cortana_cw5n1h2txyewy" -Destination "%windir%\SystemApps\Microsoft.Windows.Cortana_cw5n1h2txyewy.bak"
        Write-Output "Done"
    }
    
    function ImproveSSD {
        # SSD life improvement
        fsutil behavior set DisableLastAccess 1
        fsutil behavior set EncryptPagingFile 0
    }
    
    function GodMode {
        $DesktopPath = [Environment]::GetFolderPath("Desktop");
        mkdir "$DesktopPath\GodMode.{ED7BA470-8E54-465E-825C-99712043E01C}"
    }
    
    function TBSingleClick {
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -ErrorAction SilentlyContinue | Out-Null
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "LastActiveClick" -Type Dword -Value 0x00000001 -Force
    }
    # UI Tweaks
    
    function RemoveThisPClutter {
        # Remove Desktop from This PC
        Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}"
        Remove-Item -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}"
        # Remove Documents from This PC
        Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{A8CDFF1C-4878-43be-B5FD-F8091C1C60D0}"
        Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{d3162b92-9365-467a-956b-92703aca08af}"
        Remove-Item -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{A8CDFF1C-4878-43be-B5FD-F8091C1C60D0}"
        Remove-Item -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{d3162b92-9365-467a-956b-92703aca08af}"
        # Remove Downloads from This PC
        Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{374DE290-123F-4565-9164-39C4925E467B}"
        Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{088e3905-0323-4b02-9826-5d99428e115f}"
        Remove-Item -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{374DE290-123F-4565-9164-39C4925E467B}"
        Remove-Item -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{088e3905-0323-4b02-9826-5d99428e115f}"
        # Remove Music from This PC
        Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{1CF1260C-4DD0-4ebb-811F-33C572699FDE}"
        Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}"
        Remove-Item -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{1CF1260C-4DD0-4ebb-811F-33C572699FDE}"
        Remove-Item -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}"
        # Remove Pictures from This PC
        Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3ADD1653-EB32-4cb0-BBD7-DFA0ABB5ACCA}"
        Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{24ad3ad4-a569-4530-98e1-ab02f9417aa8}"
        Remove-Item -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3ADD1653-EB32-4cb0-BBD7-DFA0ABB5ACCA}"
        Remove-Item -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{24ad3ad4-a569-4530-98e1-ab02f9417aa8}"
        # Remove Videos from This PC
        Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{A0953C92-50DC-43bf-BE83-3742FED03C9C}"
        Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a}"
        Remove-Item -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{A0953C92-50DC-43bf-BE83-3742FED03C9C}"
        Remove-Item -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a}"
        # Remove 3D Objects from This PC
        Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}"
        Remove-Item -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}"
    }
    
    function DisableAeroShake {
        Write-Output "Disabling Aero Shake..."
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "DisallowShaking" -Type DWord -Value 1
    }