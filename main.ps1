Set-ExecutionPolicy Unrestricted -Scope CurrentUser
ls -Recurse *.ps*1 | Unblock-File
#Self-elevate the script if required
if (-Not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')) {
    if ([int](Get-CimInstance -Class Win32_OperatingSystem | Select-Object -ExpandProperty BuildNumber) -ge 6000) {
        $CommandLine = "-File `"" + $MyInvocation.MyCommand.Path + "`" " + $MyInvocation.UnboundArguments
        Start-Process -FilePath PowerShell.exe -Verb Runas -ArgumentList $CommandLine
        Exit
    }
}

Import-Module -DisableNameChecking $PSScriptRoot\functions.psm1

<# Disclaimer: This script is only ment for system administrators who know what they're doing. Please read README before proceeding
   For a more user-friendly approach, use WindowsToolbox.
   Info about tweaks is in README.md #>

<# Usage: Comment out any function that you don't want to run, all functions will run by default
    e.g: DisableWindowsDefender -> #DisableWindowsDefender #>

#Debloat functions:

    DisableWindowsDefender #Disable Windows Defender (NOT RECOMMENDED)
    RemoveDefaultApps #Remove default UWP bloatware
    RemoveOneDrive #Remove OneDrive
    OptimizeUpdates #Optimize Windows Updates
    DisableServices #Disable unused / rarely used services
    DisableCortana #Disable Cortana

#Privacy settings:

    Disable-Telemetry #Disable telemetry
    PrivacyFixSettings #Fix privacy settings
    DisableAppSuggestions #Disable app suggestions
    DisableTailoredExperiences #Disable Tailored Experiences
    DisableAdvertisingID #Disable AdvertistingID

#Tweaks

    #System tweaks:

        LowerRAMUsage #Lowers RAM usage by a lot
        EnablePhotoViewer #Enable Windows Photo Viewer
        DisablePrefetchPrelaunch #Disable Prefetch Prelaunch
        DisableEdgePrelaunch #Disable Edge Prelaunch
        UseUTC #Use UTC time (useful for syncing time between Windows and other OS)
        DisableShellExperienceHost #Disable ShellExperienceHost (breaks Explorer, Start menu, etc)
        GodMode #Create a God Mode shortcut on your desktop
        ImproveSSD #Improve SSD lifespan
        DisableSearchUI #Disable SearchUI
    
    #UI tweaks:
        RemoveThisPClutter #Remove user folders under ThisPC
        DarkMode #Enable dark mode
        DisableAeroShake #Disable Aero Shake
        TBSingleClick #Switch windows with a single click on the taskbar

#Undo (tbh dunno why would you run this at first boot but here they are)
    EnableTelemetry #(Re)enable telemetry

#Other     
    Restart #Restart the computer
    Info #Show info
