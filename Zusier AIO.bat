@echo off
title Zusier's Batch - Performance and Optimization V5.0.1
color 5
echo ---------------------------------------------------------------------------------------------------
echo 8888888888P                  d8b                       888888b.            888            888      
echo       d88P                   Y8P                       888  "88b           888            888      
echo      d88P                                              888  .88P           888            888      
echo     d88P   888  888 .d8888b  888  .d88b.  888d888      8888888K.   8888b.  888888 .d8888b 88888b.  
echo    d88P    888  888 88K      888 d8P  Y8b 888P"        888  "Y88b     "88b 888   d88P"    888 "88b 
echo   d88P     888  888 "Y8888b. 888 88888888 888          888    888 .d888888 888   888      888  888 
echo  d88P      Y88b 888      X88 888 Y8b.     888          888   d88P 888  888 Y88b. Y88b.    888  888 
echo d8888888888 "Y88888  88888P' 888  "Y8888  888          8888888P"  "Y888888  "Y888 "Y8888P 888  888 
echo ---------------------------------------------------------------------------------------------------

echo Change Log
echo .
echo V5.1.0
echo -Integrated multiple tweaks and her exe from Melody more info about her on readme.md
echo -Added TRIM option
echo -Added multiple other network, gpu and system tweaks
echo .
echo V5.0.1
echo - Removed some service tweaks for stability
echo - Reworked and revised file
echo - Wifi fix added, DM me if you have problems 
echo - reordered some tweaks to be compatible
echo - circumvented command loop, finally
echo.
echo V5.0.0
echo - hotfix for wifi
echo V4.9.1
echo - fixed command loop
echo - removed network upgrade (powershell error fuckup)
echo - fixed spelling error (actually so tired help meeeeee)
echo - next release will be completely reworked!
echo V4.4.0
echo -upgraded network tweaks to change some ethernet settings (jumbo packet, power saving etc.)
echo V4.3.41
echo -small hotfix (changelog shit)
echo.
echo V4.3.4
echo - revamped Internet optimizations
echo - added DNS server change to 1.1.1.1 
echo - re-added Temp Clean (no reason I removed it so I added it back)
echo.
echo V4.2
echo - removed some conflicting services
echo V4.1 -Overhaul! 
echo - many errors may occur (from my testing and tried to debug) (fixed)
echo - changed bcdedit to be safer and better
echo - added many tweaks for network adapter, gpu and services
echo - removed temp clean
echo.
echo V3.5.5 -adds a BCDedit option with multiple tweaks
echo.
echo V3.5 -converted DisableFSO.reg to bat
echo -removed chkdsk
echo.
echo V3.3.1
echo -hotfix for & command
echo.
echo V3.3 -tweaked title for better identification 
echo.
echo V3.2.7
echo -This version rids of reg.reg to bring a smaller file size and compatibility (integrated in .bat)
echo -uses chkdsk to find more errors (need to run chkdsk /f after restart)
echo -added Audl.exe (lowers sample rate of audio to decrease latency)
echo -tweaked reg to include system animations
echo -bat now runs sfc /scannow
:: BatchGotAdmin
:-------------------------------------
REM  --> Check for permissions
>nul 2>&1 "%SYSTEMROOT%\system32\cacls.exe" "%SYSTEMROOT%\system32\config\system"
REM --> If error flag set, we do not have admin.
if '%errorlevel%' NEQ '0' (
    echo Requesting administrative privileges...
    goto UACPrompt
) else ( goto gotAdmin )
:UACPrompt
    echo Set UAC = CreateObject^("Shell.Application"^) > "%temp%\getadmin.vbs"
    echo UAC.ShellExecute "%~s0", "", "", "runas", 1 >> "%temp%\getadmin.vbs"
    "%temp%\getadmin.vbs"
    exit /B
:gotAdmin
    if exist "%temp%\getadmin.vbs" ( del "%temp%\getadmin.vbs" )
    pushd "%CD%"
    CD /D "%~dp0"
:--------------------------------------
echo.
echo.
echo.
echo Admin Privileges Acquired!
echo.
echo.
echo.
echo Would you like start now?
pause
echo.
Echo Attempting to create a system Restore Point

Wmic.exe /Namespace:\\root\default Path SystemRestore Call CreateRestorePoint "Before Zusiers Tweaks", 100, 12

echo Restore Point Created!
echo.
echo.
echo.


echo integrating Zusier's Registry Tweak 
echo.
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowDeviceNameInTelemetry" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableInstallerDetection" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "DisallowShaking" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "EnableBalloonTips" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoLowDiskSpaceChecks" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "LinkResolveIgnoreLinkInfo" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoResolveSearch" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoResolveTrack" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoInternetOpenWith" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoInstrumentation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "Max Cached Icons" /t REG_SZ /d "2500" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive" /v "DisableFileSyncNGSC" /t REG_DWORD /d "1" /f
REG.exe add "HKLM\software\policies\microsoft\windows\skydrive" /v "disablefilesync" /t REG_DWORD /d "1" /f

echo Win32Priority is being set to 28! If you have different thoughts on W32PS please change here (this is in decimal so use a converter!)
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "Win32PrioritySeparation" /t REG_DWORD /d "40" /f

Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance" /v "MaintenanceDisabled" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" /v "VisualFXSetting" /t REG_DWORD /d "3" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\AnimateMinMax" /v "DefaultApplied" /t REG_SZ /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\ComboBoxAnimation" /v "DefaultApplied" /t REG_SZ /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\ControlAnimations" /v "DefaultApplied" /t REG_SZ /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\CursorShadow" /v "DefaultApplied" /t REG_SZ /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\DragFullWindows" /v "DefaultApplied" /t REG_SZ /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\DropShadow" /v "DefaultApplied" /t REG_SZ /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\DWMAeroPeekEnabled" /v "DefaultApplied" /t REG_SZ /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\DWMEnabled" /v "DefaultApplied" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\DWMSaveThumbnailEnabled" /v "DefaultApplied" /t REG_SZ /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\FontSmoothing" /v "DefaultApplied" /t REG_SZ /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\ListBoxSmoothScrolling" /v "DefaultApplied" /t REG_SZ /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\ListviewAlphaSelect" /v "DefaultApplied" /t REG_SZ /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\ListviewShadow" /v "DefaultApplied" /t REG_SZ /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\MenuAnimation" /v "DefaultApplied" /t REG_SZ /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\SelectionFade" /v "DefaultApplied" /t REG_SZ /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\TaskbarAnimations" /v "DefaultApplied" /t REG_SZ /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\ThumbnailsOrIcon" /v "DefaultApplied" /t REG_SZ /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\TooltipAnimation" /v "DefaultApplied" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableWindowsConsumerFeatures" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\ApplicationManagement\AllowGameDVR" /v "value" /t REG_SZ /d "00000000" /f
Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" /v "NoTileApplicationNotification" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\OneSyncSvc" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\OneSyncSvc_402ac" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\dmwappushservice" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\DiagTrack" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\DiagTrack" /v "ContentDeliveryAllowed" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\DiagTrack" /v "OemPreInstalledAppsEnabled" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\DiagTrack" /v "PreInstalledAppsEnabled" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\DiagTrack" /v "PreInstalledAppsEverEnabled" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\DiagTrack" /v "SilentInstalledAppsEnabled" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\DiagTrack" /v "SubscribedContent-338389Enabled" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\DiagTrack" /v "SystemPaneSuggestionsEnabled" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\DiagTrack" /v "SubscribedContent-338388Enabled" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\DiagTrack" /v "AppsUseLightTheme" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\DiagTrack" /v "SystemUsesLightTheme" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\DiagTrack" /v "BingSearchEnabled" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\DiagTrack" /v "DisableAntiSpyware" /t REG_SZ /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\DiagTrack" /v "DisableWebSearch" /t REG_SZ /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\DiagTrack" /v "AutoUpdateEnabled" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\DiagTrack" /v "EnableWebContentEvaluation" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Settings" /v "DownloadMode" /t REG_DWORD /d "0" /f

reg.exe add "hklm\system\currentcontrolset\control\session manager\memory management\prefetchparameters" /v "enableboottrace" /t reg_dword /d "0" /f
reg.exe add "hklm\system\currentcontrolset\control\session manager\memory management\prefetchparameters" /v "enableprefetcher" /t reg_dword /d "0" /f
reg.exe add "hklm\system\currentcontrolset\control\session manager\memory management\prefetchparameters" /v "enablesuperfetch" /t reg_dword /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "DisableAutomaticRestartSignOn" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "HiberbootEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnableSuperfetch" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnableBoottrace" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnablePrefetcher" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\System\CurrentControlSet\Services\VxD\BIOS" /v "CPUPriority" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\System\CurrentControlSet\Services\VxD\BIOS" /v "FastDRAM" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "LargeSystemCache" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettingsOverride" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettingsOverrideMask" /t REG_DWORD /d "3" /f
reg.exe ADD "HKLM\SYSTEM\CurrentControlSet\Control" /v "SvcHostSplitThresholdInKB" /t REG_DWORD /d "%ram%" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "DisableTaskOffload" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "AutoEndTasks" /t REG_SZ /d "1" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "HungAppTimeout" /t REG_SZ /d "1000" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "MenuShowDelay" /t REG_SZ /d "0" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "WaitToKillAppTimeout" /t REG_SZ /d "3000" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "LowLevelHooksTimeout" /t REG_SZ /d "1000" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control" /v "WaitToKillServiceTimeout" /t REG_SZ /d "2000" /f
reg.exe add "hklm\system\currentcontrolset\control\class\{de01174f-7fa8-4f81-8f82-bc6c84a39e47}\0000" /v "perflevelsrc" /t reg_dword /d "0x00002222" /f
reg.exe add "hklm\system\currentcontrolset\control\class\{de01174f-7fa8-4f81-8f82-bc6c84a39e47}\0000" /v "powermizerenable" /t reg_dword /d "00000001" /f
reg.exe add "hklm\system\currentcontrolset\control\class\{de01174f-7fa8-4f81-8f82-bc6c84a39e47}\0000" /v "powermizerlevel" /t reg_dword /d "00000001" /f
reg.exe add "hklm\system\currentcontrolset\control\class\{de01174f-7fa8-4f81-8f82-bc6c84a39e47}\0000" /v "powermizerlevelac" /t reg_dword /d "00000001" /f
reg.exe add "hklm\system\currentcontrolset\control\class\{de01174f-7fa8-4f81-8f82-bc6c84a39e47}\0000" /v "enablecoreslowdown" /t reg_dword /d "00000000" /f
reg.exe add "hklm\system\currentcontrolset\control\class\{de01174f-7fa8-4f81-8f82-bc6c84a39e47}\0000" /v "enablemclkslowdown" /t reg_dword /d "00000000" /f
reg.exe add "hklm\system\currentcontrolset\control\class\{de01174f-7fa8-4f81-8f82-bc6c84a39e47}\0000" /v "enablenvclkslowdown" /t reg_dword /d "00000000" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Serialize" /v "StartupDelayInMSec" /t REG_DWORD /d "3" /f

Reg.exe add "HKCU\Control Panel\Mouse" /v "MouseHoverTime" /t REG_SZ /d "0" /f
Reg.exe add "HKCU\Control Panel\Mouse" /v "MouseSensitivity" /t REG_SZ /d "10" /f
Reg.exe add "HKU\.DEFAULT\Control Panel\Mouse" /v "MouseSpeed" /t REG_SZ /d "0" /f
Reg.exe add "HKU\.DEFAULT\Control Panel\Mouse" /v "MouseThreshold1" /t REG_SZ /d "0" /f
Reg.exe add "HKU\.DEFAULT\Control Panel\Mouse" /v "MouseThreshold2" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\mouhid\Parameters" /v "TreatAbsolutePointerAsAbsolute" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\mouhid\Parameters" /v "TreatAbsoluteAsRelative" /t REG_DWORD /d "0" /f

Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "SystemResponsiveness" /t REG_SZ /d "00000000" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "NetworkThrottlingIndex" /t REG_SZ /d "fffffff" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Background Only" /t REG_SZ /d "False" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Clock Rate" /t REG_DWORD /d "10000" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "GPU Priority" /t REG_DWORD /d "8" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Priority" /t REG_DWORD /d "6" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Scheduling Category" /t REG_SZ /d "High" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "SFIO Priority" /t REG_SZ /d "High" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Latency Sensitive" /t REG_SZ /d "True" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "LocalPriority" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "HostsPriority" /t REG_DWORD /d "5" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "DnsPriority" /t REG_DWORD /d "6" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "NetbtPriority" /t REG_DWORD /d "7" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{de01174f-7fa8-4f81-8f82-bc6c84a39e47}\0000" /v "PerfLevelSrc" /t REG_DWORD /d "8738" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{de01174f-7fa8-4f81-8f82-bc6c84a39e47}\0000" /v "PowerMizerEnable" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{de01174f-7fa8-4f81-8f82-bc6c84a39e47}\0000" /v "PowerMizerLevel" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{de01174f-7fa8-4f81-8f82-bc6c84a39e47}\0000" /v "PowerMizerLevelAC" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling" /f
powercfg -devicedisablewake "HID-compliant mouse"
powercfg -devicedisablewake "HID keyboard Device"
powercfg -setactive "de01174f-7fa8-4f81-8f82-bc6c84a39e47"


echo.
echo.
echo.
echo Tweaking Steam priorities
echo.
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\gameoverlayui.exe\PerfOptions" /v CpuPriorityClass /t REG_DWORD /d 00000001 /f
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\gameoverlayui.exe\PerfOptions" /v IoPriority /t REG_DWORD /d 00000000 /f
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\steamservice.exe\PerfOptions" /v CpuPriorityClass /t REG_DWORD /d 00000001 /f
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\steamservice.exe\PerfOptions" /v IoPriority /t REG_DWORD /d 00000000 /f
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\steamwebhelper.exe\PerfOptions" /v CpuPriorityClass /t REG_DWORD /d 00000001 /f
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\steamwebhelper.exe\PerfOptions" /v IoPriority /t REG_DWORD /d 00000000 /f
echo.
echo The Registry integration error level is %ErrorLevel%
echo Finished!

echo.
echo.
echo.
echo disabling some services temporarily and stopping cortana + other shit
echo.
echo.
echo.
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\MapsBroker" /v Start /t REG_DWORD /d 00000004 /f
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\TermServicentVersion\Search" /v "AllowCortana" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v "DefaultReceiveWindow" /t REG_DWORD /d "16384" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v "DefaultSendWindow" /t REG_DWORD /d "16384" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v "FastCopyReceiveThreshold" /t REG_DWORD /d "16384" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v "FastSendDatagramThreshold" /t REG_DWORD /d "16384" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v "DynamicSendBufferDisable" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v "IgnorePushBitOnReceives" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v "NonBlockingSendSpecialBuffering" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v "DisableRawSecurity" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "BingSearchEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "CortanaEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "SearchboxTaskbarMode" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortana" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCloudSearch" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchUseWeb" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchUseWebOverMeteredConnections" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "DisableWebSearch" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowSearchToUseLocation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortanaAboveLock" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Speech_OneCore\Preferences" /v "ModelDownloadAllowed" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\InputPersonalization\TrainedDataStore" /v "HarvestContacts" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\InputPersonalization" /v "RestrictImplicitTextCollection" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\InputPersonalization" /v "RestrictImplicitInkCollection" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Personalization\Settings" /v "AcceptedPrivacyPolicy" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\ServiceUI" /v "EnableCortana" /t REG_DWORD /d "0" /f >nul
netsh advfirewall firewall add rule name="SearchUI.exe Telemetry" dir=out action=block program="%SystemRoot%\SystemApps\Microsoft.Windows.Cortana_cw5n1h2txyewy\SearchUI.exe"
echo.
echo.
echo.



echo disabling shit services..."
sc config FontCache start= demand
sc config CDPSvc start= demand
sc config OneSyncSvc start= disabled
sc config BcastDVRUserService start= disabled
sc config WSearch start= disabled
sc config TrkWks start= disabled
sc config ShellHWDetection start= demand
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\SharedAccess" /v Start /t REG_DWORD /d 00000004 /f
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\SEMgrSvc" /v Start /t REG_DWORD /d 00000004 /f
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\PhoneSvc" /v Start /t REG_DWORD /d 00000004 /f
sc config stisvc start= demand
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\SensorDataService" /v Start /t REG_DWORD /d 00000004 /f
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\SensrSvc" /v Start /t REG_DWORD /d 00000004 /f
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\SensorService" /v Start /t REG_DWORD /d 00000004 /f
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\RemoteRegistry" /v Start /t REG_DWORD /d 00000004 /f
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\HomeGroupListener" /v Start /t REG_DWORD /d 00000004 /f
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\HomeGroupProvider" /v Start /t REG_DWORD /d 00000004 /f
echo.
echo.
echo.

echo The Next process will begin soon...
Echo.
Echo.
Echo.
:optiz
set /P c=Do you want to customize your services? Script segment created by OptiZ Script (This may overwrite the previous service tweak fix)[Y/N]?
if /I "%c%" EQU "Y" goto :next3000
if /I "%c%" EQU "N" goto :no

goto :next

:next3000
Echo. [101;41mDisable Microsoft Xbox?:[0m
Echo. Press "Y" to apply.
Echo. Press "N" to skip.
Echo.
SET /P choice=  [101;42mY / N:[0m  
IF /I "%choice%"=="Y" goto apply
IF /I "%choice%"=="N" goto next
Echo.
:apply
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\XboxNetApiSvc" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\ApplicationManagement\AllowGameDVR" /v "value" /t REG_SZ /d "00000000" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\GameDVR" /v "AllowGameDVR" /t REG_SZ /d "0" /f
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\XblGameSave" /v "Start" /t REG_DWORD /d "4" /f
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\XblAuthManager" /v "Start" /t REG_DWORD /d "4" /f
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\xbgm" /v "Start" /t REG_DWORD /d "4" /f
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\XboxGipSvc" /v "Start" /t REG_DWORD /d "4" /f
Echo.
Echo. [101;41mThe services has been disabled.[0m

goto :next

:next
Echo. [101;41mDisable Telemetry and Diagnostics?:[0m
Echo. Press "Y" to apply.
Echo. Press "N" to skip.
Echo.
SET /P choice=  [101;42mY / N:[0m  
IF /I "%choice%"=="Y" goto apply
IF /I "%choice%"=="N" goto next
Echo.
:apply
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\DiagTrack" /v "Start" /t REG_DWORD /d "4" /f
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\diagsvc" /v "Start" /t REG_DWORD /d "4" /f
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\DPS" /v "Start" /t REG_DWORD /d "4" /f
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\WdiServiceHost" /v "Start" /t REG_DWORD /d "4" /f
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\WdiSystemHost" /v "Start" /t REG_DWORD /d "4" /f
reg.exe add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 00000000 /f
reg.exe add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 00000000 /f
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\dmwappushsvc" /v "Start" /t REG_DWORD /d "4" /f
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\diagnosticshub.standardcollector.service" /v "Start" /t REG_DWORD /d "4" /f
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\TroubleshootingSvc" /v "Start" /t REG_DWORD /d "4" /f
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\DsSvc" /v "Start" /t REG_DWORD /d "4" /f

Echo.
Echo. [101;41mThe services has been disabled.[0m

goto :next

:next
Echo. [101;41mDisable Windows Defender?:[0m
Echo. Press "Y" to apply.
Echo. Press "N" to skip.
Echo.
SET /P choice=  [101;42mY / N:[0m  
IF /I "%choice%"=="Y" goto apply
IF /I "%choice%"=="N" goto next
Echo.
:apply
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\Sense" /v "Start" /t REG_DWORD /d "4" /f
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\WdNisSvc" /v "Start" /t REG_DWORD /d "4" /f
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\WinDefend" /v "Start" /t REG_DWORD /d "4" /f
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\SamSs" /v "Start" /t REG_DWORD /d "4" /f
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\wscsvc" /v "Start" /t REG_DWORD /d "4" /f
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\SgrmBroker" /v "Start" /t REG_DWORD /d "4" /f
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\SecurityHealthService" /v "Start" /t REG_DWORD /d "4" /f
Echo.
Echo. [101;41mThe services has been disabled.[0m

goto :next

:next
Echo. [101;41mDisable Windows Firewall?:[0m
Echo. Press "Y" to apply.
Echo. Press "N" to skip.
Echo.
SET /P choice=  [101;42mY / N:[0m  
IF /I "%choice%"=="Y" goto apply
IF /I "%choice%"=="N" goto next
Echo.
:apply
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\mpssvc" /v "Start" /t REG_DWORD /d "4" /f
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\BFE" /v "Start" /t REG_DWORD /d "4" /f
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile" /v "EnableFirewall" /t REG_DWORD /d 00000000 /f
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile" /v "DoNotAllowExceptions" /t REG_DWORD /d 00000001 /f
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile" /v "EnableFirewall" /t REG_DWORD /d 00000000 /f
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile" /v "DoNotAllowExceptions" /t REG_DWORD /d 00000001 /f
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile" /v "EnableFirewall" /t REG_DWORD /d 00000000 /f
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile" /v "DoNotAllowExceptions" /t REG_DWORD /d 00000001 /f
Echo.
Echo. [101;41mThe services has been disabled.[0m

goto :next

:next
Echo. [101;41mDisable Hyper-V?:[0m
Echo. Press "Y" to apply.
Echo. Press "N" to skip.
Echo.
SET /P choice=  [101;42mY / N:[0m  
IF /I "%choice%"=="Y" goto apply
IF /I "%choice%"=="N" goto next
Echo.
:apply
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\HvHost" /v "Start" /t REG_DWORD /d "4" /f
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\vmickvpexchange" /v "Start" /t REG_DWORD /d "4" /f
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\vmicguestinterface" /v "Start" /t REG_DWORD /d "4" /f
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\vmicshutdown" /v "Start" /t REG_DWORD /d "4" /f
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\vmicheartbeat" /v "Start" /t REG_DWORD /d "4" /f
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\vmicvmsession" /v "Start" /t REG_DWORD /d "4" /f
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\vmicrdv" /v "Start" /t REG_DWORD /d "4" /f
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\vmictimesync" /v "Start" /t REG_DWORD /d "4" /f
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\vmicvss" /v "Start" /t REG_DWORD /d "4" /f
Echo.
Echo. [101;41mThe services has been disabled.[0m

goto :next

:next
Echo. [101;41mDisable Windows Error Reporting and Windows Push Notifications?:[0m
Echo. Press "Y" to apply.
Echo. Press "N" to skip.
Echo.
SET /P choice=  [101;42mY / N:[0m  
IF /I "%choice%"=="Y" goto apply
IF /I "%choice%"=="N" goto next
Echo.
:apply
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\WerSvc" /v "Start" /t REG_DWORD /d "4" /f
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\WpnService" /v "Start" /t REG_DWORD /d "4" /f
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\WpnUserService" /v "Start" /t REG_DWORD /d "4" /f
Echo.
Echo. [101;41mThe services has been disabled.[0m

goto :next

:next
Echo. [101;41mDisable Remote Desktop?:[0m
Echo. Press "Y" to apply.
Echo. Press "N" to skip.
Echo.
SET /P choice=  [101;42mY / N:[0m  
IF /I "%choice%"=="Y" goto apply
IF /I "%choice%"=="N" goto next
Echo.
:apply
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\RasMan" /v "Start" /t REG_DWORD /d "4" /f
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\TermService" /v "Start" /t REG_DWORD /d "4" /f
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\UmRdpService" /v "Start" /t REG_DWORD /d "4" /f
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\RemoteRegistry" /v "Start" /t REG_DWORD /d "4" /f
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\RpcLocator" /v "Start" /t REG_DWORD /d "4" /f
Echo.
Echo. [101;41mThe services has been disabled.[0m

goto :next

:next
Echo. [101;41mDisable Print?:[0m
Echo. Press "Y" to apply.
Echo. Press "N" to skip.
Echo.
SET /P choice=  [101;42mY / N:[0m  
IF /I "%choice%"=="Y" goto apply
IF /I "%choice%"=="N" goto next
Echo.
:apply
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\Fax" /v "Start" /t REG_DWORD /d "4" /f
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\Spooler" /v "Start" /t REG_DWORD /d "4" /f
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\PrintNotify" /v "Start" /t REG_DWORD /d "4" /f
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\PrintWorkflowUserSvc" /v "Start" /t REG_DWORD /d "4" /f
Echo.
Echo. [101;41mThe services has been disabled.[0m

goto :next

:next
Echo. [101;41mDisable Tablet support?:[0m
Echo. Press "Y" to apply.
Echo. Press "N" to skip.
Echo.
SET /P choice=  [101;42mY / N:[0m  
IF /I "%choice%"=="Y" goto apply
IF /I "%choice%"=="N" goto next
Echo.
:apply
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\TabletInputService" /v "Start" /t REG_DWORD /d "4" /f
Echo.
Echo. [101;41mThe services has been disabled.[0m

goto :next2

Echo.
Echo.
Echo.
Echo.
Echo.
Echo Services script by OptiZ Script has finished!
color 5
:next2
echo The next process will begin soon
color 5
:no
color 5
 
set /P c=Do you want to disable FSO globally? (sometimes a program will reenable it)[Y/N]?
if /I "%c%" EQU "Y" goto :fso
if /I "%c%" EQU "N" goto :next3
 

:fso
Reg.exe add "HKCU\System\GameConfigStore" /v "GameDVR_Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\System\GameConfigStore" /v "GameDVR_FSEBehaviorMode" /t REG_DWORD /d "2" /f
Reg.exe add "HKCU\System\GameConfigStore" /v "GameDVR_HonorUserFSEBehaviorMode" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\System\GameConfigStore" /v "GameDVR_DXGIHonorFSEWindowsCompatible" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\System\GameConfigStore" /v "GameDVR_EFSEFeatureFlags" /t REG_DWORD /d "0" /f
echo The Registry integration error level is %ErrorLevel%
echo FSO disabled attempt successful!
Echo.
Echo.
Echo.
:next3
echo Network optimization begins
ipconfig /release
ipconfig /renew
ipconfig /flushdns
netsh winsock reset catalog 
netsh winsock reset 
netsh int ip reset 
netsh int tcp reset  
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "NetworkThrottlingIndex" /t REG_SZ /d "fffffff" /f
netsh int tcp set supplemental internet congestionprovider=ctcp
Powershell.exe Set-NetTCPSetting -SettingName internet -AutoTuningLevelLocal normal
Powershell.exe Set-NetTCPSetting -SettingName internet -ScalingHeuristics disabled
powershell.exe Set-NetOffloadGlobalSetting -ReceiveSegmentCoalescing enabled
powershell.exe Set-NetOffloadGlobalSetting -ReceiveSideScaling enabled
powershell.exe Set-NetTCPSetting -SettingName internet -Timestamps disabled
powershell.exe Set-NetOffloadGlobalSetting -Chimney disabled
powershell.exe Set-NetTCPSetting -SettingName internet -EcnCapability disabled
powershell.exe Set-NetTCPSetting -SettingName internet -MaxSynRetransmissions 2
powershell.exe Set-NetTCPSetting -SettingName internet -NonSackRttResiliency disabled
powershell.exe Set-NetTCPSetting -SettingName internet -InitialRto 2000
powershell.exe Set-NetTCPSetting -SettingName internet -MinRto 300
netsh interface ipv4 add dnsserver "Local Area Connection" 1.1.1.1
netsh interface ipv6 add dnsserver "Local Area Connection" 2606:4700:4700::1111
netsh interface ipv4 add dnsserver "Wireless Network Connection" 1.0.0.1
netsh interface ipv6 add dnsserver "Wireless Network Connection" 2606:4700:4700::1001
netsh interface ipv4 set subinterface "Ethernet" mtu=1500 store=persistent
netsh interface ipv6 set subinterface "Ethernet" mtu=1500 store=persistent
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "MaxUserPort" /t REG_DWORD /d "65534" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "DisableTaskOffload" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TCPTimedWaitDelay" /t REG_DWORD /d "30" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "EnablePMTUDiscovery" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "EnablePMTUBHDetect" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "DefaultTTL" /t REG_DWORD /d "64" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{0A21087F-330E-485C-8E14-994C1F397879}" /v "TCPDelackTicks" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{0A21087F-330E-485C-8E14-994C1F397879}" /v "TCPNoDelay" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MAXCONNECTIONSPER1_0SERVER" /v "explorer.exe" /t REG_DWORD /d "10" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MAXCONNECTIONSPER1_0SERVER" /v "iexplore.exe" /t REG_DWORD /d "10" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Psched" /v "NonBestEffortLimit" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Psched" /v "MaxOutstandingSends" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MAXCONNECTIONSPERSERVER" /v "explorer.exe" /t REG_DWORD /d "10" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MAXCONNECTIONSPERSERVER" /v "iexplore.exe" /t REG_DWORD /d "10" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "DnsPriority" /t REG_DWORD /d "6" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "HostsPriority" /t REG_DWORD /d "5" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "LocalPriority" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "NetbtPriority" /t REG_DWORD /d "7" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "DelayedAckFrequency" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "DelayedAckTicks" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "CongestionAlgorithm" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "MultihopSets" /t REG_DWORD /d "15" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "FastCopyReceiveThreshold" /t REG_DWORD /d "16384" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "FastSendDatagramThreshold" /t REG_DWORD /d "16384" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\MSMQ\Parameters" /v "TCPNoDelay" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\NetBT" /v "Start" /t REG_DWORD /d "2" /f
netsh int ip set global taskoffload=disabled 
netsh int tcp set heuristics disabled 
netsh int tcp set global rss=enabled 
netsh int tcp show global
netsh int tcp set global rsc=disabled 
netsh int tcp set global timestamps=disabled 
netsh int tcp set global nonsackrttresiliency=disabled 
netsh int tcp set global maxsynretransmissions=2 
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\QoS" /v "Tcp Autotuning Level" /t REG_SZ /d "Off" /f
netsh int tcp set global ecncapability=enabled
netsh int tcp set global fastopen=enabled 
netsh int ip set global icmpredirects=disabled
netsh int tcp set security mpp=disabled profiles=disabled
netsh int ip set global multicastforwarding=disabled

Echo.
Echo.
Echo.
echo The next process will start soon...

 
set /P c=Do you use wifi? (DONT USE IF ETHERNET) This tries to fix a problem with wifi users. (Hard to troubleshoot because I use ethernet :p) [Y/N]?
if /I "%c%" EQU "Y" goto :WifiFix
if /I "%c%" EQU "N" goto :next98367
 

:WifiFix
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\WlanSvc" /v "Start" /t REG_DWORD /d "2" /f
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\WwanSvc" /v "Start" /t REG_DWORD /d "2" /f
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\NcaSvc" /v "Start" /t REG_DWORD /d "2" /f
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\NcbService" /v "Start" /t REG_DWORD /d "2" /f
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\NcdAutoSetup" /v "Start" /t REG_DWORD /d "2" /f
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\Netman" /v "Start" /t REG_DWORD /d "2" /f
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\netprofm" /v "Start" /t REG_DWORD /d "2" /f
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\NetSetupSvc" /v "Start" /t REG_DWORD /d "2" /f
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\NlaSvc" /v "Start" /t REG_DWORD /d "2" /f
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\nsi" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\CSC" /v "Start" /t REG_DWORD /d "2" /f
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\vwififlt" /v "Start" /t REG_DWORD /d "2" /f
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\NcaSvc" /v "Start" /t REG_DWORD /d "2" /f
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\wscsvc" /v "Start" /t REG_DWORD /d "2" /f
netsh interface set interface name="Wireless Network Connection" admin=ENABLED



:next98367
echo.
 
set /P c=Do you want to lower latency? (disables dynamic tick etc, platform tick etc.)[Y/N]?
if /I "%c%" EQU "Y" goto :tick100
if /I "%c%" EQU "N" goto :next45
 
echo.
echo.
echo.



:tick100
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "SystemResponsiveness" /t REG_DWORD /d "0" /f
start audl.exe 
echo Finished!
echo.
echo.
echo.
echo Then next process will begin soon...
echo.
echo.
echo.
:next45

echo Debloating useless packages (This may take some time. errors occur when package is missing... ignore them)
@powershell "Get-AppxPackage *3dbuilder* | Remove-AppxPackage"
@powershell "Get-AppxPackage *sway* | Remove-AppxPackage"
@powershell "Get-AppxPackage *messaging* | Remove-AppxPackage"
@powershell "Get-AppxPackage *zunemusic* | Remove-AppxPackage"
@powershell "Get-AppxPackage *windowsalarms* | Remove-AppxPackage"
@powershell "Get-AppxPackage *officehub* | Remove-AppxPackage"
@powershell "Get-AppxPackage *skypeapp* | Remove-AppxPackage"
@powershell "Get-AppxPackage *getstarted* | Remove-AppxPackage"
@powershell "Get-AppxPackage *windowsmaps* | Remove-AppxPackage"
@powershell "Get-AppxPackage *solitairecollection* | Remove-AppxPackage"
@powershell "Get-AppxPackage *bingfinance* | Remove-AppxPackage"
@powershell "Get-AppxPackage *zunevideo* | Remove-AppxPackage"
@powershell "Get-AppxPackage *bingnews* | Remove-AppxPackage"
@powershell "Get-AppxPackage *people* | Remove-AppxPackage"
@powershell "Get-AppxPackage *windowsphone* | Remove-AppxPackage"
@powershell "Get-AppxPackage *bingsports* | Remove-AppxPackage"
@powershell "Get-AppxPackage *soundrecorder* | Remove-AppxPackage"
@powershell "Get-AppxPackage *phone* | Remove-AppxPackage"
@powershell "Get-AppxPackage *windowsdvdplayer* | Remove-AppxPackage"
@powershell "GetAppxPackage -allusers *disney* | Remove-AppxPackage"
echo.
echo.
echo.
echo Preventing Data Collection and Telemetry 
Echo.
Echo.
Echo.
sc stop DiagTrack
net stop DiagTrack
sc config DiagTrack start= disabled
sc delete DiagTrack
sc config diagnosticshub.standardcollector.service start= disabled
net stop diagnosticshub.standardcollector.service > NUL 2>&1
takeown /f "%WinDir%\System32\smartscreen.exe" /a
icacls "%WinDir%\System32\smartscreen.exe" /grant:r Administrators:F /c
takeown /f "%WinDir%\System32\GameBarPresenceWriter.exe" /a
icacls "%WinDir%\System32\GameBarPresenceWriter.exe" /grant:r Administrators:F /c
takeown /f "%WinDir%\System32\mobsync.exe" /a
icacls "%WinDir%\System32\mobsync.exe" /grant:r Administrators:F /c
takeown /f "%WinDir%\System32\HelpPane.exe" /a
icacls "%WinDir%\System32\HelpPane.exe" /grant:r Administrators:F /c
TASKKILL /t /f /im smartscreen.exe > NUL 2>&1 
TASKKILL /t /f /im GameBarPresenceWriter.exe > NUL 2>&1 
TASKKILL /t /f /im mobsync.exe > NUL 2>&1 
TASKKILL /t /f /im HelpPane.exe > NUL 2>&1 
del "%WinDir%\System32\smartscreen.exe" /s /f /q > NUL 2>&1
del "%WinDir%\System32\GameBarPresenceWriter.exe" /s /f /q > NUL 2>&1
del "%WinDir%\System32\mobsync.exe" /s /f /q > NUL 2>&1
del "%WinDir%\System32\HelpPane.exe" /s /f /q > NUL 2>&1
takeown /f "c:\windows\system32\mcupdate_genuineintel.dll" /r /d y
takeown /f "c:\windows\system32\mcupdate_authenticamd.dll" /r /d y
del "c:\windows\system32\mcupdate_genuineintel.dll" /s /f /q
del "c:\windows\system32\mcupdate_authenticamd.dll" /s /f /q
Echo y| Reg.exe delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "NvBackend" > NUL
Echo.
Echo. smartscreen.exe Deleted
Echo.
Echo. GameBarPresenceWriter.exe Deleted
Echo.
Echo. mobsync.exe Deleted
Echo.
Echo. HelpPane.exe Deleted
Echo.
Echo. NvBackend Stopped if exist 
Echo.
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\AutoLogger\AutoLogger-Diagtrack-Listener" /v "Start" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\WindowsSelfHost\UI\Visibility" /v "DiagnosticErrorText" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\WindowsSelfHost\UI\Strings" /v "DiagnosticErrorText" /t REG_SZ /d "" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\WindowsSelfHost\UI\Strings" /v "DiagnosticLinkText" /t REG_SZ /d "" /f
Reg.exe add "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\PhishingFilter" /v "EnabledV9" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\TabletPC" /v "PreventHandwritingDataSharing" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports" /v "PreventHandwritingErrorReports" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "DisableInventory" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "DisableUAR" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization" /v "NoLockScreenCamera" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Input\TIPC" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\System" /v "AllowExperimentation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\Bluetooth" /v "AllowAdvertising" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\SQMClient\Windows" /v "CEIPEnable" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Messaging" /v "AllowMessageSync" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Biometrics" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Control Panel\International\User Profile" /v "HttpAcceptLanguageOptOut" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\AppHost" /v "EnableWebContentEvaluation" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{C1D23ACC-752B-43E5-8448-8D0E519CD6D6}" /v "Value" /t REG_SZ /d "Deny" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_TrackProgs" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowSyncProviderNotifications" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{2297E4E2-5DBE-466D-A12B-0F8286F0D9CA}" /v "Value" /t REG_SZ /d "Deny" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{E5323777-F976-4f5b-9B55-B94699C46E44}" /v "Value" /t REG_SZ /d "Deny" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{2EEF81BE-33FA-4800-9670-1CD474972C3F}" /v "Value" /t REG_SZ /d "Deny" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{52079E78-A92B-413F-B213-E8FE35712E72}" /v "Value" /t REG_SZ /d "Deny" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{7D7E8402-7C54-4821-A34E-AEEFD62DED93}" /v "Value" /t REG_SZ /d "Deny" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{D89823BA-7180-4B81-B50C-7E471E6121A3}" /v "Value" /t REG_SZ /d "Deny" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{8BC668CF-7728-45BD-93F8-CF2B3B41D7AB}" /v "Value" /t REG_SZ /d "Deny" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{9231CB4C-BF57-4AF3-8C55-FDA7BFCC04C5}" /v "Value" /t REG_SZ /d "Deny" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{E390DF20-07DF-446D-B962-F5C953062741}" /v "Value" /t REG_SZ /d "Deny" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{992AFA70-6F47-4148-B3E9-3003349C1548}" /v "Value" /t REG_SZ /d "Deny" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /v "GlobalUserDisabled" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\DiagTrack" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\dmwappushservice" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\WMI\Autologger\AutoLogger-Diagtrack-Listener" /v "Start" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WMDRM" /v "DisableOnline" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{A8804298-2D5F-42E3-9531-9C8C39EB29CE}" /v "Value" /t REG_SZ /d "Deny" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\LooselyCoupled" /v "Value" /t REG_SZ /d "Deny" /f
Reg.exe add "HKLM\Software\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform" /v "NoGenTicket" /t "REG_DWORD" /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\Browser" /v "AllowAddressBarDropdown" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\Privacy" /v "EnableEncryptedMediaExtensions" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync" /v "SyncPolicy" /t REG_DWORD /d "5" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Personalization" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\BrowserSettings" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Credentials" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Language" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Accessibility" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\AppSync" /v Enabled /t REG_DWORD /d 0 /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\StartLayout" /v Enabled /t REG_DWORD /d 0 /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Windows" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCloudSearch" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchUseWeb" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "DisableWebSearch" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowSearchToUseLocation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortana" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Speech_OneCore\Preferences" /v "ModelDownloadAllowed" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\InputPersonalization\TrainedDataStore" /v "HarvestContacts" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\InputPersonalization" /v "RestrictImplicitTextCollection" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\InputPersonalization" /v "RestrictImplicitInkCollection" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Personalization\Settings" /v "AcceptedPrivacyPolicy" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableWindowsLocationProvider" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableLocationScripting" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Sensor\Permissions\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" /v "SensorPermissionState" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "DoNotShowFeedbackNotifications" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "MaxTelemetryAllowed" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" /v "DODownloadMode" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization" /v "SystemSettingsDownloadMode" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Speech" /v "AllowSpeechModelUpdate" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "DeferUpgrade" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "DeferUpgradePeriod" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "DeferUpdatePeriod" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsStore\WindowsUpdate" /v "AutoDownload" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "NoAutoUpdate" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\SettingSync" /v "DisableSettingSync" /t "REG_DWORD" /d "2" /f
Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\SettingSync" /v "DisableSettingSyncUserOverride" /t "REG_DWORD" /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v "SpyNetReporting" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v "SubmitSamplesConsent" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\MRT" /v "DontReportInfectionInformation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\MRT" /v "DontOfferThroughWUAU" /t "REG_DWORD" /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "BingSearchEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SilentInstalledAppsEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SoftLandingEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\ScheduledDiagnostics" /v "EnabledExecution" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\OneDrive" /v "PreventNetworkTrafficPreUserSignIn" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\Experience" /v "AllowCortana" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\Experience" /v "AllowTailoredExperiencesWithDiagnosticData" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\System\CurrentControlSet\Control\WMI\Autologger\DefenderApiLogger" /v "Start" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\System\CurrentControlSet\Control\WMI\Autologger\DefenderAuditLogger" /v "Start" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" /v "EnableVirtualizationBasedSecurity" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" /v "HVCIMATRequired" /t REG_DWORD /d "0" /f


echo.
echo.
echo.
echo Finished prevention of Data Collection and Telemetry!
echo.
echo.
echo.
set /P c=Would you like Tweaks provided by Melody? (Highly reccomend, includes per system device tweaks and more).[Y/N]?
if /I "%c%" EQU "Y" goto :melody
if /I "%c%" EQU "N" goto :gpucpuetx
:melody
powershell Set-ProcessMitigation -System -Disable DEP,EmulateAtlThunks,ForceRelocateImages,RequireInfo,BottomUp,HighEntropy,StrictHandle,DisableWin32kSystemCalls,AuditSystemCall,DisableExtensionPoints,BlockDynamicCode,AllowThreadsToOptOut,AuditDynamicCode,CFG,SuppressExports,StrictCFG,MicrosoftSignedOnly,AllowStoreSignedBinaries,AuditMicrosoftSigned,AuditStoreSigned,EnforceModuleDependencySigning,DisableNonSystemFonts,AuditFont,BlockRemoteImageLoads,BlockLowLabelImageLoads,PreferSystem32,AuditRemoteImageLoads,AuditLowLabelImageLoads,AuditPreferSystem32,EnableExportAddressFilter,AuditEnableExportAddressFilter,EnableExportAddressFilterPlus,AuditEnableExportAddressFilterPlus,EnableImportAddressFilter,AuditEnableImportAddressFilter,EnableRopStackPivot,AuditEnableRopStackPivot,EnableRopCallerCheck,AuditEnableRopCallerCheck,EnableRopSimExec,AuditEnableRopSimExec,SEHOP,AuditSEHOP,SEHOPTelemetry,TerminateOnError,DisallowChildProcessCreation,AuditChildProcess
powershell Disable-MMAgent -MemoryCompression -ApplicationPreLaunch

:gpucpuetx
echo Tweaking GPU, CPU, power and other Processes
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" /v "Affinity" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" /v "Background Only" /t REG_SZ /d "True" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" /v "BackgroundPriority" /t REG_DWORD /d "24" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" /v "Clock Rate" /t REG_DWORD /d "10000" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" /v "GPU Priority" /t REG_DWORD /d "18" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" /v "Priority" /t REG_DWORD /d "8" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" /v "Scheduling Category" /t REG_SZ /d "High" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" /v "SFIO Priority" /t REG_SZ /d "High" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" /v "Latency Sensitive" /t REG_SZ /d "True" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "TdrLevel" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "AlwaysOn" /t REG_DWORD /d "1" /f

Reg.exe add "HKLM\SOFTWARE\Microsoft\Direct3D" /v "DisableVidMemVBs" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Direct3D" /v "MMX Fast Path" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Direct3D" /v "FlipNoVsync" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Direct3D\Drivers" /v "SoftwareOnly" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "NoLazyMode" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Psched" /v "TimerResolution" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio" /v "Affinity" /t REG_DWORD /d "7" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio" /v "Background Only" /t REG_SZ /d "True" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio" /v "Clock Rate" /t REG_DWORD /d "10000" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio" /v "GPU Priority" /t REG_DWORD /d "8" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio" /v "Priority" /t REG_DWORD /d "6" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio" /v "Scheduling Category" /t REG_SZ /d "Medium" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio" /v "SFIO Priority" /t REG_SZ /d "Normal" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Affinity" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Background Only" /t REG_SZ /d "False" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Clock Rate" /t REG_DWORD /d "10000" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "GPU Priority" /t REG_DWORD /d "18" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Priority" /t REG_DWORD /d "6" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Scheduling Category" /t REG_SZ /d "High" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "SFIO Priority" /t REG_SZ /d "High" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "EnergyEstimationEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "CsEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "EnergyEstimationEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "PerfCalculateActualUtilization" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "SleepReliabilityDetailedDiagnostics" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "EventProcessorEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "QosManagesIdleProcessors" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "DisableVsyncLatencyUpdate" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "DisableSensorWatchdog" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "ExitLatencyCheckEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling" /v "PowerThrottlingOff" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Input\Settings\ControllerProcessor\CursorMagnetism" /v "MagnetismUpdateIntervalInMilliseconds" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Input\Settings\ControllerProcessor\CursorSpeed" /v "CursorUpdateInterval" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Reliability" /v "TimeStampInterval" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\DWM" /v "CompositionPolicy" /t REG_DWORD /d "0" /f

Reg.exe add "HKCU\Control Panel\Desktop" /v "WaitToKillAppTimeout" /t REG_SZ /d "5000" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "LowLevelHooksTimeout" /t REG_SZ /d "5000" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "HungAppTimeout" /t REG_SZ /d "5000" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "MenuShowDelay" /t REG_SZ /d "0" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "MouseWheelRouting" /t REG_DWORD /d "0" /f
echo.
echo.
echo.
set /P c=Do you have windows installed on a ssd? (if yes trim will be enabled)
if /I "%c%" EQU "Y" goto :ssd!
if /I "%c%" EQU "N" goto :Hw23

:ssd!
fsutil behavior set disabledeletenotify 0
 
:Hw23
set /P c=Would you like BCDedit tweaks? (Would reccomend as long as you have done your research).[Y/N]?
if /I "%c%" EQU "Y" goto :bcdedit67
if /I "%c%" EQU "N" goto :next766
 
echo.
:bcdedit67
echo.
bcdedit /set useplatformclock No
bcdedit /set useplatformtick No
bcdedit /set disabledynamictick Yes
bcdedit /set bootmenupolicy Legacy
bcdedit /set debug No
bcdedit /set isolatedcontext No
bcdedit /set pae ForceEnable
bcdedit /set bootux disabled
bcdedit /set sos Yes
bcdedit /set ems No
bcdedit /set hypervisorlaunchtype off
bcdedit /set nx optout
bcdedit /set quietboot yes
bcdedit /timeout 3
bcdedit /set uselegacyapicmode no
bcdedit /set usefirmwarepcisettings No
bcdedit /set tscsyncpolicy Enhanced
bcdedit /set x2apicpolicy Enable
bcdedit /set usephysicaldestination No
echo.
echo.
echo.
:next766

echo Finished Main Processes, beginning Post Process/Wrap-Up
echo.
echo.
echo.
echo Cleaning temp
echo.
del /s /f /q c:\windows\temp\*.*
rd /s /q c:\windows\temp
md c:\windows\temp
del /s /f /q C:\WINDOWS\Prefetch
del /s /f /q %temp%\*.*
rd /s /q %temp%
md %temp%
del c:\WIN386.SWP
del /s /f /q %WinDir%\temp\*.*
del /s /f /q %WinDir%\Prefetch\*.*
del /s /f /q %Temp%\*.*
del /s /f /q %AppData%\temp\*.*
del /s /f /q %HomePath%\AppData\LocalLow\temp\*.*
rd /s /q %WinDir%\temp
rd /s /q %WinDir%\Prefetch
rd /s /q %Temp%
rd /s /q %AppData%\temp
rd /s /q %HomePath%\AppData\LocalLow\temp
md %WinDir%\temp
md %WinDir%\Prefetch
md %Temp%
md %AppData%\temp
md %HomePath%\AppData\LocalLow\temp
echo.
echo Temp Clean Finished!

echo Checking System Integrity and Repairs. This may take long
cleanmgr /autoclean
sfc /scannow
dism /online /cleanup-image /startcomponentcleanup /resetbase /defer
dism /Online /Cleanup-image /Restorehealth
diskperf -N
echo.
echo.
echo.
echo ------------------------------------------------------
echo Process Complete! RESTART YOUR COMPUTER :)
echo 
echo Created with blood, sweat and tears by Zusier (Zusier#0834 on Discord)
PAUSE
echo.
exit