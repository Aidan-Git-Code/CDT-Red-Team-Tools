reg add HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f
auditpol /set /subcategory:"Process Creation" /success:enable
Register-ScheduledTask -TaskName "FirewallOpenedTrigger4" `
    -Xml (Get-Content "C:\PATH\KillonPowershellTrigger.xml" | Out-String) `
    -User "SYSTEM"
