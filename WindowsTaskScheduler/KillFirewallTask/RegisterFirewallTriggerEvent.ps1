Register-ScheduledTask -TaskName "FirewallOpenedTrigger" `
    -Xml (Get-Content "C:\Temp\FirewallTriggerEvent.xml" | Out-String) `
    -User "SYSTEM"
