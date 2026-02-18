<#.AUTHOR
Nathan Russell (russell.nw@mail.rit.edu)
#>

param (
    [int] $WatcherPID = 0,
    [switch] $WatchdogTriggered,
    
    [int] $ClockRate = 10,
    [int] $UpdateRate = 600
)

$Self = $MyInvocation.MyCommand.ScriptBlock.ToString()
$SelfPID = $PID

$SharedData = [hashtable]::Synchronized(@{
        WatchdogTriggered     = $WatchdogTriggered
        CurrentKeyboardLayout = $(Get-WinUserLanguageList)[0].InputMethodTips[0]

        ClockRate             = $ClockRate
        UpdateRate            = $UpdateRate

        EasyKeyboardLayouts   = @{
            "US_DVORAK"       = "0409:00010409"
            "US_DVORAK_LEFT"  = "0409:00030409"
            "US_DVORAK_RIGHT" = "0409:00040409"
            "FR_AZERTY"       = "0409:0000040C"
            "LV"              = "0409:00000426"
        }
        HardKeyboardLayouts   = @{
            "SYC" = "0409:0000045A"
        }
    })

function Invoke-ShuffleJob {
    <#.SYNOPSIS
    Create a thread that triggers a keyboard layout change if time has passed or watchdog is triggered
    #>
    return Start-ThreadJob -ArgumentList $SharedData -ScriptBlock {
        param($Data)
        $Timer = [System.Diagnostics.Stopwatch]::StartNew()
        while ($true) {
            Start-Sleep -Seconds $Data.ClockRate
            [System.Threading.Monitor]::Enter($Data.SyncRoot)

            # Check watchdog/timer triggers, skip if not triggered
            if ($Data.WatchdogTriggered) {
                [System.Console]::WriteLine("[$(Get-Date)] NOTICE / Watchdog triggered, selecting keyboard layout from hard list.")
                $LayoutSet = $Data.HardKeyboardLayouts
                $Data.WatchdogTriggered = $false
            }
            elseif ($Timer.Elapsed.Seconds -gt $Data.UpdateRate) {
                [System.Console]::WriteLine("[$(Get-Date)] NOTICE / Timer triggered, selecting keyboard layout from easy list.")
                $LayoutSet = $Data.EasyKeyboardLayouts
            }
            else {
                [System.Threading.Monitor]::Exit($Data.SyncRoot)
                continue
            }
            $Timer.Restart()

            # Get and set keyboard layout from random layout in set
            $NewLayout = $($LayoutSet.GetEnumerator() | Get-Random -Count 1).Value
            try {
                $Layout = Get-WinUserLanguageList
                $Layout[0].InputMethodTips[0] = $NewLayout
                Set-WinUserLanguageList -LanguageList $Layout -Force
                $Data.CurrentKeyboardLayout = $NewLayout
                [System.Console]::WriteLine("[$(Get-Date)] SUCCESS / Set keyboard layout to $NewLayout")
            }
            catch {
                [System.Console]::WriteLine("[$(Get-Date)] FAILURE / Failed to set keyboard layout")
            }

            [System.Threading.Monitor]::Exit($Data.SyncRoot)
        }
    }
}

function Invoke-MonitorJob {
    <#.SYNOPSIS
    Creates a thread to trigger watchdog when unexpected keyboard layout changes are detected
    #>
    return Start-ThreadJob -ArgumentList $SharedData -ScriptBlock {
        param($Data)
        while ($true) {
            Start-Sleep -Seconds $($Data.ClockRate / 5)
            [System.Threading.Monitor]::Enter($Data.SyncRoot)
            
            # Check if keyboard layout was changed and trigger watchdog
            if ($Data.CurrentKeyboardLayout -ne $(Get-WinUserLanguageList)[0].InputMethodTips[0] -and !$Data.WatchdogTriggered) {
                [System.Console]::WriteLine("[$(Get-Date)] NOTICE / Language changed unexpectedly.")
                $Data.WatchdogTriggered = $true
            }
            
            [System.Threading.Monitor]::Exit($Data.SyncRoot)
        }
    }
}

function Invoke-Main {
    # Install ThreadJob module if not present
    if ($null -eq $(Get-Command -ErrorAction Ignore -Type Cmdlet Start-ThreadJob)) {
        Write-Host "[$(Get-Date)] NOTICE / ThreadJobs module not detected, installing ..."
        Install-Module -Scope CurrentUser ThreadJob -Force -ErrorAction Ignore
        Write-Host "[$(Get-Date)] SUCCESS / ThreadJobs module installed."
    }

    # Start process to watch if WatcherPID is not passed in or get watcher process
    if ($WatcherPID -eq 0) {
        Write-Host "[$(Get-Date)] INFO / WatcherPID not set, executing as watcher process ..."
        $EncodedSelf = [System.Convert]::ToBase64String(
            [System.Text.Encoding]::Unicode.GetBytes("& { $Self } -WatcherPID $SelfPID -ClockRate $ClockRate -UpdateRate $UpdateRate")
        )
        $PartnerProcess = Start-Process powershell.exe -WindowStyle Hidden -PassThru -ArgumentList "-EncodedCommand `"$EncodedSelf`""
        Write-Host "[$(Get-Date)] SUCCESS / Created new shuffler process."
    }
    else {
        Write-Host "[$(Get-Date)] INFO / WatcherPID set, executing as shuffler process ..."
        try {
            $PartnerProcess = Get-Process -Id $WatcherPID -ErrorAction Stop
            Write-Host "[$(Get-Date)] SUCCESS / Got watcher process."
            $null = Invoke-MonitorJob
            Write-Host "[$(Get-Date)] SUCCESS / Started monitoring ThreadJob."
            $null = Invoke-ShuffleJob
            Write-Host "[$(Get-Date)] SUCCESS / Started shuffling ThreadJob."
        }
        catch {
            Write-Host "[$(Get-Date)] FAILURE / Failed to get watcher process."

            Write-Host "[$(Get-Date)] INFO / Converting to watcher process ..."
            $WatcherPID = 0
            Write-Host "[$(Get-Date)] SUCCESS / Converted to watcher process."
            $EncodedSelf = [System.Convert]::ToBase64String(
                [System.Text.Encoding]::Unicode.GetBytes("& { $Self } -WatcherPID $SelfPID -ClockRate $ClockRate -UpdateRate $UpdateRate")
            )
            $PartnerProcess = Start-Process powershell.exe -WindowStyle Hidden -PassThru -ArgumentList "-EncodedCommand `"$EncodedSelf`""
            Write-Host "[$(Get-Date)] SUCCESS / Created new shuffler process."
        }
    }

    # Wait for partner process to exit and create new partner on exit
    while ($true) {
        Write-Host "[$(Get-Date)] INFO / Now watching partner process."
        $PartnerProcess.WaitForExit()
        if ($WatcherPID -eq 0) {
            Write-Host "[$(Get-Date)] NOTICE / Shuffler process exited, starting new shuffler process ..."
        }
        else {
            Write-Host "[$(Get-Date)] NOTICE / Watcher process exited, converting to watcher process and creating new shuffler process ..."
            $WatcherPID = 0
            Write-Host "[$(Get-Date)] SUCCESS / Converted to watcher process."
        }
        $EncodedSelf = [System.Convert]::ToBase64String(
            [System.Text.Encoding]::Unicode.GetBytes("& { $Self } -WatcherPID $SelfPID -ClockRate $ClockRate -UpdateRate $UpdateRate -WatchdogTriggered")
        )
        $PartnerProcess = Start-Process powershell.exe -WindowStyle Hidden -PassThru -ArgumentList "-EncodedCommand `"$EncodedSelf`""
        Write-Host "[$(Get-Date)] SUCCESS / Created new shuffler process."
    }
}

Invoke-Main
