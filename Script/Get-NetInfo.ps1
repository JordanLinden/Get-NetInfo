# Get-NetInfo
# Version 1.0
# List current TCP/IP network connections on a host with associated process information

# Jordan Linden @https://github.com/JordanLinden
# 04 Jun 2023

# Disclaimer: This script is not production-ready. Use at your own risk.


Param(
    [string]$proto = "TCP",
    [switch]$resolveNames = $false,
    [switch]$consoleOut = $false,
    [switch]$help = $false
)

$Banner = "`nGet-NetInfo v1.0 - List network connections on a host with associated process information"
$Banner += "`nCreated by Jordan Linden"
$Banner += "`nhttps://github.com/JordanLinden`n"

Write-Host $Banner

function showHelp {
    Write-Host "`nDESCRIPTION:"
    Write-Host "    Get-NetInfo v1.0"
    Write-Host "    Author: Jordan Linden"
    
    $desc = "`n    Output to grid view all listening/established TCP connections with associated process information, or simply output UDP connections"
    Write-Host $desc
    
    Write-Host "`nOPTIONS:"
    Write-Host "           proto - show network connections for a given protocol"
    Write-Host "                 - [options: TCP, UDP]"
    Write-Host "                 - [default: TCP]"
    Write-Host "    resolveNames - reverse DNS lookup, translate IP addresses to hostnames (significantly slower)"
    Write-Host "                 - type switch"
    Write-Host "                 - [default: false]"
    Write-Host "      consoleOut - output results to console as well"
    Write-Host "                 - type switch"
    Write-Host "                 - [default: false]"
    Write-Host "            help - display this help menu"
    Write-Host "                 - type switch"
    Write-Host "                 - [default: false]"
    Write-Host "`n"
}

if ($help) {
    showHelp
    return
}


if ($proto.ToUpper() -eq "TCP") {
    $states = @(
        "Listen"
        "Established"
    )
    
    $fields = @(
        "LocalAddress"
        "LocalPort"
        "RemoteAddress"
        "RemotePort"
        "State"
        "ProcessID"
        "ProcessName"
        "ProcessPath"
        "User"
    )
    
    if ($resolveNames) {$fields = $fields -Replace 'RemoteAddress','RemoteHost'}
    
    Get-NetTCPConnection -State $states | ForEach-Object {
        if (($resolveNames) -and ($_.RemoteAddress -ne "0.0.0.0")) {
            $hostName = (Resolve-DnsName $_.RemoteAddress -ea SilentlyContinue).NameHost | % {if ($_) { $_.replace('.','[.]')}}
            Add-Member -InputObject $_ -NotePropertyName "RemoteHost" -NotePropertyValue $hostName
        }
        
        $processInfo = Get-Process -IncludeUserName -Id $_.OwningProcess | Select ID, ProcessName, Path, Username
        
        Add-Member -InputObject $_ -NotePropertyName "ProcessID" -NotePropertyValue $([string]$processInfo.ID)
        Add-Member -InputObject $_ -NotePropertyName "ProcessName" -NotePropertyValue $processInfo.ProcessName
        Add-Member -InputObject $_ -NotePropertyName "ProcessPath" -NotePropertyValue $processInfo.Path
        Add-Member -InputObject $_ -NotePropertyName "User" -NotePropertyValue $processInfo.Username
        
        $_
    } | Select-Object -Property $fields | Tee-Object -Variable results |
    Out-GridView -Title "$env:computername TCP Network Connections"
} elseif ($proto.ToUpper() -eq "UDP") {
    Get-NetUDPEndpoint | Tee-Object -Variable results |
    Out-GridView -Title "$env:computername UDP Network Connections"
}

if ($consoleOut) {$results | Format-Table | Out-String -Width 4096}
