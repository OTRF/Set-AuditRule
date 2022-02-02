Invoke-Expression (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/OTRF/Set-AuditRule/master/Set-AuditRule.ps1')

$AuditRules = @"
regKey;wellKnownSidType;rights;inheritanceFlags;propagationFlags;auditFlags
"HKLM:\SYSTEM\CurrentControlSet\Control\CloudDomainJoin";"WorldSid";"ReadKey";"ContainerInherit";"InheritOnly";"Success"
"@

write-host "Enabling audit rules.."
$AuditRules | ConvertFrom-Csv -Delimiter ';' | ForEach-Object {
    if(!(Test-Path $_.regKey)){
        Write-Host $_.regKey " does not exist.."
    }
    else {
        Write-Host "Updating SACL of " $_.regKey
        Set-AuditRule -RegistryPath $_.regKey -WellKnownSidType $_.wellKnownSidType -Rights $_.rights.split(",") -InheritanceFlags $_.inheritanceFlags -PropagationFlags $_.propagationFlags -AuditFlags $_.auditFlags -ErrorAction SilentlyContinue
    }
}