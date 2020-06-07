# Winlogon

Adversaries might query HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon for Registry Auto-logon Settings.

## Adversary Actions

Query

## Set Audit Rule

```
Set-AuditRule -RegistryPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -IdentityReference Everyone -Rights QueryValues -InheritanceFlags None -PropagationFlags None -AuditFlags Success
```

## Event Occurrence

Medium

## Notes

* TPAutoConnect (vmware) from time to time

## Object Properties

```
PS C:\Tools\scripts> Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'

AutoRestartShell             : 1
Background                   : 0 0 0
CachedLogonsCount            : 10
DebugServerCommand           : no
DisableBackButton            : 1
EnableSIHostIntegration      : 1
ForceUnlockLogon             : 0
LegalNoticeCaption           : 
LegalNoticeText              : 
PasswordExpiryWarning        : 5
PowerdownAfterShutdown       : 0
PreCreateKnownFolders        : {A520A1A4-1780-4FF6-BD18-167343C5AF16}
ReportBootOk                 : 1
Shell                        : explorer.exe
ShellCritical                : 0
ShellInfrastructure          : sihost.exe
SiHostCritical               : 0
SiHostReadyTimeOut           : 0
SiHostRestartCountLimit      : 0
SiHostRestartTimeGap         : 0
VMApplet                     : SystemPropertiesPerformance.exe /pagefile
WinStationsDisabled          : 0
scremoveoption               : 0
LastLogOffEndTimePerfCounter : 1760355028
ShutdownFlags                : 7
Userinit                     : C:\Windows\system32\userinit.exe,
DisableCad                   : 1
DisableLockWorkstation       : 0
EnableFirstLogonAnimation    : 1
AutoLogonSID                 : S-1-5-21-3825400013-1856045589-1834093677-1001
LastUsedUsername             : wardog
DefaultUserName              : wardog
DefaultDomainName            : .
AutoAdminLogon               : 0
PSPath                       : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon
PSParentPath                 : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion
PSChildName                  : Winlogon
PSDrive                      : HKLM
PSProvider                   : Microsoft.PowerShell.Core\Registry

```

## Object Security Descriptor

```
PS C:\Tools\scripts> Get-Acl -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Audit | fl

Path   : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon
Owner  : NT AUTHORITY\SYSTEM
Group  : NT AUTHORITY\SYSTEM
Access : NT SERVICE\TrustedInstaller Allow  FullControl
         NT SERVICE\TrustedInstaller Allow  268435456
         NT AUTHORITY\SYSTEM Allow  FullControl
         NT AUTHORITY\SYSTEM Allow  268435456
         BUILTIN\Administrators Allow  FullControl
         BUILTIN\Administrators Allow  268435456
         BUILTIN\Users Allow  ReadKey
         BUILTIN\Users Allow  -2147483648
         APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES Allow  ReadKey
         APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES Allow  -2147483648
         S-1-15-3-1024-1065365936-1281604716-3511738428-1654721687-432734479-3232135806-4053264122-3456934681 Allow  ReadKey
         S-1-15-3-1024-1065365936-1281604716-3511738428-1654721687-432734479-3232135806-4053264122-3456934681 Allow  -2147483648
Audit  : 
Sddl   : O:SYG:SYD:AI(A;ID;KA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;CIIOID;GA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;ID;KA;;;SY)(A;C
         IIOID;GA;;;SY)(A;ID;KA;;;BA)(A;CIIOID;GA;;;BA)(A;ID;KR;;;BU)(A;CIIOID;GR;;;BU)(A;ID;KR;;;AC)(A;CIIOID;GR;;;AC)(A;ID;KR;;;S-1-15-3-1024-1065365936-1281604716-3511738428-1654721687-432
         734479-3232135806-4053264122-3456934681)(A;CIIOID;GR;;;S-1-15-3-1024-1065365936-1281604716-3511738428-1654721687-432734479-3232135806-4053264122-3456934681)S:AI
```

## Object Default Events

<img src="https://github.com/Cyb3rWard0g/Set-AuditRule/blob/master/images/winlogon-service-networkservice.png" alt="Event 4663 user" width="625" height="625">

<img src="https://github.com/Cyb3rWard0g/Set-AuditRule/blob/master/images/winlogon-service-localservice.png" alt="Event 4663 user" width="625" height="625">

<img src="https://github.com/Cyb3rWard0g/Set-AuditRule/blob/master/images/winlogon-tpautoconnect-user.png" alt="Event 4663 user" width="625" height="625">