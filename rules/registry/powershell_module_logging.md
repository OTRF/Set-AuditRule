# PowerShell Module Logging

Adversaries might query HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging for PowerShell Module Logging settings.

## Adversary Actions

Query

## Set Audit Rule

```
Set-AuditRule -RegistryPath HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging -IdentityReference Everyone -Rights QueryValues -InheritanceFlags None -PropagationFlags None -AuditFlags Success
```

## Event Occurrence

Low

## Notes

Registry key annd property set by default

## Object Properties

```
PS C:\Tools\scripts> Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging

EnableModuleLogging : 1
PSPath              : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging
PSParentPath        : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell
PSChildName         : ModuleLogging
PSDrive             : HKLM
PSProvider          : Microsoft.PowerShell.Core\Registry
```

## Object Security Descriptor

```
PS C:\Tools\scripts> get-acl -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging -Audit | fl

Path   : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging
Owner  : NT AUTHORITY\SYSTEM
Group  : NT AUTHORITY\SYSTEM
Access : NT AUTHORITY\Authenticated Users Allow  ReadKey
         NT AUTHORITY\Authenticated Users Allow  -2147483648
         NT AUTHORITY\SYSTEM Allow  FullControl
         NT AUTHORITY\SYSTEM Allow  268435456
         BUILTIN\Administrators Allow  FullControl
         BUILTIN\Administrators Allow  268435456
         APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES Allow  ReadKey
         APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES Allow  -2147483648
         S-1-15-3-1024-1065365936-1281604716-3511738428-1654721687-432734479-3232135806-4053264122-3456934681 Allow  ReadKey
         S-1-15-3-1024-1065365936-1281604716-3511738428-1654721687-432734479-3232135806-4053264122-3456934681 Allow  -2147483648
Audit  : 
Sddl   : O:SYG:SYD:AI(A;ID;KR;;;AU)(A;OICIIOID;GR;;;AU)(A;ID;KA;;;SY)(A;OICIIOID;GA;;;SY)(A;ID;KA;;;BA)(A;OICIIOID;GA;;;BA)(A;ID;KR;;;AC)(A;OICIIOID;GR;;;AC)(A;ID;KR;;;S-1-15-3-1024-106536593
         6-1281604716-3511738428-1654721687-432734479-3232135806-4053264122-3456934681)(A;OICIIOID;GR;;;S-1-15-3-1024-1065365936-1281604716-3511738428-1654721687-432734479-3232135806-40532641
         22-3456934681)S:AI
```

## Object Default Events
