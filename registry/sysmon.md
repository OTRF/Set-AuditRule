# Sysmon

Adversaries might query for Sysmon configurations.

# Adversary Actions

Query

## Set Audit Rule

```
Set-AuditRule -RegistryPath HKLM:\SYSTEM\CurrentControlSet\Services\SysmonDrv\Parameters -IdentityReference Everyone -Rights QueryValues -InheritanceFlags None -PropagationFlags None -AuditFlags Success
```

## Event Occurrence

Low

## Notes


## Object Properties

```
PS C:\Tools\scripts> Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\SysmonDrv\Parameters\

Options          : 3
HashingAlgorithm : 2147483663
Rules            : {1, 0, 1, 0...}
PSPath           : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SysmonDrv\Parameters\
PSParentPath     : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SysmonDrv
PSChildName      : Parameters
PSDrive          : HKLM
```

## Object Security Descriptor

```
PS C:\Tools\scripts> Get-Acl -Path HKLM:\SYSTEM\CurrentControlSet\Services\SysmonDrv\Parameters -Audit | fl

Path   : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SysmonDrv\Parameters
Owner  : BUILTIN\Administrators
Group  : DESKTOP-WARDOG\None
Access : BUILTIN\Administrators Allow  FullControl
         BUILTIN\Users Allow  ReadKey
         BUILTIN\Users Allow  -2147483648
         BUILTIN\Administrators Allow  FullControl
         BUILTIN\Administrators Allow  268435456
         NT AUTHORITY\SYSTEM Allow  FullControl
         NT AUTHORITY\SYSTEM Allow  268435456
         CREATOR OWNER Allow  268435456
         APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES Allow  ReadKey
         APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES Allow  -2147483648
         S-1-15-3-1024-1065365936-1281604716-3511738428-1654721687-432734479-3232135806-4053264122-3456934681 Allow  ReadKey
         S-1-15-3-1024-1065365936-1281604716-3511738428-1654721687-432734479-3232135806-4053264122-3456934681 Allow  -2147483648
Audit  : 
Sddl   : O:BAG:S-1-5-21-3825400013-1856045589-1834093677-513D:AI(A;;KA;;;BA)(A;ID;KR;;;BU)(A;CIIOID;GR;;;BU)(A;ID;KA;;;BA)(A;CIIOID;GA;;;BA)(A;ID;KA;;;SY)(A;CIIOID;GA;;;SY)(A;CIIOID;GA;;;CO)(
         A;ID;KR;;;AC)(A;CIIOID;GR;;;AC)(A;ID;KR;;;S-1-15-3-1024-1065365936-1281604716-3511738428-1654721687-432734479-3232135806-4053264122-3456934681)(A;CIIOID;GR;;;S-1-15-3-1024-1065365936
         -1281604716-3511738428-1654721687-432734479-3232135806-4053264122-3456934681)S:AI
```

## Object Default Events