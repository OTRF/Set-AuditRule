# LSA

Adversaries might query HKLM:\SYSTEM\CurrentControlSet\Control\Lsa for LSA settings (i.e Security Packages).

# Adversary Actions

Query

## Set Audit Rule

```
Set-AuditRule -RegistryPath HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -IdentityReference Everyone -Rights QueryValues -InheritanceFlags None -PropagationFlags None -AuditFlags Success
```

## Event Occurrence

High

## Notes

Queried a lot by the Local Service account via svchost

## Object Properties

```
PS C:\Tools\scripts> Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa

auditbasedirectories      : 0
auditbaseobjects          : 0
Bounds                    : {0, 48, 0, 0...}
crashonauditfail          : 0
fullprivilegeauditing     : {0}
LimitBlankPasswordUse     : 1
NoLmHash                  : 1
Security Packages         : {""}
Notification Packages     : {scecli}
Authentication Packages   : {msv1_0}
disabledomaincreds        : 0
everyoneincludesanonymous : 0
forceguest                : 0
LsaPid                    : 820
ProductType               : 4
restrictanonymous         : 0
restrictanonymoussam      : 1
SecureBoot                : 1
LsaCfgFlagsDefault        : 0
PSPath                    : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa
PSParentPath              : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control
PSChildName               : Lsa
PSDrive                   : HKLM
PSProvider                : Microsoft.PowerShell.Core\Registry
```

## Object Security Descriptor

```
PS C:\Tools\scripts> Get-Acl -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Audit | fl

Path   : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa
Owner  : NT AUTHORITY\SYSTEM
Group  : NT AUTHORITY\SYSTEM
Access : CREATOR OWNER Allow  FullControl
         NT AUTHORITY\SYSTEM Allow  FullControl
         BUILTIN\Administrators Allow  FullControl
         BUILTIN\Users Allow  ReadKey
         APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES Allow  ReadKey
         S-1-15-3-1024-1065365936-1281604716-3511738428-1654721687-432734479-3232135806-4053264122-3456934681 Allow  ReadKey
Audit  : 
Sddl   : O:SYG:SYD:PAI(A;CIIO;KA;;;CO)(A;CI;KA;;;SY)(A;CI;KA;;;BA)(A;CI;KR;;;BU)(A;CI;KR;;;AC)(A;CI;KR;;;S-1-15-3-1024-1065365936-1281604716-3511738428-1654721687-432734479-3232135806-4053264
         122-3456934681)S:AI
```

## Object Default Events

<img src="https://github.com/Cyb3rWard0g/Set-AuditRule/blob/master/images/lsa-taskhost-user.png" alt="Event 4663 user" width="625" height="625">

<img src="https://github.com/Cyb3rWard0g/Set-AuditRule/blob/master/images/lsa-runtimebroker-user.png" alt="Event 4663 user" width="625" height="625">

<img src="https://github.com/Cyb3rWard0g/Set-AuditRule/blob/master/images/lsa-svchost-localservice.png" alt="Event 4663 user" width="625" height="625">

<img src="https://github.com/Cyb3rWard0g/Set-AuditRule/blob/master/images/lsa-officeclient-machine.png" alt="Event 4663 user" width="625" height="625">