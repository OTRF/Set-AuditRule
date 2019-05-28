# System Audit Policies

Adversaries might query HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit for audit policies settings.

# Adversary Actions

Query

## Set Audit Rule

```
Set-AuditRule -RegistryPath HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit -IdentityReference Everyone -Rights QueryValues -InheritanceFlags None -PropagationFlags None -AuditFlags Success
```

## Event Occurrence

Low

## Notes

The Audit Key is not queried at all. However, the parent System registry key queried a lot by Network Service account.

## Object Properties

```

```

## Object Security Descriptor

```
PS C:\Tools\scripts> Get-Acl -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit -Audit | fl

Path   : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
Owner  : BUILTIN\Administrators
Group  : NT AUTHORITY\SYSTEM
Access : BUILTIN\Users Allow  ReadKey
         BUILTIN\Administrators Allow  FullControl
         NT AUTHORITY\SYSTEM Allow  FullControl
         CREATOR OWNER Allow  FullControl
         APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES Allow  ReadKey
         S-1-15-3-1024-1065365936-1281604716-3511738428-1654721687-432734479-3232135806-4053264122-3456934681 Allow  ReadKey
Audit  : 
Sddl   : O:BAG:SYD:AI(A;CIID;KR;;;BU)(A;CIID;KA;;;BA)(A;CIID;KA;;;SY)(A;CIIOID;KA;;;CO)(A;CIID;KR;;;AC)(A;CIID;KR;;;S-1-15-3-1024-1065365936-1281604716-3511738428-1654721687-432734479-3232135
         806-4053264122-3456934681)S:AI
```

## Object Default Events
