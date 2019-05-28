# RunMRU

Adversaries might query HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU to list recently run commands.

## Adversary Actions

Query

## Set Audit Rule

```
Set-AuditRule -RegistryPath HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU -IdentityReference Everyone -Rights QueryValues -InheritanceFlags None -PropagationFlags None -AuditFlags Success
```

## Event Occurrence

Low

## Notes

## Object Properties

```
PS C:\Tools\scripts> Get-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU

a            : notepad.exe\1
MRUList      : a
PSPath       : Microsoft.PowerShell.Core\Registry::HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
PSParentPath : Microsoft.PowerShell.Core\Registry::HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer
PSChildName  : RunMRU
PSDrive      : HKCU
PSProvider   : Microsoft.PowerShell.Core\Registry
```

## Object Security Descriptor

```
PS C:\Tools\scripts> Get-Acl -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU -Audit | fl

Path   : Microsoft.PowerShell.Core\Registry::HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
Owner  : DESKTOP-WARDOG\wardog
Group  : DESKTOP-WARDOG\None
Access : NT AUTHORITY\RESTRICTED Allow  ReadKey
         NT AUTHORITY\SYSTEM Allow  FullControl
         BUILTIN\Administrators Allow  FullControl
         DESKTOP-WARDOG\wardog Allow  FullControl
         APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES Allow  ReadKey
         DESKTOP-WARDOG\wardog Allow  FullControl
         NT AUTHORITY\SYSTEM Allow  FullControl
         BUILTIN\Administrators Allow  FullControl
         NT AUTHORITY\RESTRICTED Allow  ReadKey
         APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES Allow  ReadKey
         S-1-15-3-1024-1065365936-1281604716-3511738428-1654721687-432734479-3232135806-4053264122-3456934681 Allow  ReadKey
Audit  : 
Sddl   : O:S-1-5-21-3825400013-1856045589-1834093677-1001G:S-1-5-21-3825400013-1856045589-1834093677-513D:AI(A;OICI;KR;;;RC)(A;OICI;KA;;;SY)(A;OICI;KA;;;BA)(A;OICI;KA;;;S-1-5-21-3825400013-18
         56045589-1834093677-1001)(A;OICI;KR;;;AC)(A;OICIID;KA;;;S-1-5-21-3825400013-1856045589-1834093677-1001)(A;OICIID;KA;;;SY)(A;OICIID;KA;;;BA)(A;OICIID;KR;;;RC)(A;OICIID;KR;;;AC)(A;OICI
         ID;KR;;;S-1-15-3-1024-1065365936-1281604716-3511738428-1654721687-432734479-3232135806-4053264122-3456934681)
```

## Object Default Events