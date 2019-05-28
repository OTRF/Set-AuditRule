# System Policies

Adversaries might query HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System for UAC system policies

# Adversary Actions

Query

## Set Audit Rule

```
Set-AuditRule -RegistryPath HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -IdentityReference Everyone -Rights QueryValues -InheritanceFlags None -PropagationFlags None -AuditFlags Success
```

## Event Occurrence

High

## Notes

Queried a lot by NETWORK SERVICE account only

## Object Properties

```
PS C:\Tools\scripts> Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment'

ConsentPromptBehaviorAdmin   : 5
ConsentPromptBehaviorUser    : 3
DSCAutomationHostEnabled     : 2
EnableCursorSuppression      : 1
EnableFullTrustStartupTasks  : 2
EnableInstallerDetection     : 1
EnableLUA                    : 1
EnableSecureUIAPaths         : 1
EnableUIADesktopToggle       : 0
EnableUwpStartupTasks        : 2
EnableVirtualization         : 1
PromptOnSecureDesktop        : 1
SupportFullTrustStartupTasks : 1
SupportUwpStartupTasks       : 1
ValidateAdminCodeSignatures  : 0
dontdisplaylastusername      : 0
legalnoticecaption           : 
legalnoticetext              :  
scforceoption                : 0
shutdownwithoutlogon         : 1
undockwithoutlogon           : 1
PSPath                       : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System
PSParentPath                 : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies
PSChildName                  : System
PSDrive                      : HKLM
PSProvider                   : Microsoft.PowerShell.Core\Registry
```

## Object Security Descriptor

```
Path   : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System
Owner  : NT AUTHORITY\SYSTEM
Group  : NT AUTHORITY\SYSTEM
Access : BUILTIN\Users Allow  ReadKey
         BUILTIN\Administrators Allow  FullControl
         NT AUTHORITY\SYSTEM Allow  FullControl
         CREATOR OWNER Allow  FullControl
         APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES Allow  ReadKey
         S-1-15-3-1024-1065365936-1281604716-3511738428-1654721687-432734479-3232135806-4053264122-3456934681 Allow  ReadKey
Audit  : 
Sddl   : O:SYG:SYD:AI(A;CIID;KR;;;BU)(A;CIID;KA;;;BA)(A;CIID;KA;;;SY)(A;CIIOID;KA;;;CO)(A;CIID;KR;;;AC)(A;CIID;KR;;;S-1-15-3-1024-1065365936-1281604716-3511738428-1654721687-432734479-3232135
         806-4053264122-3456934681)S:AI
```

## Object Default Events

<img src="https://github.com/Cyb3rWard0g/Set-AuditRule/blob/master/images/system-svchost-networkservice.png" alt="Event 4663 user" width="625" height="625">