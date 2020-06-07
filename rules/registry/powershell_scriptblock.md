# PowerShell ScriptBlock Logging

Adversaries might query HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging to check if PowerShell ScriptBlockLogging settings are enabled.

## Adversary Actions

Query

## Set Audit Rule

```
Set-AuditRule -RegistryPath HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging -IdentityReference Everyone -Rights QueryValues -InheritanceFlags None -PropagationFlags None -AuditFlags Success
```

## Event Occurrence

High

## Notes

* Registry key not set by default
* Very noisy in relation to users using PowerShell. It generates several events when user executes a command via PowerShell console
* One could filter out everything from powershell.exe to catch other potential PowerShell hosts.

## Object Properties

```
PS C:\WINDOWS\system32> Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging


EnableScriptBlockLogging : 1
PSPath                   : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
PSParentPath             : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell
PSChildName              : ScriptBlockLogging
PSDrive                  : HKLM
PSProvider               : Microsoft.PowerShell.Core\Registry
```

## Object Security Descriptor

```
Path   : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
Owner  : BUILTIN\Administrators
Group  : RIVENDELL\None
Access : NT AUTHORITY\Authenticated Users Allow  ReadKey
         NT AUTHORITY\Authenticated Users Allow  -2147483648
         NT AUTHORITY\SYSTEM Allow  FullControl
         NT AUTHORITY\SYSTEM Allow  268435456
         BUILTIN\Administrators Allow  FullControl
         BUILTIN\Administrators Allow  268435456
         APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES Allow  ReadKey
         APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES Allow  -2147483648
Audit  :
```

## Object Default Events
