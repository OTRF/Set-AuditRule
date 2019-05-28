# Ennvironment Variables

Adversaries might query 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment' for current system environment variables

## Adversary Actions

Query

## Set Audit Rule

```
Set-AuditRule -RegistryPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment' -IdentityReference Everyone -Rights QueryValues -InheritanceFlags None -PropagationFlags None -AuditFlags Success
```

## Event Occurrence

Medium

## Notes

## Object Properties

```
PS C:\Tools\scripts> Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment'


ComSpec                : C:\WINDOWS\system32\cmd.exe
DriverData             : C:\Windows\System32\Drivers\DriverData
OS                     : Windows_NT
PATHEXT                : .COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC
PROCESSOR_ARCHITECTURE : AMD64
PSModulePath           : C:\Program Files\WindowsPowerShell\Modules;C:\WINDOWS\system32\WindowsPowerShell\v1.0\Modules
TEMP                   : C:\WINDOWS\TEMP
TMP                    : C:\WINDOWS\TEMP
USERNAME               : SYSTEM
windir                 : C:\WINDOWS
Path                   : \\.\C:\;C:\WINDOWS\system32;C:\WINDOWS;C:\WINDOWS\System32\Wbem;C:\WINDOWS\System32\WindowsPowerShell\v1.0\;C:\Program Files\OpenVPN\bin;;C:\WINDOWS\System32\OpenSSH\
NUMBER_OF_PROCESSORS   : 1
PROCESSOR_LEVEL        : 6
PROCESSOR_IDENTIFIER   : Intel64 Family 6 Model 142 Stepping 9, GenuineIntel
PROCESSOR_REVISION     : 8e09
PSPath                 : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Environment
PSParentPath           : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager
PSChildName            : Environment
PSDrive                : HKLM
PSProvider             : Microsoft.PowerShell.Core\Registry
```

## Object Security Descriptor

```
Path   : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Environment
Owner  : NT AUTHORITY\SYSTEM
Group  : NT AUTHORITY\SYSTEM
Access : BUILTIN\Users Allow  ReadKey
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
Sddl   : O:SYG:SYD:AI(A;ID;KR;;;BU)(A;CIIOID;GR;;;BU)(A;ID;KA;;;BA)(A;CIIOID;GA;;;BA)(A;ID;KA;;;SY)(A;CIIOID;GA;;;SY)(A;CIIOID;GA;;;CO)(A;ID;KR;;;AC)(A;CIIOID;GR;;;AC)(A;ID;KR;;;S-1-15-3-1024
         -1065365936-1281604716-3511738428-1654721687-432734479-3232135806-4053264122-3456934681)(A;CIIOID;GR;;;S-1-15-3-1024-1065365936-1281604716-3511738428-1654721687-432734479-3232135806-
         4053264122-3456934681)S:AI
```

## Object Default Events

<img src="https://github.com/Cyb3rWard0g/Set-AuditRule/blob/master/images/environment-svchost-user.png" alt="Event 4663 user" width="625" height="625">

<img src="https://github.com/Cyb3rWard0g/Set-AuditRule/master/images/environment-svchost-machine.png" alt="Event 4663 machine" width="625" height="625">

<img src="https://github.com/Cyb3rWard0g/Set-AuditRule/blob/master/images/environment-msmpeng-machine.png" alt="Event 4663 user" width="625" height="625">