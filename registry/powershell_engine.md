# PowerShell Engine

Adversaries might query HKLM:\SOFTWARE\Microsoft\PowerShell\1\PowerShellEngine and HKLM:\SOFTWARE\Microsoft\PowerShell\3\PowerShellEngine to gather information about the PowerShell versions available in the system.

# Adversary Actions

Query

## Set Audit Rule

```
Set-AuditRule -RegistryPath HKLM:\SOFTWARE\Microsoft\PowerShell\1\ -IdentityReference Everyone -Rights QueryValues -InheritanceFlags ContainerInherit -PropagationFlags InheritOnly -AuditFlags Success
```

```
Set-AuditRule -RegistryPath HKLM:\SOFTWARE\Microsoft\PowerShell\3\ -IdentityReference Everyone -Rights QueryValues -InheritanceFlags ContainerInherit -PropagationFlags InheritOnly -AuditFlags Success
```

## Event Occurrence

Low

## Notes

* Audit Rule cannot be applied to HKLM:\SOFTWARE\Microsoft\PowerShell\1\PowerShellEngine directly. Audit rule needs to be applied to HKLM:\SOFTWARE\Microsoft\PowerShell\1\ with `InheritanceFlag` set to `ContainerInherit`
* Audit Rule cannot be applied to HKLM:\SOFTWARE\Microsoft\PowerShell\3\PowerShellEngine directly. Audit rule needs to be applied to HKLM:\SOFTWARE\Microsoft\PowerShell\3\ with `InheritanceFlag` set to `ContainerInherit`
* In a Windows 10 computer (PS version 5), HKLM:\SOFTWARE\Microsoft\PowerShell\3\PowerShellEngine is queried every time the PowerShell console is opened.

## Object Properties

```
PS C:\> Get-ItemProperty HKLM:\SOFTWARE\Microsoft\PowerShell\1\PowerShellEngine


ApplicationBase         : C:\Windows\System32\WindowsPowerShell\v1.0
ConsoleHostAssemblyName : Microsoft.PowerShell.ConsoleHost, Version=1.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35, ProcessorArchitecture=msil
ConsoleHostModuleName   : C:\Windows\System32\WindowsPowerShell\v1.0\Microsoft.PowerShell.ConsoleHost.dll
PowerShellVersion       : 2.0
PSCompatibleVersion     : 1.0, 2.0
RuntimeVersion          : v2.0.50727
PSPath                  : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PowerShell\1\PowerShellEngine
PSParentPath            : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PowerShell\1
PSChildName             : PowerShellEngine
PSDrive                 : HKLM
PSProvider              : Microsoft.PowerShell.Core\Registry
```

```
PS C:\Tools\scripts> Get-ItemProperty HKLM:\SOFTWARE\Microsoft\PowerShell\3\PowerShellEngine


ApplicationBase         : C:\Windows\System32\WindowsPowerShell\v1.0
ConsoleHostAssemblyName : Microsoft.PowerShell.ConsoleHost, Version=3.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35, ProcessorArchitecture=msil
ConsoleHostModuleName   : C:\Windows\System32\WindowsPowerShell\v1.0\Microsoft.PowerShell.ConsoleHost.dll
PowerShellVersion       : 5.1.17134.1
PSCompatibleVersion     : 1.0, 2.0, 3.0, 4.0, 5.0, 5.1
PSPluginWkrModuleName   : C:\Windows\System32\WindowsPowerShell\v1.0\system.management.automation.dll
RuntimeVersion          : v4.0.30319
PSPath                  : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PowerShell\3\PowerShellEngine
PSParentPath            : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PowerShell\3
PSChildName             : PowerShellEngine
PSDrive                 : HKLM
PSProvider              : Microsoft.PowerShell.Core\Registry
```

## Object Security Descriptor

```
PS C:\Tools\scripts> Get-Acl -Path HKLM:\SOFTWARE\Microsoft\PowerShell\1\PowerShellEngine -Audit | fl


Path   : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PowerShell\1\PowerShellEngine
Owner  : NT SERVICE\TrustedInstaller
Group  : NT SERVICE\TrustedInstaller
Access : NT AUTHORITY\SYSTEM Allow  -2147483648
         NT AUTHORITY\SYSTEM Allow  ReadKey
         BUILTIN\Administrators Allow  ReadKey
         BUILTIN\Administrators Allow  -2147483648
         BUILTIN\Users Allow  -2147483648
         BUILTIN\Users Allow  ReadKey
         NT SERVICE\TrustedInstaller Allow  268435456
         NT SERVICE\TrustedInstaller Allow  FullControl
         APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES Allow  ReadKey
         APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES Allow  -2147483648
         S-1-15-3-1024-1065365936-1281604716-3511738428-1654721687-432734479-3232135806-4053264122-3456934681 Allow  ReadKey
         S-1-15-3-1024-1065365936-1281604716-3511738428-1654721687-432734479-3232135806-4053264122-3456934681 Allow  -2147483648
Audit  : 
Sddl   : O:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464G:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464D:PAI(A;CIIO;GR;;;SY)(A;;KR;;;SY)(A;;KR;;;BA)(A;CIIO;G
         R;;;BA)(A;CIIO;GR;;;BU)(A;;KR;;;BU)(A;CIIO;GA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;;KA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464
         )(A;;KR;;;AC)(A;CIIO;GR;;;AC)(A;;KR;;;S-1-15-3-1024-1065365936-1281604716-3511738428-1654721687-432734479-3232135806-4053264122-3456934681)(A;CIIO;GR;;;S-1-15-3-1024-1065365936-12816
         04716-3511738428-1654721687-432734479-3232135806-4053264122-3456934681)S:AI
```

```
PS C:\Tools\scripts> Get-Acl -Path 'HKLM:\SOFTWARE\Microsoft\PowerShell\3\PowerShellEngine' -Audit | fl


Path   : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PowerShell\3\PowerShellEngine
Owner  : NT SERVICE\TrustedInstaller
Group  : NT SERVICE\TrustedInstaller
Access : NT AUTHORITY\SYSTEM Allow  -2147483648
         NT AUTHORITY\SYSTEM Allow  ReadKey
         BUILTIN\Administrators Allow  ReadKey
         BUILTIN\Administrators Allow  -2147483648
         BUILTIN\Users Allow  -2147483648
         BUILTIN\Users Allow  ReadKey
         NT SERVICE\TrustedInstaller Allow  268435456
         NT SERVICE\TrustedInstaller Allow  FullControl
         APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES Allow  ReadKey
         APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES Allow  -2147483648
         S-1-15-3-1024-1065365936-1281604716-3511738428-1654721687-432734479-3232135806-4053264122-3456934681 Allow  ReadKey
         S-1-15-3-1024-1065365936-1281604716-3511738428-1654721687-432734479-3232135806-4053264122-3456934681 Allow  -2147483648
Audit  : 
Sddl   : O:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464G:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464D:PAI(A;CIIO;GR;;;SY)(A;;KR;;;SY)(A;;KR;;;BA)(A;CIIO;G
         R;;;BA)(A;CIIO;GR;;;BU)(A;;KR;;;BU)(A;CIIO;GA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;;KA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464
         )(A;;KR;;;AC)(A;CIIO;GR;;;AC)(A;;KR;;;S-1-15-3-1024-1065365936-1281604716-3511738428-1654721687-432734479-3232135806-4053264122-3456934681)(A;CIIO;GR;;;S-1-15-3-1024-1065365936-12816
         04716-3511738428-1654721687-432734479-3232135806-4053264122-3456934681)S:AI
```

## Object Default Events

<img src="https://github.com/Cyb3rWard0g/Set-AuditRuleblob/master/images/powershell-engine-powershell-user.png" alt="Event 4663 user" width="625" height="625">