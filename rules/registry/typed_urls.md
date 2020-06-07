# Typed URLs

Adversaries might query HKCU:\SOFTWARE\Microsoft\Internet Explorer\TypedURLs for Internet Explorer (All Users) history

## Adversary Actions

Query

## Set Audit Rule

```
Set-AuditRule -RegistryPath 'HKCU:\SOFTWARE\Microsoft\Internet Explorer\TypedURLs' -IdentityReference Everyone -Rights QueryValues -InheritanceFlags None -PropagationFlags None -AuditFlags Success
```

## Event Occurrence

Low

## Notes

## Object Properties

```
PS C:\Tools\scripts> Get-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Internet Explorer\TypedURLs'

url1         : http://go.microsoft.com/fwlink/p/?LinkId=255141
PSPath       : Microsoft.PowerShell.Core\Registry::HKEY_CURRENT_USER\SOFTWARE\Microsoft\Internet Explorer\TypedURLs
PSParentPath : Microsoft.PowerShell.Core\Registry::HKEY_CURRENT_USER\SOFTWARE\Microsoft\Internet Explorer
PSChildName  : TypedURLs
PSDrive      : HKCU
PSProvider   : Microsoft.PowerShell.Core\Registry
```

## Object Security Descriptor

```
PS C:\Tools\scripts> get-acl -Path 'HKCU:\SOFTWARE\Microsoft\Internet Explorer\TypedURLs' -Audit | fl

Path   : Microsoft.PowerShell.Core\Registry::HKEY_CURRENT_USER\SOFTWARE\Microsoft\Internet Explorer\TypedURLs
Owner  : NT AUTHORITY\SYSTEM
Group  : NT AUTHORITY\SYSTEM
Access : NT AUTHORITY\RESTRICTED Allow  ReadKey
         NT AUTHORITY\SYSTEM Allow  FullControl
         BUILTIN\Administrators Allow  FullControl
         DESKTOP-WARDOG\wardog Allow  FullControl
         APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES Allow  -2147483648
         APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES Allow  ReadKey
         S-1-15-3-4096 Allow  ReadKey
         S-1-15-2-3469964869-263285312-1618360021-2343290171-1786798556-2722298370-1585569900 Allow  ReadKey
         S-1-15-2-3624051433-2125758914-1423191267-1740899205-1073925389-3782572162-737981194 Allow  ReadKey
         S-1-15-2-3795941342-518727550-4290142327-3574433603-4273787745-1450327651-649988109 Allow  ReadKey
         S-1-15-3-1024-1065365936-1281604716-3511738428-1654721687-432734479-3232135806-4053264122-3456934681 Allow  ReadKey
         S-1-15-3-1024-1065365936-1281604716-3511738428-1654721687-432734479-3232135806-4053264122-3456934681 Allow  -2147483648
Audit  : 
Sddl   : O:SYG:SYD:(A;CI;KR;;;RC)(A;CI;KA;;;SY)(A;CI;KA;;;BA)(A;OICI;KA;;;S-1-5-21-3825400013-1856045589-1834093677-1001)(A;CIIO;GR;;;AC)(A;OICI;KR;;;AC)(A;CI;KR;;;S-1-15-3-4096)(A;CI;KR;;;S-
         1-15-2-3469964869-263285312-1618360021-2343290171-1786798556-2722298370-1585569900)(A;CI;KR;;;S-1-15-2-3624051433-2125758914-1423191267-1740899205-1073925389-3782572162-737981194)(A;
         CI;KR;;;S-1-15-2-3795941342-518727550-4290142327-3574433603-4273787745-1450327651-649988109)(A;OICI;KR;;;S-1-15-3-1024-1065365936-1281604716-3511738428-1654721687-432734479-323213580
         6-4053264122-3456934681)(A;CIIO;GR;;;S-1-15-3-1024-1065365936-1281604716-3511738428-1654721687-432734479-3232135806-4053264122-3456934681)S:AI
```

## Object Default Events