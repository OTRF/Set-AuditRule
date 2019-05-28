# PowerShell ScriptBlock Logging

Adversaries might query HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging to check if PowerShell ScriptBlockLogging settings are enabled.

# Adversary Actions

Query

## Set Audit Rule

```
Set-AuditRule -RegistryPath HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging -IdentityReference Everyone -Rights QueryValues -InheritanceFlags None -PropagationFlags None -AuditFlags Success
```

## Event Occurrence

Low

## Notes

Registry key not set by default

## Object Properties

```

```

## Object Security Descriptor

```

```

## Object Default Events
