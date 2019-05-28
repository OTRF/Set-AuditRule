# PowerShell Transcript

Adversaries might query HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription to check if PowerShell transcript settings are enabled.

## Adversary Actions

Query

## Set Audit Rule

```
Set-AuditRule -RegistryPath HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription -IdentityReference Everyone -Rights QueryValues -InheritanceFlags None -PropagationFlags None -AuditFlags Success
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
