# LAPS

Adversaries might query HKLM:\Software\Policies\Microsoft Services\AdmPwd for LAPS settings.

## Adversary Actions

Query

## Set Audit Rule

```
Set-AuditRule -RegistryPath 'HKLM:\Software\Policies\Microsoft Services\AdmPwd' -IdentityReference Everyone -Rights QueryValues -InheritanceFlags None -PropagationFlags None -AuditFlags Success
```

## Event Occurrence

Unknown

## Notes


## Object Properties

```

```

## Object Security Descriptor

```

```

## Object Default Events