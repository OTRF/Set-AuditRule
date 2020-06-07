# WEF Subscription Manager

Adversaries might query HKLM:\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager for WEF settings.

## Adversary Actions

Query

## Set Audit Rule

```
Set-AuditRule -RegistryPath HKLM:\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager -IdentityReference Everyone -Rights QueryValues -InheritanceFlags None -PropagationFlags None -AuditFlags Success
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