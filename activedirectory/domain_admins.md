# Domain Admins

Adversaries might query the `Domain Admins` AD object to list its members.

# Adversary Actions

GeenricRead

## Set Audit Rule

```
Example:

Set-AuditRule -AdObjectPath 'AD:\CN=Domain Admins,CN=Users,DC=RIVENDELL,DC=local' -IdentityReference Everyone -Rights GenericRead -InheritanceFlags None -AuditFlags Success
```

## Event Occurrence

Low

## Notes

## Object Properties

```

```

## Object Security Descriptor

```

```

## Object Default Events
