# Set-AuditRule

[![Open_Threat_Research Community](https://img.shields.io/badge/Open_Threat_Research-Community-brightgreen.svg)](https://twitter.com/OTR_Community)
[![Open Source Love svg1](https://badges.frapsoft.com/os/v3/open-source.svg?v=103)](https://github.com/ellerbrock/open-source-badges/)

A repository of useful access control entries (ACE) that could be added to the system access control list (SACL) of a securable object's security descriptor to monitor potential adversarial activity.
These entries are categorized by specific securable objects such as files, registry keys and Active Directory objects.
In addition, this project comes with a PowerShell script that will help you to set the audit rules in a programmatic way at scale.
The script also leverages PowerShell dynamic parameters to provide auto-complete capabilities and provide the values needed for each flag directly from the access control and directory service classes.

# Goals

* Document useful audit rules to monitor and detect potential adversaries accessing specific securable objects
* Expedite development and deployment of audit rules in network environments
* Test audit rules volume and share findings with the community
* Map audit rules to adversarial tooling 
* Learn about System Access Control Lists (SACL)
* Learn about PowerShell Dynamic Parameters
* Learn about Microsoft Security Access Control classes

# References

* [Access Control Namespace](https://docs.microsoft.com/en-us/dotnet/api/system.security.accesscontrol?view=netframework-4.8)
* [Registry Access Control Rights](https://docs.microsoft.com/en-us/dotnet/api/system.security.accesscontrol.registryrights?view=dotnet-plat-ext-3.1#fields)
* [Files Access Control Rights](https://docs.microsoft.com/en-us/dotnet/api/system.security.accesscontrol.filesystemrights?view=netframework-4.8)
* [Well Known Sid Types](https://docs.microsoft.com/en-us/dotnet/api/system.security.principal.wellknownsidtype?view=net-5.0)
* [Security Descriptor](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-azod/ec52bde3-9c86-4484-9080-e72148a2d53b)

# Authors

* Roberto Rodriguez [@Cyb3rWard0g](https://twitter.com/Cyb3rWard0g)

# Contributing

If you have an audit rule that you believe is useful in your environment to monitor and detect potential adversarial activity and would like to share it with the community, feel free to open a PR!

# License: GPL-3.0

[ Set-AuditRule's GNU General Public License](https://github.com/Cyb3rWard0g/Set-AuditRule/blob/master/LICENSE)