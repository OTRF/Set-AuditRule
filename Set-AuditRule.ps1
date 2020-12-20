function Set-AuditRule
{
    <#
    .SYNOPSIS

    Sets an access control entry (ACE) on a system access control list (SACL) of a file, registry or ad object security descriptor.

    .PARAMETER RegistryPath

    Path of the registry securable object
    
    .PARAMETER FilePath

    Path of the file securable object

    .PARAMETER AdObjectPath

    Path of the Ad securable object

    .PARAMETER WellKnownSidType

    Commonly used Security Identifier. We leverage the parameter attribute called ArgumentCompleter to add tab completion values.
    These values are obtained from the System.Security.Principal.WellKnownSidType enum.
    Examples:
    - WorldSid -> Indicates a SID that matches everyone.
    - NetworkSid -> Indicates a SID for a network account. This SID is added to the process of a token when it logs on across a network.
    - BuiltinAdministratorsSid -> Indicates a SID that matches the administrator account.
    - AccountDomainAdminsSid -> Indicates a SID that matches the account domain administrator group.
    - AccountDomainUsersSid -> Indicates a SID that matches the account domain users group.

    .PARAMETER Rights
    
    Specifies the types of access attempts to monitor. Access control rights that can be applied to a registry, file or ad objects.
    These values are served dynamically from the following Enums: System.Security.AccessControl.RegistryRights, System.Security.AccessControl.FileSystemRights and System.DirectoryServices.ActiveDirectoryRights.

    .PARAMETER InheritanceFlag

    Inheritance flags specify the semantics of inheritance for access control entries (ACEs).
    These values are served dynamically from the following Enums: System.DirectoryServices.ActiveDirectorySecurityInheritance and System.Security.AccessControl.InheritanceFlags.

    .PARAMETER PropagationFlags

    Specifies how Access Control Entries (ACEs) are propagated to child objects. These flags are significant only if inheritance flags are present.
    These values are serverd dynamically from the following Enum: System.Security.AccessControl.PropagationFlags. 

    .PARAMETER AuditFlags

    Specifies the conditions for auditing attempts to access a securable object. Success or Failure.
    These values are served dynamically from the following Enum: System.Security.AccessControl.AuditFlags.

    .NOTES
    
    Author: Roberto Rodriguez (@Cyb3rWard0g)
    License: GPL-3.0

    Reference: 
    - @adbertram - https://www.enowsoftware.com/solutions-engine/bid/185867/Powershell-Upping-your-Parameter-Validation-Game-with-Dynamic-Parameters-Part-II
    - https://social.technet.microsoft.com/Forums/ie/en-US/b012f66e-08d1-46d2-b659-6ee004e721c0/powershell-to-set-sacl-on-files?forum=ITCG
    - http://giuoco.org/security/configure-file-and-registry-auditing-with-powershell/
    - https://medium.com/@cryps1s/detecting-windows-endpoint-compromise-with-sacls-cd748e10950
    - https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_functions_advanced_parameters?view=powershell-7.1#argumentcompleter-attribute
    - https://docs.microsoft.com/en-us/dotnet/api/system.security.principal.wellknownsidtype?view=net-5.0
    - https://docs.microsoft.com/en-us/windows/win32/secauthz/sid-strings

    .EXAMPLE

    PS > Get-Acl -Path HKLM:\SYSTEM\CurrentControlSet\Services\Sysmondrv\Parameters\ -Audit | fl

    Path   : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Sysmondrv\Parameters\
    Owner  : BUILTIN\Administrators
    Group  : DESKTOP-WARDOG\None
    Access : BUILTIN\Administrators Allow  FullControl
             ..
             ...
    Audit  :
    Sddl   : O:BAG:...
    
    PS > Set-AuditRule -RegistryPath HKLM:\SYSTEM\CurrentControlSet\Services\Sysmondrv\Parameters\ -WellKnownSidType WorldSid -Rights ReadKey,QueryValues -InheritanceFlags None -PropagationFlags None -AuditFlags Success
    
    PS > Get-Acl -Path HKLM:\SYSTEM\CurrentControlSet\Services\Sysmondrv\Parameters\ -Audit | fl

    Path   : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Sysmondrv\Parameters\
    Owner  : BUILTIN\Administrators
    Group  : DESKTOP-WARDOG\None
    Access : BUILTIN\Administrators Allow  FullControl
             ..
             ...
    Audit  : Everyone Success  ReadKey
    Sddl   : O:BAG:...S:AI(AU;SA;KR;;;WD)

    .EXAMPLE

    PS > Get-Acl -Path C:\tools\test.txt -Audit | fl

    Path   : Microsoft.PowerShell.Core\FileSystem::C:\tools\test.txt
    Owner  : RIVENDELL\cbrown
    Group  : 
    Access : BUILTIN\Administrators Allow  FullControl
             NT AUTHORITY\SYSTEM Allow  FullControl
             BUILTIN\Users Allow  ReadAndExecute, Synchronize
             NT AUTHORITY\Authenticated Users Allow  Modify, Synchronize
    Audit  : 
    Sddl   : O:S-1-5...

    PS > Set-AuditRule -FilePath C:\tools\test4.txt.txt -WellKnownSidType WorldSid -Rights Read,Modify -InheritanceFlags None -PropagationFlags None -AuditFlags Success

    PS > Get-Acl -Path C:\tools\test.txt -Audit | fl

    Path   : Microsoft.PowerShell.Core\FileSystem::C:\tools\test.txt
    Owner  : RIVENDELL\cbrown
    Group  : 
    Access : BUILTIN\Administrators Allow  FullControl
             NT AUTHORITY\SYSTEM Allow  FullControl
             BUILTIN\Users Allow  ReadAndExecute, Synchronize
             NT AUTHORITY\Authenticated Users Allow  Modify, Synchronize
    Audit  : Everyone Success  Modify
    Sddl   : O:S-1-5... S:AI(AU;SA;CCDCLCSWRPWPLOCRSDRC;;;WD)

    .EXAMPLE

    PS > Enter-PSSession MORDORDC -Credential theshire\pgustavo
    [MORDORDC]: PS > Import-Module activedirectory 
    [MORDORDC]: PS > Get-Acl -Path 'AD:\CN=Domain Admins,CN=Users,DC=theshire,DC=local' -Audit | fl
    [MORDORDC]: PS > Set-AuditRule -AdObjectPath 'AD:\CN=Domain Admins,CN=Users,DC=theshire,DC=local' -WellKnownSidType WorldSid -Rights GenericRead -InheritanceFlags None -AuditFlags Success
    [MORDORDC]: PS > Get-Acl -Path 'AD:\CN=Domain Admins,CN=Users,DC=theshire,DC=local' -Audit | fl

    #>

    [CmdletBinding(DefaultParameterSetName='NoParam')]
    param
    (
        [Parameter(Position=0,Mandatory=$true,ParameterSetname='RegistryAudit')]
        [ValidateScript({Test-Path $_})]
        [string]$RegistryPath,

        [Parameter(Position=0,Mandatory=$true,ParameterSetname='FileAudit')]
        [ValidateScript({Test-Path $_})]
        [string]$FilePath,
        
        [Parameter(Position=0,Mandatory=$true,ParameterSetname='AdObjectAudit')]
        [string]$AdObjectPath,

        [Parameter(Position=1,Mandatory=$true)]
        [ArgumentCompleter( {
            param (
                $CommandName,
                $ParameterName,
                $WordToComplete,
                $CommandAst,
                $FakeBoundParameters
            )
            [System.Security.Principal.WellKnownSidType].DeclaredMembers | Where-object { $_.IsStatic } | Select-Object -ExpandProperty name | Where-object {$_ -like "$wordToComplete*"}
        })]
        [String]$WellKnownSidType
    )
    DynamicParam {
        if ($PSCmdlet.ParameterSetName -eq 'AdObjectAudit')
        {
            $ParamOptions = @(
                @{
                'Name' = 'Rights';
                'Mandatory' = $true;
                'ValidateSetOptions' = ([System.DirectoryServices.ActiveDirectoryRights]).DeclaredMembers | Where-object { $_.IsStatic } | Select-Object -ExpandProperty name
                },
                @{
                'Name' = 'InheritanceFlags';
                'Mandatory' = $true;
                'ValidateSetOptions' = ([System.DirectoryServices.ActiveDirectorySecurityInheritance]).DeclaredMembers | Where-object { $_.IsStatic } | Select-Object -ExpandProperty name
                },
                @{
                'Name' = 'AuditFlags';
                'Mandatory' = $true;
                'ValidateSetOptions' = ([System.Security.AccessControl.AuditFlags]).DeclaredMembers | Where-object { $_.IsStatic } | Select-Object -ExpandProperty name
                },
                @{
                'Name' = 'AttributeGUID';
                'Mandatory' = $false;
                }
            )

            $DomainSidArray = ("AccountAdministratorSid","AccountGuestSid","AccountKrbtgtSid","AccountDomainAdminsSid","AccountDomainUsersSid","AccountDomainGuestsSid","AccountComputersSid","AccountControllersSid","AccountCertAdminsSid","AccountSchemaAdminsSid","AccountEnterpriseAdminsSid","AccountPolicyAdminsSid","AccountRasAndIasServersSid")
            if ($DomainSidArray.Contains($WellKnownSidType))
            {
                $DomainSidOption = @{
                    'Name' = 'DomainSid';
                    'Mandatory' = $true
                }
                $ParamOptions = @($DomainSidOption) + $ParamOptions
            }
        }
        else
        {
            If ($PSCmdlet.ParameterSetName -eq 'RegistryAudit'){$AccessRights = [System.Security.AccessControl.RegistryRights]}
            If ($PSCmdlet.ParameterSetName -eq 'FileAudit'){$AccessRights = [System.Security.AccessControl.FileSystemRights]}
            $ParamOptions = @(
                @{
                'Name' = 'Rights';
                'Mandatory' = $true;
                'ValidateSetOptions' = ($AccessRights).DeclaredMembers | Where-object { $_.IsStatic } | Select-Object -ExpandProperty name
                },
                @{
                'Name' = 'InheritanceFlags';
                'Mandatory' = $true;
                'ValidateSetOptions' = ([System.Security.AccessControl.InheritanceFlags]).DeclaredMembers | Where-object { $_.IsStatic } | Select-Object -ExpandProperty name
                },
                @{
                'Name' = 'PropagationFlags';
                'Mandatory' = $true;
                'ValidateSetOptions' = ([System.Security.AccessControl.PropagationFlags]).DeclaredMembers | Where-object { $_.IsStatic } | Select-Object -ExpandProperty name
                },
                @{
                'Name' = 'AuditFlags';
                'Mandatory' = $true;
                'ValidateSetOptions' = ([System.Security.AccessControl.AuditFlags]).DeclaredMembers | Where-object { $_.IsStatic } | Select-Object -ExpandProperty name
                }
            )
        }

        $RuntimeParamDic = New-Object System.Management.Automation.RuntimeDefinedParameterDictionary
        foreach ($Param in $ParamOptions) {
            $RuntimeParam = New-DynamicParam @Param
            $RuntimeParamDic.Add($Param.Name, $RuntimeParam)
        }
        return $RuntimeParamDic
    }

    begin {
        $PsBoundParameters.GetEnumerator() | ForEach-Object { New-Variable -Name $_.Key -Value $_.Value -ea 'SilentlyContinue'}
    }

    process
    {
        try 
        {
            if ($DomainSid)
            {
                $IdentityReference = New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]$WellKnownSidType, [System.Security.Principal.SecurityIdentifier]$DomainSid)
            }
            else
            {
                $IdentityReference = New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType] $WellKnownSidType,$Null)
            }
            if ($PSCmdlet.ParameterSetName -eq 'AdObjectAudit')
            {
                if ($AttributeGUID)
                {
                    $AuditRuleObject = New-Object System.DirectoryServices.ActiveDirectoryAuditRule($IdentityReference,$Rights,$AuditFlags,[guid]$AttributeGUID, $InheritanceFlags,[guid]'00000000-0000-0000-0000-000000000000')
                }
                else {
                    $AuditRuleObject = New-Object System.DirectoryServices.ActiveDirectoryAuditRule($IdentityReference,$Rights,$AuditFlags,[guid]'00000000-0000-0000-0000-000000000000', $InheritanceFlags,[guid]'00000000-0000-0000-0000-000000000000')
                    
                }
                $path = $AdObjectPath
            }
            else
            {
                If($PSCmdlet.ParameterSetName -eq 'RegistryAudit')
                {
                    $AuditRule = "System.Security.AccessControl.RegistryAuditRule"
                    $Path = $RegistryPath
                }
                If($PSCmdlet.ParameterSetName -eq 'FileAudit')
                {
                    $AuditRule = "System.Security.AccessControl.FileSystemAuditRule"
                    $Path = $FilePath
                }
                $AuditRuleObject = New-Object $AuditRule($IdentityReference,$Rights,$InheritanceFlags,$PropagationFlags,$AuditFlags)
            }
            $Acl = Get-Acl $Path -Audit
            Write-Verbose "[+] Old ACL: $($Acl | Format-List | Out-String)"
            Write-Verbose "[+] Adding ACE to SACL: $($AuditRuleObject | Out-String)"
            $Acl.SetAuditRule($AuditRuleObject)
            Set-Acl $Path $Acl
            Write-Verbose "[+] New ACL: $($Acl | Format-List | Out-String)"
        } 
        catch 
        {
            Write-Error $_.Exception.Message
        }
    }
}

function New-DynamicParam {
    [CmdletBinding()]
    [OutputType('System.Management.Automation.RuntimeDefinedParameter')]
    param (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Name,
        [Parameter(Mandatory=$false)]
        [array]$ValidateSetOptions,
        [Parameter()]
        [switch]$Mandatory = $false,
        [Parameter()]
        [switch]$ValueFromPipeline = $false,
        [Parameter()]
        [switch]$ValueFromPipelineByPropertyName = $false
    )

    $Attrib = New-Object System.Management.Automation.ParameterAttribute
    $Attrib.Mandatory = $Mandatory.IsPresent
    $Attrib.ValueFromPipeline = $ValueFromPipeline.IsPresent
    $Attrib.ValueFromPipelineByPropertyName = $ValueFromPipelineByPropertyName.IsPresent

    # Create AttributeCollection object for the attribute
    $Collection = new-object System.Collections.ObjectModel.Collection[System.Attribute]
    # Add our custom attribute
    $Collection.Add($Attrib)
    # Add Validate Set
    if ($ValidateSetOptions)
    {
        $ValidateSet= new-object System.Management.Automation.ValidateSetAttribute($Param.ValidateSetOptions)
        $Collection.Add($ValidateSet)
    }

    # Create Runtime Parameter
    if ($Param.Name -eq 'Rights' -or $Param.Name -eq 'AuditFlags')
    {
        $DynParam = New-Object System.Management.Automation.RuntimeDefinedParameter($Param.Name, [array], $Collection)
    }
    else
    {
        $DynParam = New-Object System.Management.Automation.RuntimeDefinedParameter($Param.Name, [string], $Collection)
    }
    $DynParam
}