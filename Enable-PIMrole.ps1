<#
.Synopsis
    Enable or disable Priviledged role in Azure PIM
.DESCRIPTION
    With this script you can enable or disable privileged role assignments
    You need to have the module AzureADPreview
   
    To get all active roles use this command
    .\Enable-PIM.ps1 -ShowActive
.EXAMPLE
    .\Enable-PIM.ps1 -pimroles 'Exchange Administrator','SharePoint Service Administrator', 'User Administrator' -ticketnumber "nvt" -reason "changes" -duration 8
    Enables roles Exchange Administrator, SharePoint Service Administrator and User Administrator
.EXAMPLE
    .\Enable-PIM.ps1 -pimroles 'Exchange Administrator','SharePoint Service Administrator', 'User Administrator' -ticketnumber "nvt" -reason "changes" -duration 8 -RenewRole
    Renews the roles Exchange Administrator, SharePoint Service Administrator and User Administrator
.EXAMPLE
    .\Enable-PIM.ps1 -pimroles 'Exchange Administrator','SharePoint Service Administrator' -Disable
    Disable roles Exchange Administrator and SharePoint Service Administrator
.EXAMPLE
    .\Enable-PIM.ps1 -DisableAll
    Disable all active roles
.EXAMPLE
    .\Enable-PIM.ps1 -ShowActive
    Shows all active roles
#>

Param
(
    # What PIM role should be activated
    [Parameter(Mandatory=$true, Position=1, ParameterSetName='Addrole')]
    [Parameter(ParameterSetName='Removerole')]
    [ValidateSet("Search Administrator","External ID User Flow Attribute Administrator","Guest User","Power Platform Administrator","Cloud Application Administrator","Compliance Administrator","Security Administrator","Exchange Administrator","Restricted Guest User","Device Managers","Office Apps Administrator","Insights Business Leader","Desktop Analytics Administrator","Intune Administrator","Teams Devices Administrator","B2C IEF Policy Administrator","Dynamics 365 Administrator","Reports Reader","Partner Tier1 Support","License Administrator","Customer LockBox Access Approver","Security Reader","Security Operator","Global Administrator","Printer Administrator","Teams Administrator","External ID User Flow Administrator","Helpdesk Administrator","Azure Information Protection Administrator","Kaizala Administrator","Usage Summary Reports Reader","Skype for Business Administrator","Cloud Device Administrator","Message Center Reader","Privileged Authentication Administrator","Search Editor","Directory Readers","Hybrid Identity Administrator","Directory Writers","Guest Inviter","Password Administrator","Application Administrator","Device Join","Attack Payload Author","Azure AD Joined Device Local Administrator","Power BI Administrator","B2C IEF Keyset Administrator","Message Center Privacy Reader","Billing Administrator","Conditional Access Administrator","Teams Communications Administrator","External Identity Provider Administrator","Workplace Device Join","Attack Simulation Administrator","Authentication Administrator","Application Developer","Directory Synchronization Accounts","Network Administrator","Device Users","Partner Tier2 Support","Azure DevOps Administrator","Compliance Data Administrator","Privileged Role Administrator","Printer Technician","Insights Administrator","Service Support Administrator","SharePoint Administrator","Global Reader","Teams Communications Support Engineer","Teams Communications Support Specialist","Groups Administrator","User Administrator")]
    [string[]]$pimroles,

    # What is the ticketnumber
    [Parameter(Mandatory=$true, Position=1, ParameterSetName='Addrole')]
    [string]$ticketnumber,

    # What is the reason for activating
    [Parameter(Mandatory=$true, Position=2, ParameterSetName='Addrole')]
    [string]$reason,

    # What is the duration for the activation.
    [Parameter(Mandatory=$true, Position=3, ParameterSetName='Addrole')]
    [int]$duration,

    # should we disable the role? Default is enable
    [Parameter(Mandatory=$true, ParameterSetName='Removerole')]
    [switch]$Disable,

    # should we remove all roles
    [Parameter(Mandatory=$true, ParameterSetName='RemoveAllroles')]
    [switch]$DisableAll,

    # should we renew the roles
    [Parameter(Mandatory=$false, ParameterSetName='Addrole')]
    [switch]$RenewRole,

    # Show Active Roles
    [Parameter(Mandatory=$false, ParameterSetName='ShowActive')]
    [switch]$ShowActive
)

# Check if we are connected to AzureAD
try 
{
    $tenantInfo = Get-AzureADCurrentSessionInfo -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
    $tenantId = $tenantInfo.TenantId
}
catch
{
    Connect-AzureAD
    $tenantId =(Get-AzureADCurrentSessionInfo).TenantId
}

$providerId = "aadRoles"
$currentUser = (Get-AzureADUser -SearchString (Get-AzureADCurrentSessionInfo).Account).ObjectId

$Allroledefs = Get-AzureADMSPrivilegedRoleDefinition -ProviderId $providerId -ResourceId $tenantId
$indexedRolesId = @{}
$i=0
$Allroledefs.foreach({
    $indexedRolesId["$($psitem.ExternalId)"] = $i
    $i++
})
$indexedRolesName = @{}
$i=0
$Allroledefs.foreach({
    $indexedRolesName["$($psitem.DisplayName)"] = $i
    $i++
})
$myRoles = Get-AzureADMSPrivilegedRoleAssignment -ProviderId $providerId -ResourceId $tenantId -Filter "subjectId eq '$currentUser'"

if($DisableAll.IsPresent)
{
    # Disable all roles
    Write-Host "Disabling all active roles"
    $myRoles | Where-Object {$_.AssignmentState -eq "Active" -and $_.null -ne $_.EndDateTime} | ForEach-Object {
        Write-Host "Disabling $(($Allroledefs[($indexedRolesId[$_.RoleDefinitionId])]).DisplayName)" -ForegroundColor Green
        $roleId = ($Allroledefs[($indexedRolesId[$_.RoleDefinitionId])]).ExternalId
        $schedule = New-Object Microsoft.Open.MSGraph.Model.AzureADMSPrivilegedSchedule
        Open-AzureADMSPrivilegedRoleAssignmentRequest -ProviderId $providerId -ResourceId $tenantId -RoleDefinitionId $roleId -SubjectId $currentUser -Type 'UserRemove' -AssignmentState 'Active' -Schedule $schedule | Out-Null
    }    
}
elseif ($ShowActive.IsPresent) 
{
    Get-AzureADMSPrivilegedRoleAssignment -ProviderId $providerId -ResourceId $tenantId -Filter "subjectId eq '$currentUser' and assignmentState eq 'Active'" | ForEach-Object {
        Write-Output "$(($Allroledefs[($indexedRolesId[$_.RoleDefinitionId])]).DisplayName) until $($_.EndDateTime.ToString('dd MMM yyyy HH:mm'))"
    }
}
else
{
    $schedule = New-Object Microsoft.Open.MSGraph.Model.AzureADMSPrivilegedSchedule
    $schedule.Type = "Once"
    $schedule.StartDateTime = Get-Date
    $schedule.endDateTime = $schedule.StartDateTime.AddHours($duration)

    foreach($pimrole in $pimroles)
    {
        $roleId = ($Allroledefs[($indexedRolesName[$pimrole])]).ExternalId
        $myRole = $myRoles | Where-Object { $_.RoleDefinitionId -eq $roleId}
        if($null -eq $myRole)
        {
            Write-Error -Message "Cannot find '$pimrole' for your account"
        }
        else 
        {
            $activeRole = $myRole |Where-Object{ $_.AssignmentState -eq "Active"}
            if($Disable.IsPresent)
            {
                Write-Host "Disabling $pimrole" -ForegroundColor Green
                $schedule = New-Object Microsoft.Open.MSGraph.Model.AzureADMSPrivilegedSchedule
                Open-AzureADMSPrivilegedRoleAssignmentRequest -ProviderId $providerId -ResourceId $tenantId -RoleDefinitionId $roleId -SubjectId $currentUser -Type 'UserRemove' -AssignmentState 'Active' -Schedule $schedule | Out-Null
            }
            elseif($null -ne $activeRole -and !$RenewRole.IsPresent)
            {
                Write-Host "$pimrole is already enabled, until $($activeRole.EndDateTime.ToString('dd MMM yyyy HH:mm'))" -ForegroundColor Yellow
            }
            else
            {
                Write-Host "Enabling $pimrole for $duration hours"
                Open-AzureADMSPrivilegedRoleAssignmentRequest -ProviderId $providerId -ResourceId $tenantId -RoleDefinitionId $roleId -SubjectId $currentUser -Type 'UserAdd' -AssignmentState 'Active' -Schedule $schedule -reason "Ticketnumber: $ticketnumber; Reason: $reason" | Out-Null
                $until = $schedule.endDateTime.ToString("dd MMM yyyy HH:mm")
                Write-Host "Enabled until $until" -ForegroundColor Green
            }
        }
    }

    Write-Host "Reconnect to Azure AD for the roles to become active" -ForegroundColor Yellow
}
