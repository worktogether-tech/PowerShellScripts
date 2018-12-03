<#
.Synopsis
   Enable or disable Priviledged role in Azure PIM
.DESCRIPTION
   With this script you can enable or disable privileged role assignments
   You need to have the module Microsoft.Azure.ActiveDirectory.PIM.PSModule
   
   To get all active roles use this command Get-PrivilegedRoleAssignment |? {$_.IsElevated -eq $true -and $_.IsPermanent -eq $false}
.EXAMPLE
   .\Enable-PIMrole.ps1 -pimroles 'Exchange Administrator','SharePoint Service Administrator', 'User Administrator' -ticketnumber "nvt" -reason "changes" -duration 8
   Enables roles Exchange Administrator, SharePoint Service Administrator and User Administrator
.EXAMPLE
   .\Enable-PIMrole.ps1 -pimroles 'Exchange Administrator','SharePoint Service Administrator' -Disable
   Disable roles Exchange Administrator and SharePoint Service Administrator
.EXAMPLE
   .\Enable-PIMrole.ps1 -DisableAll
   Disable all active roles
#>

Param
(
    # What PIM role should be activated
    [Parameter(Mandatory=$true, Position=1, ParameterSetName='Addrole')]
    [Parameter(ParameterSetName='Removerole')]
    [ValidateSet("Application Administrator","Application Developer","Billing Administrator","Cloud Application Administrator","Cloud Device Administrator","Compliance Administrator","Conditional Access Administrator","CRM Service Administrator","Customer LockBox Access Approver","Desktop Analytics Administrator","Device Administrators","Directory Readers","Directory Writers","Exchange Administrator","Global Administrator","Guest Inviter","Information Protection Administrator","Intune Service Administrator","License Administrator","Message Center Reader","Password Administrator","Power BI Service Administrator","Privileged Role Administrator","Reports Reader","Security Administrator","Security Reader","Service Administrator","SharePoint Service Administrator","Skype for Business Administrator","Teams Communications Administrator","Teams Communications Support Engineer","Teams Communications Support Specialist","Teams Service Administrator","User Administrator")]
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
    [switch]$DisableAll
)

#check if we are connected to PIM
if([string]::IsNullOrEmpty((Show-PimServiceConnection).UserName))
{
    Connect-PimService
}

if($DisableAll)
{
    # Disable all roles
    Write-Host "Disabling all active roles"
    Get-PrivilegedRoleAssignment | Where-Object {$_.IsElevated -eq $true -and $_.IsPermanent -eq $false} | Disable-PrivilegedRoleAssignment
}
else
{
    foreach($pimrole in $pimroles)
    {
        $roleAssignment = $null
        $roleAssignment = Get-PrivilegedRoleAssignment | Where-Object {$_.RoleName -eq $pimrole}
        if([string]::IsNullOrEmpty($roleAssignment))
        {
            Write-Error -Message "Cannot find $pimrole for your account"
        }
        else
        {
            $roleid = $roleAssignment.RoleId
            if($Disable)
            {
                Write-Host "Disabling $pimrole"
                Disable-PrivilegedRoleAssignment -RoleId $roleid
            }
            else
            {
                Write-Host "Enabling $pimrole for $duration hours"
                Enable-PrivilegedRoleAssignment -TicketNumber $ticketnumber -Reason $reason -Duration $duration -RoleId $roleid
            }
        }
    }
}
