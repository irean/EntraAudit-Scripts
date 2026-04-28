[CmdletBinding()]
param()
#helper method to manager fething paged results
function igall {
    [CmdletBinding()]
    param (
        [string]$Uri
    )
    $nextUri = $uri
    do {
        $result = $null
        $time = Measure-Command { 
            $result = Invoke-MgGraphRequest -Method GET -Uri $nextUri
        }
        Write-Debug "callto $nextURI took $time"
        $nextUri = $result.'@odata.nextLink'
        if ($result -and $result.ContainsKey('value')) {
            $result.value
        }
        else {
            $result
        }
    } while ($nextUri)
}



$cache = @{}
function Get-User {
    param (
        [string]$Id
    )

    
    if (-not $cache[$Id]) {

        $user = igall "https://graph.microsoft.com/v1.0/users/$($id)?`$select=Displayname%2CUserprincipalname%2CUsertype%2CcompanyName%2CaccountEnabled%2CCreatedDatetime%2CLastPasswordChangeDateTime%2csignInActivity%2clastNonInteractiveSignInDateTime%2clastSignInDateTime%2CassignedLicenses%2CassignedPlans"

        $temp = [pscustomobject]$user
        $result = $temp
        | Add-Member -NotePropertyName lastSignInDateTime -NotePropertyValue $user.signInActivity.lastSignInDateTime -Force -PassThru
        | Add-Member -NotePropertyName lastNonInteractiveSignInDateTime -NotePropertyValue $user.signInActivity.lastNonInteractiveSignInDateTime -Force -PassThru
        | Add-Member -NotePropertyName hasStrongMFA -NotePropertyValue $false -Force -PassThru
        | Add-Member -NotePropertyName 'Roles' -NotePropertyValue @() -PassThru -Force
        | Add-Member -NotePropertyName "EligibleRoles" -NotePropertyValue @() -PassThru -Force
        | Add-Member -NotePropertyName 'AzureRoles' -NotePropertyValue @() -PassThru -Force
        | Add-Member -NotePropertyName 'AdminRiskScore' -NotePropertyValue 0 -PassThru -Force
        | Add-Member -NotePropertyName 'AdminRiskLevel' -NotePropertyValue 0 -PassThru -Force


        Start-Sleep -Milliseconds 250 

        $auth = Invoke-MgGraphRequest -Method GET  -Uri "https://graph.microsoft.com/beta/users/$Id/authentication/methods"
        $count = $auth.value.'@odata.type' | Where-Object {
            $_ -notmatch 'passwordAuthenticationMethod|phoneAuthenticationMethod'
        } | measure-object 

        $result | Add-Member -NotePropertyName StrongAuthCount -NotePropertyValue $count.count -Force

        foreach ($method in $auth.value) {

            switch ($method.'@odata.type') {

                '#microsoft.graph.passwordAuthenticationMethod' {
                    $result | Add-Member -NotePropertyName AuthPassword -NotePropertyValue $method.createdDateTime -Force

                }

                '#microsoft.graph.phoneAuthenticationMethod' {
                    $result | Add-Member -NotePropertyName AuthPhone -NotePropertyValue $method.phoneNumber -Force

                    
                }

                '#microsoft.graph.microsoftAuthenticatorAuthenticationMethod' {
                    $result | Add-Member -NotePropertyName AuthMicrosoftAuthenticator -NotePropertyValue $method.displayName -Force
                    $result.hasStrongMFA = $true
                }

                '#microsoft.graph.passwordlessMicrosoftAuthenticatorAuthenticationMethod' {
                    $result | Add-Member -NotePropertyName AuthPasswordless -NotePropertyValue $method.displayName -Force
                    $result.hasStrongMFA = $true
                }

                '#microsoft.graph.fido2AuthenticationMethod' {

                    $result | Add-Member -NotePropertyName AuthFido2 -NotePropertyValue $method.displayName -Force
                    $result.hasStrongMFA = $true

                }
            }
        }
        if ($user.assignedLicenses.Count -gt 0) {
            $result | Add-Member -NotePropertyName IsLicensed -NotePropertyValue $true -Force
            $result | Add-Member -NotePropertyName ProductivityServicesEnabled -NotePropertyValue $true -Force
        }
        else {
            $result | Add-Member -NotePropertyName IsLicensed -NotePropertyValue $false -Force
            $result | Add-Member -NotePropertyName ProductivityServicesEnabled -NotePropertyValue $false -Force
        }


        $cache[$Id] = $result
    }

    return $cache[$Id]
}

function Get-ServicePrincipal {
    param (
        [string]$Id
    )
    # todo hämta service principal
    
    if (-not $cache[$Id]) {
        $user = igall "https://graph.microsoft.com/v1.0/servicePrincipals/$($id)?`$select=id,displayName,appId,servicePrincipalType"
        if (-not $user) {
            $cache[$id] = $null
            return $null
        }
        $temp = [pscustomobject]$user
        $result = $temp
        | Add-Member -NotePropertyName lastSignInDateTime -NotePropertyValue '' -Force -PassThru
        | Add-Member -NotePropertyName lastNonInteractiveSignInDateTime -NotePropertyValue '' -Force -PassThru
        | Add-Member -NotePropertyName hasStrongMFA -NotePropertyValue $false -Force -PassThru
        | Add-Member -NotePropertyName 'Roles' -NotePropertyValue @() -PassThru -Force
        | Add-Member -NotePropertyName "EligibleRoles" -NotePropertyValue $() -PassThru -Force
        | Add-Member -NotePropertyName 'AzureRoles' -NotePropertyValue @() -PassThru -Force
        | Add-Member -NotePropertyName 'AdminRiskScore' -NotePropertyValue 0 -PassThru -Force
        | Add-Member -NotePropertyName 'AdminRiskLevel' -NotePropertyValue 0 -PassThru -Force
        | Add-Member -NotePropertyName 'UserType' -NotePropertyValue 'ServicePrincipal' -PassThru -Force
        | Add-Member -NotePropertyName 'ServicePrincipalType' -NotePropertyValue $user.servicePrincipalType -PassThru -Force
        $cache[$Id] = $result
    }

    return $cache[$Id]
}


# ROLE RISK
$RoleRiskTable = @{
    "Global Administrator"          = 10
    "Privileged Role Administrator" = 9
    "Security Administrator"        = 8
    "User Administrator"            = 7
    "Groups Administrator"          = 6
}


function Get-AdminRiskScore {
    param($User)

    # ==================================================
    # 0. BASELINE
    # ==================================================
    if ($User.accountEnabled -eq $false) {
        return 0
    }

    $score = 0

    # ==================================================
    # 1. IMPACT (Privilege power)
    # ==================================================
    $impact = 0

    foreach ($role in $User.Roles) {
        if ($RoleRiskTable.ContainsKey($role)) {
            $impact = [math]::Max($impact, $RoleRiskTable[$role])
        }
        else {
            $impact = [math]::Max($impact, 4)
        }
    }

    foreach ($role in $User.EligibleRoles.Role) {
        if ($RoleRiskTable.ContainsKey($role)) {
            #  Eligible is almost as dangerous
            $impact = [math]::Max($impact, ($RoleRiskTable[$role] * 0.95))
        }
        else {
            $impact = [math]::Max($impact, 4)
        }
    }

    foreach ($az in $User.AzureRoles) {
        if ($az.RoleDefinitionName -match "Owner") { $impact = [math]::Max($impact, 10) }
        elseif ($az.RoleDefinitionName -match "User Access Administrator") { $impact = [math]::Max($impact, 9) }
        elseif ($az.RoleDefinitionName -match "Contributor") { $impact = [math]::Max($impact, 7) }
    }

    # Role chaining
    if ($User.EligibleRoles.Count -ge 2 -or $User.Roles.Count -ge 2) {
        $impact += 1
    }

    # ==================================================
    # 2. LIKELIHOOD (Compromise probability)
    # ==================================================
    $likelihood = 1

    $hasPrivilegedRole =
    ($User.Roles.Count -gt 0) -or
    ($User.EligibleRoles.Count -gt 0)

    # MFA
    if ($User.UserType -eq "Guest") {
        $likelihood += 2
    }
    elseif (-not $User.hasStrongMFA) {
        $likelihood += 10
    }
    else {
        if ($User.StrongAuthCount -eq 1) { $likelihood += 4 }
        if ($User.AuthPhone) { $likelihood += 2 }

        if (-not $User.AuthFido2 -and -not $User.AuthPasswordless) {
            $likelihood += 2
        }

        if ($User.AuthFido2) { $likelihood -= 1 }
    }

    # Sign-in
    if (-not $User.lastSignInDateTime) {
        $likelihood += 4
    }
    else {
        $last = [datetime]$User.lastSignInDateTime

        if ($last -lt (Get-Date).AddDays(-90)) { $likelihood += 3 }
        elseif ($last -lt (Get-Date).AddDays(-30)) { $likelihood += 1 }
    }

    # Password
    if (-not $User.AuthFido2 -and -not $User.AuthPasswordless) {
        if ($User.LastPasswordChangeDateTime) {
            $pwd = [datetime]$User.LastPasswordChangeDateTime

            if ($pwd -lt (Get-Date).AddDays(-365)) { $likelihood += 3 }
            elseif ($pwd -lt (Get-Date).AddDays(-180)) { $likelihood += 1 }
        }
    }

    #  PIM activation is NOT safe
    if (-not $User.Roles.Count -and $User.EligibleRoles.Count -gt 0) {
        $likelihood += 2
    }

    # ==================================================
    # 3. EXPOSURE (Blast radius)
    # ==================================================
    $exposure = 0

    if ($User.ProductivityServicesEnabled) { $exposure += 5 }
    elseif ($User.IsLicensed) { $exposure += 2 }

    if ($User.AzureRoles.Count -gt 0) { $exposure += 2 }

    if ($User.UserType -eq "Guest") { $exposure += 2 }

    # ==================================================
    # 4. BASE SCORE
    # ==================================================
    $score = ($impact * 0.5) + ($likelihood * 0.3) + ($exposure * 0.2)

    # ==================================================
    # 5. HARD SECURITY RULES (REAL WORLD)
    # ==================================================

    #  Admin without MFA = CRITICAL pattern
    if ($hasPrivilegedRole -and -not $User.hasStrongMFA) {
        $score = [math]::Max($score, 15)
    }

    #  High privilege floor
    if ($impact -ge 8) {
        $score = [math]::Max($score, 12)
    }
    elseif ($impact -ge 6) {
        $score = [math]::Max($score, 8)
    }

    #  Inactive privileged accounts
    if ($hasPrivilegedRole -and $User.lastSignInDateTime) {
        $last = [datetime]$User.lastSignInDateTime

        if ($last -lt (Get-Date).AddDays(-90)) {
            $score = [math]::Max($score, 12)
        }
    }

    # ==================================================
    # 6. CRITICAL ESCALATION (ATTACK PATHS)
    # ==================================================

    $hasGlobalAdmin = $User.Roles -contains "Global Administrator"
    $hasEligibleGA = $User.EligibleRoles.Role -contains "Global Administrator"

    $criticalRoles = @(
        "Global Administrator",
        "Privileged Role Administrator",
        "Security Administrator"
    )

    $criticalCount = ($User.Roles | Where-Object { $_ -in $criticalRoles }).Count

    $hasAzureOwner = $User.AzureRoles | Where-Object {
        $_.RoleDefinitionName -match "Owner"
    }
    $hasEntraAdmin = $User.Roles.Count -gt 0

    #  Standing Global Admin
    if ($hasGlobalAdmin -and -not $hasEligibleGA) {
        $score = [math]::Max($score, 20)
    }

    #  Role chaining
    if ($criticalCount -ge 2) {
        $score = [math]::Max($score, 18)
    }

    # Identity + Azure control
    if ($hasAzureOwner -and $hasEntraAdmin) {
        $score = [math]::Max($score, 18)
    }

    #  Worst case combo
    if (
        ($hasGlobalAdmin -and -not $hasEligibleGA) -and
        ($criticalCount -ge 2) -and
        $hasAzureOwner
    ) {
        $score = [math]::Max($score, 22)
    }

    # ==================================================
    # 7. LIMITED RISK REDUCTION
    # ==================================================
    if (
        $User.AuthFido2 -and
        $User.StrongAuthCount -ge 2 -and
        $User.hasStrongMFA
    ) {
        if ($score -gt 10) {
            $score -= 1
        }
    }

    # ==================================================
    # 8. FINAL
    # ==================================================
    if ($score -gt 30) { $score = 30 }

    return [math]::Round($score, 1)
}

function Get-ExploitabilityScore {
    param($User)

    $score = 0

    $hasPrivilegedRole =
    ($User.Roles.Count -gt 0) -or
    ($User.EligibleRoles.Count -gt 0)

    # 🚨 NO MFA = biggest signal
    if (-not $User.hasStrongMFA) { $score += 10 }

    # Weak MFA
    if ($User.StrongAuthCount -eq 1) { $score += 3 }
    if ($User.AuthPhone) { $score += 2 }

    # No phishing-resistant MFA
    if (-not $User.AuthFido2 -and -not $User.AuthPasswordless) {
        $score += 3
    }

    # Never signed in
    if (-not $User.lastSignInDateTime) { $score += 3 }

    # Old password
    if ($User.LastPasswordChangeDateTime) {
        $pwd = [datetime]$User.LastPasswordChangeDateTime
        if ($pwd -lt (Get-Date).AddDays(-365)) { $score += 3 }
    }

    #  Eligible admin is still exploitable
    if ($User.EligibleRoles.Count -gt 0 -and $User.Roles.Count -eq 0) {
        $score += 3
    }

    # Only care about privileged identities
    if (-not $hasPrivilegedRole) {
        return 0
    }

    return [math]::Min($score, 20)
}
function Get-AttackPathScore {
    param($User)

    $score = 0

    $hasPrivileged =
    ($User.Roles.Count -gt 0) -or
    ($User.EligibleRoles.Count -gt 0)

    if (-not $hasPrivileged) { return 0 }

    # ENTRY
    if (-not $User.hasStrongMFA) { $score += 8 }

    # ESCALATION
    if ($User.EligibleRoles.Count -gt 0) { $score += 5 }

    # IMPACT
    if ($User.Roles -contains "Global Administrator") { $score += 10 }

    if ($User.AzureRoles.RoleDefinitionName -match "Owner") {
        $score += 8
    }

    return [math]::Min($score, 25)
}
function Get-AttackRole {
    param($User)

    # --- IMPACT FIRST ---
    if (
        ($User.Roles -contains "Global Administrator") -or
        ($User.AzureRoles.RoleDefinitionName -match "Owner")
    ) {
        return "Impact"
    }

    # --- ESCALATION ---
if (
    $User.EligibleRoles.Count -gt 0 -and
    (
        -not $User.hasStrongMFA -or
        $User.StrongAuthCount -le 1
    )
) {
    return "Escalation"
}
    # --- ENTRY ---
    if (-not $User.hasStrongMFA) {
        return "Entry"
    }

    return "Other"
}
function Get-AdminRiskLevel {

    param($Score)

    if ($Score -ge 20) { return "Critical" }
    elseif ($Score -ge 12) { return "High" }
    elseif ($Score -ge 6) { return "Medium" }
    else { return "Low" }
}

function Add-SafeFormatting {
    param($ws, $column, $rows)

    if ($rows -le 1) { return }

    $range = "$column`2:$column$rows"

    Add-ConditionalFormatting -Worksheet $ws -Address $range -RuleType ContainsText -ConditionValue "Critical" -BackgroundColor Red
    Add-ConditionalFormatting -Worksheet $ws -Address $range -RuleType ContainsText -ConditionValue "High" -BackgroundColor Orange
    Add-ConditionalFormatting -Worksheet $ws -Address $range -RuleType ContainsText -ConditionValue "Medium" -BackgroundColor Yellow
    Add-ConditionalFormatting -Worksheet $ws -Address $range -RuleType ContainsText -ConditionValue "Low" -BackgroundColor LightGreen
}



function test-module {
    [CmdletBinding()]
    param(
        [String]$Name
  
    )
    Write-Host "Checking module $name..." -ForegroundColor Cyan
    if (-not (Get-Module $Name)) {
        Write-Host "Module $Name not imported, trying to import..." -ForegroundColor Yellow
        try {
            if ($Name -eq 'Microsoft.Graph') {
                Write-Host "Microsoft.Graph module import takes a while..." -ForegroundColor Yellow
                Import-Module $Name  -ErrorAction Stop
            }
            elseif ($Name -eq 'Az') {
                Write-Host "Module Az is being imported. This might take a while..." -ForegroundColor Yellow
            }
            else {
                Import-Module $Name  -ErrorAction Stop
            }
        
        }
        catch {
            Write-Host "Module $Name not found, trying to install..." -ForegroundColor Yellow
            Install-Module $Name -Scope CurrentUser -AllowClobber -Force -AcceptLicense -SkipPublisherCheck
            Write-Host "Importing module $Name..." -ForegroundColor Yellow
            Import-Module $Name -ErrorAction Stop
        }
    } 
    else {
        Write-Host "Module $Name is already imported." -ForegroundColor Green
    }   
}
#imports /installs require modules 
Write-Host "Importing required modules: Az.Resources, Az.Accounts, Microsoft.Graph.Authentication, ImportExcel" -ForegroundColor Cyan
Test-Module -Name Az.Resources
Test-Module -Name Az.Accounts
Test-Module -Name Microsoft.Graph.Authentication
Test-Module -Name ImportExcel
Write-Host "✅ All modules are installed and imported." -ForegroundColor Green
# Disconnect any existing sessions
Write-Host "Disconnecting any existing sessions..." -ForegroundColor Cyan
disconnect-Mggraph -ErrorAction SilentlyContinue
Disconnect-AzAccount  
Write-Host "✅ All sessions disconnected." -ForegroundColor Green
# Connect new sessions
Write-Host "Connecting to AzAccount..." -ForegroundColor Cyan
Disable-AzContextAutosave -Scope Process
Update-AzConfig -LoginExperienceV2 Off -Scope Process
Connect-AzAccount
Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Cyan
 Connect-MgGraph -Scopes 'RoleManagement.Read.Directory', 'User.Read.All', 'User.ReadBasic.All', 'User.Read', 'GroupMember.Read.All', 'Group.Read.All', 'Directory.Read.All', 'Directory.AccessAsUser.All', 'RoleEligibilitySchedule.Read.Directory', 'RoleManagement.Read.All', 'SecurityActions.Read.All', 'SecurityActions.ReadWrite.All', 'SecurityEvents.Read.All', "Organization.Read.All", "AuditLog.Read.All", "UserAuthenticationMethod.Read.All"   -ContextScope Process
Write-Host "✅ You are now fully connected!" -ForegroundColor Green


# Select folder for export 
Write-Host "--------------------------------------------------------" -ForegroundColor DarkGray
Write-Host "Please select a folder where the report will be saved." -ForegroundColor Cyan
Write-Host "⚠️  The folder selection window may appear behind other open windows." -ForegroundColor Yellow
Write-Host "If you don't see it, try minimizing other windows." -ForegroundColor Yellow
Write-Host "--------------------------------------------------------" -ForegroundColor DarkGray
Add-Type -AssemblyName System.Windows.Forms
$FileBrowser = New-Object System.Windows.Forms.FolderBrowserDialog -Property @{ 
    InitialDirectory = [Environment]::GetFolderPath('Desktop') 
}
$result = $FileBrowser.ShowDialog(((New-Object System.Windows.Forms.Form -Property @{TopMost = $true })))
if ($result -eq [Windows.Forms.DialogResult]::OK) {
    $folder = $FileBrowser.SelectedPath
    Write-Host "Export folder selected: $folder" -ForegroundColor Green
}
else {
    Write-Host "❌ No folder selected. Exiting script." -ForegroundColor Red
    return
}

#Get org displayname
Write-Host "Fetching organization display name..." -ForegroundColor Yellow
$orgdisplayname = igall https://graph.microsoft.com/beta/organization | Select-Object -ExpandProperty displayName
Write-Host "Organization: $orgdisplayname" -ForegroundColor Green
    
$date = Get-Date -Format yyyy-MM-dd
Write-Host "Fetching directory roles..." -ForegroundColor Yellow
$directoryRoles = igall https://graph.microsoft.com/beta/directoryRoles | foreach-object {
    [PsCustomObject]$_
}
Write-Host "✅ Retrieved $($directoryRoles.Count) directory roles." -ForegroundColor Green

# In a live tenant the will be a lot of instances so we filter
# on endDateTime to limit the responses to active instances
$now = (Get-Date -AsUTC).ToString("yyyy-MM-ddTHH:mm:ssZ")
Write-Host "Fetching active role assignments (PIM activated roles)..." -ForegroundColor Yellow
$assignmentSchedules = @()
$assignmentSchedules += igall  "https://graph.microsoft.com/beta/roleManagement/directory/roleAssignmentScheduleInstances?`$expand=roleDefinition,principal&`$filter=assignmentType eq 'Activated' and endDateTime ge $now" | ForEach-Object {
    [PsCustomObject]$_
} |
Where-Object {
    $_.RoleDefinitionId -in $directoryRoles.roleTemplateId
}
Write-Host "✅ Retrieved $($assignmentSchedules.Count) active assignment schedules." -ForegroundColor Green
# Fetch role assignments to be able to filter out
# admins that have used PIM to activate a role
Write-Host "Fetching assignment admins..." -ForegroundColor Yellow
$assignmentAdmins = @()
$assignmentAdmins += $assignmentSchedules | Where-Object {
    $_.principal.'@odata.type' -notmatch "#microsoft.graph.servicePrincipal"
} | ForEach-Object {
    $assignment = $_
    if ($_.principal.'@odata.type' -match '#microsoft.graph.group') {
        igall -Uri "https://graph.microsoft.com/beta/groups/$($assignment.principalId)/transitiveMembers" | ForEach-Object {
            $member = [pscustomobject]$_
            Add-Member -InputObject $member -NotePropertyName 'Role' -NotePropertyValue $assignment.roleDefinition.displayName -PassThru
        }
        
    }
    else {
        $member = Get-User -Id $_.principalId
        $member = $member | Select-Object *
        Add-Member -InputObject $member -NotePropertyName 'Role' -NotePropertyValue $assignment.roleDefinition.displayName -PassThru
    }
}
Write-Host "✅ Assignment admins processed." -ForegroundColor Green
Write-Host "Building administrator list..." -ForegroundColor Yellow
$administrators = $directoryRoles | ForEach-Object {
    $role = $_.displayName    
    Write-Host "───────────────────────────────────────────────" -ForegroundColor DarkGray
    Write-Host "🔹 Processing directory role: $role" -ForegroundColor Cyan
    Write-Host " → Fetching members of role '$role'..." -ForegroundColor DarkGray
    igall -Uri "https://graph.microsoft.com/beta/directoryRoles/$($_.id)/members" | ForEach-Object {
        $member = [PSCustomObject]$_
        if ($member.'@odata.type' -notmatch 'group|ServicePrincipal') {
            Write-Host "   ↳ Found user: $($member.displayName)" -ForegroundColor Cyan
            Write-Host "     → Getting user details from Graph..." -ForegroundColor DarkGray
            $user = Get-User -id $member.id 

            Write-Host "     → Adding user '$($user.DisplayName)' to role '$role'" -ForegroundColor Yellow
            
            $user.Roles += $role

              
            Write-Host "     ✅ Completed: $($user.DisplayName)" -ForegroundColor Green
            $user
        }
        elseif ($member.'@odata.type' -match 'group') {
            Write-Host "   ↳ Expanding group: $($member.displayName)" -ForegroundColor Cyan
            Write-Host "     → Fetching transitive members..." -ForegroundColor DarkGray

            igall -Uri "https://graph.microsoft.com/beta/groups/$($member.id)/transitiveMembers" | ForEach-Object {
                Write-Host "       ↳ Adding group member: $($_.displayName)" -ForegroundColor Yellow
                $member = [PSCustomObject]$_
                Add-Member -InputObject $member -NotePropertyName 'Role' -NotePropertyValue $role -PassThru  
                Write-Host "       ✅ Added $($member.DisplayName) (from group $($member.displayName))" -ForegroundColor Green
            }
            
        }
    }
} | Sort-Object -Property id | Sort-Object -Unique -Property id | 
Where-Object {
    # Filter out PIM activated admins as they
    # are displayed in the Eligible sheet
    $admin = $_
    $foundInAssignments = $assignmentAdmins | Where-Object {
        $admin.id -match $_.id -and $admin.Roles -contains $_.Role
    }
    -not $foundInAssignments
} 

Write-Host "✅ Administrator list compiled successfully." -ForegroundColor Green
Write-Host "───────────────────────────────────────────────" -ForegroundColor DarkGray
Write-Host "Fetching eligible roles..." -ForegroundColor Yellow
$eligible = igall -Uri 'https://graph.microsoft.com/beta/roleManagement/directory/roleEligibilityScheduleInstances/?$expand=roleDefinition,principal' | ForEach-Object {
    $e = [PSCustomObject]$_
    $principal = [PSCustomObject]$e.principal
        
    if ($e.memberType -match 'Direct' -and $principal.'@odata.type' -notmatch 'group|ServicePrincipal') {
        Write-Host "Processing eligible direct user: $($principal.displayName)" -ForegroundColor Cyan
        Write-Host " → Fetching detailed info for $($principal.userPrincipalName)" -ForegroundColor DarkGray
        $user = Get-User -id $principal.id  
        Write-Host " → Adding role '$($e.roleDefinition["displayName"])' (MemberType: $($e.memberType))" -ForegroundColor Yellow
            
        $user.EligibleRoles += [pscustomobject]@{
            'Role'       = $e.roleDefinition.displayName
            'MemberType' = $e.memberType
        }

        $user
        Write-Host " ✅ Completed processing for $($principal.DisplayName)" -ForegroundColor Green

    }
    elseif ($principal.'@odata.type' -match 'group') {
        Write-Host "Expanding eligible group: $($e.principal.displayName)" -ForegroundColor Cyan
        Write-Host " → Fetching members from group ID: $($e.principalId)" -ForegroundColor DarkGray
        $groupMembers = igall -Uri "https://graph.microsoft.com/beta/groups/$($e.principalId)/transitiveMembers" | Sort-Object id -Unique
        $total = $groupMembers.Count
        $counter = 0
        $groupMembers | ForEach-Object  -Begin {
            Write-Progress -Activity "Expanding group: $($e.principal.displayName)" -Status "0 of $total members" -PercentComplete 0
        } -Process {
            $counter++
            $percent = [math]::Round(($counter / $total) * 100, 2)
            Write-Progress -Activity "Expanding group: $($e.principal.displayName)" -Status "$counter of $total members" -PercentComplete $percent
            if ($_.'@odata.type' -eq '#microsoft.graph.user') {

                $user = Get-User -id $_.id
            }
            elseif ($_.'@odata.type' -eq '#microsoft.graph.servicePrincipal') {
                $user = Get-ServicePrincipal -id $_.id
            }
            elseif ($_.'@odata.type' -eq '#microsoft.graph.group') {

                Write-Warning "Nested group detected: $($_.displayName)"

                $nested = [pscustomobject]@{
                    displayName                = $_.displayName
                    UserPrincipalName          = $null
                    EligibleRole               = $e.roleDefinition.displayName
                    DirectRole                 = $null
                    EligibleRoleGroup          = $e.principal.displayName
                    AdminRiskScore             = 7
                    AdminRiskLevel             = "Medium"
                    memberType                 = "NestedGroup"
                    createdDateTime            = $null
                    LastPasswordChangeDateTime = $null
                    lastSignInDateTime         = $null
                    hasStrongMFA               = $false
                    StrongAuthCount            = 0
                    AuthPassword               = $null
                    AuthPhone                  = $null
                    AuthFido2                  = $null
                    AuthPasswordless           = $null
                    AuthMicrosoftAuthenticator = $null
                }

                $nested

                continue
            }
            $user.EligibleRoles += [pscustomobject]@{
                'Role'       = $e.roleDefinition["displayName"]
                'MemberType' = 'Group'
                'Group'      = $e.principal.displayname
            }

            $user
            Write-Host "     ✅ Added $($member.DisplayName) from group $($e.principal.displayName)" -ForegroundColor Green
        } -End {
            Write-Progress -Activity "Expanding group: $($e.principal.displayName)" -Completed
            Write-Host "✅ Finished expanding group $($e.principal.displayName) ($total members)" -ForegroundColor Green
        }
    }
} | Sort-Object -Property id | Sort-Object -Unique -Property id

Write-Host "✅ Finished collecting all eligible role assignments." -ForegroundColor Green
Write-Host "Fetching Azure role assignments..." -ForegroundColor Yellow
$azroles = Get-AzSubscription | ForEach-Object {
    $id = $_.id 
    $name = $_.name 

    Write-Host "Fetching role assignments for subscription: $name" -ForegroundColor DarkCyan

    Get-AzRoleAssignment -Scope /subscriptions/$id | ForEach-Object {

        $assignment = $_
        $assignmentSource = "Direct"

        if ($assignment.ObjectType -eq "Group") {
            $assignmentSource = "Group"
        }

        if ($assignment.ObjectType -eq "User") {
            $user = Get-User -Id $assignment.ObjectId
        }
        elseif ($assignment.ObjectType -match "ServicePrincipal") {
            return
            $user = Get-ServicePrincipal -Id $assignment.ObjectId
            if (-not $user) {
                return
            }
        }
        else {
            Write-Warning "Unknown ObjectType '$($assignment.ObjectType)'"
            return
        }

        $user.AzureRoles += [pscustomobject]@{
            'RoleDefinitionName' = $assignment.RoleDefinitionName
            'MemberType'         = $assignmentSource
            'Subscription'       = $name
        }

        $user
    }

} 

foreach ($admin in $administrators + $eligible + $azroles) {
    $admin.Roles = $admin.Roles | Sort-Object -Unique
    $admin.EligibleRoles = $admin.EligibleRoles | Sort-Object Role -Unique
    $admin.AzureRoles = $admin.AzureRoles | Sort-Object RoleDefinitionName -Unique

    $riskScore = Get-AdminRiskScore -User $admin
    $riskLevel = Get-AdminRiskLevel $riskScore

    $admin | Add-Member -NotePropertyName AttackPathScore -NotePropertyValue (Get-AttackPathScore $admin) -Force
    $admin | Add-Member -NotePropertyName AttackRole -NotePropertyValue (Get-AttackRole $admin) -Force
    $displayLabel = if ($admin.displayName) {
        $admin.displayName
    }
    elseif ($admin.UserPrincipalName) {
        ($admin.UserPrincipalName -split "@")[0]
    }
    else {
        "Unknown"
    }

    $admin | Add-Member -NotePropertyName DisplayLabel -NotePropertyValue $displayLabel -Force


    # --- SAFETY: ensure properties exist ---
    if (-not $admin.PSObject.Properties["AdminRiskScore"]) {
        $admin | Add-Member -NotePropertyName "AdminRiskScore" -NotePropertyValue 0 -Force

    }

    if (-not $admin.PSObject.Properties["AdminRiskLevel"]) {
        $admin | Add-Member -NotePropertyName "AdminRiskLevel" -NotePropertyValue "" -Force
    }

    # --- assign values ---
    $admin.AdminRiskScore = $riskScore
    $admin.AdminRiskLevel = $riskLevel

   
    
}
$allAdminsRaw = $administrators + $eligible + $azroles
foreach ($admin in $allAdminsRaw) {

    if (-not $admin.PSObject.Properties["Roles"]) {
        $admin | Add-Member -NotePropertyName 'Roles' -NotePropertyValue @() -Force
    }

    if (-not $admin.PSObject.Properties["EligibleRoles"]) {
        $admin | Add-Member -NotePropertyName 'EligibleRoles' -NotePropertyValue @() -Force
    }

    if (-not $admin.PSObject.Properties["AzureRoles"]) {
        $admin | Add-Member -NotePropertyName 'AzureRoles' -NotePropertyValue @() -Force
    }
}
$entryPoints = ($allAdminsRaw | Where-Object { $_.AttackRole -eq "Entry" }).Count
$escalationPoints = ($allAdminsRaw | Where-Object { $_.AttackRole -eq "Escalation" }).Count
$impactPoints = ($allAdminsRaw | Where-Object { $_.AttackRole -eq "Impact" }).Count
Write-Host "✅ Azure role assignments gathered." -ForegroundColor Green

$exportPath = "$folder\$orgdisplayname-EntraIDAdminReport$date.xlsx"
if (Test-Path $exportPath) {
    Write-Host "Removing existing report..." -ForegroundColor Yellow
    Remove-Item $exportPath -Force
}
$allAdmins = $administrators + $eligible + $azroles | Sort-Object -Property id | Sort-Object -Property id -Unique


$allAdmins = $allAdmins | Select-Object @{L = 'Roles'; E = { $_.Roles -join ',' } }, @{L = 'EligibleRoles'; E = { $_.EligibleRoles.Role -join ',' } }, @{L = 'AzureRoles'; E = { $_.AzureRoles.RoleDefinitionName -join ',' } }, displayName, Userprincipalname, companyName, AdminRiskScore, AdminRiskLevel, AttackRole,
AttackPathScore, accountEnabled, CreatedDatetime , LastPasswordChangeDateTime, lastSignInDateTime, hasStrongMFA, StrongAuthCount, AuthPassword, AuthPhone, AuthFido2, AuthPasswordless, AuthMicrosoftAuthenticator, IsLicensed, userType, DisplayLabel
# =====================================================
#  Attack Path Properties
# =====================================================
$allAdmins | Group-Object AttackRole
foreach ($admin in $allAdmins) {
    $admin | Add-Member -NotePropertyName AttackRole -NotePropertyValue (Get-AttackRole $admin) -Force
    $admin | Add-Member -NotePropertyName AttackPathScore -NotePropertyValue (Get-AttackPathScore $admin) -Force
}
$eligible = $eligible | ForEach-Object {
    $e = $_
    $e.EligibleRoles | foreach-object {
        $e.PSObject.Copy() |
        Add-Member -NotePropertyName 'MemberType' -NotePropertyValue $_.MemberType -Passthru |
        Add-Member -NotePropertyName 'DirectRole' -NotePropertyValue $_.MemberType -Passthru |
        Add-Member -NotePropertyName 'EligibleRoleGroup' -NotePropertyValue $_.Role -Passthru
    }
}
# ----------------------------------------------------
# ATTACK CHAIN IDENTITIES (TOP 3 PER STAGE)
# ----------------------------------------------------

# exploitable list
$attackCandidates = $allAdminsRaw |
ForEach-Object {
    $_ | Add-Member -NotePropertyName ExploitScore -NotePropertyValue (Get-ExploitabilityScore $_) -Force -PassThru
} |
Where-Object { $_.ExploitScore -gt 0 } |
Sort-Object ExploitScore -Descending

# split to stages
$entryAdmins = $attackCandidates |
Where-Object { $_.AttackRole -eq "Entry" } |
Select-Object -First 3

$escalationAdmins = $attackCandidates |
Where-Object { $_.AttackRole -eq "Escalation" } |
Select-Object -First 3

$impactAdmins = $attackCandidates |
Where-Object { $_.AttackRole -eq "Impact" } |
Select-Object -First 3

# fallback if empty 
if (-not $entryAdmins) {
    $entryAdmins = $attackCandidates | Select-Object -First 3
}

if (-not $escalationAdmins) {
    $escalationAdmins = $attackCandidates | Select-Object -Skip 3 -First 3
}

if (-not $impactAdmins) {
    $impactAdmins = $attackCandidates | Select-Object -Skip 6 -First 3
}

function Get-RiskReason {
    param($u)

    if (-not $u.hasStrongMFA) {
        return "No MFA"
    }

    if ($u.Roles -contains "Global Administrator") {
        return "Global Admin"
    }

    if ($u.AzureRoles.RoleDefinitionName -match "Owner") {
        return "Azure Owner"
    }

    if ($u.EligibleRoles.Count -gt 0) {
        return "Eligible Role"
    }

    if (-not $u.lastSignInDateTime) {
        return "Never signed in"
    }
        return "Weak controls"
}

$topRiskAdmins = $allAdmins |
Sort-Object AdminRiskScore -Descending |
Select-Object -First 10 @{

    Name       = 'displayName'
    Expression = { $_.DisplayLabel }

}, Role, AdminRiskScore, AdminRiskLevel

$topRiskAdmins = $topRiskAdmins | Sort-Object AdminRiskScore

$topExploitableAdmins = $allAdmins |
ForEach-Object {
    [PSCustomObject]@{
        displayName  = $_.DisplayLabel
        ExploitScore = Get-ExploitabilityScore $_
    }
} |
Sort-Object ExploitScore -Descending |
Select-Object -First 10 |
Sort-Object ExploitScore


# ----------------------------------------------------
# Summary metrics
# ----------------------------------------------------
$totalAdmins = $allAdmins.Count

$criticalAdmins = ($allAdmins | Where-Object { $_.AdminRiskLevel -eq "Critical" }).Count


$noMFAAdmins = ($allAdmins | Where-Object { 
        $_.UserType -ne "Guest" -and -not $_.hasStrongMFA 
    }).Count

$inactiveAdmins = ($allAdmins | Where-Object {
        $_.lastSignInDateTime -and
        [datetime]$_.lastSignInDateTime -lt (Get-Date).AddDays(-90)
    }).Count

# ----------------------------------------------------
# ATTACK KPI METRICS
# ----------------------------------------------------

$exploitableAdmins = ($allAdmins | Where-Object {
        -not $_.hasStrongMFA -and
        ($_.Roles.Count -gt 0 -or $_.EligibleRoles.Count -gt 0)
    }).Count

$entryPoints = ($allAdmins | Where-Object { $_.AttackRole -eq "Entry" }).Count
$escalationPoints = ($allAdmins | Where-Object { $_.AttackRole -eq "Escalation" }).Count
$impactPoints = ($allAdmins | Where-Object { $_.AttackRole -eq "Impact" }).Count

$fullCompromise = if ($entryPoints -gt 0 -and $impactPoints -gt 0) { 1 } else { 0 }

# ----------------------------------------------------
# GLOBAL ADMIN ANALYSIS (NIST + Microsoft aligned)
# ----------------------------------------------------

# All Global Administrators
$globalAdmins = $allAdmins | Where-Object {
    $_.Roles -match "Global Administrator"
}

# Permanent (standing) Global Admins
$standingGlobalAdmins = $globalAdmins | Where-Object {
    $_.EligibleRoles.Count -eq 0
}

# PIM-enabled Global Admins
$pimGlobalAdmins = $globalAdmins | Where-Object {
    $_.EligibleRoles.Count -gt 0
}

# Stale Global Admins (not signed in 90 days)
$staleGlobalAdmins = $globalAdmins | Where-Object {
    -not $_.lastSignInDateTime -or
    ([datetime]$_.lastSignInDateTime -lt (Get-Date).AddDays(-90))
}

# WORST CASE: Permanent + not tested
$staleStandingGlobalAdmins = $standingGlobalAdmins | Where-Object {
    -not $_.lastSignInDateTime -or
    ([datetime]$_.lastSignInDateTime -lt (Get-Date).AddDays(-90))
}

# Counts (you will use these everywhere)
$totalGlobalAdmins = $globalAdmins.Count
$standingGlobalAdminCount = $standingGlobalAdmins.Count
$pimGlobalAdminCount = $pimGlobalAdmins.Count
$staleGlobalAdminCount = $staleGlobalAdmins.Count
$staleStandingGlobalAdminCount = $staleStandingGlobalAdmins.Count

# ----------------------------------------------------
# LIFECYCLE MATURITY 
# ----------------------------------------------------

$inactiveRatio = if ($totalAdmins -gt 0) {
    [math]::Round(($inactiveAdmins / $totalAdmins) * 100, 0)
}
else { 0 }

$productivityAdmins = ($allAdmins | Where-Object {
        $_.ProductivityServicesEnabled -eq $true
    }).Count
$externalAdmins = ($allAdmins | Where-Object { $_.UserType -eq "Guest" }).Count
# ----------------------------------------------------
# EXTERNAL ADMIN MATURITY 
# ----------------------------------------------------

$externalRatio = if ($totalAdmins -gt 0) {
    [math]::Round(($externalAdmins / $totalAdmins) * 100, 0)
}
else { 0 }

# ----------------------------------------------------
# MFA MATURITY
# ----------------------------------------------------

$totalInternalAdmins = ($allAdmins | Where-Object { $_.UserType -ne "Guest" }).Count

$strongMFAAdmins = ($allAdmins | Where-Object {
        $_.UserType -ne "Guest" -and $_.hasStrongMFA
    }).Count

$fidoAdmins = ($allAdmins | Where-Object {
        $_.AuthFido2
    }).Count

$mfaCoverage = if ($totalInternalAdmins -gt 0) {
    [math]::Round(($strongMFAAdmins / $totalInternalAdmins) * 100, 0)
}
else { 0 }

$fidoCoverage = if ($totalInternalAdmins -gt 0) {
    [math]::Round(($fidoAdmins / $totalInternalAdmins) * 100, 0)
}
else { 0 }

# ----------------------------------------------------
# PIM MATURITY CALCULATION 
# ----------------------------------------------------

$totalPrivilegedAssignments = ($allAdmins | Where-Object {
        $_.Roles.Count -gt 0
    }).Count

$pimEligibleAdmins = ($allAdmins | Where-Object {
        $_.EligibleRoles.Count -gt 0
    }).Count

$standingAdmins = ($allAdmins | Where-Object {
        $_.Roles.Count -gt 0
    }).Count

$pimCoverage = if ($totalPrivilegedAssignments -gt 0) {
    [math]::Round(($pimEligibleAdmins / $totalPrivilegedAssignments) * 100, 0)
}
else { 0 }
# ----------------------------------------------------
# MONITORING MATURITY
# ----------------------------------------------------

# We assume no visibility into monitoring/alerting from this dataset
$monitoringCoverage = 0

# ----------------------------------------------------
# Largest Risk Calculation
# ----------------------------------------------------

$risks = @()

$risks += [PSCustomObject]@{
    Name  = "Missing MFA on admins"
    Count = $noMFAAdmins
}

$risks += [PSCustomObject]@{
    Name  = "Critical role exposure"
    Count = $criticalAdmins
}

$risks += [PSCustomObject]@{
    Name  = "Inactive privileged accounts"
    Count = $inactiveAdmins
}

$risks += [PSCustomObject]@{
    Name  = "Admins with M365 access"
    Count = $productivityAdmins
}
$risks += [PSCustomObject]@{
    Name  = "Standing Global Administrators"
    Count = $standingGlobalAdminCount
}

$risks += [PSCustomObject]@{
    Name  = "Unmonitored Global Administrators"
    Count = $staleStandingGlobalAdminCount
}

$largestRisk = $risks |
Where-Object { $_.Count -gt 0 } |
Sort-Object Count -Descending |
Select-Object -First 1

$topRisks = $risks |
Where-Object { $_.Count -gt 0 } |
Sort-Object Count -Descending |
Select-Object -First 3

# Fallback (prevents empty card)
if (-not $topRisks -or $topRisks.Count -eq 0) {
    $topRisks = @(
        [PSCustomObject]@{
            Name  = "No major risk drivers identified"
            Count = 0
        }
    )
}
# ----------------------------------------------------
# MFA NARRATIVE 
# ----------------------------------------------------

$mfaNarrative = ""

if ($noMFAAdmins -gt 0) {
    $mfaNarrative = "Privileged accounts are not consistently protected by strong authentication."
}
elseif ($fidoCoverage -lt 50) {
    $mfaNarrative = "Phishing-resistant MFA is available but not widely enforced across privileged accounts."
}
elseif ($fidoCoverage -lt 90) {
    $mfaNarrative = "Strong authentication is in place, but phishing-resistant methods are not fully enforced."
}
else {
    $mfaNarrative = "Privileged accounts are protected with phishing-resistant authentication."
}

# ----------------------------------------------------
# PIM NARRATIVE 
# ----------------------------------------------------

$pimNarrative = ""

if ($standingAdmins -gt 0 -and $pimEligibleAdmins -eq 0) {
    $pimNarrative = "Privileged access is assigned permanently with no use of Just-In-Time controls."
}
elseif ($pimCoverage -lt 50) {
    $pimNarrative = "Privileged Identity Management is partially implemented but not consistently used."
}
elseif ($pimCoverage -lt 90) {
    $pimNarrative = "Just-In-Time access is in place, but permanent role assignments still exist."
}
else {
    $pimNarrative = "Privileged access is managed through Just-In-Time activation."
}
# ----------------------------------------------------
# LIFECYCLE NARRATIVE
# ----------------------------------------------------

$lifecycleNarrative = ""

if ($inactiveAdmins -eq 0) {
    $lifecycleNarrative = "Privileged accounts are actively used and aligned with operational needs."
}
elseif ($inactiveRatio -lt 10) {
    $lifecycleNarrative = "A small number of inactive privileged accounts exist, indicating gaps in lifecycle governance."
}
elseif ($inactiveRatio -lt 30) {
    $lifecycleNarrative = "Inactive privileged accounts are present and not consistently governed or reviewed."
}
else {
    $lifecycleNarrative = "A significant number of privileged accounts are inactive, indicating lack of lifecycle control and automated deprovisioning."
}
# ----------------------------------------------------
# EXTERNAL ACCESS NARRATIVE 
# ----------------------------------------------------

$externalNarrative = $null

if ($externalAdmins -gt 0) {

    if ($externalRatio -lt 10) {
        $externalNarrative = "External privileged access exists but governance and control cannot be fully verified."
    }
    elseif ($externalRatio -lt 30) {
        $externalNarrative = "External privileged accounts are present, and governance cannot be verified through available data."
    }
    else {
        $externalNarrative = "A significant portion of privileged access is assigned to external identities, and governance cannot be verified."
    }
}
# ----------------------------------------------------
# MONITORING NARRATIVE 
# ----------------------------------------------------

$monitoringNarrative = "Privileged activity monitoring and detection capability cannot be verified based on available data."

# -----------------------------------------------------
# Attack Narrative
# -----------------------------------------------------
$attackNarrative = "This analysis identifies how an attacker could move through the identity environment: gaining initial access through weak authentication, escalating privileges through misconfigured or weakly protected roles, and ultimately reaching critical administrative control."

$allAdmins | Export-Excel `
    -Path $exportPath `
    -WorksheetName "All Admins" `
    -TableName AllAdminsTable `
    -AutoSize `

#Inactive data 

$activityTable = @(
    [PSCustomObject]@{ Status = "Active"; Count = $totalAdmins - $inactiveAdmins }
    [PSCustomObject]@{ Status = "Inactive"; Count = $inactiveAdmins }
)

$activityTable | Export-Excel `
    -Path $exportPath `
    -WorksheetName "Activity Data" `
    -TableName ActivityTable `
    -AutoSize `
    -Append

# MFA DATA
$mfaTable = @()

$mfaTable += [PSCustomObject]@{
    MFAStatus = "Strong MFA"
    Count     = ($allAdmins | Where-Object { $_.hasStrongMFA -and $_.UserType -ne "Guest" }).Count
}

$mfaTable += [PSCustomObject]@{
    MFAStatus = "No MFA"
    Count     = ($allAdmins | Where-Object { -not $_.hasStrongMFA -and $_.UserType -ne "Guest" }).Count
}

$mfaTable += [PSCustomObject]@{
    MFAStatus = "External (GDAP)"
    Count     = $externalAdmins
}
$mfaTable | Export-Excel `
    -Path $exportPath `
    -WorksheetName "MFA Data" `
    -TableName 'MfaTable' `
    -AutoSize `
    -Append

# ----------------------------
# Risk Data
# -----------------------------

$riskLevels = @("Critical", "High", "Medium", "Low")

$riskTable = @(
    foreach ($level in $riskLevels) {

        $count = @($allAdmins | Where-Object { $_.AdminRiskLevel -eq $level }).Count

        [PSCustomObject]@{
            RiskLevel = $level
            Count     = $count
        }
    }
)

$riskTable | Format-Table
$riskTable | Get-Member
$riskTable.Count

$riskTable | Export-Excel `
    -Path $exportPath `
    -WorksheetName "Risk Data" `
    -TableName 'RiskTable' `
    -AutoSize `
    -Append

Write-Host "MFA rows: $($mfaTable.Count)"
Write-Host "Risk rows: $($riskTable.Count)"



# ---------------------------------
# TopRiskAdmins Data 
# ---------------------------------

$topRiskAdmins | Export-Excel `
    -Path $exportPath `
    -WorksheetName "TopRiskAdmin Data" `
    -TableName 'TopRiskAdmins' `
    -AutoSize `
    -Append


# ---------------------------------------
# Top ExplotaibleAdmins 
#----------------------------------------
$topExploitableAdmins | Export-Excel `
    -Path $exportPath `
    -WorksheetName "TopExploitableAdmins" `
    -TableName 'TopExploitableAdmins' `
    -AutoSize `
    -Append


$riskNarrative = @()

# ----------------------------------------------------
# INTERPRETATION 
# ----------------------------------------------------

$riskNarrative += $mfaNarrative
$riskNarrative += $pimNarrative
$riskNarrative += $lifecycleNarrative
if ($externalNarrative) {
    $riskNarrative += $externalNarrative
}
$riskNarrative += $monitoringNarrative
if ($noMFAAdmins -gt 0) {
    $riskNarrative += "Privileged accounts are exposed to compromise due to weak or missing authentication."
}

if ($criticalAdmins -gt 0) {
    $riskNarrative += "Standing administrative access increases the risk of full environment compromise."
}

if ($inactiveAdmins -gt 0) {
    $riskNarrative += "Inactive privileged accounts create undetected attack paths."
}


# fallback
if ($riskNarrative.Count -eq 0) {
    $riskNarrative += "Privileged access is generally well controlled with no significant exposure detected."
}

$impactNarrative = @()

if ($noMFAAdmins -gt 0) {
    $impactNarrative += "Risk of credential theft and account takeover"
}

if ($criticalAdmins -gt 0) {
    $impactNarrative += "Potential full tenant compromise"
}

if ($inactiveAdmins -gt 0) {
    $impactNarrative += "Delayed detection of malicious activity"
}

# ----------------------------------------------------
# Identity Posture Score
# ----------------------------------------------------
$total = $totalAdmins
$postureScore = 100

if ($total -gt 0) {

    # ----------------------------------------------------
    # RATIOS (reduced weight, signal only)
    # ----------------------------------------------------
    $mfaRatio = $noMFAAdmins / $total
    $criticalRatio = $criticalAdmins / $total
    $inactiveRatio = $inactiveAdmins / $total
    $productivityRatio = $productivityAdmins / $total

    # MFA (most important control)
    $postureScore -= ($mfaRatio * 40)

    # Privileged exposure
    $postureScore -= ($criticalRatio * 15)

    # Lifecycle hygiene
    $postureScore -= ($inactiveRatio * 10)

    # Attack surface
    $postureScore -= ($productivityRatio * 5)
}

# ----------------------------------------------------
# HARD CONTROL PENALTIES (NIST aligned)
# ----------------------------------------------------

#  Missing MFA (critical control failure)
if ($noMFAAdmins -gt 0) {
    $postureScore -= 20
}

#  Large MFA gap
if ($noMFAAdmins -gt 5) {
    $postureScore -= 10
}

#  Critical roles permanently assigned
if ($criticalAdmins -gt 0) {
    $postureScore -= 15
}

# High concentration of critical admins
if ($criticalAdmins -gt 10) {
    $postureScore -= 10
}

#  Inactive privileged accounts
if ($inactiveAdmins -gt 0) {
    $postureScore -= 10
}

#  No PIM / JIT
if ($pimCoverage -eq 0) {
    $postureScore -= 10
}
# ----------------------------------------------------
# GLOBAL ADMIN GOVERNANCE (CRITICAL CONTROL)
# ----------------------------------------------------

# More than 2 permanent Global Admins = overexposure
if ($standingGlobalAdminCount -gt 2) {
    $postureScore -= 15
}

# Break-glass accounts not tested
if ($staleGlobalAdminCount -gt 0) {
    $postureScore -= 10
}

# WORST CASE: permanent + not tested
if ($staleStandingGlobalAdminCount -gt 0) {
    $postureScore -= 15
}

# ----------------------------------------------------
# FAIL-SAFE 
# ----------------------------------------------------
if (
    $noMFAAdmins -gt 0 -or
    $criticalAdmins -gt 0 -or
    $staleStandingGlobalAdminCount -gt 0
) {
    if ($postureScore -gt 74) {
        $postureScore = 74
    }
}

# ----------------------------------------------------
# NORMALIZE
# ----------------------------------------------------
if ($postureScore -lt 0) { $postureScore = 0 }
if ($postureScore -gt 100) { $postureScore = 100 }

$postureScore = [math]::Round($postureScore, 0)


# -----------------------------
# Level (human readable)
# -----------------------------
switch ($postureScore) {
    { $_ -ge 90 } { $postureLevel = "Mature"; break }
    { $_ -ge 75 } { $postureLevel = "Managed"; break }
    { $_ -ge 60 } { $postureLevel = "Controlled"; break }
    { $_ -ge 40 } { $postureLevel = "Developing"; break }
    default { $postureLevel = "Initial"; break }
}

# ----------------------------------------------------
# Reality override (NIST aligned)
# ----------------------------------------------------

if ($postureScore -le 50) {
    $postureLevel = "Developing"
}
elseif ($postureScore -le 65) {
    $postureLevel = "Controlled"
}

# -----------------------------
# Grade (executive friendly)
# -----------------------------
switch ($postureScore) {
    { $_ -ge 85 } { $grade = "A"; break }
    { $_ -ge 70 } { $grade = "B"; break }
    { $_ -ge 50 } { $grade = "C"; break }
    { $_ -ge 30 } { $grade = "D"; break }
    default { $grade = "F" }
}

# -----------------------------
# UX label 
# -----------------------------
$postureLabel = "$postureLevel — Score $postureScore (Grade $grade)"

# -----------------------------
# Export Object
# -----------------------------
$posture = @(
    [PSCustomObject]@{ Metric = "Privileged Identity Security Score"; Value = $postureScore }
    [PSCustomObject]@{ Metric = "Posture Level"; Value = $postureLevel }
    [PSCustomObject]@{ Metric = "Security Grade"; Value = $grade }
    [PSCustomObject]@{ Metric = "Display"; Value = $postureLabel }
)



Write-Host "Exporting data to Excel..." -ForegroundColor Cyan


# Administrators
$administrators | Select-Object @{L = 'Roles'; E = { $_.Roles -join ',' } }, displayName, Userprincipalname, companyName, AdminRiskScore, AdminRiskLevel, accountEnabled, CreatedDatetime , LastPasswordChangeDateTime, lastSignInDateTime, hasStrongMFA, StrongAuthCount, AuthPassword, AuthPhone, AuthFido2, AuthPasswordless, AuthMicrosoftAuthenticator, IsLicensed, usertype | 
Export-Excel `
    -NoNumberConversion * `
    -Path $exportPath `
    -WorksheetName "Administrators" `
    -TableName Administrators `
    -FreezeTopRow `
    -AutoSize `
    -TableStyle Medium2 `
    -Append

# Eligible Roles
$eligible |  Select-Object id, displayName, Userprincipalname, DirectRole, EligibleRoleGroup, memberType, AdminRiskScore, AdminRiskLevel, createdDateTime, LastPasswordChangeDateTime, lastSignInDateTime, hasStrongMFA, StrongAuthCount, AuthPassword, AuthPhone, AuthFido2, AuthPasswordless, AuthMicrosoftAuthenticator, IsLicensed, userType |
Export-Excel `
    -NoNumberConversion * `
    -Path $exportPath `
    -WorksheetName "Eligible Roles" `
    -TableName EligibleRoles `
    -FreezeTopRow `
    -AutoSize `
    -Append `
    -TableStyle Medium2

# Azure Roles
$azroles | Select-Object @{L = 'AzureRoles'; E = { $_.AzureRoles.RoleDefinitionName -join ',' } }, displayName, Userprincipalname, companyName, AdminRiskScore, AdminRiskLevel, accountEnabled, CreatedDatetime , LastPasswordChangeDateTime, lastSignInDateTime, hasStrongMFA, StrongAuthCount, AuthPassword, AuthPhone, AuthFido2, AuthPasswordless, AuthMicrosoftAuthenticator, IsLicensed, userType |
Export-Excel `
    -NoNumberConversion * `
    -Path $exportPath `
    -WorksheetName "Azure Roles" `
    -TableName AzureRoles `
    -FreezeTopRow `
    -AutoSize `
    -Append `
    -TableStyle Medium2

# Attack Table 
$attackTable = @(
    [PSCustomObject]@{ Stage = "Entry (Weak Auth)"; Count = $entryPoints }
    [PSCustomObject]@{ Stage = "Privilege Escalation Risk"; Count = $escalationPoints }
    [PSCustomObject]@{ Stage = "Impact (Critical Access)"; Count = $impactPoints }
)

$attackTable | Export-Excel `
    -Path $exportPath `
    -WorksheetName "Attack Data" `
    -TableName 'AttackTable' `
    -AutoSize `
    -Append `
    -TableStyle Medium2



# ----------------------------------------------------
# Dashboard Charts
# ----------------------------------------------------

$posture | Export-Excel `
    -Path $exportPath `
    -WorksheetName "Identity Posture" `
    -TableName IdentityPosture `
    -AutoSize `
    -Append `
    -TableStyle Medium2







Write-Host "Adding conditional formatting..." -ForegroundColor Cyan

$excel = Open-ExcelPackage $exportPath
$excel.Workbook.Worksheets["All Admins"].Hidden = "Hidden"
$excel.Workbook.Worksheets["Activity Data"].Hidden = "Hidden"
$excel.Workbook.Worksheets["TopRiskAdmin Data"].Hidden = "Hidden"
$excel.Workbook.Worksheets["Identity Posture"].Hidden = "Hidden"
$excel.Workbook.Worksheets["MFA Data"].Hidden = "Hidden"
$excel.Workbook.Worksheets["Risk Data"].Hidden = "Hidden"

$adminRows = $administrators.Count + 1
$eligibleRows = $eligible.Count + 1
$azRows = $azroles.Count + 1

# Administrators sheet
$ws = $excel.Workbook.Worksheets["Administrators"]

Add-SafeFormatting $excel.Workbook.Worksheets["Administrators"] "F" $adminRows

# Eligible Sheet 

$ws = $excel.Workbook.Worksheets["Eligible Roles"]

Add-SafeFormatting $excel.Workbook.Worksheets["Eligible Roles"] "H" $eligibleRows

$ws = $excel.Workbook.Worksheets["Azure Roles"]

Add-SafeFormatting $excel.Workbook.Worksheets["Azure Roles"] "I" $azRows

$Summaryws = $excel.Workbook.Worksheets["Executive Summary"]
if (-not $Summaryws) {
    $Summaryws = $excel.Workbook.Worksheets.Add("Executive Summary")
}

# ----------------------------------------------------
# SELF-CONTAINED DASHBOARD
# ----------------------------------------------------


$ws = $excel.Workbook.Worksheets["Identity Dashboard"]
if (-not $ws) {
    $ws = $excel.Workbook.Worksheets.Add("Identity Dashboard")
}
# Move dashboard to first
$excel.Workbook.View.ActiveTab = $ws.Index - 1
$ws.Select()
# Remove default borders 
$ws.Cells.Style.Border.Top.Style = "None"
$ws.Cells.Style.Border.Bottom.Style = "None"
$ws.Cells.Style.Border.Left.Style = "None"
$ws.Cells.Style.Border.Right.Style = "None"
$ws.Cells.Style.Fill.PatternType = "Solid"
$ws.Cells.Style.Fill.BackgroundColor.SetColor(
    [System.Drawing.Color]::FromArgb(248, 248, 250)
)

# ----------------------------------------------------
# BACKGROUND CONTAINER
# ----------------------------------------------------

$dashboardRange = "B2:P75"
$ws.Column(1).Width = 5

# Clean background
$ws.Cells[$dashboardRange].Style.Fill.PatternType = "Solid"
$ws.Cells[$dashboardRange].Style.Fill.BackgroundColor.SetColor(
    [System.Drawing.Color]::FromArgb(248, 248, 250)
)

$ws.Cells["A75:P75"].Style.Border.Bottom.Style = "Medium"
$ws.Cells["A2:A75"].Style.Border.Left.Style = "Medium"
$ws.Cells["P2:P75"].Style.Border.Right.Style = "Medium"



# ----------------------------------------------------
# REMOVE GRIDLINES 
# ----------------------------------------------------
try {
    $ws.View.ShowGridLines = $false
}
catch {
    Write-Host "Gridlines property not available, applying fallback..." -ForegroundColor Yellow
    
    # Fallback: make gridlines invisible by setting background
    $ws.Cells.Style.Fill.PatternType = "Solid"
    $ws.Cells.Style.Fill.BackgroundColor.SetColor([System.Drawing.Color]::White)
}

# ----------------------------------------------------
# COLUMN WIDTHS 
# ----------------------------------------------------
1..16 | ForEach-Object {
    $ws.Column($_).Width = 18
}

# ----------------------------------------------------
# ROW HEIGHT (SPACING FOR CARDS)
# ----------------------------------------------------
$ws.Row(3).Height = 22
$ws.Row(4).Height = 28
$ws.Row(5).Height = 10
$ws.Row(6).Height = 22
$ws.Row(7).Height = 28
$ws.Row(8).Height = 25
$ws.Row(9).Height = 25

# ----------------------------------------------------
# TITLE
# ----------------------------------------------------
$ws.Cells["A1"].Value = "Entra Administrator Identity Security Dashboard"
$ws.Cells["A1:P1"].Merge = $true
$ws.Cells["A1"].Style.Font.Size = 28
$ws.Cells["A1"].Style.Font.Bold = $true
$ws.Cells["A1"].Style.HorizontalAlignment = "Center"
$ws.Cells["A1"].Style.VerticalAlignment = "Center"

$ws.Cells["A1"].Style.Fill.PatternType = "Solid"
$ws.Cells["A1"].Style.Fill.BackgroundColor.SetColor([System.Drawing.Color]::FromArgb(122, 31, 162))
$ws.Cells["A1"].Style.Font.Color.SetColor([System.Drawing.Color]::White)
$ws.Cells["A1:P1"].Style.Border.Bottom.Style = "Medium"
$ws.Cells["A1:P1"].Style.Border.Bottom.Style = "Medium"

# ----------------------------------------------------
# KPI CARDS
# ----------------------------------------------------
# KPI GRID (centered)
$ws.Cells["B3:C3"].Merge = $true
$ws.Cells["B4:C4"].Merge = $true

$ws.Cells["E3:F3"].Merge = $true
$ws.Cells["E4:F4"].Merge = $true

$ws.Cells["H3:I3"].Merge = $true
$ws.Cells["H4:I4"].Merge = $true

$ws.Cells["K3:L3"].Merge = $true
$ws.Cells["K4:L4"].Merge = $true

$ws.Cells["N3:O3"].Merge = $true
$ws.Cells["N4:O4"].Merge = $true

$ws.Cells["Q3:R3"].Merge = $true
$ws.Cells["Q4:R4"].Merge = $true

$ws.Cells["B6:C6"].Merge = $true
$ws.Cells["B7:C7"].Merge = $true

$ws.Cells["E6:F6"].Merge = $true
$ws.Cells["E7:F7"].Merge = $true

$ws.Cells["H6:I6"].Merge = $true
$ws.Cells["H7:I7"].Merge = $true

$ws.Cells["K6:L6"].Merge = $true
$ws.Cells["K7:L7"].Merge = $true

$ws.Cells["N6:O6"].Merge = $true
$ws.Cells["N7:O7"].Merge = $true

# Values (reuse your variables)
$ws.Cells["B3"].Value = "Total Admins"
$ws.Cells["B4"].Value = $totalAdmins

$ws.Cells["E3"].Value = "Critical"
$ws.Cells["E4"].Value = $criticalAdmins

$ws.Cells["H3"].Value = "No MFA"
$ws.Cells["H4"].Value = $noMFAAdmins

$ws.Cells["K3"].Value = "Inactive"
$ws.Cells["K4"].Value = $inactiveAdmins

$ws.Cells["N3"].Value = "External (GDAP)"
$ws.Cells["N4"].Value = $externalAdmins


$ws.Cells["B6"].Value = "Exploitable Admins"
$ws.Cells["B7"].Value = $exploitableAdmins

$ws.Cells["E6"].Value = "Entry Points"
$ws.Cells["E7"].Value = $entryPoints

$ws.Cells["H6"].Value = "Escalation Paths"
$ws.Cells["H7"].Value = $escalationPoints

$ws.Cells["K6"].Value = "Impact Nodes"
$ws.Cells["K7"].Value = $impactPoints

$ws.Cells["N6"].Value = "Attack Chain Complete"
$ws.Cells["N7"].Value = $fullCompromise



# Style KPI cards
function Set-KPI {
    param(
        $range,
        $titleCell,
        $valueCell
    )

    # Card styling
    $ws.Cells[$range].Style.Fill.PatternType = "Solid"
    $ws.Cells[$range].Style.Fill.BackgroundColor.SetColor(
        [System.Drawing.Color]::FromArgb(255, 255, 255)
    )

    $ws.Cells[$range].Style.HorizontalAlignment = "Center"
    $ws.Cells[$range].Style.VerticalAlignment = "Center"

    $ws.Cells[$range].Style.Border.Top.Style = "Thin"
    $ws.Cells[$range].Style.Border.Left.Style = "Thin"
    $ws.Cells[$range].Style.Border.Bottom.Style = "Medium"
    $ws.Cells[$range].Style.Border.Right.Style = "Medium"

    # SAFE GUARD
    if ($titleCell) {
        $ws.Cells[$titleCell].Style.Font.Color.SetColor([System.Drawing.Color]::DimGray)
        $ws.Cells[$titleCell].Style.Font.Size = 11
    }

    if ($valueCell) {
        $ws.Cells[$valueCell].Style.Font.Size = 18
        $ws.Cells[$valueCell].Style.Font.Bold = $true
    }
}
Set-KPI "B3:C4" "B3" "B4"
Set-KPI "E3:F4" "E3" "E4"
Set-KPI "H3:I4" "H3" "H4"
Set-KPI "K3:L4" "K3" "K4"
Set-KPI "N3:O4" "N3" "N4"
Set-KPI "B6:C7" "B6" "B7"
Set-KPI "E6:F7" "E6" "E7"
Set-KPI "H6:I7" "H6" "H7"
Set-KPI "K6:L7" "K6" "K7"
Set-KPI "N6:O7" "N6" "N7"
Set-KPI "C10:G15" $null $null
Set-KPI "H10:M15" $null $null






# ----------------------------------------------------
# HERO AREA (Risk + Posture)
# ----------------------------------------------------

# LEFT CARD (PRIMARY RISK)
$riskRange = $ws.Cells["C10:G15"]
$riskRange.Merge = $true



$riskCell = $ws.Cells["C10"]
$riskCell.Value = ""
$riskCell.Style.WrapText = $true

# TEXT
if ($largestRisk) {
    $textTitle = "⚠ PRIMARY RISK"
    $textMain = $largestRisk.Name
    $textSubLines = @()

    if ($largestRisk) {
        $textSubLines += "$($largestRisk.Count) admins affected"
    }

    if ($externalAdmins -gt 0) {
        $textSubLines += "$externalAdmins external admins (GDAP)"
    }

    $textSub = ($textSubLines -join "`n")
}
else {
    $textTitle = "PRIMARY RISK"
    $textMain = "No major risks detected"
    $textSub = ""
}

$rt = $riskCell.RichText
$rt.Clear()

$t1 = $rt.Add("$textTitle`n")
$t1.Size = 14
$t1.Color = [System.Drawing.Color]::DimGray

$t2 = $rt.Add("$textMain`n")
$t2.Bold = $true
$t2.Size = 24
$t2.Color = [System.Drawing.Color]::DarkOrange

$t3 = $rt.Add("$textSub")
$t3.Size = 14
$t3.Color = [System.Drawing.Color]::Gray
$riskRange.Style.Fill.BackgroundColor.SetColor(
    [System.Drawing.Color]::FromArgb(255, 245, 220)
)

# RIGHT CARD (POSTURE SCORE)

if ($postureScore -ge 85) {
    $scoreColor = [System.Drawing.Color]::FromArgb(0, 150, 0)
    $scoreBg = [System.Drawing.Color]::FromArgb(220, 255, 220)
}
elseif ($postureScore -ge 60) {
    $scoreColor = [System.Drawing.Color]::FromArgb(255, 140, 0)
    $scoreBg = [System.Drawing.Color]::FromArgb(255, 240, 200)
}
else {
    $scoreColor = [System.Drawing.Color]::FromArgb(200, 0, 0)
    $scoreBg = [System.Drawing.Color]::FromArgb(255, 220, 220)
}
$scoreRange = $ws.Cells["H10:M15"]
$scoreRange.Merge = $true



$scoreCell = $ws.Cells["H10"]
$scoreCell.Value = ""
$scoreCell.Style.WrapText = $true

$rt = $scoreCell.RichText
$rt.Clear()

$t1 = $rt.Add("Identity Security Score`n")
$t1.Size = 14
$t1.Color = [System.Drawing.Color]::DimGray

$t2 = $rt.Add("$postureScore`n")
$t2.Bold = $true
$t2.Size = 36
$t2.Color = [System.Drawing.Color]$scoreColor

$t3 = $rt.Add("$postureLevel`n")
$t3.Size = 14
$t3.Color = [System.Drawing.Color]::DimGray

$t4 = $rt.Add("Grade $grade")
$t4.Size = 12
$t4.Color = [System.Drawing.Color]::Gray

$ws.Row(10).Height = 60
$ws.Row(11).Height = 60

$scoreRange.Style.Fill.BackgroundColor.SetColor($scoreBg)


# ----------------------------------------------------
# CHARTS
# ----------------------------------------------------

# Risk

Add-ExcelChart `
    -Worksheet $ws `
    -ChartType Doughnut `
    -Title "Admin Risk Distribution" `
    -XRange "RiskTable[RiskLevel]" `
    -YRange "RiskTable[Count]" `
    -Row 22 `
    -Column 1 `
    -Width 340 `
    -Height 280
$chart = $ws.Drawings[-1]
$chart.Style = 26

# Risk chart (left)
$chart.SetPosition(22, 0, 2, 15)
# FIX COLORS
$chartXml = $chart.ChartXml

$ns = New-Object System.Xml.XmlNamespaceManager($chartXml.NameTable)
$ns.AddNamespace("c", "http://schemas.openxmlformats.org/drawingml/2006/chart")
$ns.AddNamespace("a", "http://schemas.openxmlformats.org/drawingml/2006/main")

$points = $chartXml.SelectNodes("//c:ser/c:dPt", $ns)

# Ensure datapoints exist 
if ($points.Count -eq 0) {
    $serNode = $chartXml.SelectSingleNode("//c:ser", $ns)

    0..3 | ForEach-Object {
        $dPt = $chartXml.CreateElement("c:dPt", $ns.LookupNamespace("c"))

        $idx = $chartXml.CreateElement("c:idx", $ns.LookupNamespace("c"))
        $idx.SetAttribute("val", $_)

        $spPr = $chartXml.CreateElement("c:spPr", $ns.LookupNamespace("c"))
        $solidFill = $chartXml.CreateElement("a:solidFill", $ns.LookupNamespace("a"))
        $srgbClr = $chartXml.CreateElement("a:srgbClr", $ns.LookupNamespace("a"))

        switch ($_) {
            0 { $srgbClr.SetAttribute("val", "C00000") } # Critical (red)
            1 { $srgbClr.SetAttribute("val", "FF8C00") } # High (orange)
            2 { $srgbClr.SetAttribute("val", "5B9BD5") } # Medium (neutral blue)
            3 { $srgbClr.SetAttribute("val", "00B050") } # Low (green)
        }

        $solidFill.AppendChild($srgbClr) | Out-Null
        $spPr.AppendChild($solidFill) | Out-Null
        $dPt.AppendChild($idx) | Out-Null
        $dPt.AppendChild($spPr) | Out-Null

        $serNode.AppendChild($dPt) | Out-Null
    }
}
$holeNode = $chartXml.SelectSingleNode("//c:holeSize", $ns)
if ($holeNode) {
    $holeNode.SetAttribute("val", "60")
}



$chart.Legend.Position = "Right"
$chart.Border.Fill.Style = "NoFill"
#Inactive
Add-ExcelChart `
    -Worksheet $ws `
    -ChartType Doughnut `
    -Title "Admin Activity (90 days)" `
    -XRange "ActivityTable[Status]" `
    -YRange "ActivityTable[Count]" `
    -Row 22 `
    -Column 1 `
    -Width 340 `
    -Height 280

$chart = $ws.Drawings[-1]
$chart.Style = 26
$chart.SetPosition(22, 0, 6, 15)

$chartXml = $chart.ChartXml

$ns = New-Object System.Xml.XmlNamespaceManager($chartXml.NameTable)
$ns.AddNamespace("c", "http://schemas.openxmlformats.org/drawingml/2006/chart")
$ns.AddNamespace("a", "http://schemas.openxmlformats.org/drawingml/2006/main")

$serNode = $chartXml.SelectSingleNode("//c:ser", $ns)

0..1 | ForEach-Object {

    $dPt = $chartXml.CreateElement("c:dPt", $ns.LookupNamespace("c"))

    $idx = $chartXml.CreateElement("c:idx", $ns.LookupNamespace("c"))
    $idx.SetAttribute("val", $_)

    $spPr = $chartXml.CreateElement("c:spPr", $ns.LookupNamespace("c"))
    $solidFill = $chartXml.CreateElement("a:solidFill", $ns.LookupNamespace("a"))
    $srgbClr = $chartXml.CreateElement("a:srgbClr", $ns.LookupNamespace("a"))

    switch ($_) {
        0 { $srgbClr.SetAttribute("val", "00B050") } # Active = green
        1 { $srgbClr.SetAttribute("val", "FF8C00") } # Inactive = orange
    }

    $solidFill.AppendChild($srgbClr) | Out-Null
    $spPr.AppendChild($solidFill) | Out-Null
    $dPt.AppendChild($idx) | Out-Null
    $dPt.AppendChild($spPr) | Out-Null

    $serNode.AppendChild($dPt) | Out-Null
}
$holeNode = $chartXml.SelectSingleNode("//c:holeSize", $ns)
if ($holeNode) {
    $holeNode.SetAttribute("val", "60")
}



$chart.Legend.Position = "Right"
$chart.Border.Fill.Style = "NoFill"

# MFA
Add-ExcelChart `
    -Worksheet $ws `
    -ChartType Doughnut `
    -Title "MFA Coverage" `
    -XRange "MfaTable[MFAStatus]" `
    -YRange "MfaTable[Count]" `
    -Row 22 `
    -Column 1 `
    -Width 340 `
    -Height 280



$chart = $ws.Drawings[-1]
$chart.Style = 26
$chart.SetPosition(22, 0, 10, 15)

$chartXml = $chart.ChartXml

$ns = New-Object System.Xml.XmlNamespaceManager($chartXml.NameTable)
$ns.AddNamespace("c", "http://schemas.openxmlformats.org/drawingml/2006/chart")
$ns.AddNamespace("a", "http://schemas.openxmlformats.org/drawingml/2006/main")

$serNode = $chartXml.SelectSingleNode("//c:ser", $ns)

0..1 | ForEach-Object {
    $dPt = $chartXml.CreateElement("c:dPt", $ns.LookupNamespace("c"))

    $idx = $chartXml.CreateElement("c:idx", $ns.LookupNamespace("c"))
    $idx.SetAttribute("val", $_)

    $spPr = $chartXml.CreateElement("c:spPr", $ns.LookupNamespace("c"))
    $solidFill = $chartXml.CreateElement("a:solidFill", $ns.LookupNamespace("a"))
    $srgbClr = $chartXml.CreateElement("a:srgbClr", $ns.LookupNamespace("a"))

    switch ($_) {
        0 { $srgbClr.SetAttribute("val", "00B050") } # Strong MFA = green
        1 { $srgbClr.SetAttribute("val", "C00000") } # No MFA = red
    }

    $solidFill.AppendChild($srgbClr) | Out-Null
    $spPr.AppendChild($solidFill) | Out-Null
    $dPt.AppendChild($idx) | Out-Null
    $dPt.AppendChild($spPr) | Out-Null

    $serNode.AppendChild($dPt) | Out-Null
}
$holeNode = $chartXml.SelectSingleNode("//c:holeSize", $ns)
if ($holeNode) {
    $holeNode.SetAttribute("val", "60")
}



$chart.Legend.Position = "Right"
$chart.Border.Fill.Style = "NoFill"



# Top admins
Add-ExcelChart `
    -Worksheet $ws `
    -ChartType BarClustered `
    -Title "Top Risk (Impact)" `
    -XRange "TopRiskAdmins[displayName]" `
    -YRange "TopRiskAdmins[AdminRiskScore]" `
    -Row 32 `
    -Column 1 `
    -Width 500  `
    -Height 340

$chart = ($ws.Drawings | Select-Object -Last 1)
$chart.Style = 26
$chart.SetPosition(40, 0, 2, 0)
$chart.Legend.Remove()
$chart.Border.Fill.Style = "NoFill"

# Top Exploitable Admins 
Add-ExcelChart `
    -Worksheet $ws `
    -ChartType BarClustered `
    -Title "Top Exploitable (Entry)" `
    -XRange "TopExploitableAdmins[displayName]" `
    -YRange "TopExploitableAdmins[ExploitScore]" `
    -Row 32 `
    -Column 1 `
    -Width 500  `
    -Height 340



$chart = ($ws.Drawings | Select-Object -Last 1)
$chart.Style = 26
$chart.SetPosition(40, 0, 6, 0)
$chart.Legend.Remove()
$chart.Border.Fill.Style = "NoFill"

# $chart = $ws.Drawings | Where-Object {
#   $_.Title.Text -eq "Top 10 Highest Risk Admins"
# }
# Attacj Path 
Add-ExcelChart `
    -Worksheet $ws `
    -ChartType ColumnClustered `
    -Title "Identity Attack Surface" `
    -XRange "AttackTable[Stage]" `
    -YRange "AttackTable[Count]" `
    -Row 32 `
    -Column 1 `
    -Width 500  `
    -Height 340

$chart = ($ws.Drawings | Select-Object -Last 1)
$chart.Style = 26
$chart.SetPosition(40, 0, 10, 0)
$chart.Legend.Remove()
$chart.Border.Fill.Style = "NoFill"



# ----------------------------------------------------
# ATTACK CHAIN (CLEAN LAYOUT)
# ----------------------------------------------------

# CONTAINER
$range = $ws.Cells["C59:N72"]

$range.Style.Fill.PatternType = "Solid"
$range.Style.Fill.BackgroundColor.SetColor([System.Drawing.Color]::White)

$range.Style.Border.Top.Style = "None"
$range.Style.Border.Left.Style = "None"
$range.Style.Border.Bottom.Style = "None"
$range.Style.Border.Right.Style = "None"

$ws.View.ShowGridLines = $false

$range.Style.Fill.PatternType = "Solid"
$range.Style.Fill.BackgroundColor.SetColor(
    [System.Drawing.Color]::FromArgb(252, 252, 255)
)

$cell = $ws.Cells["C$row"]
$cell.Value = "• $name"
$cell.Value = $cell.Value
$cell.Style.Font.Name = "Calibri"
$cell.Style.Font.Size = 12
$cell.Style.Font.Color.SetColor([System.Drawing.Color]::FromArgb(50,50,50))

# TITLE
$ws.Cells["C59:N59"].Merge = $true
$ws.Cells["C59"].Value = "Attack Chain"

$ws.Cells["C59"].Style.Font.Size = 16
$ws.Cells["C59"].Style.Font.Bold = $true
$ws.Cells["C59"].Style.HorizontalAlignment = "Center"
$ws.Cells["C59"].Style.VerticalAlignment = "Center"

# HEADERS
$ws.Cells["C61:F61"].Merge = $true
$ws.Cells["G61:J61"].Merge = $true
$ws.Cells["K61:N61"].Merge = $true

$ws.Cells["C61"].Value = "Entry (Initial Access)"
$ws.Cells["G61"].Value = "Escalation (Privilege Gain)"
$ws.Cells["K61"].Value = "Impact (Full Control)"

# Style headers
"C61", "G61", "K61" | ForEach-Object {
    $ws.Cells[$_].Style.Font.Bold = $true
    $ws.Cells[$_].Style.HorizontalAlignment = "Center"
}

# START ROW
$row = 63

# ENTRY
$row = 63
foreach ($u in $entryAdmins) {
    $name = $u.DisplayLabel
    $ws.Cells["C$row:F$row"].Merge = $true
    $ws.Cells["C$row"].Value = "• $name"
    $row++
}

# ESCALATION
$row = 63
foreach ($u in $escalationAdmins) {
    $name = $u.DisplayLabel
    $ws.Cells["G$row:J$row"].Merge = $true
    $ws.Cells["G$row"].Value = "• $name"
    $row++
}

# IMPACT
$row = 63
foreach ($u in $impactAdmins) {
    $name = $u.DisplayLabel
    $ws.Cells["K$row:N$row"].Merge = $true
    $ws.Cells["K$row"].Value = "• $name"
    $row++
}

# ARROWS (center columns)
$ws.Cells["F65"].Value = "→"
$ws.Cells["J65"].Value = "→"

$ws.Cells["F65"].Style.Font.Size = 20
$ws.Cells["J65"].Style.Font.Size = 20

$ws.Cells["F65"].Style.HorizontalAlignment = "Center"
$ws.Cells["J65"].Style.HorizontalAlignment = "Center"


# -----------------------------------
# COLOR BY RISK LEVEL 
# -----------------------------------

$chartXml = $chart.ChartXml

$ns = New-Object System.Xml.XmlNamespaceManager($chartXml.NameTable)
$ns.AddNamespace("c", "http://schemas.openxmlformats.org/drawingml/2006/chart")
$ns.AddNamespace("a", "http://schemas.openxmlformats.org/drawingml/2006/main")

$serNode = $chartXml.SelectSingleNode("//c:ser", $ns)
$points = $chartXml.SelectNodes("//c:ser/c:dPt", $ns)

# säkerställ datapoints finns
if ($points.Count -eq 0) {
    for ($i = 0; $i -lt $topRiskAdmins.Count; $i++) {

        $admin = $topRiskAdmins[$i]

        $dPt = $chartXml.CreateElement("c:dPt", $ns.LookupNamespace("c"))

        $idx = $chartXml.CreateElement("c:idx", $ns.LookupNamespace("c"))
        $idx.SetAttribute("val", $i)

        $spPr = $chartXml.CreateElement("c:spPr", $ns.LookupNamespace("c"))
        $solidFill = $chartXml.CreateElement("a:solidFill", $ns.LookupNamespace("a"))
        $srgbClr = $chartXml.CreateElement("a:srgbClr", $ns.LookupNamespace("a"))

        switch ($admin.AdminRiskLevel) {
            "Critical" { $srgbClr.SetAttribute("val", "C00000") } # red
            "High" { $srgbClr.SetAttribute("val", "FF8C00") } # orange
            "Medium" { $srgbClr.SetAttribute("val", "5B9BD5") } # blue
            default { $srgbClr.SetAttribute("val", "00B050") } # green
        }

        $solidFill.AppendChild($srgbClr) | Out-Null
        $spPr.AppendChild($solidFill) | Out-Null
        $dPt.AppendChild($idx) | Out-Null
        $dPt.AppendChild($spPr) | Out-Null

        $serNode.AppendChild($dPt) | Out-Null
    }
}

# -------------------------
# Executive Summary Text
# -------------------------

$bgRange = $Summaryws.Cells["A1:F200"]

$bgRange.Style.Fill.PatternType = [OfficeOpenXml.Style.ExcelFillStyle]::Solid
$bgRange.Style.Fill.BackgroundColor.SetColor(
    [System.Drawing.Color]::FromArgb(248, 248, 250)
)

# Clean background
$Summaryws.Cells.Style.Fill.PatternType = "Solid"
$Summaryws.Cells.Style.Fill.BackgroundColor.SetColor(
    [System.Drawing.Color]::FromArgb(248, 248, 250)
)

# Column width
1..6 | ForEach-Object { $Summaryws.Column($_).Width = 28 }

# ----------------------------------------------------
# HEADER
# ----------------------------------------------------
#Epical Colors
$epicalPurple = [System.Drawing.Color]::FromArgb(122, 31, 162)
$lightPurple = [System.Drawing.Color]::FromArgb(240, 235, 248)
$darkGray = [System.Drawing.Color]::FromArgb(64, 64, 64)
$lightGray = [System.Drawing.Color]::FromArgb(245, 245, 247)
$accentGreen = [System.Drawing.Color]::FromArgb(0, 150, 0)
$accentOrange = [System.Drawing.Color]::FromArgb(255, 140, 0)
$accentRed = [System.Drawing.Color]::FromArgb(200, 0, 0)
$Summaryws.Cells.Clear()

# Column layout
$Summaryws.Column(1).Width = 32
$Summaryws.Column(2).Width = 105

# Header
$Summaryws.Cells["A1:B1"].Merge = $true
$Summaryws.Cells["A1"].Value = "Entra Identity Security Executive Summary"

$Summaryws.Cells["A1"].Style.Font.Size = 24
$Summaryws.Cells["A1"].Style.Font.Bold = $true
$Summaryws.Cells["A1"].Style.Font.Color.SetColor([System.Drawing.Color]::White)

$Summaryws.Cells["A1"].Style.Fill.PatternType = "Solid"
$Summaryws.Cells["A1"].Style.Fill.BackgroundColor.SetColor($epicalPurple)

$Summaryws.Cells["A1"].Style.HorizontalAlignment = "Center"
$Summaryws.Row(1).Height = 40

$row = 3
function Set-CardStyle {
    param($range, $bgColor)

    $range.Style.Fill.PatternType = "Solid"
    $range.Style.Fill.BackgroundColor.SetColor($bgColor)
    $range.Style.Border.BorderAround("Thin")

    $range.Style.WrapText = $true
    $range.Style.HorizontalAlignment = "Left"
    $range.Style.VerticalAlignment = "Top"

    $range.Style.Indent = 1
}


# Columns
$Summaryws.Column(1).Width = 30
$Summaryws.Column(2).Width = 110

# Title
$Summaryws.Cells["A1:B1"].Merge = $true
$Summaryws.Cells["A1"].Value = "Identity Security Executive Summary"
$Summaryws.Cells["A1"].Style.Font.Size = 22
$Summaryws.Cells["A1"].Style.Font.Bold = $true
$Summaryws.Cells["A1"].Style.HorizontalAlignment = "Center"

$row = 3
# ----------------------------------------------------
# McKinsey style 
# ----------------------------------------------------
function Add-ExecSection {
    param(
        $title,
        $text,
        $color = $lightGray
    )

    $cellTitle = $Summaryws.Cells["A$row"]
    $cellContent = $Summaryws.Cells["B$row"]

    # ---------------------------
    # INIT 
    # ---------------------------
    $cellTitle.Value = $title
    $cellContent.Value = $text

    # ---------------------------
    # TITLE STYLE
    # ---------------------------
    $cellTitle.Style.Font.Bold = $true
    $cellTitle.Style.Font.Size = 12
    $cellTitle.Style.Font.Color.SetColor($epicalPurple)

    # ---------------------------
    # CONTENT STYLE
    # ---------------------------
    $cellContent.Style.WrapText = $true
    $cellContent.Style.Font.Size = 12

    # ---------------------------
    # BACKGROUND
    # ---------------------------
    $range = $Summaryws.Cells["A$row:B$row"]
    $range.Style.Fill.PatternType = "Solid"
    $range.Style.Fill.BackgroundColor.SetColor($color)
    $range.Style.Border.Bottom.Style = "Thin"

    # ---------------------------
    # AUTO HEIGHT (fix för multiline)
    # ---------------------------
    $lines = ($text -split "`n").Count
    $Summaryws.Row($row).Height = [Math]::Max(40, ($lines * 15))

    $script:row += 2
}

# ----------------------------------------------------
# GLOBAL FONT 
# ----------------------------------------------------
$Summaryws.Cells.Style.Font.Name = "Calibri"
$Summaryws.Cells.Style.Font.Size = 11

# ----------------------------------------------------
# HEADER (SAFE)
# ----------------------------------------------------
$headerScore = $Summaryws.Cells["A3"]
$headerLevel = $Summaryws.Cells["A4"]

$Summaryws.Cells["A3:B3"].Merge = $true
$Summaryws.Cells["A4:B4"].Merge = $true

# INIT
$headerScore.Value = "$postureScore"
$headerLevel.Value = $postureLevel

# STYLE
$headerScore.Style.Font.Size = 30
$headerScore.Style.Font.Bold = $true
$headerScore.Style.HorizontalAlignment = "Center"

$headerLevel.Style.Font.Size = 18
$headerLevel.Style.HorizontalAlignment = "Center"

$row = 6

# ----------------------------------------------------
# EXECUTIVE SUMMARY
# ----------------------------------------------------
$summaryParts = @()

if ($noMFAAdmins -gt 0) { $summaryParts += "privileged accounts lack strong MFA" }
if ($inactiveAdmins -gt 0) { $summaryParts += "inactive privileged accounts remain assigned" }
if ($criticalAdmins -gt 0) { $summaryParts += "high-impact roles are permanently assigned" }
if ($pimCoverage -lt 50) { $summaryParts += "Just-In-Time access is not consistently enforced" }

$summaryMessage = if ($summaryParts.Count -eq 0) {
    "Privileged access is well controlled with limited exposure."
} else {
    "Privileged access is partially controlled, but key risks remain: " + ($summaryParts -join ", ") + "."
}

Add-ExecSection "Executive Summary" $summaryMessage $lightPurple

# ----------------------------------------------------
# SECURITY RATING
# ----------------------------------------------------
$gradeText = "Grade $grade ($postureScore/100) — posture indicates elevated risk exposure."
Add-ExecSection "Security Rating" $gradeText $lightPurple

# ----------------------------------------------------
# PRIORITY
# ----------------------------------------------------
if ($noMFAAdmins -gt 5 -or $criticalAdmins -gt 10) {
    $priorityLevel = "🔴 High priority"
    $priorityBg = [System.Drawing.Color]::FromArgb(255,220,220)
}
elseif ($postureScore -lt 60) {
    $priorityLevel = "🟠 Medium priority"
    $priorityBg = [System.Drawing.Color]::FromArgb(255,240,200)
}
else {
    $priorityLevel = "🟢 Low priority"
    $priorityBg = [System.Drawing.Color]::FromArgb(220,255,220)
}

Add-ExecSection "Priority Level" $priorityLevel $priorityBg

# ----------------------------------------------------
# PRIMARY RISK
# ----------------------------------------------------
$primaryRisk = $risks | Sort-Object Count -Descending | Select-Object -First 1
$primaryRiskText = "$($primaryRisk.Name) ($($primaryRisk.Count) accounts)"

Add-ExecSection "Primary Risk" $primaryRiskText ([System.Drawing.Color]::FromArgb(255,230,230))

# ----------------------------------------------------
# KEY RISK DRIVERS
# ----------------------------------------------------
$keyRiskText = ($topRisks | ForEach-Object {
    "• $($_.Name) ($($_.Count))"
}) -join "`n"

Add-ExecSection "Key Risk Drivers" $keyRiskText ([System.Drawing.Color]::FromArgb(255,245,220))

# ----------------------------------------------------
# ATTACK PATH OVERVIEW
# ----------------------------------------------------
$topEntry = $attackCandidates | Where-Object AttackRole -eq "Entry" | Select-Object -First 2
$topEsc = $attackCandidates | Where-Object AttackRole -eq "Escalation" | Select-Object -First 2
$topImpact = $attackCandidates | Where-Object AttackRole -eq "Impact" | Select-Object -First 2

$entryNames = ($topEntry | ForEach-Object { $_.DisplayLabel }) -join ", "
$escNames = ($topEsc | ForEach-Object { $_.DisplayLabel }) -join ", "
$impactNames = ($topImpact | ForEach-Object { $_.DisplayLabel }) -join ", "

if ($entryPoints -gt 0 -and $impactPoints -gt 0) {
    $attackText = "An end-to-end attack path exists. Entry ($entryPoints): $entryNames → Impact ($impactPoints): $impactNames."
}
elseif ($escalationPoints -gt 0 -and $impactPoints -gt 0) {
    $attackText = "Escalation paths ($escalationPoints) can lead to critical roles ($impactPoints): $escNames → $impactNames."
}
elseif ($entryPoints -gt 0) {
    $attackText = "Weak entry points ($entryPoints): $entryNames, but no full escalation path identified."
}
else {
    $attackText = "No clear attack paths identified."
}

Add-ExecSection "Attack Path Overview" $attackText ([System.Drawing.Color]::FromArgb(255,240,200))

# ----------------------------------------------------
# RISK INTERPRETATION
# ----------------------------------------------------
$riskText = ($riskNarrative | ForEach-Object { "• $_" }) -join "`n"
Add-ExecSection "Risk Interpretation" $riskText

# ----------------------------------------------------
# ACTIONS
# ----------------------------------------------------
$actions = @()
if ($noMFAAdmins -gt 0) { $actions += "Enforce strong MFA" }
if ($inactiveAdmins -gt 0) { $actions += "Remove inactive accounts" }
if ($pimCoverage -lt 80) { $actions += "Implement Just-In-Time access" }

$actionText = ($actions | ForEach-Object { "• $_" }) -join "`n"
Add-ExecSection "Recommended Actions" $actionText ([System.Drawing.Color]::FromArgb(230,245,230))

# ----------------------------------------------------
# STRENGTHS
# ----------------------------------------------------
$strengths = @()
if ($noMFAAdmins -eq 0) { $strengths += "All admins protected with MFA" }
if ($criticalAdmins -eq 0) { $strengths += "No critical role exposure" }
if ($strengths.Count -eq 0) { $strengths += "Security baseline established" }

$strengthText = ($strengths | ForEach-Object { "• $_" }) -join "`n"
Add-ExecSection "Security Strengths" $strengthText ([System.Drawing.Color]::FromArgb(235,235,245))




$attackTable | Format-Table
$allAdmins | Select displayName, AttackRole, AttackPathScore | ft -AutoSize
$Summaryws.Row(3).Height = 30

Close-ExcelPackage -ExcelPackage  $excel

Write-Host "✅ Export completed successfully: $exportPath" -ForegroundColor Green