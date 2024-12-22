  param ($menuSelection, $howMany, $configPath)


function AADSync($AADCServer){
    
    $remoteSession = $false
    if($AADCServer -ne $env:COMPUTERNAME){
        $remoteSession = $true
        Enter-PSSession -HostName $AADCServer
    }

    try{
        $runState = Get-ADSyncConnectorRunStatus
    }catch{
        write-host "[Warning]: AADC not installed on this machine. Cannot perform AADC Sync"
        return
    }

    if($runState -ne $null){
        write-host "[INFO]: Starting AD Sync Cycle"
        Start-ADSyncSyncCycle -PolicyType delta
    }else{
        if($runState.runState -ne "Busy"){
            write-host "[INFO]: Starting AD Sync Cycle"
            Start-ADSyncSyncCycle -PolicyType delta
        }
    }

    if($remoteSession -eq $true){
        Exit-PSSession
    }

    start-sleep -seconds 10
}

function GenerateRandomSelection($topRange, $howMany){

    # 'randomise' seed
    # 2147483647 = Int maximum allowed value
    $seed = Get-Random
    for($i=0;$i -lt 100;$i++){
        $seed = $seed + (Get-random -Maximum (2147483647-$seed) -Minimum 0)
        $seed = Get-Random -SetSeed $seed -Maximum 21474836 -Minimum 0
    }

    #Select Random Users
    $randomSelect = @()
    while($randomSelect.count -lt $howMany){
        $newRand = Get-Random -Minimum 0 -Maximum $topRange 
        if(!($randomSelect.Contains($newRand))){
            $randomSelect += $newRand
        }
    }

    return @($randomSelect)

}

function GenerateRandomPassword{
    param (
        [Parameter(Mandatory)]
        [int] $length,
        [int] $amountOfNonAlphanumeric = 1
    )
    Add-Type -AssemblyName 'System.Web'
    return [System.Web.Security.Membership]::GeneratePassword($length, $amountOfNonAlphanumeric)
}

function RemoveExcludedAccounts($allAccounts){

    write-host "[INFO]: -----Starting RemoveExcludedAccounts Function-----"
    write-host "[INFO]: Excluded Group $($config.excludedUsersGroup)"

    #Get Excluded Users group
    $excludedUserGroup = Get-ADGroup -Identity $config.excludedUsersGroup -server $config.domain
    $excludedUsers = Get-ADGroupMember $excludedUserGroup -Server $config.domain
    $excludedUsers += Get-ADUser krbtgt -server $config.domain

    $nonGroupMembers = foreach($account in $allAccounts)
    {
        $isGroupMember = $false
        foreach($member in $excludedUsers)
        {
            if($account.sAMAccountName -eq $member.sAMAccountName)
            {
                $isGroupMember = $true
                break
            }
        }
        if(-not $isGroupMember)
        {
            $account
        }
    }

    return $nonGroupMembers
}

function ResetADPassword($samAcccountName){
    
   # $userAccount = Get-ADUser $samAcccountName
    $password = ConvertTo-SecureString (GenerateRandomPassword -length 16 -amountOfNonAlphanumeric 4) -AsPlainText -Force

    Set-ADAccountPassword $samAcccountName -NewPassword $password -Server $config.domain -Reset

}

function SimulateHowManyUsers(){
    #Ensure user enters a number
    write-host "How many users would you like to simulate?" 
    $howMany = read-host "Enter the number 1 to select a user to simulate"
    if(!($howMany -match "^[\d\.]+$")){
        write-host "[Error] $howMany is not a number"
        write-host "[INFO]: Setting Simulation to 10 users"
        $howMany = 10
    }else{
        $howMany = [int]$howMany
    }

    return $howMany
}

function BulkImpersonateUsers($enabledusers, $howmany){

    write-host "[INFO]: ------Starting BulkImpersonateUsers Function-----" -ForegroundColor Cyan

    if($howMany -eq -1){
        $howMany = SimulateHowManyUsers
    }
    if($howMany -eq 1){
        
        $username = Read-host "Enter a username (eg, dt3543)"
        $user = Get-ADUser $username -ErrorAction SilentlyContinue -Server $config.domain
        if($user -ne $null){
            $upn = "$($username)@$($config.domain)"
            write-host "[INFO]: Impersonating $upn"
            $windowsIdentity = New-Object System.Security.Principal.WindowsIdentity($upn)
            $impersonatedContext = $windowsIdentity.Impersonate()
            $impersonatedContext.Undo()
        }else{
            Write-host "[Warning]: Could not find user. User was not impersonated" -ForegroundColor Yellow
        }

    }else{
        write-host "[INFO]: Selecting Random Users within allEnableduser Range"
        $randomSelect = GenerateRandomSelection -topRange ($enabledUsers.count) -howMany $howMany

         for($i=0;$i -lt $randomSelect.count; $i++){
        
            $index = $randomSelect[$i]
            $username = $enabledUsers[$index].SamAccountName
        
            $upn = "$($username)@$($config.domain)"

            write-host "[INFO]: Impersonating $upn"
            $windowsIdentity = New-Object System.Security.Principal.WindowsIdentity($upn)
            $impersonatedContext = $windowsIdentity.Impersonate()
            $impersonatedContext.Undo()
        }

    }
    

}

function BulkResetPasswords($allUsers, $howMany){

     write-host "[INFO]: ------Starting BulkResetPasswords Function-----" -ForegroundColor Cyan

    if($howMany -eq -1){
        $howMany = SimulateHowManyUsers
    }

    if($howMany -eq 1){
        
        $username = Read-host "Enter a username (eg, dt3543)"
        $user = Get-ADUser $username -ErrorAction SilentlyContinue -Server $config.domain
        if($user -ne $null){
            Write-host "[INFO]: Resetting $($username)'s password"
            ResetADPassword -samAcccountName $username

        }else{
            Write-host "[Warning]: Could not find user. User's password was not reset" -ForegroundColor Yellow
        }

    }else{    
        write-host "[INFO]: Selecting Random Users within allEnableduser Range"
        $randomSelect = GenerateRandomSelection -topRange $allUsers.count -howMany $howMany

        for($i=0; $i -lt $howMany; $i++){
        
            Write-host "[INFO]: Resetting $($allUsers[($randomSelect[$i])])'s password"
            ResetADPassword -samAcccountName $allUsers[($randomSelect[$i])]

        }
    }

}

function BulkLockAccounts($enabledUsers, $howMany){
    
    write-host "[INFO]: ------Starting BulkLockAccounts Function-----" -ForegroundColor Cyan

    if($howMany -eq -1){
        $howMany = SimulateHowManyUsers
    }

    
    if($howMany -eq 1){
        
        $username = Read-host "Enter a username (eg, dt3543)" -Server $config.domain
        $user = Get-ADUser $username -ErrorAction SilentlyContinue
        if($user -ne $null){

            $lockoutCount = $config.lockoutAttempts
        
            $badPassword = ConvertTo-SecureString "A" -AsPlainText -Force

            Write-host "[INFO]: Locking out $($username)"
            for($x=0; $x -lt $lockoutCount+1; $x++){
                Invoke-Command -ComputerName $config.testLoginServer {Get-Process}`
                        -Credential (New-Object System.Management.Automation.PSCredential ($($username), $badPassword))`
                        -ErrorAction SilentlyContinue
                
            }
            

        }else{
            Write-host "[Warning]: Could not find user. User's password was not reset" -ForegroundColor Yellow
        }

    }else{ 
    
        write-host "[INFO]: Selecting Random Users within allEnableduser Range"
        $randomSelect = GenerateRandomSelection -topRange $enabledUsers.count -howMany $howMany

        $lockoutCount = $config.lockoutAttempts
        for($i=0; $i -lt $howMany; $i++){
        
            $badPassword = ConvertTo-SecureString "A" -AsPlainText -Force

            Write-host "[INFO]: Locking out $($enabledUsers[($randomSelect[$i])])"
            for($x=0; $x -lt $lockoutCount+1; $x++){
                Invoke-Command -ComputerName $config.testLoginServer {Get-Process}`
                     -Credential (New-Object System.Management.Automation.PSCredential ($($enabledUsers[($randomSelect[$i])].SamAccountName), $badPassword))`
                     -ErrorAction SilentlyContinue
                
            }
        }
    }

}

function BulkUnlockAccounts($enabledUsers, $howMany){

    write-host "[INFO]: ------Starting BulkUnlockAccounts Function-----" -ForegroundColor Cyan

    $allLockedAccounts = Search-ADAccount -UsersOnly -LockedOut

    #if no accounts are locked, give option to lock some
    if(($allLockedAccounts.count -eq 0) -and ($howMany -eq -1)){
        Write-host "[Warning]: There are no locked out accounts"
        $selection = read-host "Would you like to lock out some accounts? (y/n)"
        
        switch($selection.ToLower()){
            "y" {BulkLockAccounts -enabledUsers $enabledUsers -howMany -1 ; $allLockedAccounts = Search-ADAccount -UsersOnly -LockedOut -Server $config.domain}
            default {"Returning to Menu"; exit}
        }

    }elseif($allLockedAccounts.count -eq 0){
        Write-host "[Warning]: There are no locked out accounts"
        BulkLockAccounts -enabledUsers $enabledUsers -howMany ($howMany*2)
        $allLockedAccounts = Search-ADAccount -UsersOnly -LockedOut -Server $config.domain
    }

    if($howMany -eq -1){
        $howMany = SimulateHowManyUsers
    }

    
    if($howMany -eq 1){

        $howMany = SimulateHowManyUsers
        $username = Read-host "Enter a username (eg, dt3543)"
        $user = Get-ADUser $username -ErrorAction SilentlyContinue -Server $config.domain

        if($user -ne $null){
            $locked = $false
            
            foreach($lockedAccount in $allLockedAccounts){
                if($lockedAccount.samAccountName -eq $user.samAccountName){
                    write-host "[INFO]: Unlocking account: $($username)"
                    Unlock-ADAccount -Identity $username -Server $config.domain
                    $locked = $true
                }
            }
            if($locked -eq $false){
                write-host "[Warning]: $($username)'s account was not locked. Skipping unlock" -ForegroundColor Yellow
            }
        }else{
             Write-host "[Warning]: Could not find user. User's password was not reset" -ForegroundColor Yellow
        }


    }else{

        if($howMany -gt $allLockedAccounts.count){
            write-host "[Warning]: There are only $($allLockedAccounts.count) Locked accounts, changing to match Maximum"
            $howMany = $allLockedAccounts.count
        }

        write-host "[INFO]: Selecting Random Users within allEnableduser Range"
        $randomSelect = GenerateRandomSelection -topRange $allLockedAccounts.count -howMany $howMany

        for($i=0;$i -lt $howMany; $i++){
        
            write-host "[INFO]: Unlocking account: $($allLockedAccounts[($randomSelect[$i])])"
            Unlock-ADAccount -Identity $allLockedAccounts[($randomSelect[$i])]
        }
 
    }

}

function BulkDisableAccounts($enabledUsers, $howMany){

    write-host "[INFO]: ------Starting BulkDisableAccounts Function-----" -ForegroundColor Cyan

    if($howMany -eq -1){
        $howMany = SimulateHowManyUsers
    }
    if($howMany -eq 1){
        
        $username = Read-host "Enter a username (eg, dt3543)"
        $user = Get-ADUser $username -ErrorAction SilentlyContinue -Server $config.domain

        if($user -ne $null){
            write-host "[INFO]: Disabling account: $($username)"
            Disable-ADAccount -Identity $($username)
        }else{
            write-host "[Warning]: Could not find $($username). Skipping account" -ForegroundColor Yellow
        }


    }else{
    
        write-host "[INFO]: Selecting Random Users within allEnableduser Range"
        $randomSelect = GenerateRandomSelection -topRange $enabledUsers.count -howMany $howMany
    
    
        for($i=0;$i -lt $howMany; $i++){
        
            write-host "[INFO]: Disabling account: $($enabledUsers[($randomSelect[$i])])"
            Disable-ADAccount -Identity $enabledUsers[($randomSelect[$i])]-Server $config.domain
        }
    }
}

function BulkEnableAccounts($disabledUsers, $howMany){

    write-host "[INFO]: ------Starting BulkEnableAccounts Function-----" -ForegroundColor Cyan

    if($howMany -eq -1){
        $howMany = SimulateHowManyUsers
    }

    if($howMany -eq 1){
        
        $username = Read-host "Enter a username (eg, dt3543)"
        $user = Get-ADUser $username -ErrorAction SilentlyContinue -Server $config.domain

        if($user -ne $null){
            if(!($user.enabled)){
                write-host "[INFO]: Enabling account: $($username)"
                Enable-ADAccount -Identity $username
            }else{
                write-host "[Warning]: $($username) is not disabled. Skipping account" -ForegroundColor Yellow
            }
        }else{
            write-host "[Warning]: Could not find $($username). Skipping account" -ForegroundColor Yellow
        }


    }else{
    
        if([int]$howMany -gt [int]$disabledUsers.count){
            write-host "[Warning]: There are only $($disabledUsers.count) Disabled accounts, changing to match maximum" -ForegroundColor Yellow
            $howMany = $disabledUsers.count
        }

        write-host "[INFO]: Selecting Random Users within disableduser Range"
        $randomSelect = GenerateRandomSelection -topRange $disabledUsers.count -howMany $howMany
    
        if($disabledUsers.count -lt 2){
        write-host "[INFO]: Enabling account: $($disabledUsers)"
                Enable-ADAccount -Identity $disabledUsers -Server $config.domain
        }
        else{
            for($i=0;$i -lt $howMany; $i++){
                write-host "[INFO]: Enabling account: $($disabledUsers[($randomSelect[$i])])"
                Enable-ADAccount -Identity $disabledUsers[($randomSelect[$i])] -Server $config.domain
            }
        }
    }
}

function BulkFailLogin($enabledUsers, $howMany){
    
    write-host "[INFO]: ------Starting BulkFailLogin Function-----" -ForegroundColor Cyan

    if($howMany -eq -1){
        $howMany = SimulateHowManyUsers
    }
    
    $lockoutCount = 10

    if($howMany -eq 1){

        $badPassword = ConvertTo-SecureString "A" -AsPlainText -Force
        $username = Read-host "Enter a username (eg, dt3543)"
        $user = Get-ADUser $username -ErrorAction SilentlyContinue -Server $config.domain

        if($user -ne $null){
            if(($user.enabled)){
                for($x=0; $x -lt $lockoutCount-2; $x++){
                    Invoke-Command -ComputerName $config.testLoginServer {Get-Process}`
                         -Credential (New-Object System.Management.Automation.PSCredential ($($user.SamAccountName), $badPassword))`
                         -ErrorAction SilentlyContinue
                }

            }else{
                write-host "[Warning]: $($username) is disabled. Skipping account" -ForegroundColor Yellow
            }
        }else{
            write-host "[Warning]: Could not find $($username). Skipping account" -ForegroundColor Yellow
        }


    }else{

        write-host "[INFO]: Selecting Random Users within allEnableduser Range"
        $randomSelect = GenerateRandomSelection -topRange $enabledUsers.count -howMany $howMany

        for($i=0; $i -lt $howMany; $i++){
        
            $badPassword = ConvertTo-SecureString "A" -AsPlainText -Force

            Write-host "[INFO]: Failing login for $($enabledUsers[($randomSelect[$i])])"
            for($x=0; $x -lt $lockoutCount-2; $x++){
                Invoke-Command -ComputerName $config.testLoginServer {Get-Process}`
                     -Credential (New-Object System.Management.Automation.PSCredential ($($enabledUsers[($randomSelect[$i])].SamAccountName), $badPassword))`
                     -ErrorAction SilentlyContinue
                
            }
        }
    }

}

function BulkMoveAccounts ($allUsers, $howMany){

    write-host "[INFO]: ------Starting BulkMoveAccounts Function-----" -ForegroundColor Cyan

    if($howMany -eq -1){
        $howMany = SimulateHowManyUsers
    }
    
    if($howMany -eq 1){
        $username = Read-host "Enter a username (eg, dt3543)"
        $user = Get-ADUser $username -ErrorAction SilentlyContinue -Server $config.domain

        if($user -ne $null){
            $allOUs = Get-ADOrganizationalUnit -Server $config.domain -filter * -SearchBase $config.baseUserOU -SearchScope Subtree | select DistinguishedName
            $randOU = GenerateRandomSelection -topRange $allOUs.count -howMany 1
                
            Write-host "[INFO]: Moving user $($User.DistinguishedName) to $($allOus[$randOU].DistinguishedName)"
            Move-ADObject -Server $config.domain -Identity $user.DistinguishedName -TargetPath $allOus[$randOU].DistinguishedName 
        }else{
            write-host "[Warning]: Could not find $($username). Skipping account" -ForegroundColor Yellow
        }

    }else{
    
        write-host "[INFO]: Selecting Random Users within allEnableduser Range"
        $randomSelect = GenerateRandomSelection -topRange $allUsers.count -howMany $howMany

        $allOUs = Get-ADOrganizationalUnit -Server $config.domain -filter * -SearchBase $config.baseUserOU -SearchScope Subtree | select DistinguishedName

        for($i=0;$i -lt $howMany; $i++){
            $user = Get-ADUser $allUsers[($randomSelect[$i])].samAccountName -Server $config.domain
            $randOU = GenerateRandomSelection -topRange $allOUs.count -howMany 1
        
            Write-host "[INFO]: Moving user $($User.DistinguishedName) to $($allOus[$randOU].DistinguishedName)"
            Move-ADObject -Server $config.domain -Identity $user.DistinguishedName -TargetPath $allOus[$randOU].DistinguishedName
        }
    }

}

function BulkUpdateDepartments($allUsers, $howMany){
    
    write-host "[INFO]: ------Starting BulkUpdateDepartments Function-----" -ForegroundColor Cyan

    $allDepartments = get-content $config.departmentsList


    if($howMany -eq -1){
        $howMany = SimulateHowManyUsers
    }

    if($howMany -eq 1){

        $username = Read-host "Enter a username (eg, dt3543)"
        $user = Get-ADUser $username -ErrorAction SilentlyContinue -Server $config.domain

        if($user -ne $null){
               
                $randDept = GenerateRandomSelection -topRange $allDepartments.count -howMany 1
        
                Write-host "[INFO]: Updating $($User.DistinguishedName)'s department to $($allDepartments[$randDept])"
                Set-ADUser -Identity $user.DistinguishedName -Department $allDepartments[$randDept] -Server $config.domain
           
        }else{
            write-host "[Warning]: Could not find $($username). Skipping account" -ForegroundColor Yellow
        }


    }else{
    
        write-host "[INFO]: Selecting Random Users within allEnableduser Range"
        $randomSelect = GenerateRandomSelection -topRange $allUsers.count -howMany $howMany

         for($i=0; $i -lt $howMany; $i++){
                for($i=0;$i -lt $howMany; $i++){
                    $user = Get-ADUser $allUsers[($randomSelect[$i])].samAccountName -Server $config.domain
                    $randDept = GenerateRandomSelection -topRange $allDepartments.count -howMany 1
        
                    Write-host "[INFO]: Updating $($User.DistinguishedName)'s department to $($allDepartments[$randDept])"
                    Set-ADUser -Identity $user.DistinguishedName -Department $allDepartments[$randDept] -Server $config.domain
                }
          }  
    }
    
}

function BulkDepartUsers($enabledUsers, $howMany){

    write-host "------Starting BulkDepartUsers Function-----" -ForegroundColor Cyan

    if($howMany -eq -1){
        $howMany = SimulateHowManyUsers
    }
    
    if($howMany -eq 1){
        $username = Read-host "Enter a username (eg, dt3543)"
        $user = Get-ADUser $username -ErrorAction SilentlyContinue -Server $config.domain

        if($user -ne $null){
            write-host "[INFO]: Disabling User $($user.samAccountName)"
            $user | set-aduser -Enabled $false

            write-host "[INFO]: Moving User $($user.samAccountName) to Departed OU"
            $Object = Get-ADObject -Identity $user.DistinguishedName -Server $config.domain
            $object | Move-ADObject -TargetPath $config.departedOU -Server $config.domain
        }else{
            write-host "[Warning]: Could not find $($username). Skipping account" -ForegroundColor Yellow
        }

    }else{
        write-host "[INFO]: Selecting Random Users within enabledUsers Range"
        $randomSelect = GenerateRandomSelection -topRange $enabledUsers.count -howMany $howMany

        if($howMany -gt 1){
            for($i=0; $i -lt $howMany; $i++){
                write-host "[INFO]: Disabling User $($enabledUsers[($randomSelect[$i])].samAccountName)"
                $user = Get-ADUser $enabledUsers[($randomSelect[$i])].samAccountName -Server $config.domain
                $user | set-aduser -Enabled $false -Server $config.domain
                write-host "[INFO]: Moving User $($enabledUsers[($randomSelect[$i])].samAccountName) to Departed OU"
                $Object = Get-ADObject -Identity $user.DistinguishedName -Server $config.domain
                $object | Move-ADObject -TargetPath $config.departedOU -Server $config.domain
            }
        }
    }

}

function BulkChangeEndDates($enabledUsers, $howMany){

    write-host "[INFO]: ------Starting BulkDepartUsers Function-----" -ForegroundColor Cyan

    if($howMany -eq -1){
        $howMany = SimulateHowManyUsers
    }

    if($howMany -eq 1){
        
        $username = Read-host "Enter a username (eg, dt3543)"
        $user = Get-ADUser $username -ErrorAction SilentlyContinue -Server $config.domain

        if($user -ne $null){
            $mod = $randomSelect % 365
            $newDate = (Get-Date).AddDays($mod)
            
            write-host "[INFO]: Updating account expiration date for $($user.samAccountName) to $newDate"
            $user | set-ADUser -AccountExpirationDate $newDate -Server $config.domain

        }else{
            write-host "[Warning]: Could not find $($username). Skipping account" -ForegroundColor Yellow
        }
        

    }else{
        write-host "[INFO]: Selecting Random Users within enabledUsers Range"
        $randomSelect = GenerateRandomSelection -topRange $enabledUsers.count -howMany $howMany

        for($i=0; $i -lt $howMany; $i++){

            $mod = $randomSelect[$i] % 365
            $newDate = (Get-Date).AddDays($mod)
            
            write-host "[INFO]: Updating account expiration date for $($enabledUsers[$randomSelect[$i]].samAccountName) to $newDate"
            $user = Get-ADUser $enabledUsers[$randomSelect[$i]].samAccountName -Server $config.domain
            $user | set-ADUser -AccountExpirationDate $newDate -Server $config.domain

        }
    }

}

function BulkUpdateNotes($allUsers, $howMany){
    
    write-host "[INFO]: ------Starting BulkUpdateNotes Function-----" -ForegroundColor Cyan

    $date = Get-Date
    $notes = "Added Simulated notes $date"

    if($howMany -eq -1){
        $howMany = SimulateHowManyUsers
    }

    if($howMany -eq 1){
        
        $username = Read-host "Enter a username (eg, dt3543)"
        $user = Get-ADUser $username -ErrorAction SilentlyContinue -Server $config.domain
        if($user -ne $null){
            write-host "[INFO]: Updating Notes for $username to $notes"
            $user | set-ADUser -Replace @{"info"=$notes} -Server $config.domain
        }

       
    }else{
        write-host "[INFO]: Selecting Random Users within enabledUsers Range"
        $randomSelect = GenerateRandomSelection -topRange $allUsers.count -howMany $howMany

        for($i=0;$i -lt $howMany; $i++){
            $user = Get-ADUser $allUsers[$randomSelect[$i]].samAccountName -Server $config.domain
            write-host "[INFO]: Updating Notes for $($user.samAccountName) to '$($notes)'"
            $user | set-ADUser -Replace @{"info"=$notes} -Server $config.domain

        }

    }

}

function SimulateEverything($allUsers, $enabledUsers, $disabledUsers, $howMany){

    if($howMany -eq -1){
        $howMany = SimulateHowManyUsers
    }
    
    BulkImpersonateUsers -enabledusers $enabledUsers -howmany $howMany
    BulkResetPasswords -allUsers $allUsers -howMany $howMany
    BulkLockAccounts -enabledUsers $enabledUsers -howMany $howMany
    BulkUnlockAccounts -enabledUsers $enabledUsers -howMany $howMany
    BulkDisableAccounts -enabledUsers $enabledUsers -howMany $howMany
    BulkEnableAccounts -disabledUsers $disabledUsers -howMany $howMany
    BulkFailLogin -enabledUsers $enabledUsers -howMany $howMany
    BulkMoveAccounts -allUsers $allUsers -howMany $howMany
    BulkUpdateDepartments -allUsers $allUsers -howMany $howMany
    BulkDepartUsers -enabledUsers $enabledUsers -howMany $howMany
    BulkChangeEndDates -enabledUsers $enabledUsers -howMany $howMany
    BulkUpdateNotes -allUsers $allUsers -howMany $howMany
}
    
function Menu($allDirectoryUsers, $allEnabledUsers, $allDisabledUsers, $selection, $howMany, $AADCServer){

    do{
        write-host "---------------------MENU----------------------------" -ForegroundColor Yellow
        write-host "Please select a simulation from the following options"
        write-host "1. Login to Machines"
        write-host "2. Reset Passwords"
        write-host "3. Lock Accounts"
        write-host "4. Unlock Accounts"
        write-host "5. Disable Accounts"
        write-host "6. Enable Accounts"
        write-host "7. Shuffle users"
        write-host "8. Shuffle Departments"
        write-host "9. Failed Logins"
        write-host "10. Depart Users"
        write-host "11. Change End Dates"
        write-host "12. Update Notes section"
        write-host "13. All of the above"
        write-host "14. Finished"
        $selection = Read-host "Selection"


        switch($selection){
            "1" {BulkImpersonateUsers -enabledUsers $allEnabledUsers -howMany -1}
            "2" {BulkResetPasswords -allUsers $allDirectoryUsers -howMany -1}
            "3" {BulkLockAccounts -enabledUsers $allEnabledUsers -howMany -1}
            "4" {BulkUnlockAccounts -enabledUsers $allEnabledUsers -howMany -1}
            "5" {BulkDisableAccounts -enabledUsers $allEnabledUsers -howMany -1}
            "6" {BulkEnableAccounts -disabledUsers $allDisabledUsers -howMany -1}
            "7" {BulkMoveAccounts -allUsers $allDirectoryUsers -howMany -1}
            "8" {BulkUpdateDepartments -allUsers $allDirectoryUsers -howMany -1}
            "9" {BulkFailLogin -enabledUsers $allEnabledUsers -howMany -1}
            "10" {BulkDepartUsers -enabledUsers $allEnabledUsers -howMany -1}
            "11" {BulkChangeEndDates -enabledUsers $allEnabledUsers -howMany -1}
            "12" {BulkUpdateNotes -allUsers $allDirectoryUsers -howMany -1}
            "13" {SimulateEverything -allUsers $allDirectoryUsers -enabledUsers $allEnabledUsers -disabledUsers $allDisabledUsers -howMany -1}
            "14" {"Quitting Simulation"; AADSync -AADCServer $AADCServer}
            "Default" {"That selection is invaild, please try again"}
        }

    }while ($selection -ne 14)

}

$logDateTime = get-date -Format "dd-MM-yyyy hh-mm-ss"

if($configPath -eq $null){
    $configPath = "C:\simulation\simulation_AllStaff_config.xml"
}

Start-Transcript -Path "$($config.logPath)\MenuOption $($menuSelection)-$($logDateTime).log"

write-host "[INFO]: ConfigPath: $configPath"
$config = ([xml](Get-Content $configPath)).config

if($config -eq $null){
    write-host "[ERROR]: Could not load config file at path $configPath"
    write-host "[ERROR]: Terminating"
    return
}

Write-host "[INFO]: Current Config"
write-host "---------------"
$config
write-host "---------------"

if($menuSelection -eq $null){$menuSelection = 0}
if($howMany -eq $null){$howMany = -1}

write-host "[INFO]: Menu Selection: $menuSelection"
write-host "[INFO]: How many users: $howMany"


#Get all users
write-host "[INFO]: Getting all users in the environment, this may take a few minutes"
$allDirectoryUsers = Get-ADUser -Filter * -Server $config.domain -SearchBase $config.baseUserOU -SearchScope Subtree | Where-Object {($_.memberOf -notcontains $exludedUserGroup.DistinguishedName)}
write-host "[INFO]: Removing excluded users from simulation, this may take a few minutes"
$allDirectoryUsers = RemoveExcludedAccounts -allAccounts $allDirectoryUsers

$allEnabledUsers = $allDirectoryUsers | ?{$_.enabled -eq $true}

$allDisabledUsers = $allDirectoryUsers | ?{$_.enabled -eq $false}

switch($menuSelection){
    "0" {Menu -allDirectoryUsers $allDirectoryUsers -allEnabledUsers $allEnabledUsers -allDisabledUsers $allDisabledUsers -selection 0 -howMany -1 -AADCServer $config.AADCServer}
    "1" {BulkImpersonateUsers -enabledUsers $allEnabledUsers -howMany $howMany}
    "2" {BulkResetPasswords -allUsers $allDirectoryUsers -howMany $howMany}
    "3" {BulkLockAccounts -enabledUsers $allEnabledUsers -howMany $howMany}
    "4" {BulkUnlockAccounts -enabledUsers $allEnabledUsers -howMany $howMany}
    "5" {BulkDisableAccounts -enabledUsers $allEnabledUsers -howMany $howMany}
    "6" {BulkEnableAccounts -disabledUsers $allDisabledUsers -howMany $howMany}
    "7" {BulkMoveAccounts -allUsers $allDirectoryUsers -howMany $howMany}
    "8" {BulkUpdateDepartments -allUsers $allDirectoryUsers -howMany $howMany}
    "9" {BulkFailLogin -enabledUsers $allEnabledUsers -howMany $howMany}
    "10" {BulkDepartUsers -enabledUsers $allEnabledUsers -howMany $howMany}
    "11" {BulkChangeEndDates -enabledUsers $allEnabledUsers -howMany $howMany}
    "12" {BulkUpdateNotes -allUsers $allDirectoryUsers -howMany $howMany}
    "13" {SimulateEverything -allUsers $allDirectoryUsers -enabledUsers $allEnabledUsers -disabledUsers $allDisabledUsers -howMany $howMany}
    "14" {"Quitting Simulation"; AADSync -AADCServer $config.AADCServer}
    "Default" {Menu -allDirectoryUsers $allDirectoryUsers -allEnabledUsers $allEnabledUsers -allDisabledUsers $allDisabledUsers -selection 0 -howMany -1}
}

Stop-Transcript

$allLogs = Get-ChildItem -path $config.logPath | select name, creationTime | ?{$_.CreationTime -lt ((Get-date).AddDays(-$config.logRetentionDays))}
foreach($log in $allLogs){
    Remove-Item "$($config.logPath)\$($log.name)"
} 
 