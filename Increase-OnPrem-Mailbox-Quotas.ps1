#############################
# Update Mailbox Storage	#
# Created by Dion Walker	#
# On 10/18/2018				#
# Revision 7				#
#############################

	#Get today's date
	$date=Get-Date -UFormat "%m-%d-%Y"
	#$date="11-28-2018"

	#Create a log to capture all data
	Start-Transcript -Append -Path "uncpath\Logs\CLF-MBX-Update-Logs-$date-B1.txt"

	#Import list off users who need there mailbox quota updated
	$users = Import-Csv -Path "uncpath\UserToUpgrade\CLF\CLF-MBX-Pilot-Move-$date-B1.csv"

	#Create empty array for data outputs
	$mbxOutput= @()
	
	#Set Output Path
	$outputPath="uncpath\Reports\CLF-Mailbox-Expansion-Completion-Report-$date-B1.csv"

    function Replicate-AllDomainController {
        (Get-ADDomainController).Name | Foreach-Object {repadmin /syncall /APed $_ (Get-ADDomain).DistinguishedName /e /A | Out-Null}; Start-Sleep 10; Write-Host "Change was successfully replicated in Active Directory." -Backgroundcolor Green -ForeGroundColor Black	
    }
	
	#Loop through the list on a person by person basis
	foreach($tempuser in $users){
	
		#Get user from csv file
		$user=$tempUser.Name
	
		if( (Get-Mailbox $user) -ne $null){
	
			#Get user's name
			$userName=Get-Mailbox $user | Select Name
		
			#Get user's email alias
			$userAlias=Get-Mailbox $user | Select Alias
			
			#Get Mailbox Info
			$mbxInfo = Get-Mailbox $userAlias.Alias | select Database,IssueWarningQuota,ProhibitSendQuota,UseDatabaseQuotaDefaults, PrimarySMTPAddress
			
			#Confirm all data is there
			$mbxInfo
			
			#Get Database Name where the user's mailbox resides
			$userDB= $mbxInfo.Database.Name
			
			#Get mailbox warning quota
			$userWarningQuota= $mbxInfo.IssueWarningQuota.Value
			
			#Get mailbox prohibit send quota
			$userProhibitQuota= $mbxInfo.ProhibitSendQuota.Value
			
			#Get user's primary smtp address
			$userSMTP= $mbxInfo.PrimarySMTPAddress.Address
			
			#Get user's mailbox size
			$userMBXSize= Get-Mailbox $user | Get-MailboxStatistics | select TotalItemSize
			
			#Confirm all variables contain data
			$userDB,$userWarningQuota,$userProhibitQuota,$userSMTP, $userMBXSize
			
			#Send email advising the user that their mailbox is going to be moved
			Send-MailMessage -To $userSMTP -From NoReply-EmailUpgrade@smtpdomain -Bcc Targeted Mail Objects  -Subject "Notification: Starting Mailbox Upgrade" -Body "Hello `n`nPlease be aware that your mailbox is in the process of being upgraded to 10GB to provide you more email capacity. `n`nWe are requesting that you save any open or draft emails and calendar invites to ensure you do not lose any content. `n`n`Upon the completion of this task you will receive an email advising you to close & re-open Outlook so you can connect to your mailbox with the new capacity.  `n`nYour response or acknowledgment to this email is not required. `n`nThank you" -Priority Normal -SMTPServer smtp-relay

			#Set warning quota 0.25 away from the send quota
			$warning="9.75GB"
			
			#Set prohibit send quota
			$quota="10GB"

			#Set the batch name for the mailbox move
			$batchname= $userAlias.Alias + " 10GB Upgrade"
			
			#Get the intended DB from the csv file
			$targetDB= $tempUser.Database
			
			#Get the Database Name
			$dbName= Get-MailboxDatabase $targetDB -Status | select -ExpandProperty Name
			
			#Get the Database primary Exchange Server
			$dbPrimaryServer= Get-MailboxDatabase $targetDB -Status | select -ExpandProperty Server
			
			#Set and store DB to Primary Server
			$dbTemp= $dbName+"\"+$dbPrimaryServer
			
			#Get DB total DB size
			$dbTotalSize= Get-MailboxDatabaseCopyStatus $dbTemp | select -ExpandProperty DiskTotalSpace
			
			#Get DB free space
			$dbFreeSpace= Get-MailboxDatabaseCopyStatus $dbTemp | select -ExpandProperty DiskFreeSpace
			
			#Get DB's log path
			$dbLogFilePath= Get-MailboxDatabase $targetDB -Status | select -ExpandProperty LogFolderPath
			
			#Get a sum of all logs files in the log DB
			$tempDBSize=Get-ChildItem -Path $dbLogFilePath.PathName -Recurse -Force | Measure-Object -Property Length -Sum
			
			#Get the size of log DB in GB
			$dbLogFileSize= "{0:N2} GB" -f ($tempDBSize.Sum/1GB)
			
			#Confirm the data
			$dbName, $dbTotalSize, $dbFreeSpace, $dbLogFilePath.PathName, $dbLogFileSize
				
			#Get date/time stamp
			$startTime=Get-Date
			
			#Display to the console
			$startTime.DateTime
			
			#Start DB move to new Database
			Get-Mailbox $user | New-MoveRequest -TargetDatabase $targetDB -AllowLargeItems -BatchName $batchname -BadItemLimit unlimited -AcceptLargeDataLoss

			#Check on the status of DB move
			do{}while((Get-MoveRequestStatistics $user | select -ExpandProperty Percent*) -ne 99)
				
			#Get date/time stamp
			$completionTime=Get-Date
			
			#Display to the console
			$completionTime.DateTime
				
			#Send email to the user advising them of DB move completion
			Send-MailMessage -To $userSMTP -From NoReply-EmailUpgrade@smtpdomain -Bcc Targeted Mail Objects -Subject "Notification: Mailbox Upgrade Completed" -Body "Hello `n`nPlease be aware that your mailbox capacity has been upgraded to 10GB. Please close & reopen Outlook to access your new email capacity. `n`nYour response or acknowledgment to this email is not required. `n`nThank you" -Priority Normal -SMTPServer smtp-relay
			
			#Wait 10 seconds
			Start-Sleep -Seconds 10

			#Upgrade mailbox quotas
			Get-Mailbox $user | Set-Mailbox -IssueWarningQuota $warning -ProhibitSendQuota $quota -UseDatabaseQuotaDefaults $false -Force

			#Get confirmation of mailbox quota upgrade
			$confirmation=Get-Mailbox $user | select Name,Database,IssueWarningQuota,ProhibitSendQuota,UseDatabaseQuotaDefaults
			
			#Get new warning quota
			$newWarningQuota= $confirmation.IssueWarningQuota.Value
			
			#Get new prohibit send quota
			$newProhibitQuota= $confirmation.ProhibitSendQuota.Value
			
			#Get new DB name
			$newDatabase= $confirmation.Database.Name
				
			#Export all contents collected to the hash table for output to the array.
			$mbxInfo = New-Object PSObject -Property ([ordered] @{
		
				"User Name" = $userName.Name
				"User Alias" = $userAlias.Alias
				"User Primary SMTP Address" = $userSMTP
				"User Current Warning Quota" = $newWarningQuota
				"User Current Mailbox Quota" = $newProhibitQuota
				"User Current Database Location" = $newDatabase
				"Database Total Size" = $dbTotalSize
				"Database Free Space" = $dbFreeSpace
				"Database Log Path" = $dbLogFilePath
				"Database Log File Size" = $dbLogFileSize
				"User Mailbox Size" = $userMBXSize.TotalItemSize.Value
				"User Former Database Location" = $userDB
				"Mailbox Migration Start Time" = $startTime.DateTime
				"Mailbox Migration End Time" = $completionTime.DateTime
			})
		
		#Add the collected per user data to the array for holding until the entire program has finished running.
		$mbxOutput += $mbxInfo
		
		#Export all collected data to a CSV file for review and confirmation.
		$mbxOutput | Export-CSV -NoTypeInformation -Path $outputPath
		
		#Force AD Replication
		Replicate-AllDomainController
				
		Write-Host "Change was successfully replicated." -Backgroundcolor Green -ForeGroundColor Black	
	
	}
}


#Export all collected data to a CSV file for review and confirmation.
#$mbxOutput | Export-CSV -NoTypeInformation -Append -Path "uncpath\Mailbox-Expansion-Completion-Report-$date.csv"

#Send email to Windows team of completion
Send-MailMessage -To Targeted Mail Objects -From NoReply-EmailUpgrade@smtpdomain -Subject "CLF/HOB Mailbox Capacity Upgrades - Batch 1" -Body "The attached list of user mailboxes have had their mailbox quotas increased. `n`n A copy of this report is also stored here: uncpath\Reports\ `n`nThank you" -Attachments $outputPath -Priority Normal -SMTPServer smtp-relay

Stop-Transcript