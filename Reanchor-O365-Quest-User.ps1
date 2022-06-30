#############################
# Reanchor O365 Quest User	#
# Created by Dion Walker	#
# On 2/10/2022				#
# Revision	3				#
#############################

#Get Today's Date
$date=Get-Date -UFormat "%m-%d-%Y"

#Start Script Logging
Start-Transcript -Append -Path "uncpath\Logs\Reanchor-O365-QuestUsers-$date.txt"

#Store all input data into a variable
#Example of input file "D:\Import Files\users\2021-08-20-Remaining-NY-OUs-138.txt"
$users = Import-CSV uncpath\SourceFiles\Reanchor-O365-QuestUsers-$date.csv

#Store all acquired data into variable for export
$outputPath="uncpath\Reports\Reanchor-O365-QuestUsers-Report-$date.csv"
$outputPath2="uncpath\FlipUser\Import-Orbis-User-$date.csv"
$outputPath3= "uncpath\Reports\Add-MHBK-Securities-Contacts-LegacyExchangeDN-to-MSUSA-Mailboxes-Report-$date.csv"


#Create empty array for data outputs
$mbxReport= @()
$spReport= @()
$syncReport = @()

function Replicate-AllDomainController {
(Get-ADDomainController).Name | Foreach-Object {repadmin /syncall /APed $_ (Get-ADDomain).DistinguishedName /e /A | Out-Null}; Start-Sleep 10; Write-Host "Change was successfully replicated in Active Directory." -Backgroundcolor Green -ForeGroundColor Black	
}

$usiDC=(Get-ADDomainController).Name 

$sourceDC="source DC FQDN"

#####################################
# Move Accounts out of AADC Scope	#
#####################################

ForEach ($user in $users){
	
	$bksmtp=Get-ADUser $user.MSUSA -Properties * -Server $sourceDC | select -ExpandProperty mail
	
	#Check to see if Quest created USI account exists
    Write-Host "Checking to see if account exists in MSUSA for $bksmtp"
	
	if((Get-ADUser -Properties * -Filter {mail -like $bksmtp} -ErrorAction SilentlyContinue) -ne $null){
		$acct=Get-ADuser -Properties * -Filter {mail -like $bksmtp} | select *
		$sam=$acct.SAMAccountName
		$ADUserDN = $acct.distinguishedName
		$UserOU = $aduserdn.substring($aduserdn.indexof('OU='))
		write-host "Checking to see if $sam is not in a No Sync OU"
			If ($UserOU -notmatch "OU=Not Synced to Azure")
			{
			write-host "User object needs to move to Not Synced to Azure OU"

			$TargetOU = "OU=Not Synced to Azure,"+$UserOU
			write-host "TargetOU= "$targetOU
			Get-ADuser $sam| Move-ADObject -TargetPath $TargetOU -Verbose
			}
	}
}

#Force AD & AAD Replication
Replicate-AllDomainController
Invoke-Command -ComputerName Azure AD Connect Server -ScriptBlock {Start-ADSyncSyncCycle -PolicyType Delta}

ForEach ($user in $users){
	
	$mbxAlias=Get-ADUser $user.MSUSA | select -ExpandProperty SamAccountName
	
	$exchangeGUID=Get-ADUser $user.MSUSA -Properties * -Server $sourceDC | select msExchMailboxGuid
	
	Write-Host "Checking to see if the $user is enabled in the Bank domain."  -BackgrounDColor Green -ForeGrounDColor Black
	#Check to see if the account is enabled in the MHBK domain
	if((Get-ADUser $user.MSUSA -Properties * -Server $sourceDC | select -ExpandProperty Enabled) -eq $true){
	
		Write-Host "Checking to see if the mailuser $user exists."  -BackgrounDColor Green -ForeGrounDColor Black
		#Check to see if the MailUser exists in the MSUSA
		#Update with try/catch to check to see if it is enabled.

		if ((Get-MailUser $user.MSUSA -ErrorAction SilentlyContinue) -ne $null){
		
			#Convert the MailUser to a RemoteMailbox
			Get-MailUser $user.MSUSA | Enable-RemoteMailbox
			
			#Append the Exchange GUID to the RemoteMailbox
			Get-RemoteMailbox $user.MSUSA | Set-RemoteMailbox -ExchangeGuid $exchangeGUID.msExchMailboxGuid -Verbose
			
		}
	
	Write-Host "##############################################################################" -Backgroundcolor Black -ForeGroundColor White
	Write-Host "------------------------------------------------------------------------------" -Backgroundcolor Black -ForeGroundColor White
	Write-Host "##############################################################################" -Backgroundcolor Black -ForeGroundColor White
		
	Write-Host "Adding $mbxAlias to the necessary RES groups."  -BackgrounDColor Green -ForeGrounDColor Black
		
	#####################################
	# Provision to AirWatch RES Group	#
	#####################################
		
	#Add user to RES_APP_AIRWATCH_O365
	Write-Host "Adding $mbxAlias to RES_APP_AIRWATCH_O365, RES_APP_AIRWATCH_BOXERO365MODERNAUTH, RES_APP_AIRWATCH_IOSAPP_MIZUHOPLS, RES_APP_AIRWATCH_CONTENT_ENABLEHOMESHARE & RES_APP_AIRWATCH_IOSAPP_MIZUHOJAPANPLSs." -BackgrounDColor Green -ForeGrounDColor Black
	Add-ADGroupMember RES_APP_AIRWATCH_O365 -Members $mbxAlias #-Confirm:$true
	Add-ADGroupMember RES_APP_AIRWATCH_BOXERO365MODERNAUTH -Members $mbxAlias
	Add-ADGroupMember RES_APP_AIRWATCH_IOSAPP_MIZUHOPLS -Members $mbxAlias
	Add-ADGroupMember RES_APP_AIRWATCH_IOSAPP_MIZUHOJAPANPLS -Members $mbxAlias
	Add-ADGroupMember RES_APP_AIRWATCH_CONTENT_ENABLEHOMESHARE -Members $mbxAlias
		
	#################################
	# Provision to WebEx RES Group	#
	#################################
	
	#Add user to RES_APP_WebEx_Users
	Write-Host "Adding $mbxAlias to RES_APP_WebEx_Users."
	Add-ADGroupMember RES_APP_WebEx_Users -Members $mbxAlias #-Confirm:$true
	
	#################################
	# Provision to Zoom RES Group	#
	#################################
	
	#Add user to RES_APP_Zoom_Users
	Write-Host "Adding $mbxAlias to RES_APP_Zoom_Users."
	Add-ADGroupMember RES_APP_Zoom_Users -Members $mbxAlias #-Confirm:$true
	
	#####################################
	# Provision to Cache Mode RES Group	#
	#####################################
	
	#Add user to RES_APP_ENABLE_Outlook_Cached_Mode
	Write-Host "Adding $mbxAlias to RES_APP_ENABLE_Outlook_Cached_Mode."
	Add-ADGroupMember RES_APP_ENABLE_Outlook_Cached_Mode -Members $mbxAlias -Server $usiDC #-Confirm:$true
	
	#####################################
	# Provision to SSO RES Group	#
	#####################################
	
	#Add user to RES_GPO_Office365-SSO
	Write-Host "Adding $mbxAlias to RES_GPO_Office365-SSO."
	Add-ADGroupMember RES_GPO_Office365-SSO -Members $mbxAlias -Server $usiDC #-Confirm:$true
	
	#####################################
	# Provision to O365 E3 Licensing	#
	#####################################
	
	#Add user to RES_APP_Office365_ExchangeOnline_Access
	Write-Host "Adding $mbxAlias to RES_APP_Office365_ExchangeOnline_Access."
	Add-ADGroupMember RES_APP_Office365_ExchangeOnline_Access -Members $mbxAlias -Server $usiDC #-Confirm:$true
	
	#############################################
	# Provision to Enterprise Vault RES Group	#
	#############################################
	
	#Add user to RES_SCCM_EnterpriseVault.12_PRD
	#Write-Host "Adding $mbxAlias to RES_SCCM_EnterpriseVault.12_PRD."
	#Add-ADGroupMember RES_SCCM_EnterpriseVault.12_PRD -Members $mbxAlias -Server $usiDC #-Confirm:$true
	
	#####################################
	# Provision to Symphony RES Groups	#
	#####################################
	
	#Add user to RES_Symphony_Users
	Write-Host "Adding $mbxAlias to RES_Symphony_Users."
	Add-ADGroupMember RES_Symphony_Users -Members $mbxAlias -Server $usiDC #-Confirm:$true
	
	#Add user to RES_Symphony_Business_Users
	Write-Host "Adding $mbxAlias to RES_Symphony_Business_Users."
	Add-ADGroupMember RES_Symphony_Business_Users -Members $mbxAlias -Server $usiDC #-Confirm:$true
	
	#####################################
	# Provision to Jabber RES Groups	#
	#####################################
	
	#Add user to RES_APP_CiscoJabber_Users
	Write-Host "Adding $mbxAlias to RES_APP_CiscoJabber_Users."
	Add-ADGroupMember RES_APP_CiscoJabber_Users -Members $mbxAlias -Server $usiDC #-Confirm:$true
	
	#########################
	# Provision to MS Teams	#
	#########################
	
	#Add user to RES_Office365_MSTEAMS_ACCESS
	Write-Host "Adding $mbxAlias to RES_Office365_MSTEAMS_ACCESS & RES_MS-Teams_Users."
	Add-ADGroupMember RES_Office365_MSTEAMS_ACCESS -Members $mbxAlias -Server $usiDC
	Add-ADGroupMember RES_MS-Teams_Users -Members $mbxAlias -Server $usiDC
	
	#########################
	# Provision to LastPass	#
	#########################
	
	#Remove user account from MHBK and add to MSUSA LastPass Group
	Write-Host "Moving LastPass Membership from MHBK to MSUSA for $mbxAlias" -ForegroundColor Green
	Add-ADGroupMember -Identity RES_APP_LASTPASS -Members $mbxAlias -Verbose
	
	#####################################
	# Provision to Contract Onboarding	#
	#####################################
	
	if (((Get-ADUser $user.MSUSA -Properties * | select -ExpandProperty Extensionattribute1) -ne "Consultant") -and ((Get-ADUser $user.MSUSA -Properties * | select -ExpandProperty Displayname) -notmatch "Consultant")){
		
		Add-ADGroupMember -Identity RES_SHRPT_CONTRACT_REQUESTER_RW -Members $user.MSUSA -Verbose
		
	}
	
	Write-Host "##############################################################################" -Backgroundcolor Black -ForeGroundColor White
	Write-Host "------------------------------------------------------------------------------" -Backgroundcolor Black -ForeGroundColor White
	Write-Host "##############################################################################" -Backgroundcolor Black -ForeGroundColor White
	
	}
}

<#########################################
# Move Accounts into a AADC Scope OU	#
#########################################

ForEach ($user in $users){
	
	$bksmtp=Get-ADUser $user.MSUSA -Properties * -Server $sourceDC | select -ExpandProperty mail
	
	#Check to see if Quest created USI account exists
    Write-Host "Checking to see if account exists in MSUSA for $bksmtp"
	
	if((Get-ADUser -Properties * -Filter {mail -like $bksmtp} -ErrorAction SilentlyContinue) -ne $null){
		
		$acct=Get-ADuser -Properties * -Filter {mail -like $bksmtp} | select *
		$sam=$acct.SAMAccountName
		$ADUserDN = $acct.distinguishedName
		$UserOU = $aduserdn.substring($aduserdn.indexof('OU='))
		write-host "Checking to see if $sam is in a No Sync OU"
		if ($UserOU -match "OU=Not Synced to Azure"){
			write-host "User object needs to move out of the Not Synced to Azure OU"

			$TargetOU = $UserOU -replace "OU=Not Synced to Azure,",""
			write-host "TargetOU= "$targetOU
			Get-ADuser $sam| Move-ADObject -TargetPath $TargetOU -Verbose
		}
	}
}#>

#################################
# Move accounts to Entity OU	#
#################################

ForEach ($user in $users){
	
	#move to MAS OU
	Get-ADUser $user.MSUSA | Move-ADObject -TargetPath "Target OU" -Server $usiDC
	
	
}

#Force AD Replication
Replicate-AllDomainController

foreach($user in $users){
	
	$mbxAlias=Get-ADUser $user.MSUSA | select -ExpandProperty SamAccountName
	
	Write-Host "Checking to see if the $user is enabled in the Bank domain."  -BackgrounDColor Green -ForeGrounDColor Black
	#Check to see if the account is enabled in the MHBK domain
	if((Get-ADUser $user.MSUSA -Properties * -Server $sourceDC | select -ExpandProperty Enabled) -eq $true){
	
		#################
		# Clean-up FSPs	#
		#################
		
		Write-Host "Obtaining ObjectSIDHistory for $mbxAlias" -Backgroundcolor Black -ForeGroundColor Green
		$fsp=Get-ADUser $user.MSUSA -Properties * -Server $sourceDC  | select -ExpandProperty SID | select -ExpandProperty Value
		
		Write-Host "Obtaining group membership for $fsp"
		$grps=Get-ADObject -Filter {ObjectSID -like $fsp} -Properties * | select -ExpandProperty MemberOf | Get-ADGroup | select -ExpandProperty Name
		
		if ($grps -ne $null){
			
			foreach($grp in $grps){
				
				Write-Host "Adding $mbxAlias to $grp"
				Add-ADGroupMember $grp -Members $mbxAlias -Verbose #-WhatIf
			}
			
			Write-Host "##############################################################################" -Backgroundcolor Black -ForeGroundColor White
			Write-Host "------------------------------------------------------------------------------" -Backgroundcolor Black -ForeGroundColor White
			Write-Host "##############################################################################" -Backgroundcolor Black -ForeGroundColor White
			
			Write-Host "Deleting $fsp from the USI Domain"
			Get-ADObject -Filter {ObjectSID -like $fsp} -Properties * | Remove-ADObject -Verbose -Confirm:$False #-WhatIf
		}
		
		Write-Host "##############################################################################" -Backgroundcolor Black -ForeGroundColor White
		Write-Host "------------------------------------------------------------------------------" -Backgroundcolor Black -ForeGroundColor White
		Write-Host "##############################################################################" -Backgroundcolor Black -ForeGroundColor White
		
		######################################
		# RemoteMailbox Confirmation Section #
		######################################
		
		Write-Host "##############################################################################" -Backgroundcolor Black -ForeGroundColor White
		Write-Host "------------------------------------------------------------------------------" -Backgroundcolor Black -ForeGroundColor White
		Write-Host "##############################################################################" -Backgroundcolor Black -ForeGroundColor White
		
		Write-Host "Acquiring account info for $mbxAlias."
		#Get MSUSA User Name
		$mbxName=Get-RemoteMailbox $mbxAlias| select -ExpandProperty Name
		
		#Get MSUSA User Principal Name
		$mbxUPN=Get-RemoteMailbox $mbxAlias | select -ExpandProperty UserPrincipalName

		#Get MSUSA SMTP Address
		$mbxSMTP=Get-RemoteMailbox $mbxAlias | select -ExpandProperty PrimarySMTPAddress | select -ExpandProperty Address #-Verbose

		#Get Proxy Addresses
		$mbxProxy= Get-RemoteMailbox $mbxAlias | select -ExpandProperty EmailAddresses | select -ExpandProperty ProxyAddressString | Out-String
		
		#Get Extension Attribute 13
		$mbxEA13= Get-RemoteMailbox $mbxAlias | select -ExpandProperty CustomAttribute13 #-Verbose
		
		#Get Exchange GUID
		$mbxGUID=Get-RemoteMailbox $mbxAlias | select -ExpandProperty ExchangeGuid | select -ExpandProperty GUID
		
		#Get Exchange GUID
		$mbxType=Get-RemoteMailbox $mbxAlias | select -ExpandProperty RecipientTypeDetails
		
		#Get WebEx RES Group Enrollment
		$webex=Get-ADUser $mbxAlias -Properties * -Server $usiDC | select -ExpandProperty *memberof* | Get-ADGroup | where {$_.Name -like "*WebEX*"} | select -ExpandProperty Name | Out-String
		
		#Get Zoom RES Group Enrollment
		$zoom=Get-ADUser $mbxAlias -Properties * -Server $usiDC | select -ExpandProperty *memberof* | Get-ADGroup | where {$_.Name -like "*Zoom*"} | select -ExpandProperty Name | Out-String
		
		#Get Cache Mode RES Group Enrollment
		$cache=Get-ADUser $mbxAlias -Properties * -Server $usiDC | select -ExpandProperty *memberof* | Get-ADGroup | where {$_.Name -like "*Cached*"} | select -ExpandProperty Name | Out-String
		
		#Get EV RES Group Enrollment
		$ev="The Enterprise Vault must be access via Internet Explorer."#Get-ADUser $mbxAlias -Properties * -Server $usiDC | select -ExpandProperty *memberof* | Get-ADGroup | where {$_.Name -like "*EnterpriseVault*"} | select -ExpandProperty Name | Out-String
		
		#Get Symphony Group Enrollment
		$symphony=Get-ADUser $mbxAlias -Properties * -Server $usiDC | select -ExpandProperty *memberof* | Get-ADGroup | where {$_.Name -like "*Symphony*"} | select -ExpandProperty Name | Out-String
		
		#Get O365 AirWatch Group Enrollment
		$airwatch=Get-ADUser $mbxAlias -Properties * -Server $usiDC | select -ExpandProperty *memberof* | Get-ADGroup | where {$_.Name -like "*AIRWATCH*"} | select -ExpandProperty Name | Out-String
		
		#Get Jabber Group Enrollment
		$jabber=Get-ADUser $mbxAlias -Properties * -Server $usiDC | select -ExpandProperty *memberof* | Get-ADGroup | where {$_.Name -like "*Jabber*"} | select -ExpandProperty Name | Out-String
		
		#Get Office365 E3 Enrollment
		$e3=Get-ADUser $mbxAlias -Properties * -Server $usiDC | select -ExpandProperty *memberof* | Get-ADGroup | where {$_.Name -like "*APP_Office365_ExchangeOnline*"} | select -ExpandProperty Name | Out-String
		
		#Get SSO Enrollment
		$sso=Get-ADUser $mbxAlias -Properties * -Server $usiDC | select -ExpandProperty *memberof* | Get-ADGroup | where {$_.Name -like "*RES_GPO_Office365-SSO*"} | select -ExpandProperty Name | Out-String
		
		#Get Teams Group Enrollment
		$teams=Get-ADUser $mbxAlias -Properties * -Server $usiDC | select -ExpandProperty *memberof* | Get-ADGroup | where {$_.Name -like "*Teams*"} | select -ExpandProperty Name | Out-String
		
		#Get LastPass Group Enrollment
		$lastpass=Get-ADUser $mbxAlias -Properties * -Server $usiDC | select -ExpandProperty *memberof* | Get-ADGroup | where {$_.Name -like "*LastPass*"} | select -ExpandProperty Name | Out-String
		
		
		if($mbxName -eq $null){$mbxName="There is no MailUser/RemoteMailbox for this account."}
		if($mbxAlias -eq $null){$mbxAlias="There is no MailUser/RemoteMailbox for this account."}
		if($mbxUPN -eq $null){$mbxUPN="There is no MailUser/RemoteMailbox for this account."}
		if($mbxSMTP -eq $null){$mbxSMTP="There is no MailUser/RemoteMailbox for this account."}
		if($mbxProxy -eq $null){$mbxProxy="There is no MailUser/RemoteMailbox for this account."}
		if($mbxEA13 -eq $null){$mbxEA13="There is no MailUser/RemoteMailbox for this account."}
		if($mbxGUID -eq $null){$mbxGUID="There is no MailUser/RemoteMailbox for this account."}
		if($webex -eq $null){$webex="There is no MailUser for this account or this is a shared/service Mailbox."}
		if($zoom -eq $null){$zoom="There is no MailUser for this account or this is a shared/service Mailbox."}
		if($cache -eq $null){$cache="There is no MailUser for this account or this is a shared/service Mailbox."}
		if($ev -eq $null){$ev="There is no MailUser for this account or this is a shared/server MailUser."}
		if($symphony -eq $null){$symphony="There is no MailUser for this account or this is a shared/service Mailbox."}
		if($airwatch -eq $null){$airwatch="There is no MailUser for this account or this is a shared/service Mailbox."}
		if($jabber -eq $null){$jabber="There is no MailUser for this account or this is a shared/service Mailbox."}
		if($e3 -eq $null){$e3="There is no MailUser for this account or this is a shared/service Mailbox."}
		if($sso -eq $null){$sso="There is no MailUser for this account or this is a shared/service Mailbox."}
		if($teams -eq $null){$teams="There is no MailUser for this account or this is a shared/service Mailbox."}
		if($lastpass -eq $null){$lastpass="There is no MailUser for this account or this is a shared/service Mailbox."}
		
		$mbxOutput=New-Object PSObject -Property ([ordered] @{
		
			"MSUSA User Name"=$mbxName
			"MSUSA User Alias"=$mbxAlias
			"MSUSA User Principal Name"=$mbxUPN
			"MSUSA User Primary SMTP"=$mbxSMTP
			"MSUSA User Proxy Addresses"=$mbxProxy
			"MSUSA User ExtensionAttribute13"=$mbxEA13
			"MSUSA User Exchange GUID"=$mbxGUID
			"MSUSA User Mail Object Type"=$mbxType
			"MSUSA User WebEx Enrollment Groups"=($webex).Trim()
			"MSUSA User Zoom Enrollment Groups"=($zoom).Trim()
			"MSUSA User Cache Mode Enrollment Group"=($cache).Trim()
			"MSUSA User Enterprise Vault Enrollment Group"=($ev).Trim()
			"MSUSA User Symphony Enrollment Group"=($symphony).Trim()
			"MSUSA User AirWatch Enrollment Group"=($airwatch).Trim()
			"MSUSA User Jabber Enrollment Group"=($jabber).Trim()
			"MSUSA User Teams Enrollment Group"=($teams).Trim()
			"MSUSA User O365 E3 License Enrollment Group"=($e3).Trim()
			"MSUSA User LastPass Enrollment Group"=($lastpass).Trim()
			"MHBK Object SID/ForeignSecurityPrincipal SID"=$fsp
			"ForeignSecurityPrincipal Group Membership"=(@($grps) | Out-String).Trim()
			
		})
		
		$mbxReport+=$mbxOutput
		
		$mbxReport | Export-CSV -NoTypeInformation -Path $outputPath
		
		$fsp=$null
	}
}

#Enable AD Connect Sync
Write-Host "Syncing AD Connect Sync"
Invoke-Command -ComputerName Azure AD Connect Server -ScriptBlock {Start-ADSyncSyncCycle -PolicyType Delta}

#Send-MailMessage -From NoReply.QuestUserReAnchorMigrationReport@smtp domain -To Targeted Mail Object -Subject "Quest Users Mailbox Reanchor Report $date" -Body "Hello,`n`n`The attached document contains the output for users that were reanchored from MHBK to MSUSA for Project Orbis and the accounts were enrolled into the necessary WebEx, AirWatch, Symphony, EV, Zoom, O365 Licensing and Jabber RES groups along with their emails configured for 90 days worth of cache mode. `n`nA copy of this report is also stored here: uncpath\Reports\ `n`nThank you" -Attachments $outputPath -Priority Normal -SMTPServer smtp-relay
Send-MailMessage -From NoReply.ProjectOrbisReAnchorMigrationReports@smtp domain -Cc Targeted Mail Object -To Targeted Mail Object -Subject "Project Orbis Mailbox Reanchor Report $date" -Body "Hello,`n`n`The attached document contains the output for users that were reanchored from MHBK to MSUSA for Project Orbis and the accounts were enrolled into the necessary WebEx, AirWatch, Symphony, Teams, Zoom and Jabber RES groups along with their emails configured for 90 days worth of cache mode. `n`nA copy of this report is also stored here: uncpath\Reports\ `n`nThank you" -Attachments $outputPath -Priority Normal -SMTPServer smtp-relay

Write-Host "##############################################################################" -Backgroundcolor Black -ForeGroundColor White
Write-Host "------------------------------------------------------------------------------" -Backgroundcolor Black -ForeGroundColor White
Write-Host "##############################################################################" -Backgroundcolor Black -ForeGroundColor White
	

#############################
#Add Accounts to SharePoint	#
#############################

Write-Host "Generating list for SharePoint User Swap." -Backgroundcolor Black -ForeGroundColor Green

foreach($user in $users){

	Write-Host "Checking to see if the $user is enabled in the Bank domain."  -BackgrounDColor Green -ForeGrounDColor Black
	#Check to see if the account is enabled in the MHBK domain
	if((Get-ADUser $user.MSUSA -Properties * -Server $sourceDC | select -ExpandProperty Enabled) -eq $true){
		
		$mbxAlias=Get-ADUser $user.MSUSA | select -ExpandProperty SamAccountName
		
		#Get MSUSA SMTP Address
		$mbxSMTP=Get-RemoteMailbox $mbxAlias | select -ExpandProperty PrimarySMTPAddress | select -ExpandProperty Address
		
		$process="FALSE"
		
		$spOutput=New-Object PSObject -Property ([ordered] @{
			
			"Email"=$mbxSMTP
			"IsRecordProcess"=$process
		})
		
		$spReport+=$spOutput
		
		$spReport | Export-CSV -NoTypeInformation -Path $outputPath2

	}
}

Send-MailMessage -From NoReply.ProjectOrbisSharePointReUserFlipReports@smtp domain -To Targeted Mail Object -Cc Targeted Mail Object, Targeted Mail Object -Subject "Project Orbis SharePoint User Flip Report $date" -Body "Hello,`n`n`The attached document contains the output for users that were reanchored from MHBK to MSUSA for Project Orbis and the accounts will need to be swapped in SharePoint. `n`nA copy of this report is also stored here: uncpath\FlipUser\ `n`nThank you" -Attachments $outputPath2 -Priority Normal -SMTPServer smtp-relay

Write-Host "##############################################################################" -Backgroundcolor Black -ForeGroundColor White
Write-Host "------------------------------------------------------------------------------" -Backgroundcolor Black -ForeGroundColor White
Write-Host "##############################################################################" -Backgroundcolor Black -ForeGroundColor White
	

<#########################
# Sync LegacyExchangeDN	#
#########################

#Get input data from MHBK by targetting the *@smtp domain for contacts only
$MHBKObjs = Get-ADObject -Filter {msExchRecipientDisplayType -eq 6} -Server $sourceDC -Properties mail,LegacyExchangeDN,TargetAddress | where {($_.TargetAddress -like "*@smtp domain") -or ($_.TargetAddress -like "*@mizuhogroup.mail.onmicrosoft.com")}


$Flag = "W" #Set to the flag to 'W' if you want to make changes


#$MHBKObjs = $MHBKObjs | select -First 10

foreach($MHBKObj in $MHBKObjs){
    
	#Get MSUSA Mailbox
	Write-Host "Checking to see if MSUSA mailbox exists for $MHBKObj.Name"
    $MSUSAObj = Get-ADObject -Filter {mail -eq $MHBKObj.mail} -Properties mail, Proxyaddresses, samaccountname -ErrorAction SilentlyContinue
    If($MSUSAObj -eq $Null){ Write-Host "Action 1 (Not Found) | MSUSA Object not Found for MHBK contact" $MHBKObj.mail -BackgroundColor Yellow -ForegroundColor Red; continue}
    
    #Write-Host $MSUSAObj.mail " ; " $MHBKObj.mail

        #Copying Legacy Exchange DN attr from MHBK
       
        $MHBKDN = "x500:"+$MHBKObj.LegacyExchangeDN
        If($MSUSAObj.Proxyaddresses -contains $MHBKDN)
        {Write-Host $MSUSAObj.mail "contains" $MHBKObj.LegacyExchangeDN -ForegroundColor Green}
        Else
        {
        Write-Host "Action 2 (LDN) | Appending LegacyDN: | " $MHBKObj.LegacyExchangeDN " to: " $MSUSAObj.Mail " : " $MSUSAObj.ObjectClass -ForegroundColor Magenta;
        If($Flag -eq "R")
        {Set-ADObject $MSUSAObj -add @{ProxyAddresses=$MHBKDN} -WhatIf}
        ElseIf($Flag -eq "W")
        {Set-ADObject $MSUSAObj -add @{ProxyAddresses=$MHBKDN}}
        }
	
	$update=Invoke-Command -ComputerName $usiDC -Scriptblock {& 'C:\Windows\System32\repadmin.exe' /syncall /APed}
	
	Write-Host "Acquiring account info for $MSUSAObj.samaccountname."
	#Get MSUSA User Name
	$syncName=Get-Recipient $MSUSAObj.mail | select -ExpandProperty Name
	
	#Get MSUSA User Alias
	$syncAlias=Get-Recipient $MSUSAObj.mail | select -ExpandProperty Alias

	#Get MSUSA SMTP Address
	$syncSMTP=Get-Recipient $MSUSAObj.mail | select -ExpandProperty PrimarySMTPAddress | select -ExpandProperty Address #-Verbose

	#Get Proxy Addresses
	$syncProxy= Get-Recipient $MSUSAObj.mail | select -ExpandProperty EmailAddresses | select -ExpandProperty ProxyAddressString | Out-String
	
	#Get Extension Attribute 13
	$syncEA13= Get-Recipient $MSUSAObj.mail | select -ExpandProperty CustomAttribute13 #-Verbose
	
	Write-Host "Acquiring account info for $MHBKObj.Name"
	#Get MHBK Securities Contact Name
	$mhbkName= Get-ADObject $MHBKObj.ObjectGUID -Server $sourceDC -Properties * | select -ExpandProperty Name
	
	#Get MHBK Securities Contact Primary SMTP
	$mhbkSMTP= Get-ADObject $MHBKObj.ObjectGUID -Server $sourceDC -Properties * | select -ExpandProperty Mail
	
	#Get MHBK Securities Contact Proxy Addresses
	$mhbkProxy=Get-ADObject $MHBKObj.ObjectGUID -Server $sourceDC -Properties * | select -ExpandProperty ProxyAddresses | Out-String
	
	if($syncName -eq $null){$syncName="There is no mailbox for this account."}
	if($syncAlias -eq $null){$syncAlias="There is no mailbox for this account."}
	if($syncSMTP -eq $null){$syncSMTP="There is no mailbox for this account."}
	if($syncProxy -eq $null){$syncProxy="There is no mailbox for this account."}
	if($syncEA13 -eq $null){$syncEA13="There is no mailbox for this account."}
	if($mhbkName -eq $null){$mhbkName="There is no contact for this account"}
	if($mhbkSMTP -eq $null){$mhbkSMTP="There is no contact for this account."}
	if($mhbkProxy -eq $null){$mhbkProxy="There is no contact for this account."}
		
	$SyncOutput=New-Object PSObject -Property ([ordered] @{
	
		"MSUSA MailObject Name"=$syncName
		"MSUSA MailObject Alias"=$syncAlias
		"MSUSA MailObject Primary SMTP Address"=$syncSMTP
		"MSUSA MailObject Proxy Addresses"=$syncProxy
		"MSUSA MailObject ExtensionAttribute13"=$syncEA13
		"MHBK MailObject Name"=$mhbkName
		"MHBK MailObject Primary SMTP"=$mhbkSMTP
		"MHBK MailObject Proxy Addresses"=$mhbkProxy
		
	})
	
	$syncReport+=$syncOutput
	
	$syncReport | Export-CSV -NoTypeInformation -Path $outputPath3
		
       
}

<#if($token -eq "enabled"){
	
		Remove-Module ActiveDirectory
	
		Remove-PSSession $admodule
	
}

#Send-MailMessage -From NoReply.MHBKtoMSUSA-LegacyExchangeDN-ImportReport@smtp domain -To Targeted Mail Object -Subject "MHBK to MSUSA LegacyExchangeDN Import Report $date" -Body "Hello,`n`n`The attached document contains the output for users that had their MHBK contacts LegacyExchangeDN imported into their MSUSA mailbox to prevent NDRs post mailbox migration. `n`nA copy of this report is also stored here: \\clf-filer01\Temp\DionWalker\Reports\ `n`nThank you" -Attachments $outputPath -Priority Normal -SMTPServer smtp-relay
Send-MailMessage -From NoReply.MHBKtoMSUSA-LegacyExchangeDN-ImportReport@smtp domain -To Targeted Mail Object -Cc Targeted Mail Object -Subject "MHBK to MSUSA LegacyExchangeDN Import Report $date" -Body "Hello,`n`n`The attached document contains the output for users that had their MHBK contacts LegacyExchangeDN imported into their MSUSA mailbox to prevent NDRs post mailbox migration. `n`nA copy of this report is also stored here: \\clf-filer01\Temp\DionWalker\Reports\ `n`nThank you" -Attachments $outputPath3 -Priority Normal -SMTPServer smtp-relay
#>

Stop-Transcript