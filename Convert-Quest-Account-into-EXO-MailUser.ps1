#############################################
# Convert Quest Account into EXO MailUsers	#
# Created by Dion Walker					#
# On 1/25/2022								#
# Revision 3								#
#############################################

#Get Today's Date
$date=Get-Date -UFormat "%m-%d-%Y-%H%M"

#Start Script Logging
Start-Transcript -Append -Path "uncpath\Logs\Convert-MailContacts-to-Quest-MailUsers-$date.txt"

#Store all input data into a variable
#Example of input file "uncpath\2022-03-04-1631-workfile.csv"
$users = Import-CSV -Path "uncpath\Import-File-$date.csv"

#Store all acquired data into variable for export
$outputPath="uncpath\Reports\Convert-MailContacts-to-Quest-MailUsers-Report-$date.csv"
$errorOutPut="uncpath\Reports\Convert-MailContacts-to-Quest-MailUsers-Error-Report-$date.txt"

#Create empty array for data outputs
$mbxReport= @()

$recipType=$null

function Replicate-AllDomainController {
(Get-ADDomainController).Name | Foreach-Object {repadmin /syncall /APed $_ (Get-ADDomain).DistinguishedName /e /A | Out-Null}; Start-Sleep 10; Write-Host "Change was successfully replicated in Active Directory." -Backgroundcolor Green -ForeGroundColor Black	
}

$usiDC=(Get-ADDomainController).Name

$sourceDC="Source DC FQDN"

$FormatEnumerationLimit=-1

#####################################
# Move Accounts out of AADC Scope	#
#####################################

ForEach ($user in $users){
	
	$usiSAM=$user.usiid
	
	#Check to see if Quest created USI account exists
    Write-Host "Checking to see if an account exists in MSUSA for $usiSAM" -Backgroundcolor Green -ForeGroundColor Black
	try{

		$acct=Get-ADuser $usiSAM -Properties * -Server $usiDC | select *
	
	}catch{

		$acct=$null
		Write-Host "User account for $usiSAM was not found in the USI forest." -Backgroundcolor Green -ForeGroundColor Black

	}
	
	if($acct -ne $null){
		
		$sam=$acct.SAMAccountName
		$ADUserDN = $acct.distinguishedName
		$UserOU = $aduserdn.substring($aduserdn.indexof('OU='))
		write-host "Checking to see if $sam is not in an Azure No Sync OU" -Backgroundcolor Green -ForeGroundColor Black
		if ($UserOU -notmatch "OU=Not Synced to Azure")
		{
		write-host "User object is being moved to the Not Synced to Azure OU" -Backgroundcolor Green -ForeGroundColor Black

		$TargetOU = "OU=Not Synced to Azure,"+$UserOU
		write-host "TargetOU= "$targetOU
		Get-ADuser $sam -Server $usiDC | Move-ADObject -TargetPath $TargetOU -Server $usiDC -Verbose
		}
	}
}

#Force AD & AAD Replication
Write-Host "Running Active Directory and Azure AD Connect Synchronization." -Backgroundcolor Green -ForeGroundColor Black
Replicate-AllDomainController
Invoke-Command -ComputerName ADConnect Server FQDN -ScriptBlock {Start-ADSyncSyncCycle -PolicyType Delta}

Write-Host "##############################################################################" -Backgroundcolor Black -ForeGroundColor White
Write-Host "------------------------------------------------------------------------------" -Backgroundcolor Black -ForeGroundColor White
Write-Host "##############################################################################" -Backgroundcolor Black -ForeGroundColor White

Write-Host "Connecting to On-premise Exchange" -Backgroundcolor Blue -ForeGroundColor Black
$session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionURI http://Exchange Server FQDN/PowerShell
import-PSsession $session -AllowClobber |out-null

Write-Host "Initializing script to perform email operations." -Backgroundcolor Green -ForeGroundColor Black
ForEach ($user in $users){

	#Check for NoSync OU
	Write-Host "Checking to see if the $($user.bkid) is in a No Sync OU." -Backgroundcolor Green -ForeGroundColor Black
	if((Get-ADUser $user.bkid -Server $sourceDC | select -ExpandProperty DistinguishedName) -notmatch "NoSync"){

		#Check to for an Enabled User Account
		Write-Host "Checking to see if the $($user.bkid) has an active user account in MHBK." -Backgroundcolor Green -ForeGroundColor Black
		if((Get-ADUser $user.bkid -Server $sourceDC | select -ExpandProperty Enabled) -ne $false){
		
			#Check MHBK account for MSExchangeEA19=syncme
			Write-Host "Checking for Sycnme Attribute in MHBK for $($user.bkid)" -Backgroundcolor Green -ForeGroundColor Black
			if((Get-ADUser $user.bkid -Properties * -Server $sourceDC | select -ExpandProperty msExchExtensionAttribute19) -like "syncme"){
				
				Write-Host "Acquiring the MHBK ExchangeGuid" -Backgroundcolor Green -ForeGroundColor Black
				$exchangeGUID=Get-ADUser $user.bkid -Properties * -Server $sourceDC | select msExchMailboxGuid
				
				Write-Host "Acquiring the MHBK mS-DS-ConsistencyGuid for $($user.bkid)" -Backgroundcolor Green -ForeGroundColor Black
				$mcntMSDSCon=Get-ADUser $user.bkid -Properties * -Server $sourceDC | select 'mS-DS-ConsistencyGuid'
				
				Write-Host "Acquiring the MHBK Email Address for $($user.bkid)" -Backgroundcolor Green -ForeGroundColor Black
				$bksmtp=Get-ADUser $user.bkid -Properties * -Server $sourceDC | select -ExpandProperty mail
				
				#Check to see if Quest created USI account exists
				Write-Host "Checking to see if account exists in MSUSA and is enabled for $($user.usiid)" -Backgroundcolor Green -ForeGroundColor Black
				if((Get-ADUser $user.usiid -ErrorAction SilentlyContinue -Server $usiDC | select -ExpandProperty Enabled) -ne $false){
					
					$mbxAlias=Get-ADUser $user.usiid -Server $usiDC | select -ExpandProperty SAMAccountName
				
					#Check to see if the Mail contact exists in the MSUSA forest
					Write-Host "Checking to see if a mail object exists in MSUSA for $bksmtp" -Backgroundcolor Green -ForeGroundColor Black
					try{
						$recipType=Get-Recipient $bksmtp -ErrorAction SilentlyContinue | select -ExpandProperty RecipientTypeDetails
					}catch{
						$recipType=$null
					}

					switch ($recipType){

						"MailContact"{
					
							Write-Host "A mail contact was found belonging to $bksmtp in the USI forest." -Backgroundcolor Blue -ForeGroundColor Black
							#################################
							# Acquire Contact Info & Export	#
							#################################
							
							#Check to see if the mail contact exists in the MSUSA and acquire.
							if ((Get-MailContact $bksmtp -ErrorAction SilentlyContinue) -ne $null){
																		
								Write-Host "Acquiring $user.bkid Contact Info" -Backgroundcolor Green -ForeGroundColor Black
								$mcntAccount=Get-Mailcontact $bksmtp -DomainController $usiDC | select Name,Alias,PrimarySMTPAddress,LegacyExchangeDN,EmailAddresses,ExternalEmailAddress,Guid

								Write-Host "Acquiring MHBK Contact's Name"
								$mcntName=$mcntAccount.Name
								
								Write-Host "Acquiring the MHBK Contact's Alias" -Backgroundcolor Green -ForeGroundColor Black			
								$mcntAlias=$mcntAccount.Alias
								
								Write-Host "Acquiring the MHBK Contact's Primary SMTP Address" -Backgroundcolor Green -ForeGroundColor Black
								$mcntSMTP=$mcntAccount.PrimarySMTPAddress
								
								Write-Host "Acquiring the MHBK Contact's Legacy Exchange DN" -Backgroundcolor Green -ForeGroundColor Black
								$mcntLegacy=$mcntAccount.LegacyExchangeDN
								
								$mcntLegacy="x500:"+$mcntLegacy
								
								Write-Host "Acquiring the MHBK Contact's Proxy Addresses" -Backgroundcolor Green -ForeGroundColor Black
								$mcntProxy=$mcntAccount.EmailAddresses
								
								Write-Host "Acquiring the MHBK Contact's Target Email Address" -Backgroundcolor Green -ForeGroundColor Black
								#$mcntTA=$mcntAccount.ExternalEmailAddress
								
								Write-Host "Acquiring the MHBK Contact's Remote Routing Address" -Backgroundcolor Green -ForeGroundColor Black
								$mcntRRA=$mcntAccount.ExternalEmailAddress
								
								Write-Host "Acquiring the MHBK Contact's GUID" -Backgroundcolor Green -ForeGroundColor Black
								$mcntGUID=$mcntAccount.Guid.Guid
								
								Write-Host "Acquiring the MHBK Contact's Local Address" -Backgroundcolor Green -ForeGroundColor Black
								$mcntLocal=$mcntSMTP -replace "primary smtp",""
								
								Write-Host "Acquiring the MHBK Contact's Group Membership" -Backgroundcolor Green -ForeGroundColor Black
								$membership=Get-ADObject $mcntGUID -Property MemberOf -Server $usiDC | select -ExpandProperty MemberOf | Get-ADGroup -Properties mail -Server $usiDC | select -ExpandProperty mail -ErrorAction SilentlyContinue
																	
								#Create Export Name
								$mhbkExport= $mcntSMTP -replace "@.*",""

								#Get Bank Contact & back it up
								Write-Host "Backing up the contact attributes for $mcntName" -Backgroundcolor Green -ForeGroundColor Black
								Get-MailContact $mcntGuid -DomainController $usiDC | fl | Out-File -Append -FilePath "uncpath\ContactBankups\$mhbkExport-MHBK-Backup-$date.txt"
								Get-ADObject $mcntGUID -Properties * -Server $usiDC | fl | Out-File -Append -FilePath "uncpath\ContactBankups\$mhbkExport-MHBK-Backup-$date.txt"
								
								#Check to see if a Mail contact exists in the MSUSA forest
								Write-Host "Checking to see if both a MailContact and a MailUser object exists in MSUSA" -Backgroundcolor Green -ForeGroundColor Black				
								if((Get-MailContact $bksmtp -DomainController $usiDC -ErrorAction SilentlyContinue) -ne $null){
									if((Get-MailUser $mbxAlias -DomainController $usiDC -ErrorAction SilentlyContinue) -ne $null){
										
										Write-Host "An inconsistent MailUser was found for $mbxAlias and will now be disabled." -Backgroundcolor Red -ForeGroundColor Black
										Get-MailUser $mbxAlias -DomainController $usiDC | Disable-MailUser -Confirm:$false -DomainController $usiDC#-WhatIf
									}
								}
														
								#Deleting the Bank Contact
								if((Get-MailContact $mcntSMTP -ErrorAction SilentlyContinue) -ne $null){
									Write-Host "Deleting the MHBK Contact for $mcntName" -Backgroundcolor Green -ForeGroundColor Black
									Remove-MailContact $mcntSMTP -DomainController $usiDC -Confirm:$false 
								}
								
								#Force AD Replication
								Write-Host "Running Active Directory Synchronization." -Backgroundcolor Green -ForeGroundColor Black
								Replicate-AllDomainController

								#############################
								# MailUser Update Section	#
								#############################
								
								#Create EA13 from MHBK contact SMTP
								$EA13=$mcntSMTP -replace "primary smtp","source legacy smtp"
								$usi=$mcntSMTP -replace "primary smtp","target legacy smtp"
											
								#Enable MailUser
								try{
									Write-Host "Mail Enabling $mbxAlias." -Backgroundcolor Green -ForeGroundColor Black
									Enable-MailUser $mbxAlias -Primarysmtpaddress $mcntSMTP -ExternalEmailAddress $mcntRRA -DomainController $usiDC #-Alias $mcntLocal
								}catch{
									$outputerror= "A mail object already exists for $mcntSMTP in the USI forest."
									$outputerror | Out-File -Append -FilePath $ErrorOutPath
								}

								#Add EA13 and disalbe EmailAddress Policy
								Write-Host "Adding EA13 and disabling the Email Address Policy for mailuser $mbxAlias" -Backgroundcolor Green -ForeGroundColor Black
								Get-MailUser $mbxAlias -DomainController $usiDC | Set-MailUser -CustomAttribute13 $EA13 -EmailAddressPolicyEnabled $false -DomainController $usiDC
											
								#Update MSUSA MailUser with EA13 as a Proxy Address
								Write-Host "Adding the EA13 as a Proxy Address on the Mailuser" -Backgroundcolor Green -ForeGroundColor Black
								Get-MailUser $mbxAlias -DomainController $usiDC | Set-MailUser -EmailAddresses @{add="smtp:$EA13"} -EmailAddressPolicyEnabled:$false -DomainController $usiDC #-Confirm:$true #-Verbose
								Get-MailUser $mbxAlias -DomainController $usiDC | Set-MailUser -EmailAddresses @{add="smtp:$usi"} -EmailAddressPolicyEnabled:$false -DomainController $usiDC #-Confirm:$true #-Verbose
								
								#Update MSUSA MailUser with Contact x500
								Write-Host "Adding the MHBK Legacy Exchange DN on the MSUSA MailUser belonging to $mcntName" -Backgroundcolor Green -ForeGroundColor Black
								Get-MailUser $mbxAlias -DomainController $usiDC | Set-MailUser -EmailAddresses @{add=$mcntLegacy} -EmailAddressPolicyEnabled:$false -DomainController $usiDC #-Confirm:$true #-Verbose
								
								#Update MSUSA MailUser with Contact Proxy Addresses
								Write-Host "Setting the Proxy Addresses with MHBK Contact Proxy Addresses" -Backgroundcolor Green -ForeGroundColor Black
								foreach($proxy in $mcntProxy){Get-MailUser $mbxAlias -DomainController $usiDC | Set-MailUser -EmailAddresses @{add=$proxy} -EmailAddressPolicyEnabled:$false -DomainController $usiDC}
								Get-MailUser $mbxAlias -DomainController $usiDC | Set-MailUser -EmailAddresses @{add=$mcntRRA} -EmailAddressPolicyEnabled:$false -DomainController $usiDC
								
								#Unhide the MSUSA MailUser
								#Get-MailUser $mbxAlias | Set-MailUser -HiddenFromAddressListsEnabled:$false -EmailAddressPolicyEnabled:$false
								
								####Add Exchange Guid
								Write-Host "Setting the $($exchangeGUID) for $mbxAlias" -Backgroundcolor Green -ForeGroundColor Black
								Get-MailUser $mbxAlias -DomainController $usiDC | Set-MailUser -ExchangeGuid $exchangeGUID.msExchMailboxGuid -DomainController $usiDC

								#Add to ModernAuth Group
						
								Write-Host "##############################################################################" -Backgroundcolor Black -ForeGroundColor White
								Write-Host "------------------------------------------------------------------------------" -Backgroundcolor Black -ForeGroundColor White
								Write-Host "##############################################################################" -Backgroundcolor Black -ForeGroundColor White

								#####################################
								# Active Directory Update Section	#
								#####################################
								
								#Add MSUSA Account to groups
								Write-Host "Adding the MHBK group memberships on the MSUSA MailUser belonging to $mcntName" -Backgroundcolor Green -ForeGroundColor Black
								foreach($group in $membership){Add-DistributionGroupMember $group -Member $mbxAlias -DomainController $usiDC -Verbose}#-Confirm:$true}
								
								#Add mS-DS-ConsistencyGuid to AD User Account
								Write-Host "Setting the $($mcntMSDSCon) for $mbxAlias" -Backgroundcolor Green -ForeGroundColor Black
								#Set-ADUser $mbxAlias -Clear 'mS-DS-ConsistencyGuid'
								Get-ADUser $mbxAlias -Server $usiDC | Set-ADUser -Replace @{'mS-DS-ConsistencyGuid'=$mcntMSDSCon.'mS-DS-ConsistencyGuid'} -Server $usiDC -Verbose
								
								#Set msDS-CloudExtensionAttribute1
								Write-Host "Setting the msDS-cloudExtensionAttribute1 for $mbxAlias" -Backgroundcolor Green -ForeGroundColor Black
								Set-ADUser $mbxAlias -Server $usiDC  -Clear 'msDS-cloudExtensionAttribute1'
								Get-ADUser $mbxAlias -Properties * -Server $usiDC | Set-ADUser -Replace @{'msDS-cloudExtensionAttribute1'=$mcntSMTP} -Verbose -Server $usiDC
								
								#Set msDS-CloudExtensionAttribute2
								Write-Host "Setting the msDS-cloudExtensionAttribute2 for $mbxAlias" -Backgroundcolor Green -ForeGroundColor Black
								Set-ADUser $mbxAlias -Server $usiDC -Clear 'msDS-cloudExtensionAttribute2'
								Get-ADUser $mbxAlias -Properties * -Server $usiDC | Set-ADUser -Replace @{'msDS-cloudExtensionAttribute2'="Federated"} -Verbose -Server $usiDC
								
								#Set msDS-CloudExtensionAttribute3
								Write-Host "Setting the msDS-cloudExtensionAttribute3 for $mbxAlias" -Backgroundcolor Green -ForeGroundColor Black
								Set-ADUser $mbxAlias -Server $usiDC -Clear 'msDS-cloudExtensionAttribute3'
								Get-ADUser $mbxAlias -Properties * -Server $usiDC | Set-ADUser -Replace @{'msDS-cloudExtensionAttribute3'=$mcntLocal} -Verbose -Server $usiDC
								
								#########################
								# Update Phone Number	#
								#########################
								
								Write-Host "Acquiring the MHBK Contact OfficePhone" -Backgroundcolor Green -ForeGroundColor Black
								$phone=Get-ADUser -Properties * -Filter {mail -like $mcntSMTP} -Server $sourceDC | select -ExpandProperty OfficePhone 
								
								Write-Host "Acquiring the MHBK Contact ipPhone" -Backgroundcolor Green -ForeGroundColor Black
								$ext=Get-ADUser -Properties * -Filter {mail -like $mcntSMTP} -Server $sourceDC | select -ExpandProperty ipPhone 
								
								Write-Host "Acquiring the MHBK Contact Mobile Number" -Backgroundcolor Green -ForeGroundColor Black
								$cell=Get-ADUser -Properties * -Filter {mail -like $mcntSMTP} -Server $sourceDC | select -ExpandProperty Mobile
								
								#Add user's Office & Mobile Number and IPPhone Extension
								Write-Host "Adding $phone, $ext & $cell for $mbxAlias." -Backgroundcolor Green -ForeGroundColor Black
								Set-ADUser $mbxAlias -OfficePhone $phone -MobilePhone $cell -Replace @{ipPhone=$ext} -Server $usiDC -Verbose
								
								Write-Host "##############################################################################" -Backgroundcolor Black -ForeGroundColor White
								Write-Host "------------------------------------------------------------------------------" -Backgroundcolor Black -ForeGroundColor White
								Write-Host "##############################################################################" -Backgroundcolor Black -ForeGroundColor White
								
							}else{Write-Host "The mail contact for $bksmtp could not be found in the USI forest."; break}
						}
						"MailUser"{

							Write-Host "A mail user was found belonging to $bksmtp in the USI forest." -Backgroundcolor Black -ForeGroundColor Blue
							
							#############################
							# MailUser Update Section	#
							#############################

							Write-Host "Acquiring the MHBK Contact's Local Address" -Backgroundcolor Green -ForeGroundColor Black
							$bkLocal=$bksmtp -replace "primary smtp",""
												
							####Add Exchange Guid
							Write-Host "Setting the $($exchangeGUID) for $mbxAlias" -Backgroundcolor Green -ForeGroundColor Black
							Get-MailUser $mbxAlias -DomainController $usiDC | Set-MailUser -ExchangeGuid $exchangeGUID.msExchMailboxGuid -DomainController $usiDC -Verbose #-Alias $bkLocal							
					
							#####################################
							# Active Directory Update Section	#
							#####################################
												
							#Add mS-DS-ConsistencyGuid to AD User Account
							Write-Host "Setting the $($mcntMSDSCon) for $mbxAlias" -Backgroundcolor Green -ForeGroundColor Black
							#Set-ADUser $mbxAlias -Clear 'mS-DS-ConsistencyGuid'
							Get-ADUser $mbxAlias -Server $usiDC | Set-ADUser -Replace @{'mS-DS-ConsistencyGuid'=$mcntMSDSCon.'mS-DS-ConsistencyGuid'} -Verbose -Server $usiDC
							
							#Set msDS-CloudExtensionAttribute1
							Write-Host "Setting the msDS-cloudExtensionAttribute1 for $mbxAlias" -Backgroundcolor Green -ForeGroundColor Black
							Set-ADUser $mbxAlias -Server $usiDC -Clear 'msDS-cloudExtensionAttribute1'
							Get-ADUser $mbxAlias -Properties * -Server $usiDC | Set-ADUser -Replace @{'msDS-cloudExtensionAttribute1'=$bksmtp} -Verbose -Server $usiDC
							
							#Set msDS-CloudExtensionAttribute2
							Write-Host "Setting the msDS-cloudExtensionAttribute2 for $mbxAlias" -Backgroundcolor Green -ForeGroundColor Black
							Set-ADUser $mbxAlias -Server $usiDC -Clear 'msDS-cloudExtensionAttribute2'
							Get-ADUser $mbxAlias -Properties * -Server $usiDC | Set-ADUser -Replace @{'msDS-cloudExtensionAttribute2'="Federated"} -Verbose -Server $usiDC
							
							#Set msDS-CloudExtensionAttribute3
							Write-Host "Setting the msDS-cloudExtensionAttribute3 for $mbxAlias" -Backgroundcolor Green -ForeGroundColor Black
							Set-ADUser $mbxAlias -Server $usiDC  -Clear 'msDS-cloudExtensionAttribute3'
							Get-ADUser $mbxAlias -Properties * -Server $usiDC | Set-ADUser -Replace @{'msDS-cloudExtensionAttribute3'=$bkLocal} -Verbose -Server $usiDC
							
							#########################
							# Update Phone Number	#
							#########################
							
							Write-Host "Acquiring the MHBK Contact OfficePhone" -Backgroundcolor Green -ForeGroundColor Black
							$phone=Get-ADUser -Properties * -Filter {mail -like $bksmtp} -Server $sourceDC | select -ExpandProperty OfficePhone
							
							Write-Host "Acquiring the MHBK Contact ipPhone" -Backgroundcolor Green -ForeGroundColor Black
							$ext=Get-ADUser -Properties * -Filter {mail -like $bksmtp} -Server $sourceDC | select -ExpandProperty ipPhone
							
							Write-Host "Acquiring the MHBK Contact Mobile Number" -Backgroundcolor Green -ForeGroundColor Black
							$cell=Get-ADUser -Properties * -Filter {mail -like $bksmtp} -Server $sourceDC | select -ExpandProperty Mobile
							
							#Add user's Office & Mobile Number and IPPhone Extension
							Write-Host "Adding $phone, $ext & $cell for $mbxAlias." -Backgroundcolor Green -ForeGroundColor Black
							Set-ADUser $mbxAlias -OfficePhone $phone -MobilePhone $cell -Replace @{ipPhone=$ext} -Server $usiDC -Verbose
							
							Write-Host "##############################################################################" -Backgroundcolor Black -ForeGroundColor White
							Write-Host "------------------------------------------------------------------------------" -Backgroundcolor Black -ForeGroundColor White
							Write-Host "##############################################################################" -Backgroundcolor Black -ForeGroundColor White
							
						}
						
						"RemoteUserMailbox"{
							
							Write-Host "A remote mailbox was found belonging to $bksmtp in the USI forest." -Backgroundcolor Black -ForeGroundColor Blue
							Write-Host "This account has already been completely migrated to the MAS Infrastructure and does not require email consolidation or should be double-checked as it may be a duplicate mailbox." -ForeGroundColor Yellow -Backgroundcolor Black
						}
						
						default{
							
							Write-Host "No mail object was found belonging to $bksmtp in the USI forest. Re-run email consolidation script after Quest Migration." -ForeGroundColor Red -Backgroundcolor Black
							
						<#####################################################
						# Acquire Mail Attributes directly from MHBK Forest	#
						#####################################################
						Write-Host "Acquiring the MHBK Account's Info from MHBK forest"
						$mcntAccount=Get-ADUser $user[0].samaccountname -Properties * -Server $sourceDC | select Mail,LegacyExchangeDN,ProxyAddresses,
						Write-Host "Acquiring the MHBK Account's Primary SMTP Address from MHBK forest"
						$mcntSMTP=$mcntAccount.Mail
						
						Write-Host "Acquiring the MHBK Account's Legacy Exchange DN from MHBK forest"
						$mcntLegacy=$mcntAccount.LegacyExchangeDN
						
						$mcntLegacy="x500:"+$mcntLegacy
						
						Write-Host "Acquiring the MHBK Account's Proxy Addresses from MHBK forest"
						$mcntProxy=$mcntAccount.ProxyAddresses
											
						Write-Host "Acquiring the MHBK Account's Remote Routing Address"
						$mcntRRA=$mcntSMTP -replace "primary smtp","@mizuhogroup.mail.onmicrosoft.com"
						Write-Host "Acquiring the MHBK Contact's Local Address"
						$mcntLocal=$mcntSMTP -replace "primary smtp",""
							#>
						}		
					}
				
					$exchangeGUID=$null
					$mcntMSDSCon=$null
					$bksmtp=$null		
					
				}else{
				
					Write-Host "The is no USI account for $($user.usiid) or the account is in a disabled state." -Backgroundcolor Red -ForeGroundColor Black
					$exchangeGUID=$null
					$mcntMSDSCon=$null
					$bksmtp=$null
					break
				}
			}else{Write-Host "SyncMe is missing from msExchExtensionAttribtue19 on the MHBK account for $($user.bkid)." -Backgroundcolor Red -ForeGroundColor Black}
		}else{Write-Host "The account for $($user.bkid) is in a disabled state in the MHBK forest." -Backgroundcolor Red -ForeGroundColor Black}
	}else{Write-Host "The account for $($user.bkid) is in an Azure un-syncable OU in the MHBK forest." -Backgroundcolor Red -ForeGroundColor Black}
}

Write-Host "##############################################################################" -Backgroundcolor Black -ForeGroundColor White
Write-Host "------------------------------------------------------------------------------" -Backgroundcolor Black -ForeGroundColor White
Write-Host "##############################################################################" -Backgroundcolor Black -ForeGroundColor White

#########################################
# Move Accounts into a AADC Scope OU	#
#########################################

ForEach ($user in $users){
	
	$usiSAM=$user.usiid
	
	#Check to see if Quest created USI account exists
    Write-Host "Checking to see if an account exists in MSUSA for $usiSAM" -Backgroundcolor Green -ForeGroundColor Black

	try{

		$acct=Get-ADuser $usiSAM -Properties * -Server $usiDC -ErrorAction SilentlyContinue | select *
	
	}catch{

		$acct=$null

	}
	
	if($acct -ne $null){
		
		$sam=$acct.SAMAccountName
		$ADUserDN = $acct.distinguishedName
		$UserOU = $aduserdn.substring($aduserdn.indexof('OU='))
		write-host "Checking to see if $sam is in an Azure No Sync OU" -Backgroundcolor Green -ForeGroundColor Black
		If ($UserOU -match "OU=Not Synced to Azure"){
			write-host "User object is being moved out of the Not Synced to Azure OU" -Backgroundcolor Green -ForeGroundColor Black

			$TargetOU = $UserOU -replace "OU=Not Synced to Azure,",""
			write-host "TargetOU= "$targetOU
			Get-ADuser $sam| Move-ADObject -TargetPath $TargetOU -Server $usiDC -Verbose
		}
	}
}

#Force AD Replication
Write-Host "Running Active Directory." -Backgroundcolor Green -ForeGroundColor Black
Replicate-AllDomainController

Write-Host "##############################################################################" -Backgroundcolor Black -ForeGroundColor White
Write-Host "------------------------------------------------------------------------------" -Backgroundcolor Black -ForeGroundColor White
Write-Host "##############################################################################" -Backgroundcolor Black -ForeGroundColor White

ForEach ($user in $users){

	#Check for Syncable OU
	Write-Host "Checking to see if the $($user.bkid) is in an Azure Syncable OU." -Backgroundcolor Green -ForeGroundColor Black
	if((Get-ADUser $user.bkid -Server $sourceDC | select -ExpandProperty DistinguishedName) -notmatch "NoSync"){

		#Check to for an Enabled User Account
		Write-Host "Checking to see if the $($user.bkid) has an active user account in MHBK." -Backgroundcolor Green -ForeGroundColor Black
		if((Get-ADUser $user.bkid -Server $sourceDC | select -ExpandProperty Enabled) -ne $false){

			#Check MHBK account for MSExchangeEA19=syncme
			Write-Host "Checking for Sycnme Attribute in MHBK for $($user.bkid)" -Backgroundcolor Green -ForeGroundColor Black
			if((Get-ADUser $user.bkid -Properties * -Server $sourceDC | select -ExpandProperty msExchExtensionAttribute19) -like "syncme"){
					
				#Check to see if the MailUser exists in the MSUSA
				if((Get-ADUser $user.usiid -Server $usiDC -ErrorAction SilentlyContinue | select -ExpandProperty Enabled) -ne $false){
											
					################################
					# MailUser Confirmation Section #
					################################
					
					Write-Host "Acquiring account info for $($user.usiid)." -Backgroundcolor Green -ForeGroundColor Black
					
					#Get user's AD data
					$userData=Get-ADUser $user.usiid -Properties * -Server $usiDC | select UserPrincipalName,'msDS-cloudExtensionAttribute1','msDS-cloudExtensionAttribute2','msDS-cloudExtensionAttribute3',OfficePhone, Mobile, ipPhone
					$mbxData=Get-Recipient $user.usiid -DomainController $usiDC | select DisplayName,PrimarySMTPAddress,SamAccountName,EmailAddresses,ExternalEmailAddress,ExchangeGuid,CustomAttribute13,Alias,RecipientTypeDetails

					#Get MSUSA User Alias
					$mbxAlias=$mbxData.SamAccountName
					
					#Get MSUSA User Name
					$mbxName=$mbxData.DisplayName

					#Get MSUSA Alias
					$mbxMailNickname=$mbxData.Alias

					#Get MSUSA SMTP Address
					$mbxSMTP=$mbxData.PrimarySMTPAddress

					#Get Proxy Addresses
					$mbxProxy=$mbxData.EmailAddresses
					
					#Get Target Address
					$mbxTA=$mbxData.ExternalEmailAddress
					
					#Get Extension Attribute 13
					$mbxEA13=$mbxData.CustomAttribute13 #-Verbose
					
					#Get Exchange Guid
					$mbxExGUID=$mbxData.ExchangeGuid

					#Get Recipient Type Details
					$mbxRecipientType=$mbxData.RecipientTypeDetails
					
					#Get MSUSA User Principal Name
					$mbxUPN=$userData.UserPrincipalName
					
					#Get Office Number
					$officenumber=$userData.OfficePhone

					#Get Mobile Number
					$mobilenumber=$userData.Mobile
					
					#Get IP Phone Extension
					$extension=$userData.ipPhone
					
					#Get MS-DS ConsistencyGuid
					$msDSConsistency=Get-ADUser $mbxAlias -Properties * -Server $usiDC | select mS-DS-ConsistencyGuid
					
					#Cloud ExtensionAttribute 1
					$mbxCEA1=$userData.'msDS-cloudExtensionAttribute1'
					
					#Cloud ExtensionAttribute 2
					$mbxCEA2=$userData.'msDS-cloudExtensionAttribute2'
					
					#Cloud ExtensionAttribute 3
					$mbxCEA3=$userData.'msDS-cloudExtensionAttribute3'

					if($mbxName -eq $null){$mbxName="There is no Mail Object for this account."}
					if($mbxAlias -eq $null){$mbxAlias="There is no Mail Object for this account."}
					if($mbxSMTP -eq $null){$mbxSMTP="There is no Mail Object for this account."}
					if($mbxProxy -eq $null){$mbxProxy="There is no Mail Object for this account."}
					if($mbxTA -eq $null){$mbxTA="There is no Mail Object for this account."}
					if($mbxMailNickName -eq $null){$mbxMailNickname="There is no Mail Object for this account."}
					if($mbxEA13 -eq $null){$mbxEA13="There is no Mail Object for this account."}
					if($mbxRecipientType -eq $null){$mbxRecipientType="There is no Mail Object for this account."}
					if($mbxUPN -eq $null){$mbxUPN="There is no Mail Object for this account."}
					if($officenumber -eq $null){$officenumber="There is no Mail Object for this account or a phone number was not provided."}
					if($extension -eq $null){$extension="There is no Mail Object for this account."}
					if($mobilenumber -eq $null){$mobilenumber="There is no Mail Object for this account."}
					if($mbxCEA1 -eq $null){$mbxCEA1="There is no Mail Object for this account."}
					if($mbxCEA2 -eq $null){$mbxCEA2="There is no Mail Object for this account."}
					if($mbxCEA3 -eq $null){$mbxCEA3="There is no Mail Object for this account."}
				}else{
					$mbxName="The account for $($user.usiid) is in a disabled state in USI."
					$mbxAlias="The account for $($user.usiid) is in a disabled state in USI."
					$mbxSMTP="The account for $($user.usiid) is in a disabled state in USI."
					$mbxProxy="The account for $($user.usiid) is in a disabled state in USI."
					$mbxTA="The account for $($user.usiid) is in a disabled state in USI."
					$mbxMailNickname="The account for $($user.usiid) is in a disabled state in USI."
					$mbxRecipientType="The account for $($user.usiid) is in a disabled state in USI."
					$mbxEA13="The account for $($user.usiid) is in a disabled state in USI."
					$mbxUPN="The account for $($user.usiid) is in a disabled state in USI."
					$officenumber="The account for $($user.usiid) is in a disabled state in USI."
					$extension="The account for $($user.usiid) is in a disabled state in USI."
					$mobilenumber="The account for $($user.usiid) is in a disabled state in USI."
					$mbxCEA1="The account for $($user.usiid) is in a disabled state in USI."
					$mbxCEA2="The account for $($user.usiid) is in a disabled state in USI."
					$mbxCEA3="The account for $($user.usiid) is in a disabled state in USI."
				}
			}else{
				$mbxName="The account for $($user.bkid) does not have SyncMe configured in the MHFG domain."
				$mbxAlias="The account for $($user.bkid) does not have SyncMe configured in the MHFG domain."
				$mbxSMTP="The account for $($user.bkid) does not have SyncMe configured in the MHFG domain."
				$mbxProxy="The account for $($user.bkid) does not have SyncMe configured in the MHFG domain."
				$mbxTA="The account for $($user.bkid) does not have SyncMe configured in the MHFG domain."
				$mbxMailNickname="The account for $($user.bkid) does not have SyncMe configured in the MHFG domain."
				$mbxRecipientType="The account for $($user.bkid) does not have SyncMe configured in the MHFG domain."
				$mbxEA13="The account for $($user.bkid) does not have SyncMe configured in the MHFG domain."
				$mbxUPN="The account for $($user.bkid) does not have SyncMe configured in the MHFG domain."
				$officenumber="The account for $($user.bkid) does not have SyncMe configured in the MHFG domain."
				$extension="The account for $($user.bkid) does not have SyncMe configured in the MHFG domain."
				$mobilenumber="The account for $($user.bkid) does not have SyncMe configured in the MHFG domain."
				$mbxCEA1="The account for $($user.bkid) does not have SyncMe configured in the MHFG domain."
				$mbxCEA2="The account for $($user.bkid) does not have SyncMe configured in the MHFG domain."
				$mbxCEA3="The account for $($user.bkid) does not have SyncMe configured in the MHFG domain."
			}
		}else{
			$mbxName="The account for $($user.bkid) is in a disabled state in the MHFG domain."
			$mbxAlias="The account for $($user.bkid) is in a disabled state in the MHFG domain."
			$mbxSMTP="The account for $($user.bkid) is in a disabled state in the MHFG domain."
			$mbxProxy="The account for $($user.bkid) is in a disabled state in the MHFG domain."
			$mbxTA="The account for $($user.bkid) is in a disabled state in the MHFG domain."
			$mbxMailNickname="The account for $($user.bkid) is in a disabled state in the MHFG domain."
			$mbxRecipientType="The account for $($user.bkid) is in a disabled state in the MHFG domain."
			$mbxEA13="The account for $($user.bkid) is in a disabled state in the MHFG domain."
			$mbxUPN="The account for $($user.bkid) is in a disabled state in the MHFG domain."
			$officenumber="The account for $($user.bkid) is in a disabled state in the MHFG domain."
			$extension="The account for $($user.bkid) is in a disabled state in the MHFG domain."
			$mobilenumber="The account for $($user.bkid) is in a disabled state in the MHFG domain."
			$mbxCEA1="The account for $($user.bkid) is in a disabled state in the MHFG domain."
			$mbxCEA2="The account for $($user.bkid) is in a disabled state in the MHFG domain."
			$mbxCEA3="The account for $($user.bkid) is in a disabled state in the MHFG domain."
		}
	}else{
		$mbxName="The account for $($user.bkid) is in a No Sync OU in the MHFG domain."
		$mbxAlias="The account for $($user.bkid) is in a No Sync OU in the MHFG domain."
		$mbxSMTP="The account for $($user.bkid) is in a No Sync OU in the MHFG domain."
		$mbxProxy="The account for $($user.bkid) is in a No Sync OU in the MHFG domain."
		$mbxTA="The account for $($user.bkid) is in a No Sync OU in the MHFG domain."
		$mbxMailNickname="The account for $($user.bkid) is in a No Sync OU in the MHFG domain."
		$mbxRecipientType="The account for $($user.bkid) is in a No Sync OU in the MHFG domain."
		$mbxEA13="The account for $($user.bkid) is in a No Sync OU in the MHFG domain."
		$mbxUPN="The account for $($user.bkid) is in a No Sync OU in the MHFG domain."
		$officenumber="The account for $($user.bkid) is in a No Sync OU in the MHFG domain."
		$extension="The account for $($user.bkid) is in a No Sync OU in the MHFG domain."
		$mobilenumber="The account for $($user.bkid) is in a No Sync OU in the MHFG domain."
		$mbxCEA1="The account for $($user.bkid) is in a No Sync OU in the MHFG domain."
		$mbxCEA2="The account for $($user.bkid) is in a No Sync OU in the MHFG domain."
		$mbxCEA3="The account for $($user.bkid) is in a No Sync OU in the MHFG domain."
	}
			
$mbxOutput=New-Object PSObject -Property ([ordered] @{

	"MSUSA User Name"=$mbxName
	"MSUSA User Alias"=$mbxAlias
	"MSUSA User Primary SMTP"=$mbxSMTP
	"MSUSA User Proxy Addresses"=$mbxProxy
	"MSUSA User Target Address"=$mbxTA
	"MSUSA User ExtensionAttribute13"=$mbxEA13
	"MSUSA O365 User Exhange GUID"=$mbxExGUID
	"MSUSA User RecipientTypeDetails"=$mbxRecipientType
	"MSUSA User Mail Nick Name"=$mbxMailNickname
	"MSUSA User Principal Name"=$mbxUPN
	"MSUSA User Phone Number"=$officenumber
	"MSUSA User IPPhone Extension"=$extension
	"MSUSA User Mobile Numbers"=$mobilenumber
	"MSUSA ConsistencyGuid"=(@($msDSConsistency.'mS-DS-ConsistencyGuid') | Out-String).Trim()
	"MSUSA CloudEA1"=$mbxCEA1
	"MSUSA CloudEA2"=$mbxCEA2
	"MSUSA CloudEA3"=$mbxCEA3
	
})

$mbxReport+=$mbxOutput

$mbxReport | Export-CSV -NoTypeInformation -Path $outputPath

Write-Host "-------------------------------------------------------------"	
}

#Sync Azure AD
Write-Host "Synchronizing Azure AD Connect." -Backgroundcolor Green -ForeGroundColor Black
Invoke-Command -ComputerName ADConnect Server FQDN -ScriptBlock {Start-ADSyncSyncCycle -PolicyType Delta}

#Email Reports
Write-Host "Sending a detailed email that contains the validation report and/or errors encountered." -Backgroundcolor Green -ForeGroundColor Black
Send-MailMessage -From NoReply.QuestMailUserCreationReport@smtpdomain -To Targeted Mail Objects -Subject "Create MailUser for Quest Migration Report $date" -Body "Hello,`n`n`The attached document contains the output for users that had a MSUSA MailUser created for the Quest migration. `n`nA copy of this report is also stored here: uncpath\Reports\ `n`nThank you" -Attachments $outputPath -Priority Normal -SMTPServer smtp relay
if($errorOutPut -ne $null){Send-MailMessage -From NoReply.QuestMailUserCreationErrorReport@smtpdomain -To Targeted Mail Objects -Subject "Create MailUser for Quest Migration Report Error $date" -Body "Hello,`n`n`The attached document contains the error output for users that tried to have a MSUSA MailUser created for the Quest migration. `n`nA copy of this report is also stored here: uncpath\Reports\ `n`nThank you" -Attachments $errorOutPut -Priority Normal -SMTPServer smtp relay}
#Send-MailMessage -From NoReply.QuestMailUserCreationReporttarget legacy smtp -To IT-Windows@mizuhogroup.com -Subject "Create MailUser for Quest Migration Report $date" -Body "Hello,`n`n`The attached document contains the output for users that had a MSUSA MailUser created for the Quest migration. `n`nA copy of this report is also stored here: uncpath\Reports\ `n`nThank you" -Attachments $outputPath -Priority Normal -SMTPServer smtp relay

Get-PSSession | Remove-PSSession
#>
Stop-Transcript