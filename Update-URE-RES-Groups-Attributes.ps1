#########################################
# Update URE RES Groups Attributes		#
# Created by Dion Walker				#
# On 01/09/2019							#
# Revision 6							#
#########################################

#Get today's date.
$date=Get-Date -UFormat "%m-%d-%Y"

#Start a log of all things done by this script
Start-Transcript -Path uncpath\Logs\Update-URE-RES-Groups-Attributes-$date.txt

#Get input data
$grps= Import-Csv -Path uncpath\SourceFiles\Update-URE-RES-Groups-Attributes-$date.csv

#Report Output location
$outputPath= "uncpath\Reports\URE-RES-Groups-Attributes-Update-Report-$date.csv"

#Create a blank array to be used later
$ureReport= @()

function Replicate-AllDomainController {
    (Get-ADDomainController).Name | Foreach-Object {repadmin /syncall /APed $_ (Get-ADDomain).DistinguishedName /e /A | Out-Null}; Start-Sleep 10; Write-Host "Change was successfully replicated in Active Directory." -Backgroundcolor Green -ForeGroundColor Black	
}
    
$usiDC=(Get-ADDomainController).Name

$sourceDC="source DC FQDN"

foreach($grp in $grps){


	$grpName=$grp.Name
	#$grpEA3= $grp.EA3
	#$grpEA4= $grp.EA4
	$grpEA5=$grp.EA5
	$grpEA8=$grp.EA8

	#Confirm if RES Group exists
	if((Get-ADGroup -Filter {name -like $grpName}) -ne $null){
	
		#Get RES Group Name
		$grpName=Get-ADGroup -Filter {name -like $grpName} -Properties * | Select -ExpandProperty Name
		
		#Get RES Group SAM Account
		$grpSAM=Get-ADGroup -Filter {name -like $grpName} -Properties * | Select -ExpandProperty SamAccountName
		
		Write-Host "Checking to see if $grpName has EA8 filled in or not."
		if(((Get-ADGroup $grpSAM -Properties * | select -ExpandProperty extensionAttribute8) -eq $null) -and ($grpEA8 -ne $null)){
			
			#Set Extension Attribute 8
			Write-Host "Clearing EA8 Attributes for $grpName" -Backgroundcolor Green -ForeGroundColor Black
			Get-ADGroup $grpSAM | Set-ADGroup -Clear extensionattribute8 -Verbose #-Whatif
			
			Start-Sleep -s 10

			#Set Extension Attribute 8
			Write-Host "Adding EA8 Attribute for $grpName" -Backgroundcolor Green -ForeGroundColor Black
			Get-ADGroup $grpSAM | Set-ADGroup -Add @{extensionattribute8=$grpEA8} -Verbose #-Whatif
			#Get-ADGroup $grpSAM | Set-ADGroup -Add @{extensionattribute8=$EA8} -Verbose
			
		} elseif(((Get-ADGroup $grpSAM -Properties * | select -ExpandProperty extensionAttribute8) -ne $null) -and ($grpEA8 -ne $null)){
			
			#Set Extension Attribute 8
			Write-Host "Clearing EA8 Attributes for $grpName" -Backgroundcolor Green -ForeGroundColor Black
			Get-ADGroup $grpSAM | Set-ADGroup -Clear extensionattribute8 -Verbose #-Whatif
			
			Start-Sleep -s 10

			#Set Extension Attribute 8
			Write-Host "Adding EA8 Attribute for $grpName" -Backgroundcolor Green -ForeGroundColor Black
			Get-ADGroup $grpSAM | Set-ADGroup -Add @{extensionattribute8=$grpEA8} -Verbose #-Whatif
			#Get-ADGroup $grpSAM | Set-ADGroup -Add @{extensionattribute8=$EA8} -Verbose

		
		}else{Write-Host "$grpName does not require an EA8 update."}
		#continue
		#Set Owner for the group
		#Write-Host "Adding an Owner for $grpName" -Backgroundcolor Green -ForeGroundColor Black
		#Get-ADGroup $grpSAM | Set-ADGroup -ManagedBy $EA5 #-Whatif
	
		Write-Host "Checking to see if $grpName has EA5 filled in or not."
		if(((Get-ADGroup $grpSAM -Properties * | select -ExpandProperty extensionAttribute5) -eq $null) -and ($grpEA5 -ne $null)){
			
			#Set Extension Attribute 5
			Write-Host "Clearing Owner/EA5 Attributes for $grpName" -Backgroundcolor Green -ForeGroundColor Black
			Get-ADGroup $grpSAM | Set-ADGroup -Clear extensionattribute5,ManagedBy -Verbose #-Whatif
			
			Start-Sleep -s 10

			#Set Extension Attribute 5
			Write-Host "Adding Owner/EA5 Attribute for $grpName" -Backgroundcolor Green -ForeGroundColor Black
			Get-ADGroup $grpSAM | Set-ADGroup -Add @{extensionattribute5=$grpEA5} -ManagedBy $EA5 -Verbose #-Whatif
			#Get-ADGroup $grpSAM | Set-ADGroup -Add @{extensionattribute8=$EA8} -Verbose
			
		} elseif(((Get-ADGroup $grpSAM -Properties * | select -ExpandProperty extensionAttribute5) -ne $null) -and ($grpEA5 -ne $null)){
			
			#Set Extension Attribute 5
			Write-Host "Clearing Owner/EA5 Attributes for $grpName" -Backgroundcolor Green -ForeGroundColor Black
			Get-ADGroup $grpSAM | Set-ADGroup -Clear extensionattribute5,ManagedBy -Verbose #-Whatif
			
			Start-Sleep -s 10

			#Set Extension Attribute 5
			Write-Host "Adding Owner/EA5 Attribute for $grpName" -Backgroundcolor Green -ForeGroundColor Black
			Get-ADGroup $grpSAM | Set-ADGroup -Add @{extensionattribute5=$grpEA5} -ManagedBy $EA5 -Verbose #-Whatif
			#Get-ADGroup $grpSAM | Set-ADGroup -Add @{extensionattribute8=$EA8} -Verbose

		
		}else{Write-Host "$grpName does not require an Owner/EA5 update."}
		#continue
		#Set Owner for the group
		#Write-Host "Adding an Owner for $grpName" -Backgroundcolor Green -ForeGroundColor Black
		#Get-ADGroup $grpSAM | Set-ADGroup -ManagedBy $EA5 #-Whatif
		
		#Set Group Scope to Domain Local
		if((Get-ADGroup $grpSAM -Properties * | Select -ExpandProperty GroupScope) -ne "DomainLocal"){
		
			Write-Host "Setting the Group Scope for $grpName" -Backgroundcolor Green -ForeGroundColor Black
			Get-ADGroup $grpSAM | Set-ADGroup -GroupScope "Universal"
			Get-ADGroup $grpSAM | Set-ADGroup -GroupScope "DomainLocal" #-Whatif
			#Get-ADGroup $grpSAM | Set-ADGroup -GroupScope "DomainLocal" -Verbose
		}
		
		#Force AD Replication
		Write-Host "Syncing the USI Domain"
		Replicate-AllDomainController
		
		Start-Sleep -s 10
		
		#Add the users to RES group
		Write-Host "Adding members to $grpName" -Backgroundcolor Green -ForeGroundColor Black
		foreach($user in $grp.Members.split(";").TrimEnd()){
	
			#Check to see if the user account is either in email or samaccountname format
			if ($user -match "@"){
				
				#Check to see if the user is a MSUSA or MHBK user first before adding to the RES group
				if((Get-ADUser -Properties * -Filter {mail -like $user} -Server $sourceDC -ErrorAction SilentlyContinue) -ne $null){
					
					#Add MHBK user to the RES group
					Write-Host "Adding $user to $grpSAM"
					Get-ADGroup $grpSAM | Add-ADGroupMember -Members (Get-ADUser -Properties * -Filter {mail -like $user} -Server $sourceDC) -Verbose
				
				}elseif((Get-ADUser -Properties * -Filter {mail -like $user} -Server $usiDC -ErrorAction SilentlyContinue) -ne $null){
							
					#Add MSUSA user to the RES group
					Write-Host "Adding $user to $grpSAM"
					Get-ADGroup $grpSAM | Add-ADGroupMember -Members (Get-ADUser -Properties * -Filter {mail -like $user}) -Verbose
				
				}else{

					$error="$user was not added to $grpName because it could not be found in neither MSUSA or MHBK domains."
					$error | Out-String | Out-File -Append -FilePath "uncpath\Reports\URE-RES-Groups-Attributes-Update-Error-Report-$date.csv"
				
				}	
			
			}elseif($user -match ","){
				
				#Check to see if the user is a MSUSA or MHBK user first before adding to the RES group
				if((Get-ADUser -Properties * -Filter {DisplayName -like $user} -Server $sourceDC -ErrorAction SilentlyContinue) -ne $null){
					
					#Add MHBK user to the RES group
					Write-Host "Adding $user to $grpSAM"
					Get-ADGroup $grpSAM | Add-ADGroupMember -Members (Get-ADUser -Properties * -Filter {DisplayName -like $user} -Server $sourceDC) -Verbose
				
				}elseif((Get-ADUser -Properties * -Filter {DisplayName -like $user} -Server $usiDC -ErrorAction SilentlyContinue) -ne $null){
				
					#Add MSUSA user to the RES group
					Write-Host "Adding $user to $grpSAM"
					Get-ADGroup $grpSAM | Add-ADGroupMember -Members (Get-ADUser -Properties * -Filter {DisplayName -like $user}) -Verbose
				
				}else{
				
					$error="$user was not added to $grpName because it could not be found in neither MSUSA or MHBK domains."
					$error| Out-File -Append -FilePath "uncpath\Reports\URE-RES-Groups-Attributes-Update-Error-Report-$date.csv"
				
				}
				
			}else{
			
				#Check to see if the user is a MSUSA or MHBK user first before adding to the RES group
				if((Get-ADUser -Properties * -Filter {SamAccountName -like $user} -Server $sourceDC -ErrorAction SilentlyContinue) -ne $null){
					
					#Add MHBK user to the RES group
					Write-Host "Adding $user to $grpSAM"
					Get-ADGroup $grpSAM | Add-ADGroupMember -Members (Get-ADUser -Properties * -Filter {SamAccountName -like $user} -Server $sourceDC) -Verbose
				
				}elseif((Get-ADUser -Properties * -Filter {SamAccountName -like $user} -Server $usiDC -ErrorAction SilentlyContinue) -ne $null){
				
					#Add MSUSA user to the RES group
					Write-Host "Adding $user to $grpSAM"
					Get-ADGroup $grpSAM | Add-ADGroupMember -Members (Get-ADUser -Properties * -Filter {SamAccountName -like $user}) -Verbose
				
				}else{
				
					$error="$user was not added to $grpName because it could not be found in neither MSUSA or MHBK domains."
					$error| Out-File -Append -FilePath "uncpath\Reports\URE-RES-Groups-Attributes-Update-Error-Report-$date.csv"
				
				}
			}
		}	

		#Get Extension Attribute 5 of the Group
		$grpEA5=Get-ADGroup $grpSAM -Properties * | Select -ExpandProperty ExtensionAttribute5 -Verbose

		#Get Extension Attribute 8 of the Group
		$grpEA8=Get-ADGroup $grpSAM -Properties * | Select -ExpandProperty ExtensionAttribute8 -Verbose
				
		#Get Group Scope
		$grpScope=Get-ADGroup $grpSAM -Properties * | Select -ExpandProperty GroupScope
		
		#Get Group Members
		$grpMembers=Get-ADGroup $grpSAM | Get-ADGroupMember -Recursive | select -ExpandProperty Name | Out-String
	
	}else{
	
		$grpName=$grp.Name
		$grpSAM="RES Group does not exist in Active Directory"
		$grp5="RES group does not exist in Active Directory"
		$grpEA8="RES Group does not exist in Active Directory"
		$grpScope="RES Group does not exist in Active Directory"
		$grpMembers="RES Group does not exist in Active Directory"
	}
	
	#Create Object for exporting
	$ureOutput=New-Object PSObject -Property ([ordered] @{
	
		"Group Name"=$grpName
		"Group SAM Account"=$grpSAM
		"Group Scope"= $grpScope
		"Group Owner/ExtentionAttribute5"=$grpEA5
		"Group ExtensionAttribute8"=$grpEA8
		"Group Members"=$grpMembers
	})
	
	$ureReport+=$ureOutput
	
	$ureReport | Export-CSV -NoTypeInformation -Path $outputPath
	
	Start-Sleep -s 5
	
	Write-Host "-----------------------------------------------------------------------------" -Backgroundcolor Green -ForeGroundColor Black

}

#Force AD Replication
Replicate-AllDomainController

Send-MailMessage -From NoReply.URERESGroupAttributeUpdateReport@smtpdomain -To Targeted Mail Objects -Cc Targeted Mail Objects -Subject "URE RES Group Attribute Update Report $date" -Body "Hello,`n`n`The attached document contains the list of URE RES Groups that had their AD Attribute updated. `n`nA copy of this report is also stored here: uncpath\Reports\ `n`nThank you" -Attachments $outputPath -Priority High -SMTPServer smtp-relay

Stop-Transcript