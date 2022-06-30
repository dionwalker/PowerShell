#####################################
# Remove Direct User Server Access	#
# Created by Dion Walker			#
# On 9/17/2021						#
# Revision 2						#
#####################################

#Get the date in mm-dd-yyyy format
$date= "10-31-2021" #Get-Date -UFormat "%m-%d-%Y"

#Start a log of all actions done
Start-Transcript -Append -Path uncpath\Logs\Remove-DirectUser-Access-to-Servers-$date.txt

#Create a blank array
$serverReport= @()

#Set variable with output for the report file
$outputPath= "uncpath\Reports\Remove-DirectUser-Access-to-Servers-Report-$date.csv"

#Import list of data to variable
$servers= Import-Csv -Path uncpath\SourceFiles\Remove-DirectUser-Access-to-Servers-$date.csv

#Iterate through each row of data
foreach($server in $servers){

	#Add Server Name to variable
	$svr= $server.Name
	
	#Add account that needs to be revocated
	$SAM=$server.Account
	#$account="USI\"+$SAM
	
	#Set local server administrators group variable to null
	$legacyadminMembers= $null
	$currentadminMembers= $null
	
	#Set local server remote desktop users group variable to null
	$legacyrdpMembers= $null
	$currentrdpMembers= $null
		
	#Confirm if the server is network accessible
	if((Test-Connection $svr -Count 1 -Quiet) -eq $true){
	
		#Get local administrators group membership on the server
		Write-Host "Obtaining the list of legacy accounts from the Local Administrators Group on $svr" -Backgroundcolor Black -ForeGroundColor Green
		$legacyadminMembers=Invoke-Command -ComputerName $svr -ScriptBlock {([ADSI]"WinNT://./Administrators").psbase.Invoke('Members') | % {([ADSI]$_).InvokeGet('AdsPath')}}
		$legacyadminMembers=$legacyadminMembers -replace "WinNT://",""
		$legacyadminMembers=$legacyadminMembers -replace "/","\"
		
		#Get local remote desktop users group membership on the server
		Write-Host "Obtaining the list of legacy accounts from the Local Remote Desktop Users Group on $svr" -Backgroundcolor Black -ForeGroundColor Green
		$legacyrdpMembers=Invoke-Command -ComputerName $svr -ScriptBlock {([ADSI]"WinNT://./Remote Desktop Users").psbase.Invoke('Members') | % {([ADSI]$_).InvokeGet('AdsPath')}}
		$legacyrdpMembers=$legacyrdpMembers -replace "WinNT://",""
		$legacyrdpMembers=$legacyrdpMembers -replace "/","\"
		
		
		##############
		# Break Line #
		##############
		
		Write-Host "------------------------------------------" -Backgroundcolor Black -ForeGroundColor White
		Write-Host "------------------------------------------" -Backgroundcolor Black -ForeGroundColor White
		Write-Host "------------------------------------------" -Backgroundcolor Black -ForeGroundColor White
		Start-Sleep -s 15
		
		##############
		# Break Line #
		##############
		
		#Remove all directly added user accounts from the local administrators group on the server.
		Write-Host "Removing direct access accounts from the Local Administrators Group on $svr" -Backgroundcolor Black -ForeGroundColor Green
		
		if((Invoke-Command -ComputerName $svr  -ScriptBlock {([ADSI]"WinNT://./Remote Desktop Users").psbase.Invoke('Members') | % {([ADSI]$_).InvokeGet('AdsPath')}}| Select-String -Pattern $SAM) -ne $null){
			
			Write-Host "Remove $SAM from the Remote Desktop Users group on $svr."
			Invoke-Command -ComputerName $svr -ScriptBlock {Remove-LocalGroupMember -Group "Remote Desktop Users" -Member $using:SAM }#-WhatIf}

		}
		
		if((Invoke-Command -ComputerName $svr  -ScriptBlock {([ADSI]"WinNT://./Administrators").psbase.Invoke('Members') | % {([ADSI]$_).InvokeGet('AdsPath')}}| Select-String -Pattern $SAM) -ne $null){
			Write-Host "Remove $SAM from the Administrators group on $svr."
			Invoke-Command -ComputerName $svr -ScriptBlock {Remove-LocalGroupMember -Group "Administrators" -Member $using:SAM }#-WhatIf}
		
		}

					
	} else{
	
		#Add comment for servers not network accessible.
		$legacyadminMembers="Could not connect to the svr to obtain local group membership."
		$legacyrdpMembers="Could not connect to the svr to obtain local group membership."
		$currentadminMembers="Could not connect to the svr to obtain local group membership."
		$currentrdpMembers="Could not connect to the svr to obtain local group membership."
		
		#Add comment for servers not network accessible.
		$svr=$svr+" is not network accessible."
	}

		##############
		# Break Line #
		##############
		
		Write-Host "------------------------------------------" -Backgroundcolor Black -ForeGroundColor White
		Write-Host "------------------------------------------" -Backgroundcolor Black -ForeGroundColor White
		Write-Host "------------------------------------------" -Backgroundcolor Black -ForeGroundColor White
		
		##############
		# Break Line #
		##############
	
		#############
		# Get Info	#
		#############
		
		Write-Host "Obtaining the list of current accounts from the Local Administrators Group on $svr" -Backgroundcolor Black -ForeGroundColor Green
		#Acquire the members of the local administrators group.
		$currentadminMembers=Invoke-Command -ComputerName $svr -ScriptBlock {([ADSI]"WinNT://./Administrators").psbase.Invoke('Members') | % {([ADSI]$_).InvokeGet('AdsPath')}}
		$currentadminMembers=$currentadminMembers -replace "WinNT://",""
		$currentadminMembers=$currentadminMembers -replace "/","\"
		
		#Acquire the members of the local administrators group.
		Write-Host "Obtaining the list of current accounts from the Local Remote Desktop Users Group on $svr" -Backgroundcolor Black -ForeGroundColor Green
		$currentrdpMembers=Invoke-Command -ComputerName $svr -ScriptBlock {([ADSI]"WinNT://./Remote Desktop Users").psbase.Invoke('Members') | % {([ADSI]$_).InvokeGet('AdsPath')}}
		$currentrdpMembers=$currentrdpMembers -replace "WinNT://",""
		$currentrdpMembers=$currentrdpMembers -replace "/","\"
		
		#Create an arraylist to store the info for export
		$serverInfo = New-Object PSObject -Property ([ordered]@{
		
			"Server Host Name" = $svr
			"Server Legacy Administrators Group Membership" = (@($legacyadminMembers) | Out-String).Trim()
			"Server Current Administrators Group Membership" = (@($currentadminMembers) | Out-String).Trim()
			"Server Legacy Remote Desktop Users Group Membership" = (@($legacyrdpMembers) | Out-String).Trim()
			"Server Current Remote Desktop Users Group Membership" = (@($currentrdpMembers) | Out-String).Trim()			
			})
	
	#Add the arraylist to the array
	$serverReport += $serverInfo

	#Export data to a csv file
	$serverReport | Export-CSV -NoTypeInformation -Path $outputPath
	
	#Set server variable back to blank
	$svr=$null
	
	#Set members variable back to blank	
	$SAM=$null
 	

}

#Send email to targeted audience with the attached report.
Send-MailMessage -From NoReply.RemoveDirectAccessfromServerReport@smtpdomain -To Targeted Mail Objects -Cc Targeted Mail Objects -Subject "Removal of Direct Server User Access Report $date" -Body "Hello,`n`n`The attached document contains the list of accounts that were removed to allow only RES Groups to be used to access to servers located in MSUSA. `n`nThe listed RES Groups can now also be found in Aveksa. `n`nA copy of this report is also stored here: uncpath\Reports\ `n`nThank you" -Attachments $outputPath -Priority Normal -SMTPServer smtp-relay

#Stop logging
Stop-Transcript