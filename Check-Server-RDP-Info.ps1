#############################
# Check Server RDP Info		#
# Created by Dion Walker	#
# On 12/01/2021				#
# Revision 1				#
#############################

#Get the date in mm-dd-yyyy format
$date= Get-Date -UFormat "%m-%d-%Y"

#Start a log of all actions done
Start-Transcript -Append -Path uncpath\Logs\Check-Server-RDP-Info-$date.txt

#Create a blank array
$serverReport= @()

#Set variable with output for the report file
$outputPath= "uncpath\Reports\Check-Server-RDP-Info-Report-$date.csv"

#Import list of data to variable
$servers= Get-ADComputer -Filter * -Properties * | where {$_.OperatingSystem -like "*Windows Server*"} | select Name,OperatingSystem #Import-Csv -Path uncpath\SourceFiles\Check-Server-RDP-Info-$date.csv

#Iterate through each server listed
foreach($server in $servers){
	
	#Add Server Name to variable
	$svr= $server.Name
	
	#Add Operating System to variable
	$OS=$server.OperatingSystem
	
	#Set local server administrators group variable to null
	$currentadminMembers= $null
	
	#Set local server remote desktop users group variable to null
	$currentrdpMembers= $null
		
	#Confirm if the server is network accessible
	if((Test-Connection $svr -Count 1 -Quiet) -eq $true){
			
		#############
		# Get Info	#
		#############
			
		#Acquire the members of the local administrators group.
		Write-Host "Obtaining the list of current accounts from the Local Administrators Group on $svr" -Backgroundcolor Black -ForeGroundColor Green
		$currentadminMembers=Invoke-Command -ComputerName $svr -ScriptBlock {([ADSI]"WinNT://./Administrators").psbase.Invoke('Members') | % {([ADSI]$_).InvokeGet('AdsPath')}}
		$currentadminMembers=$currentadminMembers -replace "WinNT://",""
		$currentadminMembers=$currentadminMembers -replace "/","\"
		
		##############
		# Break Line #
		##############
		
		Write-Host "------------------------------------------" -Backgroundcolor Black -ForeGroundColor White
		Write-Host "------------------------------------------" -Backgroundcolor Black -ForeGroundColor White
		Write-Host "------------------------------------------" -Backgroundcolor Black -ForeGroundColor White
		Start-Sleep -s 5
		
		##############
		# Break Line #
		##############
		
		#Acquire the members of the local remote desktop users group.
		Write-Host "Obtaining the list of current accounts from the Local Remote Desktop Users Group on $svr" -Backgroundcolor Black -ForeGroundColor Blue
		$currentrdpMembers=Invoke-Command -ComputerName $svr -ScriptBlock {([ADSI]"WinNT://./Remote Desktop Users").psbase.Invoke('Members') | % {([ADSI]$_).InvokeGet('AdsPath')}}
		$currentrdpMembers=$currentrdpMembers -replace "WinNT://",""
		$currentrdpMembers=$currentrdpMembers -replace "/","\"
		
		##############
		# Break Line #
		##############
		
		Write-Host "------------------------------------------" -Backgroundcolor Black -ForeGroundColor White
		Write-Host "------------------------------------------" -Backgroundcolor Black -ForeGroundColor White
		Write-Host "------------------------------------------" -Backgroundcolor Black -ForeGroundColor White
		Start-Sleep -s 5
		
		##############
		# Break Line #
		##############
					
	} else{
	
		#Add comment for servers not network accessible.
		$currentadminMembers="Could not connect to $svr to obtain local group membership."
		$currentrdpMembers="Could not connect to $svr to obtain local group membership."
		
		#Add comment for servers not network accessible.
		$svr=$svr+" is not network accessible."
	}
	
		#################
		# Export Info	#
		#################
		
		#Create an arraylist to store the info for export
		$serverInfo = New-Object PSObject -Property ([ordered]@{
		
			"Server Host Name" = $svr
			"Server Operating System"= $OS
			"Server Current Administrators Group Membership" = (@($currentadminMembers) | Out-String).Trim()
			"Server Current Remote Desktop Users Group Membership" = (@($currentrdpMembers) | Out-String).Trim()			
		})
	
	#Add the arraylist to the array
	$serverReport += $serverInfo

	#Export data to a csv file
	$serverReport | Export-CSV -NoTypeInformation -Path $outputPath
	
	#Set server variable back to blank
	$svr=$null

}

#Send email to targeted audience with the attached report.
Send-MailMessage -From NoReply.CheckServerRDPInfoReport@smtpdomain -To Targeted Mail Objects -Cc Targeted Mail Objects -Subject "Check Server RDP Info Report $date" -Body "Hello,`n`n`The attached document contains the list of servers located in MSUSA and includes the group membership of the servers' local administrators and remote desktop users groups. `n`nThe listed RES Groups can now also be found in Aveksa. `n`nA copy of this report is also stored here: uncpath\Reports\ `n`nThank you" -Attachments $outputPath -Priority Normal -SMTPServer smtp-relay

#Stop logging
Stop-Transcript