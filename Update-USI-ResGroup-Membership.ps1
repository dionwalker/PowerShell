#####################################
# Update MSUSA AD RES Groups Script	#
# Created by Dion Walker			#
# On 6/17/2019						#
# Revision 3						#
# Run everyday @ 9 PM EST			#
#####################################

$date= Get-Date -UFormat "%m-%d-%Y"

Start-Transcript -Append -Path \uncpath\Logs\Update-USI-RES-GroupMemberships-$date.txt

$grpReport= @()

$outputPath= "\uncpath\Reports\Update-USI-RES-GroupMembership-Report-$date.csv"
$errorOutputPath="\uncpath\Reports\Update-USI-RES-GroupMembership-Error-Report-$date.txt"

#Try/Catch & advise if import file exists or not.
$importGrps= Import-Csv -Path \uncpath\SourceFiles\Update-RES-GroupMembership-$date.csv

function Replicate-AllDomainController {
(Get-ADDomainController).Name | Foreach-Object {repadmin /syncall /APed $_ (Get-ADDomain).DistinguishedName /e /A | Out-Null}; Start-Sleep 10; Write-Host "Change was successfully replicated in Active Directory." -Backgroundcolor Blue -ForeGroundColor Black	
}

foreach($Grp in $importGrps){

	$grpName= $Grp.Name
	#$grpMngr= $Grp.Owner #Get Group Owner email to send too
	
	Write-Host "Updating the group membership for $grpName" -Backgroundcolor Black -ForeGroundColor Green

	if((Get-ADGroup -Filter {name -eq $grpName} -ErrorAction SilentlyContinue) -ne $null){
		
		#Purge all group members

		foreach($mbr in $grp.Members.split(";").TrimEnd()){
		
			try{
				$mbr=$mbr.Trim()
				Get-ADGroup $grpName | Add-ADGroupMember -Members $mbr -ErrorAction SilentlyContinue -Verbose #-WhatIf
			
			}catch{
				
				$error= "An AD object for $mbr could not be found in the USI forest."
				$error | Out-File -Append -FilePath $ErrorOutputPath
			}
		}
	}else{Write-Host "The AD Group called $grpName does not exist in the USI forest." -Backgroundcolor Red -ForeGroundColor Black}
	
	Write-Host "------------------------------------------------------------------------------" -Backgroundcolor Black -ForeGroundColor White
}	

Write-Host "##############################################################################" -Backgroundcolor Black -ForeGroundColor White
Write-Host "------------------------------------------------------------------------------" -Backgroundcolor Black -ForeGroundColor White
Write-Host "##############################################################################" -Backgroundcolor Black -ForeGroundColor White

#Force AD Replication
Replicate-AllDomainController

Write-Host "##############################################################################" -Backgroundcolor Black -ForeGroundColor White
Write-Host "------------------------------------------------------------------------------" -Backgroundcolor Black -ForeGroundColor White
Write-Host "##############################################################################" -Backgroundcolor Black -ForeGroundColor White
		
foreach($Grp in $importGrps){
	
	Write-Host "Acquiring Group Membership info for $($grp.Name)" -Backgroundcolor Black -ForeGroundColor Magenta
	$grpName= $Grp.Name
	$grpMembers= Get-ADGroup $grpName -Properties * | select -ExpandProperty Members | Get-ADObject -Properties * -Server sclfaddcwnprd02.usi.mizuho-sc.com| where{$_.ObjectClass -ne "ForeignSecurityPrincipal"} | Get-ADObject -Properties * -server sclfaddcwnprd02.usi.mizuho-sc.com | select -ExpandProperty SamAccountName #-WhatIf
	
	if($grpMembers -eq $null){$grpMembers="There are no members in this group."}
	
	$grpInfo = New-Object PSObject -Property ([ordered]@{
	
		"Group Name" = $grpName
		#"Group Owner" = $grpMngr
		"Group Members" = (@($grpMembers) | Out-String).Trim()
		
	})
	
 $grpReport += $grpInfo
 
 $grpReport | Export-CSV -NoTypeInformation -Path $outputPath

Write-Host "------------------------------------------------------------------------------" -Backgroundcolor Black -ForeGroundColor White
}

Write-Host "##############################################################################" -Backgroundcolor Black -ForeGroundColor White
Write-Host "------------------------------------------------------------------------------" -Backgroundcolor Black -ForeGroundColor White
Write-Host "##############################################################################" -Backgroundcolor Black -ForeGroundColor White

#Send message to group owner.
Send-MailMessage -From NoReply.UpdateUSIRESGroupMembershipReport@smtpdomain -To Targeted mail object -Cc Targeted mail object -Subject "Update USI RES Group Report $date" -Body "Hello,`n`n`The attached document contains the list of RES Groups which had their memberships updated that are used to access folders, shares or servers located in either MCM or MSUSA as well as includes the group membership. `n`nThe listed RES Groups can now also be found in Aveksa. `n`nA copy of this report is also stored here: \uncpath\Reports\ `n`nThank you" -Attachments $outputPath -Priority Normal -SMTPServer smtp-relay
Send-MailMessage -From NoReply.UpdateUSIRESGroupMembershipErrorReport@smtpdomain -To Targeted mail object -Cc Targeted mail object -Subject "Update USI RES Group Error Report $date" -Body "Hello,`n`n`The attached document contains the list of RES Groups which had their memberships updated that are used to access folders, shares or servers located in either MCM or MSUSA as well as includes the group membership errors. `n`nA copy of this report is also stored here: \uncpath\Reports\ `n`nThank you" -Attachments $errorOutputPath -Priority Normal -SMTPServer smtp-relay

Stop-Transcript