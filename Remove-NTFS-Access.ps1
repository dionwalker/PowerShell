#############################
# Remove NTFS Access		#
# Created by Dion Walker	#
# On 9/10/2021				#
# Revision 1				#
#############################

$date= Get-Date -UFormat "%m-%d-%Y"

Start-Transcript -Append -Path uncpath\Logs\Remove-NTFS-Access-$date.txt

$ntfsReport= @()

$outputPath= "uncpath\Reports\Remove-NTFS-Access-Report-$date.csv"

$dirs= Import-CSV -Path "uncpath\SourceFiles\Remove-NTFS-Access-$date.csv"

$names= @()

$childNames= @()

foreach($dir in $dirs){
	
	$root=$dir.UNCPath
	
	#Check to make sure the folder path exists
	if((Test-Path $root) -eq $true){
		
		
		#Get the level 1 names
		Write-Host "Acquiring Level 1 Folder Info."
		$names=Get-ChildItem -Path $root -Directory | select -ExpandProperty Name
		
		#Iterate through each folder
		foreach ($name in $names){
	
			$level1=$root+"\"+$name
							
			#################################
			# Fix ACLs for Level 2+	Objects	#
			#################################
			
			#Get the level 2 names
			Write-Host "Acquiring Level 2 Folder Info from $level1."
			$childNames=Get-ChildItem -Path $level1 -Directory
			
			foreach($childName in $childNames.Name){
		
				$level2=$level1+"\"+$childName
				
				#Backing up the ACLs for the level 2 folder.
				Write-Host "------------------------------------------------------------------------------" -Backgroundcolor Black -ForeGroundColor Red
				Write-Host "Backing up ACLs for $level2" -Backgroundcolor Black -ForeGroundColor Green
				$legacyinheritance2=Get-Item $level2 | Get-NTFSInheritance | select -ExpandProperty AccessInheritanceEnabled
				$legacyaccounts2=Get-NTFSAccess $level2 | select -ExpandProperty Account | select -ExpandProperty AccountName | Out-String
				$legacyACE2=Get-NTFSAccess $level2 | select -ExpandProperty AccessRights | Out-String
				$legacyaceType2=Get-NTFSAccess $level2 | select -ExpandProperty AccessControlType | Out-String
				
				#Enforce Domain Admins and Public User ACLs
				Write-Host "------------------------------------------------------------------------------" -Backgroundcolor Black -ForeGroundColor Red
				Write-Host "Adding ACLs on the level 2 folder." -Backgroundcolor Black -ForeGroundColor Green
				icacls $level2 --% /grant:r "Domain Admins":F /T /C /Q
				icacls $level2 --% /deny PUBLIC_USERS:F /T /C /Q
				$acl2=Get-Acl $level2
				
				#Force inheritance for level 2+ directories
				Write-Host "------------------------------------------------------------------------------" -Backgroundcolor Black -ForeGroundColor Red
				Write-Host "Pushing ACLs to all level 2+ objects." -Backgroundcolor Black -ForeGroundColor Green
				icacls $level2 /inheritance:e /T /C
								
				#Disable Inheritance on the level 2 directory
				Write-Host "------------------------------------------------------------------------------" -Backgroundcolor Black -ForeGroundColor Red
				Write-Host "Disabling inheritance on $level2" -Backgroundcolor Black -ForeGroundColor Green
				icacls $level2 /inheritance:d
				
				#Enforce Domain Admins and Public User ACLs
				Write-Host "------------------------------------------------------------------------------" -Backgroundcolor Black -ForeGroundColor Red
				Write-Host "Fixing ACLs on the level 2 folder." -Backgroundcolor Black -ForeGroundColor Green
				Set-Acl $level2 $acl2
				
				#Remove Open Access and Root level RES groups ACLs
				Write-Host "------------------------------------------------------------------------------" -Backgroundcolor Black -ForeGroundColor Red
				Write-Host "Removing ACLs from the $level2" -Backgroundcolor Black -ForeGroundColor Green
				icacls $level2 /remove "BUILTIN\Users" /T /C
				icacls $level2 /remove "Read-Only" /T /C
				icacls $level2 /remove "Read-Write" /T /C
				
				#Acquire ACLs for level 2 folder.
				Write-Host "------------------------------------------------------------------------------" -Backgroundcolor Black -ForeGroundColor Red
				Write-Host "Acquiring ACLs for $level2" -Backgroundcolor Black -ForeGroundColor Green
				$inheritance2=Get-Item $level2 | Get-NTFSInheritance | select -ExpandProperty AccessInheritanceEnabled
				$accounts2=Get-NTFSAccess $level2 | select -ExpandProperty Account | select -ExpandProperty AccountName | Out-String	
				$ACE2=Get-NTFSAccess $level2 | select -ExpandProperty AccessRights | Out-String
				$aceType2=Get-NTFSAccess $level2 | select -ExpandProperty AccessControlType | Out-String
				
				$aclInfo = New-Object PSObject -Property ([ordered]@{

					"Folder Name" = $level2
					"Folder Depth"="2"
					"Legacy Folder Inheritance"=$legacyinheritance2
					"Legacy ACE Membership"=($legacyaccounts2).Trim()
					"Legacy ACE Permissions"=($legacyACE2).Trim()
					"Legacy ACE Type"=($legacyaceType2).Trim()
					"Folder Inheritance Enabled" = $inheritance2
					"Folder ACE Membership" = ($accounts2).Trim()
					"Folder ACE Permissions"= ($ACE2).Trim()
					"Folder ACE Type"=($aceType2).Trim()
				})
				
				$ntfsReport += $aclInfo
		 
				$ntfsReport | Export-CSV -NoTypeInformation -Path $outputPath
				
			}
		
		
			#################################
			# Fix ACLs for Level 1 Objects	#
			#################################
			
			#Backing up the ACLs for the level 1 folder.
			Write-Host "------------------------------------------------------------------------------" -Backgroundcolor Black -ForeGroundColor Red
			Write-Host "Backing up ACLs for $level1" -Backgroundcolor Black -ForeGroundColor Green
			$legacyinheritance1=Get-Item $level1 | Get-NTFSInheritance | select -ExpandProperty AccessInheritanceEnabled
			$legacyaccounts1=Get-NTFSAccess $level1 | select -ExpandProperty Account | select -ExpandProperty AccountName | Out-String
			$legacyACE1=Get-NTFSAccess $level1 | select -ExpandProperty AccessRights | Out-String
			$legacyaceType1=Get-NTFSAccess $level1 | select -ExpandProperty AccessControlType | Out-String
			
			#Enforce Domain Admins and Public User ACLs
			Write-Host "------------------------------------------------------------------------------" -Backgroundcolor Black -ForeGroundColor Red
			Write-Host "Adding ACLs on the level 1 folder." -Backgroundcolor Black -ForeGroundColor Green
			icacls $level1 --% /grant "Domain Admins":F /T /C /Q
			icacls $level1 --% /deny PUBLIC_USERS:F /T /C /Q
			$acl1=Get-Acl $level1
			
			#Disable Inheritance on the level 1 directory
			Write-Host "------------------------------------------------------------------------------" -Backgroundcolor Black -ForeGroundColor Red
			Write-Host "Disabling inheritance on $level1" -Backgroundcolor Black -ForeGroundColor Green
			icacls $level1 /inheritance:d
			
			#Enforce Domain Admins and Public User ACLs
			Write-Host "------------------------------------------------------------------------------" -Backgroundcolor Black -ForeGroundColor Red
			Write-Host "Fixing ACLs on the level 1 folder." -Backgroundcolor Black -ForeGroundColor Green
			Set-Acl $level1 $acl1
			
			#Remove Open Access and Root level RES groups ACLs
			Write-Host "------------------------------------------------------------------------------" -Backgroundcolor Black -ForeGroundColor Red
			Write-Host "Removing ACLs from the $level1" -Backgroundcolor Black -ForeGroundColor Green
			icacls $level1 /remove "BUILTIN\Users" /T /C
			icacls $level1 /remove "Read-Only" /T /C
			icacls $level1 /remove "Read-Write" /T /C
			
			#Acquire ACLs for level 1 folder.
			Write-Host "------------------------------------------------------------------------------" -Backgroundcolor Black -ForeGroundColor Red
			Write-Host "Acquiring ACLs for $level1" -Backgroundcolor Black -ForeGroundColor Green
			$inheritance1=Get-Item $level1 | Get-NTFSInheritance | select -ExpandProperty AccessInheritanceEnabled
			$accounts1=Get-NTFSAccess $level1 | select -ExpandProperty Account | select -ExpandProperty AccountName | Out-String	
			$ACE1=Get-NTFSAccess $level1 | select -ExpandProperty AccessRights | Out-String
			$aceType1=Get-NTFSAccess $level1 | select -ExpandProperty AccessControlType | Out-String
			
			$aclInfo = New-Object PSObject -Property ([ordered]@{

				"Folder Name" = $level1
				"Folder Depth"="1"
				"Legacy Folder Inheritance"=$legacyinheritance1
				"Legacy ACE Membership"=($legacyaccounts1).Trim()
				"Legacy ACE Permissions"=($legacyACE1).Trim()
				"Legacy ACE Type"=($legacyaceType1).Trim()
				"Folder Inheritance Enabled" = $inheritance1
				"Folder ACE Membership" = ($accounts1).Trim()
				"Folder ACE Permissions"= ($ACE1).Trim()
				"Folder ACE Type"=($aceType1).Trim()
			})
			
			$ntfsReport += $aclInfo
		 
			$ntfsReport | Export-CSV -NoTypeInformation -Path $outputPath
			
		}
		
		#####################################
		# Fix ACLs for Root Level Object	#
		#####################################
		
		#Backing up the ACLs for the root level share.
		Write-Host "------------------------------------------------------------------------------" -Backgroundcolor Black -ForeGroundColor Red
		Write-Host "Backing up ACLs for $root" -Backgroundcolor Black -ForeGroundColor Green
		$legacyinheritance=Get-Item $root | Get-NTFSInheritance | select -ExpandProperty AccessInheritanceEnabled
		$legacyaccounts=Get-NTFSAccess $root | select -ExpandProperty Account | select -ExpandProperty AccountName | Out-String
		$legacyACE=Get-NTFSAccess $root | select -ExpandProperty AccessRights | Out-String
		$legacyaceType=Get-NTFSAccess $root | select -ExpandProperty AccessControlType | Out-String
		
		#Remove Open Access and Root level RES groups ACLs
		Write-Host "------------------------------------------------------------------------------" -Backgroundcolor Black -ForeGroundColor Red
		Write-Host "Removing ACLs from the $root" -Backgroundcolor Black -ForeGroundColor Green
		icacls $root /remove "BUILTIN\Users" /T /C
		
		#Acquire ACLs for level 1 folder.
		Write-Host "------------------------------------------------------------------------------" -Backgroundcolor Black -ForeGroundColor Red
		Write-Host "Acquiring ACLs for $root" -Backgroundcolor Black -ForeGroundColor Green
		$inheritance=Get-Item $root | Get-NTFSInheritance | select -ExpandProperty AccessInheritanceEnabled
		$accounts=Get-NTFSAccess $root | select -ExpandProperty Account | select -ExpandProperty AccountName | Out-String	
		$ACE=Get-NTFSAccess $root | select -ExpandProperty AccessRights | Out-String
		$aceType=Get-NTFSAccess $root | select -ExpandProperty AccessControlType | Out-String
		
		$aclInfo = New-Object PSObject -Property ([ordered]@{

			"Folder Name" = $root
			"Folder Depth"="0"
			"Legacy Folder Inheritance Enabled" = $legacyinheritance
			"Legacy Folder ACE Membership" = ($legacyaccounts).Trim()
			"Legacy Folder ACE Permissions"= ($legacyACE).Trim()
			"Legacy Folder ACE Type"=($legacyaceType).Trim()
			"Folder Inheritance Enabled" = $inheritance
			"Folder ACE Membership" = ($accounts).Trim()
			"Folder ACE Permissions"= ($ACE).Trim()
			"Folder ACE Type"=($aceType).Trim()
		})
		
		$ntfsReport += $aclInfo
	 
		$ntfsReport | Export-CSV -NoTypeInformation -Path $outputPath
		
	}

}

Send-MailMessage -From NoReply.RemoveNTFSAccessReport@smtpdomain -To targeted mail objects -Subject "Remove NTFS Access Report $date" -Body "Hello,`n`n`The attached document contains the list of folders or shares which had specific NTFS permissions revoked.`n`nThe listed RES groups retain access and can be found in Aveksa for entiltement. `n`nA copy of this report is also stored here: uncpath\Reports\ `n`nThank you" -Attachments $outputPath -Priority Normal -SMTPServer smtp-relay

Stop-Transcript
