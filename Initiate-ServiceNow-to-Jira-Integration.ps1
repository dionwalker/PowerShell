#############################################
# Initiate ServiceNow to Jira Integration   #
# Created by Dion Walker                    #
# On 4/12/2023                              #
# Revision 1                                #
#############################################

$date=Get-Date -UFormat "%m-%d-%Y-%R"
Start-Transcript \\uncpath\Logs\Import-Snow-to-Jira-$date.txt

#current sprint
$epiclink = "epiclink"
$sprintstart = "epic start date"
$sprintend = "epic end date"
$sprintname = "sprint name"
$sprintid = "sprint ID"

#Get Squad IDs
$userQuery = "https://company.service-now.com/sys_user.do?JSONv2"
$snowUsers= invoke-restmethod -uri $userQuery -Method Get -ContentType "application/json" -Credential $cred

#Add switch/case for acquiring squad name
$groupsquad = @("team members")
for($n=0;$n -le $groupsquad.Count;$n++){New-Variable -Name "sam$n" -Value $squad[$n]; New-Variable -Name "snowID$n" -Value ($snowUsers.records | where {$_.user_name -like $squad[$n]} | select sys_id).sys_id}

#Squad Product Owner
$reporter = $samaccountname0
#---------------------------------------
$sprintfields = @{customfield_10100 = $sprintid}
# basic path settings
$scriptPath = split-path -parent $MyInvocation.MyCommand.Definition
set-location $scriptPath
Import-Module JiraPS

#load credentials
#$password = Get-Content "pw.txt" | ConvertTo-SecureString -Key (Get-Content "aes.key")
$cred = Get-Credential #New-Object System.Management.Automation.PsCredential("diwalker",$password)

Set-JiraConfigServer 'https://jira.company.com/'
New-JiraSession -Credential $cred

#query jira stories from epic
$jira_stories = Get-JiraIssue -Query "'Epic Link' = '$($epiclink)'"

#query snow team tickets
$query = "https://company.service-now.com/task_list.do?JSONv2&sysparm_query=assignment_group=d9e8bc436f0129004f75cf30be3ee47d^ORassignment_group=cd49f6376fc29d044f75cf30be3ee42b^ORassignment_group=1366e29fdb082c1050a1829a1396191b^ORassignment_group=0149f6376fc29d044f75cf30be3ee428^sys_updated_onBETWEENjavascript:gs.dateGenerate('$($sprintstart)','00:00:00')@javascript:gs.dateGenerate('$($sprintend)','23:59:59')"
$snowtickets = invoke-restmethod -uri $query -Method Get -ContentType "application/json" -Credential $cred

#loop through each snow ticket
foreach($ticket in $snowtickets.records){
    #ignore prjtask tickets
    if($ticket.number -notlike "*PRJTASK*"){
    
        #only sprint members
        for($n=0;$n -le $squad.Count;$n++){
            if((Get-Variable -Name "snowID$n" -ValueOnly) -eq $ticket.assigned_to){
                $userID=Get-Variable -Name "sam$n" -ValueOnly
            }

            #loop through jira tickets to find the duplicates/existing tickets
            $jiramatch = 0
            foreach($jira in $jira_stories){
                if($jira.Summary -like "*$($ticket.number)*"){
                    $jiramatch = 1

                    # Update Labels
                    if($jira.labels -notcontains "WinSNOW"){
                        write-host "   Updating Jira Issue Label on $($jira.key) ... " -ForegroundColor Cyan -NoNewline
                        Set-JiraIssueLabel $jira.key -Add "WinSNOW"
                        Set-JiraIssue -Issue $jira.key -Fields $sprintfields
                        write-host "Done" -ForegroundColor Green
                    }


                }
            }

            if($jiramatch -eq 1){
                # ticket already exists
                write-host $ticket.number -ForegroundColor Yellow

            } else {
                # new ticket
                write-host $ticket.number -ForegroundColor Green


                #build params

                $fields = @{
                    'customfield_10101' = "$($epiclink)"
                    'customfield_10200' = 1
                    'customfield_10301' = "$($ticket.number)"
                }

                $params = @{
                    project = 'INFENG'
                    IssueType = 'Story'
                    summary = "$($ticket.number) - $($ticket.short_description)"
                    description = "Ticket Created: $($ticket.opened_at)`r`nRequestor: $($ticket.sys_created_by)`r`n$($ticket.description)"
                    reporter = "$($reporter)"
                    Fields = $fields
                }

                $newjira = New-JiraIssue @params
                Set-JiraIssue $newjira.key -Assignee $userID
                Get-JiraIssue $newjira.key | Invoke-JiraIssueTransition -Transition 391
                Get-JiraIssue $newjira.key | Invoke-JiraIssueTransition -Transition 11

            }


            #close tickets already closed in snow
            if($ticket.closed_at -like "*:*"){
                foreach($jirasearch in $jira_stories){
                    if($jirasearch.Summary -like "*$($ticket.number)*"){
                       write-host "Transitioning $($jirasearch.key) to 'PO Acceptance'" -nonewline
                       try {
                        Get-JiraIssue $jirasearch.key | Invoke-JiraIssueTransition -Transition 351
                       } catch {
                        write-host ": FAILED. Ticket already transitioned or not in 'IN PROGRESS' state." -foregroundcolor red
                       }
                       
                    }
                }
            }


            # update notes in ticket
            $notesquery = "https://company.service-now.com/api/now/table/sys_journal_field?sysparm_query=element_id=$($ticket.sys_id)"
            $notes = invoke-restmethod -uri $notesquery -Method Get -ContentType "application/json" -Credential $cred
            $found_comment = 0
            foreach($note in $notes.result){

                foreach($jirasearch in $jira_stories){
                    if($jirasearch.Summary -like "*$($ticket.number)*"){
                        $jira = Get-JiraIssue  $jirasearch.key
                    }
                }

                foreach($msg in $jira.comment){
                    if($msg.body -like "*$($note.sys_id)*"){
                        $found_comment = 1
                    }
                }

                if($found_comment -eq 0){
                    write-host "   ADDING COMMENT: $($jira.key) --- $($note.sys_id)`r`n[$($note.sys_created_on)] - *$($note.sys_created_by)*`r`n$($note.value)"
                    Get-JiraIssue $($jira.key) | Set-JiraIssue -AddComment "^$($note.sys_id)^`r`n[$($note.sys_created_on)] - *$($note.sys_created_by)*`r`n$($note.value)"
                } else {
                    write-host "   COMMENT $($note.sys_id) ALREADY EXISTS $($jira.key)" -ForegroundColor green
                }
            }

        }
    }
}
#loop through each snow ticket
$user = $cred.Username
$pass = $cred.GetNetworkCredential().Password
$base64AuthInfo = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(("{0}:{1}" -f $user, $pass)))
$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
$headers.Add('Authorization',('Basic {0}' -f $base64AuthInfo))
$headers.Add('Accept','application/json')

foreach($ticket in $snowtickets.records){
    #ignore prjtask tickets
    if($ticket.number -notlike "*PRJTASK*"){
        for($n=0;$n -le $squad.Count;$n++){
            if((Get-Variable -Name "snowID$n" -ValueOnly) -eq $ticket.assigned_to){
        #if($ticket.assigned_to -like "$($snowid1)" -or $ticket.assigned_to -like "$($snowid2)" -or $ticket.assigned_to -like "$($snowid3)" -or $ticket.assigned_to -like "$($snowid4)"){ #-or $ticket.assigned_to -like "$($snowid5)"){
    
            foreach($jira in $jira_stories){
                if($jira.Summary -like "*$($ticket.number)*"){
                    $notesquery = "https://company.service-now.com/api/now/table/sys_journal_field?sysparm_query=element_id=$($ticket.sys_id)"
                    $notes = invoke-restmethod -uri $notesquery -Method Get -ContentType "application/json" -Credential $cred
                    
                    $found_note = 0
                    foreach($note in $notes.result){
                        if($note.value -like "*Reference Jira Ticket for Tracking*"){
                            $found_note = 1
                        }
                    }

                    if($found_note -eq 0){

                        if($ticket.closed_at -notlike "*:*"){
                            # add note to SNOW ticket
                            write-host "Reference Jira Ticket: $($ticket.number) needs updating"

$json = @"

{"work_notes":"Reference Jira Ticket for Tracking: [code]<a href='https://jira.company.com/browse/$($jira.key)' target='_blank'>https://jira.company.com/browse/$($jira.key)</a>[/code]"}

"@

                        
                            if($ticket.number -like "*INC*"){
                                $post_query = "https://company.service-now.com/api/now/table/incident/$($ticket.sys_id)"
                            }
                            if($ticket.number -like "*REQ*"){
                                $post_query = "https://company.service-now.com/api/now/table/sc_request/$($ticket.sys_id)"
                            }
                            if($ticket.number -like "*PTASK*"){
                                $post_query = "https://company.service-now.com/api/now/table/problem_task/$($ticket.sys_id)"
                            }
                            
                            $post_comment = Invoke-WebRequest -uri $post_query -Headers $headers -Method Patch -ContentType "application/json" -Body $json

                        
                        }

                    } else {
                        write-host "Reference Jira Ticket: $($ticket.number) already exists" -ForegroundColor Green
                    }



                }
            }

        }
    }

}

#loop through each snow ticket
$user = $cred.Username
$pass = $cred.GetNetworkCredential().Password
$base64AuthInfo = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(("{0}:{1}" -f $user, $pass)))
$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
$headers.Add('Authorization',('Basic {0}' -f $base64AuthInfo))
$headers.Add('Accept','application/json')

foreach($ticket in $snowtickets.records){
    #ignore prjtask tickets
    if($ticket.number -notlike "*PRJTASK*"){
        for($n=0;$n -le $squad.Count;$n++){
            if((Get-Variable -Name "snowID$n" -ValueOnly) -eq $ticket.assigned_to){
        #if($ticket.assigned_to -like "$($snowid1)" -or $ticket.assigned_to -like "$($snowid2)" -or $ticket.assigned_to -like "$($snowid3)" -or $ticket.assigned_to -like "$($snowid4)"){ #-or $ticket.assigned_to -like "$($snowid5)"){
    
            foreach($jira in $jira_stories){
                if($jira.Summary -like "*$($ticket.number)*"){
                    $notesquery = "https://company.service-now.com/api/now/table/sys_journal_field?sysparm_query=element_id=$($ticket.sys_id)"
                    $notes = invoke-restmethod -uri $notesquery -Method Get -ContentType "application/json" -Credential $cred
                    
                    $found_note = 0
                    foreach($note in $notes.result){
                        if($note.value -like "*Reference Jira Ticket for Tracking*"){
                            $found_note = 1
                        }
                    }

                    if($found_note -eq 0){

                        if($ticket.closed_at -notlike "*:*"){
                            # add note to SNOW ticket
                            write-host "$($ticket.number) needs updating"

$json = @"

{"work_notes":"Reference Jira Ticket for Tracking: [code]<a href='https://jira.company.com/browse/$($jira.key)' target='_blank'>https://jira.company.com/browse/$($jira.key)</a>[/code]"}

"@

                        
                            if($ticket.number -like "*INC*"){
                                $post_query = "https://company.service-now.com/api/now/table/incident/$($ticket.sys_id)"
                            }
                            if($ticket.number -like "*REQ*"){
                                $post_query = "https://company.service-now.com/api/now/table/sc_request/$($ticket.sys_id)"
                            }
                            if($ticket.number -like "*PTASK*"){
                                $post_query = "https://company.service-now.com/api/now/table/problem_task/$($ticket.sys_id)"
                            }
                            
                            $post_comment = Invoke-WebRequest -uri $post_query -Headers $headers -Method Patch -ContentType "application/json" -Body $json

                        
                        }

                    } else {
                        write-host "$($ticket.number) already exists" -ForegroundColor Green
                    }



                }
            }

        }
    }

}

Stop-Transcript
