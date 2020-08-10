param(
    [Parameter(Mandatory=$false)]
    [switch]$EditMode
)

Function Write-log ($txt)
{
    $txt | Out-File $ScriptRoot\Dbg.txt -Append
}

Function Set-FileFolderAudit ($TargetFolder)
{
    $AuditUser = "Everyone"
    $AuditRules = "DeleteSubdirectoriesAndFiles, Modify, ChangePermissions, TakeOwnership"
    $InheritType = "ContainerInherit, ObjectInherit"
    $AuditType = [System.Security.AccessControl.AuditFlags]::Success
    $AccessRule = New-Object System.Security.AccessControl.FileSystemAuditRule($AuditUser,$AuditRules,$InheritType,"None",$AuditType)

    $ACL = Get-Acl $TargetFolder
    $ACL.SetAuditRule($AccessRule)
    $ACL | Set-Acl $TargetFolder
}

Function Start-FileSystemWatcher {
    [cmdletbinding()]
    Param (
        [parameter()]
        [string]$Path,
        [parameter()]
        [ValidateSet('Changed', 'Created', 'Deleted', 'Renamed')]
        [string[]]$EventName,
        [parameter()]
        [string]$Filter,
        [parameter()]
        [System.IO.NotifyFilters]$NotifyFilter,
        [parameter()]
        [switch]$Recurse,
        [parameter()]
        [scriptblock]$Action
    )

    #region Build  FileSystemWatcher
    $FileSystemWatcher = New-Object  System.IO.FileSystemWatcher
    If (-NOT $PSBoundParameters.ContainsKey('Path')) {
        $Path = $PWD
    }

    $FileSystemWatcher.Path = $Path
    If ($PSBoundParameters.ContainsKey('Filter')) {
        $FileSystemWatcher.Filter = $Filter
    }

    If ($PSBoundParameters.ContainsKey('NotifyFilter')) {
        $FileSystemWatcher.NotifyFilter = $NotifyFilter
    }

    If ($PSBoundParameters.ContainsKey('Recurse')) {
        $FileSystemWatcher.IncludeSubdirectories = $True
    }

    If (-NOT $PSBoundParameters.ContainsKey('EventName')) {
        $EventName = 'Changed', 'Created', 'Deleted', 'Renamed'
    }

    If (-NOT $PSBoundParameters.ContainsKey('Action')) {
        $Action = {
            Try
            {
                Function Write-log ($txt)
                {
                    $txt | Out-File $ScriptRoot\Dbg.txt -Append
                }

                Function Get-ItemSize ($ItemPath)
                {
                    try
                    {
                        $ItemObj = Get-Item -Path $ItemPath
                        if ($ItemObj -is [System.IO.FileInfo])
                        {
                            $Size = "$([math]::Round($(($itemObj.Length)/1KB),3)) KB"
                            $ItemInfo = "File"
                        }
                        else
                        {
                            $Size = "-na-"
                            $ItemInfo = "Directory"
                        }
                    }
                    catch
                    {
                        $Size = "-error-"
                        $ItemInfo = "-error-"
                    }
                    $obj = [PSCustomObject]@{
                        Size = $Size
                        ItemInfo = $ItemInfo
                    }

                    Return $obj
                }
            
                $ChangeType = $Event.SourceEventArgs.ChangeType
                $Obj = '' | Select-Object DateTime, User, ChangeType, ItemInfo, FullPath, OldPath, Size

                Switch ($ChangeType) {
                    'Renamed' {
                        $Oldpath = $Event.SourceArgs[-1].OldFullPath
                        $fullpath = $Event.SourceArgs[-1].FullPath
                        $ItemInfoObj = Get-ItemSize -ItemPath $fullpath
                        break;
                    }

                    Default {
                        $fullpath = $Event.SourceEventArgs.FullPath
                        if ($ChangeType -ne 'Deleted')
                        {
                            $ItemInfoObj = Get-ItemSize -ItemPath $fullpath
                        }
                    }
                }


                #Decode username from audit logs
                try
                {
                    [datetime]$TimeGenerated = $Event.TimeGenerated
                    $To = ($TimeGenerated.AddMilliseconds(1000)).ToUniversalTime().ToString("s") + ".999Z"
                    $From = ($TimeGenerated.AddMilliseconds(-500)).ToUniversalTime().ToString("s") + ".000Z"
                    $AuditEvent = $null
                    do
                    {
                        try
                        {
                            $query = @"
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">*[System[Provider[@Name='Microsoft-Windows-Security-Auditing'] and ( Task = 12800 or Task = 12812 ) and TimeCreated[@SystemTime&gt;="$From" and @SystemTime&lt;="$To"]]]</Select>
  </Query>
</QueryList>
"@
                            $AuditEvent = Get-WinEvent -FilterXml $query
                        }
                        catch
                        {
                            Write-log "ERROR: $($_.Exception.Message) at location: $($_.ScriptStackTrace)"
                        }
                    }
                    while($AuditEvent -eq $null)

                    $C=0
                    do
                    {
                        $logArr = @($AuditEvent.Where({$_.Properties[6].Value -eq $fullpath}))
                        if ($logArr)
                        {
                            $log = $logArr[0]
                            $User = "$($log.Properties[1].value)"
                        }
                        else
                        {
                            $C++
                            if ($c -gt 50)
                            {
                                Write-log "Unable to find log"
                                $user = "-UNKNOWN-"
                                Start-Sleep -Milliseconds 50
                                break;
                            }
                        }
                    }
                    while(-not $logArr)
                }
                catch
                {
                    Write-log "$($_.Exception.Message) + $($_.ScriptStackTrace)"
                }

                $TimeGen = $TimeGenerated.ToString("dd-MM-yyyy HH:mm:ss")
                Switch ($ChangeType) {
                    'Renamed' {
                        $Obj.DateTime = $TimeGen
                        $Obj.User = $User
                        $Obj.ItemInfo = $($ItemInfoObj.ItemInfo)
                        $Obj.ChangeType = $ChangeType
                        $obj.FullPath = $fullpath
                        $Obj.OldPath = $Oldpath
                        $Obj.Size = $($ItemInfoObj.Size)
                    
                        $Object = "{0} was  {1} to {2} at {3} by {4}" -f $Oldpath,
                        $ChangeType,
                        $fullpath,
                        $TimeGen,
                        $user
                        break;
                    }

                    Default {
                        $Obj.DateTime = $TimeGen
                        $Obj.User = $User
                        $Obj.ItemInfo = $($ItemInfoObj.ItemInfo)
                        $Obj.ChangeType = $ChangeType
                        $obj.FullPath = $fullpath
                        $Obj.OldPath = "-na-"
                        $Obj.Size = $($ItemInfoObj.Size)
                        $Object = "{0} was  {1} at {2} by {3}" -f $fullpath,
                        $ChangeType,
                        $TimeGen,
                        $user
                    }
                }

                $WriteHostParams = @{
                    ForegroundColor = 'Green'
                    BackgroundColor = 'Black'
                    Object          = $Object
                }
                Write-Host  @WriteHostParams

                $Obj | Export-Csv -Path $ScriptRoot\FileSystemWatcherLog.csv -NoTypeInformation -Append -Encoding ASCII -UseCulture
            }
            catch
            {
                Write-log "[ERROR] $($_.Exception.Message)"
            }
        }
    }
    #endregion  Build FileSystemWatcher
    #region  Initiate Jobs for FileSystemWatcher

    $ObjectEventParams = @{
        InputObject = $FileSystemWatcher
        Action      = $Action
    }

    $File = $Path.Replace(":", "").Replace("\", "").Replace(" ","")

    ForEach ($Item in  $EventName) {
        $ObjectEventParams.EventName = $Item
        $ObjectEventParams.SourceIdentifier = "$File.$($Item)"
        Write-Verbose  "Starting watcher for Event: $($Item)"
        $Null = Register-ObjectEvent  @ObjectEventParams
    }
    #endregion  Initiate Jobs for FileSystemWatcher
}

$ScriptRoot = $PSScriptRoot

if ($EditMode)
{
    #Register scheduled task
    $ScriptName = $MyInvocation.MyCommand.Source
    $str = @"
-NoExit -NoProfile -File "$ScriptName"
"@
    $RunAsAdmin = New-ScheduledJobOption -RunElevated
    $task_action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $str
    $task_settings = New-ScheduledTaskSettingsSet -RestartCount 20 -RestartInterval (New-TimeSpan -Minutes 1) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -DontStopOnIdleEnd -MultipleInstances IgnoreNew -IdleDuration 0 -IdleWaitTimeout 0 -StartWhenAvailable -RestartOnIdle -ExecutionTimeLimit (New-TimeSpan -Seconds 0)
    $class = cimclass MSFT_TaskRepetitionPattern Root/Microsoft/Windows/TaskScheduler
    $rep = $class | New-CimInstance -ClientOnly
    $rep.Duration = "P1D"
    $rep.Interval = "PT1M"
    $rep.StopAtDurationEnd = $false
    $task_trigger = New-ScheduledTaskTrigger -Daily -At 8:00am
    $task_trigger.Repetition = $rep
    $schJob = Register-ScheduledTask "PSFileSystemWatcher" -Action $task_action -User "System" -Settings $task_settings -Trigger $task_trigger -Force -RunLevel Highest
    Write-Host "Scheduled Backup Job Created"
    $schJob | Start-ScheduledTask
    Write-Host "Started $($schJob.TaskName)"

    #enable eventlogs for taskscheduler if not already enabled
    $curr = wevtutil get-log Microsoft-Windows-TaskScheduler/Operational
    if ($curr[1] -match $false)
    {
        Write-Host "Enabling Taskscheduler Logs"
        $ts = wevtutil sl Microsoft-Windows-TaskScheduler/Operational /e:true
        $curr = wevtutil get-log Microsoft-Windows-TaskScheduler/Operational
        if ($curr[1] -match $true)
        {
            Write-Host "..Enabled"
        }
        else
        {
            Write-Host "..Failed to enable Taskscheduler logs"
            Write-Host "Enable TaskScheduler logs manually from TaskScheduler"
        }
    }
}
else
{
    #Enable Auditing of Object access
    auditpol /set /category:"Object Access" /Success:enable

    #Set the directories to audit and tell the FSW to monitor
    $DirectoriesToMonitor = Import-Csv "$ScriptRoot\DirectoriesToMonitor.csv" -UseCulture
    foreach ($Line in $DirectoriesToMonitor)
    {
        $Dir = ($Line.Directory).trim()
        if ($Dir)
        {
            if (Test-Path $Dir)
            {
                Set-FileFolderAudit -TargetFolder $Dir
                Start-FileSystemWatcher -Path $Dir -EventName Changed, Created, Deleted, Renamed -Recurse
            }
        }
    }
}