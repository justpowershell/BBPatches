param($list)

clear
$patchorionmonitored=$false

$servers = @(gc $list)

$scriptfull = $PSCommandPath
$scriptpath = $PSScriptRoot
$scriptname = Split-Path -Path $scriptfull -Leaf
$scriptbase = (gci $scriptfull).BaseName
$LogFileName = "${scriptbase}.log"
$LogFilePathName = Join-Path $scriptpath $LogFileName
$LogFileName = "${scriptbase}.log"
$LogFilePathName = Join-Path $scriptpath $LogFileName

function Write-Log{
    param ($Msg, [int]$MsgType, $ForegroundColor="Gray")
    $LogDetail = (Get-Date).ToString()
    switch ($MsgType){
        1 {$LogDetail += " – .INFORMATION : " + $Msg} # Information
        2 {$LogDetail += " – @ERROR : " + $Msg} # Error
        3 {$LogDetail += " – +WARNING : " + $Msg} # Warning reserved
        Default {$LogDetail += " – .INFORMATION : " + $Msg}
    }
    Write-Host $LogDetail -ForegroundColor $ForegroundColor
    $LogDetail | Out-File -FilePath $LogFilePathName -Append
}
function Check-ToolsStatus($vm){
   try {
        $vmview = get-VM $vm -erroraction SilentlyContinue | where {$_.Powerstate -eq "PoweredOn"} | Get-View
        $status = $vmview.Guest.ToolsStatus
 
        if ($status -match "toolsOld"){
            $vmTools = "Old"}
        elseif($status -match "toolsNotRunning"){
            $vmTools = "NotRunning"}
        elseif($status -match "toolsNotInstalled"){
            $vmTools = "NotInstalled"}
        elseif($status -match "toolsOK"){
            $vmTools = "OK"}
        else{
            $vmTools = "ERROR"
	        # Read-Host "The ToolsStatus of $vm is $vmTools. Press <CTRL>+C to quit the script or press <ENTER> to continue"
	    }
    } catch {
        $vmTools = "ERROR"
    }
   return $vmTools
}
function CheckAndUpgradeTools($vm){
 
   try {
       $vmview = Get-VM $VM -erroraction SilentlyContinue | where {$_.Powerstate -eq "PoweredOn"} | Get-View
       $family = $vmview.Guest.GuestFamily
       $vmToolsStatus = Check-ToolsStatus $vm
 
       if($vmToolsStatus -eq "OK"){
          Write-Log "The VM tools are $vmToolsStatus on $vm" 
       }elseif(($family -eq "windowsGuest") -and ($vmToolsStatus -ne "NotInstalled")){
          Write-Log "The VM tools are $vmToolsStatus on $vm. Starting update/install now! This will take at few minutes." -ForegroundColor Yellow
	      Get-VMGuest $vm | where {$_.state -eq "Running"} | Update-Tools -NoReboot
	      do{
	          sleep 10
	          Write-Log "Checking ToolsStatus $vm now"
	          $vmToolsStatus = Check-ToolsStatus $vm
	      }until($vmToolsStatus -eq "OK") 
       }else{
          # ToDo: If the guest is running windows but tools notrunning/notinstalled it might be an option to invoke the installation through powershell.
	      # Options are then InvokexScript cmdlet or through windows installer: msiexec-i "D: \ VMware Tools64.msi" ADDLOCAL = ALL REMOVE = Audio, Hgfs, VMXNet, WYSE, GuestSDK, VICFSDK, VAssertSDK / qn 
	      # We're skipping all non-windows guest since automated installs are not supported
	      Write-Log "$vm is a $family with tools status $vmToolsStatus. Therefore we're skipping this VM" -MsgType 2 -ForegroundColor Red
       }
    } catch {
        Write-Log "Couldn't find $vm on vCenter server. Therefore we're skipping this VM" -MsgType 2 -ForegroundColor Red
    }
}
function Get-PendingReboot{
<#
.SYNOPSIS
    Gets the pending reboot status on a local or remote computer.

.DESCRIPTION
    This function will query the registry on a local or remote computer and determine if the
    system is pending a reboot, from Microsoft updates, Configuration Manager Client SDK, Pending Computer 
    Rename, Domain Join or Pending File Rename Operations. For Windows 2008+ the function will query the 
    CBS registry key as another factor in determining pending reboot state.  "PendingFileRenameOperations" 
    and "Auto Update\RebootRequired" are observed as being consistant across Windows Server 2003 & 2008.
	
    CBServicing = Component Based Servicing (Windows 2008+)
    WindowsUpdate = Windows Update / Auto Update (Windows 2003+)
    CCMClientSDK = SCCM 2012 Clients only (DetermineIfRebootPending method) otherwise $null value
    PendComputerRename = Detects either a computer rename or domain join operation (Windows 2003+)
    PendFileRename = PendingFileRenameOperations (Windows 2003+)
    PendFileRenVal = PendingFilerenameOperations registry value; used to filter if need be, some Anti-
                     Virus leverage this key for def/dat removal, giving a false positive PendingReboot

.PARAMETER ComputerName
    A single Computer or an array of computer names.  The default is localhost ($env:COMPUTERNAME).

.PARAMETER ErrorLog
    A single path to send error data to a log file.

.EXAMPLE
    PS C:\> Get-PendingReboot -ComputerName (Get-Content C:\ServerList.txt) | Format-Table -AutoSize
	
    Computer CBServicing WindowsUpdate CCMClientSDK PendFileRename PendFileRenVal RebootPending
    -------- ----------- ------------- ------------ -------------- -------------- -------------
    DC01           False         False                       False                        False
    DC02           False         False                       False                        False
    FS01           False         False                       False                        False

    This example will capture the contents of C:\ServerList.txt and query the pending reboot
    information from the systems contained in the file and display the output in a table. The
    null values are by design, since these systems do not have the SCCM 2012 client installed,
    nor was the PendingFileRenameOperations value populated.

.EXAMPLE
    PS C:\> Get-PendingReboot
	
    Computer           : WKS01
    CBServicing        : False
    WindowsUpdate      : True
    CCMClient          : False
    PendComputerRename : False
    PendFileRename     : False
    PendFileRenVal     : 
    RebootPending      : True
	
    This example will query the local machine for pending reboot information.
	
.EXAMPLE
    PS C:\> $Servers = Get-Content C:\Servers.txt
    PS C:\> Get-PendingReboot -Computer $Servers | Export-Csv C:\PendingRebootReport.csv -NoTypeInformation
	
    This example will create a report that contains pending reboot information.

.LINK
    Component-Based Servicing:
    http://technet.microsoft.com/en-us/library/cc756291(v=WS.10).aspx
	
    PendingFileRename/Auto Update:
    http://support.microsoft.com/kb/2723674
    http://technet.microsoft.com/en-us/library/cc960241.aspx
    http://blogs.msdn.com/b/hansr/archive/2006/02/17/patchreboot.aspx

    SCCM 2012/CCM_ClientSDK:
    http://msdn.microsoft.com/en-us/library/jj902723.aspx

.NOTES
    Author:  Brian Wilhite
    Email:   bcwilhite (at) live.com
    Date:    29AUG2012
    PSVer:   2.0/3.0/4.0/5.0
    Updated: 27JUL2015
    UpdNote: Added Domain Join detection to PendComputerRename, does not detect Workgroup Join/Change
             Fixed Bug where a computer rename was not detected in 2008 R2 and above if a domain join occurred at the same time.
             Fixed Bug where the CBServicing wasn't detected on Windows 10 and/or Windows Server Technical Preview (2016)
             Added CCMClient property - Used with SCCM 2012 Clients only
             Added ValueFromPipelineByPropertyName=$true to the ComputerName Parameter
             Removed $Data variable from the PSObject - it is not needed
             Bug with the way CCMClientSDK returned null value if it was false
             Removed unneeded variables
             Added PendFileRenVal - Contents of the PendingFileRenameOperations Reg Entry
             Removed .Net Registry connection, replaced with WMI StdRegProv
             Added ComputerPendingRename
#>

[CmdletBinding()]
param(
	[Parameter(Position=0,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
	[Alias("CN","Computer")]
	[String[]]$ComputerName="$env:COMPUTERNAME",
	[String]$ErrorLog
	)

Begin {  }## End Begin Script Block
Process {
  Foreach ($Computer in $ComputerName) {
	Try {
	    ## Setting pending values to false to cut down on the number of else statements
	    $CompPendRen,$PendFileRename,$Pending,$SCCM = $false,$false,$false,$false
                        
	    ## Setting CBSRebootPend to null since not all versions of Windows has this value
	    $CBSRebootPend = $null
						
	    ## Querying WMI for build version
	    $WMI_OS = Get-WmiObject -Class Win32_OperatingSystem -Property BuildNumber, CSName -ComputerName $Computer -ErrorAction Stop

	    ## Making registry connection to the local/remote computer
	    $HKLM = [UInt32] "0x80000002"
	    $WMI_Reg = [WMIClass] "\\$Computer\root\default:StdRegProv"
						
	    ## If Vista/2008 & Above query the CBS Reg Key
	    If ([Int32]$WMI_OS.BuildNumber -ge 6001) {
		    $RegSubKeysCBS = $WMI_Reg.EnumKey($HKLM,"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\")
		    $CBSRebootPend = $RegSubKeysCBS.sNames -contains "RebootPending"		
	    }
							
	    ## Query WUAU from the registry
	    $RegWUAURebootReq = $WMI_Reg.EnumKey($HKLM,"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\")
	    $WUAURebootReq = $RegWUAURebootReq.sNames -contains "RebootRequired"
						
	    ## Query PendingFileRenameOperations from the registry
	    $RegSubKeySM = $WMI_Reg.GetMultiStringValue($HKLM,"SYSTEM\CurrentControlSet\Control\Session Manager\","PendingFileRenameOperations")
	    $RegValuePFRO = $RegSubKeySM.sValue

	    ## Query JoinDomain key from the registry - These keys are present if pending a reboot from a domain join operation
	    $Netlogon = $WMI_Reg.EnumKey($HKLM,"SYSTEM\CurrentControlSet\Services\Netlogon").sNames
	    $PendDomJoin = ($Netlogon -contains 'JoinDomain') -or ($Netlogon -contains 'AvoidSpnSet')

	    ## Query ComputerName and ActiveComputerName from the registry
	    $ActCompNm = $WMI_Reg.GetStringValue($HKLM,"SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName\","ComputerName")            
	    $CompNm = $WMI_Reg.GetStringValue($HKLM,"SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName\","ComputerName")

	    If (($ActCompNm -ne $CompNm) -or $PendDomJoin) {
	        $CompPendRen = $true
	    }
						
	    ## If PendingFileRenameOperations has a value set $RegValuePFRO variable to $true
	    If ($RegValuePFRO) {
		    $PendFileRename = $true
	    }

	    ## Determine SCCM 2012 Client Reboot Pending Status
	    ## To avoid nested 'if' statements and unneeded WMI calls to determine if the CCM_ClientUtilities class exist, setting EA = 0
	    $CCMClientSDK = $null
	    $CCMSplat = @{
	        NameSpace='ROOT\ccm\ClientSDK'
	        Class='CCM_ClientUtilities'
	        Name='DetermineIfRebootPending'
	        ComputerName=$Computer
	        ErrorAction='Stop'
	    }
	    ## Try CCMClientSDK
	    Try {
	        $CCMClientSDK = Invoke-WmiMethod @CCMSplat
	    } Catch [System.UnauthorizedAccessException] {
	        $CcmStatus = Get-Service -Name CcmExec -ComputerName $Computer -ErrorAction SilentlyContinue
	        If ($CcmStatus.Status -ne 'Running') {
	            Write-Warning "$Computer`: Error - CcmExec service is not running."
	            $CCMClientSDK = $null
	        }
	    } Catch {
	        $CCMClientSDK = $null
	    }

	    If ($CCMClientSDK) {
	        If ($CCMClientSDK.ReturnValue -ne 0) {
		        Write-Warning "Error: DetermineIfRebootPending returned error code $($CCMClientSDK.ReturnValue)"          
		    }
		    If ($CCMClientSDK.IsHardRebootPending -or $CCMClientSDK.RebootPending) {
		        $SCCM = $true
		    }
	    }
            
	    Else {
	        $SCCM = $null
	    }

	    ## Creating Custom PSObject and Select-Object Splat
	    $SelectSplat = @{
	        Property=(
	            'Computer',
	            'CBServicing',
	            'WindowsUpdate',
	            'CCMClientSDK',
	            'PendComputerRename',
	            'PendFileRename',
	            'PendFileRenVal',
	            'RebootPending'
	        )}
	    New-Object -TypeName PSObject -Property @{
	        Computer=$WMI_OS.CSName
	        CBServicing=$CBSRebootPend
	        WindowsUpdate=$WUAURebootReq
	        CCMClientSDK=$SCCM
	        PendComputerRename=$CompPendRen
	        PendFileRename=$PendFileRename
	        PendFileRenVal=$RegValuePFRO
	        RebootPending=($CompPendRen -or $CBSRebootPend -or $WUAURebootReq -or $SCCM -or $PendFileRename)
	    } | Select-Object @SelectSplat

	} Catch {
	    Write-Warning "$Computer`: $_"
	    ## If $ErrorLog, log the file to a user specified location/path
	    If ($ErrorLog) {
	        Out-File -InputObject "$Computer`,$_" -FilePath $ErrorLog -Append
	    }				
	}			
  }## End Foreach ($Computer in $ComputerName)			
}## End Process

End {  }## End End

}## End Function Get-PendingReboot
function Go-Sccm {
    param ($server)
    $dir = New-Item -ItemType directory "\\$server\c$\source" -ErrorAction SilentlyContinue
    copy-item '\\alnfs01\source$\Misc\Invoke-SCCMUpdate.ps1' "\\$server\c$\source\Invoke-SCCMUpdate.ps1"
    try {
        Write-Log "Invoking SCCMUpdate on $server"
        Invoke-Command -Computer $server -ScriptBlock {Set-ExecutionPolicy RemoteSigned -Force; & "c:\source\Invoke-SCCMUpdate.ps1"} -AsJob | out-null
    } catch {
        Write-Log "Unable to connect to $server" -ForegroundColor Red -MsgType 2
    }
}
function Get-Windowspatches {
    param ($patchservers)
    foreach ($server in $patchservers){
        Copy-Item -Recurse "C:\Windows\System32\WindowsPowerShell\v1.0\Modules\PSWindowsUpdate" "\\$server\c$\Windows\System32\WindowsPowerShell\v1.0\Modules\" -Force
    }
    foreach ($server in $patchservers){
        Invoke-Command -Computer $server -ScriptBlock {Set-ExecutionPolicy RemoteSigned -Force; & c:\temp\invoke-wu.ps1 } -AsJob | out-null
    }
    Wait-forjob

    $jobs = @(Get-Job)

    $needspatches = @()
    foreach ($job in $jobs){
        if ($job.State -eq "Failed"){
            Write-Log "There was an error running the task on $($job.Location)"-ForegroundColor red -MsgType 2
            $global:failedsystems += $server
        } else {
            $server = $null
            $jobresult = Receive-Job -Job $job -Keep -ErrorAction SilentlyContinue
            if ($jobresult){
                $server = @($jobresult.PSComputerName) | select -First 1
                $missingpatches = @($jobresult | ?{$_.title} | select -ExpandProperty title | sort)
                if ($missingpatches){
                    $needspatches += $server
                    Write-Log -Msg "$server is missing patches:" -ForegroundColor yellow -MsgType 1
                    foreach ($missingpatch in $missingpatches){
                        Write-Log $missingpatch -ForegroundColor yellow -MsgType 1
                    }
                } else {
                    Write-Log "No missing patches found for $server" -ForegroundColor green
                    $global:succeededsystems += $server
                }
            }
        }
    }
    Get-job | Remove-Job -Force
    return $needspatches
}
function Wait-forjob {
    do {
        Start-Sleep -Seconds 10
        $jobstatus = get-job
        $Completedcount = (@($jobstatus | where {$_.State -eq "Completed"})).count
        $Runningcount = (@($jobstatus | where {$_.State -eq "Running"})).count
        $Failedcount = (@($jobstatus | where {$_.State -eq "Failed"})).count
        if ($RunningCount -gt 4){
            Write-Log "C:$Completedcount R:$Runningcount F:$Failedcount"
        } else {
            $runservers = (@($jobstatus | where {$_.State -eq "Running"})).Location -join ","
            Write-Log "C:$Completedcount R:$Runningcount F:$Failedcount - $runservers"
        }
    } while (@(get-job | where {$_.state -eq "Running"}).count -gt 0)
}
function Reboot-PendingServers {
    param ($servers)
    foreach ($server in $servers){
        if (get-orionnode $server){
            # Write-Log "$server is a managed node in Orion"
            If ($patchorionmonitored -eq $false){
                Write-Log "`$patchorionmonitored is set to $false. Skipping $server"
                continue
            }
        }
        if ((Get-PendingReboot $server).RebootPending -eq $True){
            Write-Log "Reboot needed on $server" -ForegroundColor Yellow
            if (get-orionnode $server){
                Write-Log "Unmanaging $server"
                invoke-orionnodeunmanage $server | Out-Null
            }
            Write-Log "Restarting $server" -ForegroundColor Yellow
            try {
                Restart-Computer -ComputerName $server -Wait -Force -Timeout 3000 -Delay 2
            } catch {
                Read-Host "There was an error restarting ${server}. Please investigate" -ForegroundColor Red -MsgType 2
            }
            Write-Log "Restart complete on $server"
            if (get-orionnode $server){
                Write-Log "Re-managing $server"
                Start-Sleep -Seconds 30
                invoke-orionnoderemanage $server | Out-Null
            }
        } else {
            if (get-orionnode $server){
                invoke-orionnoderemanage $server | Out-Null
            }
        }
    }
}
function Install-Windowspatches {
    param ($needspatches)
    foreach ($server in $needspatches){
        
        Invoke-WUInstall -ComputerName $server -Script {Set-ExecutionPolicy RemoteSigned -Force; & c:\temp\invoke-wu.ps1 -install } -Confirm:$false
        get-job | remove-job -force    
        $watchsched = {
            start-sleep -Seconds 20
            do {Start-Sleep -Seconds 10} while (get-item "c:\temp\pswindowsupdate.log" -ErrorAction SilentlyContinue)
        }
        Invoke-Command -Computer $server -ScriptBlock $watchsched -AsJob | out-null
    }
    Wait-forjob
    Reboot-PendingServers $needspatches
}
function Invoke-SCCM {
    param ($servers)
    $return = @()
    foreach ($server in $servers){
      Go-Sccm $server
    } 
    wait-forjob
    $jobs = Get-Job
    $failed = @($jobs | where {$_.state -eq "Failed"} | select -ExpandProperty Location)
    foreach ($fail in $failed){
        Write-Log "$fail failed SCCM deployment. Please investigate." -ForegroundColor Red -MsgType 2
    }
    Reboot-PendingServers $servers
    Get-job | Remove-Job -Force
}
function Invoke-WindowsUpdate {
    param ($servers)
    $endloop = $false
    do {
        $needspatches = @(get-windowspatches $servers)
        write-log "Servers needing patches count = $($needspatches.Count)"
        install-windowspatches $needspatches
        $needspatches = @(get-windowspatches $needspatches)
        if ($needspatches.Count -eq 0){
            $endloop = $true
        }
    } until ($endloop -eq $true)
}
function Invoke-PreFlight {
    param ($servers)
    $return = @()
    $invokewu =@'
param (
    [switch]$install = $false
)

function set-systemproxy {
    $COMPUTERNAME = $env:COMPUTERNAME
    switch -wildcard ($logonserver) {
        "BB*"  {$PXY="ALN"}
        "ALN*" {$PXY="ALN"}
        "DEV*" {$PXY="ALN"}
        "WIN*" {$PXY="ALN"}
        "AUS*" {$PXY="AUS"}
        "HOU*" {$PXY="HOU"}
        "DAL*" {$PXY="DAL"}
        "PAL*" {$PXY="PAL"}
        "NYC*" {$PXY="NYC"}
        "LON*" {$PXY="LON"}
        "WAS*" {$PXY="WAS"}
        "DXB*" {$PXY="DXB"}
        "RIY*" {$PXY="RIY"}
        "MOS*" {$PXY="MOS"}
        "HKG*" {$PXY="HKG"}
        "BRU*" {$PXY="BRU"}
        "STL*" {$PXY="STL"}
        "SFO*" {$PXY="SFO"}
        default {$PXY="ALN"}
    }
    $cmd = "netsh winhttp set proxy ${PXY}PROXY.BAKERBOTTS.NET:8080 `"<local>;*.bakerbotts.net;10.*`""
    Invoke-Expression $cmd
    $RegKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
    $Proxy = "${PXY}PROXY.BAKERBOTTS.NET:8080"
    Set-ItemProperty -Path $RegKey ProxyServer -Value $Proxy -ErrorAction Stop | out-null
    Set-ItemProperty -Path $RegKey ProxyEnable -Value 1 -ErrorAction Stop | out-null
    Start-Sleep -Seconds 10
}
$proxy = set-systemproxy
Import-Module PSWindowsUpdate
$wuserviceman = Add-WUServiceManager -ServiceID 7971f918-a847-4430-9279-4a52d1efe18d -Confirm:$false
$MSUpdate = Get-WUServiceManager | ?{$_.Name -eq "Microsoft Update"}
if ($install){
    if ($MSUpdate){
        Get-WUInstall -AcceptAll -IgnoreReboot -IgnoreUserInput -Category @('Critical Updates', 'Security Updates') -MicrosoftUpdate -Verbose | out-file c:\temp\pswindowsupdate.log -force
    } else {
        Get-WUInstall -AcceptAll -IgnoreReboot -IgnoreUserInput -Category @('Critical Updates', 'Security Updates') -WindowsUpdate -Verbose | out-file c:\temp\pswindowsupdate.log -force
    }            
    $newfile = "pswindowsupdate-" + [DateTime]::Now.ToString("yyyyMMddHHmmss") + ".log"
    move-item c:\temp\pswindowsupdate.log c:\temp\$newfile
} else {
    if ($MSUpdate){
        Get-WUList -Category @('Critical Updates', 'Security Updates') -MicrosoftUpdate
    } else {
        Get-WUList -Category @('Critical Updates', 'Security Updates') -WindowsUpdate
    }
}
'@
    
    foreach ($server in $servers){
        # Write-Log "$server" -ForegroundColor White
        if (get-orionnode $server){
            Write-Log "$server is a managed node in Orion"
            If ($patchorionmonitored -eq $false){
                Write-Log "`$patchorionmonitored is set to $false. Skipping $server"
                $global:skippedsystems += $server
                continue
            }
        }
        if (Test-Connection $server -ErrorAction SilentlyContinue){
            $path = "\\$server\c$\temp"
            If(!(test-path $path)){
                New-Item -ItemType Directory -Force -Path $path | Out-Null
            }
            If(!(test-path $path)){
                Write-Log "Unable to create Temp directory on ${server}. Marking as failed." -MsgType 2 -ForegroundColor Red
                $global:failedsystems += $server
            } else {
                $invokewu | out-file "$path\invoke-wu.ps1" -Force -Encoding ascii
                $return += $server
            }
        } else {
            Write-Log "Unable to test connection to ${server}. Setting status to failed." -MsgType 2 -ForegroundColor Red
            $global:failedsystems += $server
        }
    }
    return $return 
}
function Invoke-VMToolsCheck {
    param ($servers)
    foreach ($server in $servers){
        CheckAndUpgradeTools $server
    }
}
function Invoke-PostPatches {
    param ($servers)
    foreach ($server in $servers){    
        #Invoke-Command -ComputerName $server {MsiExec.exe /I{1693DDE2-4577-46E9-AEE2-0EAFE1F2A00E}} -AsJob | Out-Null
        $app = Get-WmiObject -Class Win32_Product -Filter "Name = 'EMC Avamar for Windows'"
        if ($app){
        write-log "Uninstalling Avamar on $server"
            $app.uninstall()
        }
        write-log "Secunia scan on $server"
        copy-item \\alnfs01\source$\Secunia\Agents\scan.bat \\$server\c$\temp\scan.bat
        invoke-command -ComputerName $server {c:\temp\scan.bat | out-file c:\temp\scan.log -Force } -asJob | out-null
        # Write-Log "Patching complete on $server" -ForegroundColor Green
        $global:succeededsystems += $server
    }
}

$global:failedsystems = @()
$global:skippedsystems = @()
$global:succeededsystems = @()


import-module orion
If (!(Get-PSSnapin "VMware.VimAutomation.Core" -ErrorAction SilentlyContinue)){Add-PSSnapin "VMware.VimAutomation.Core"}

set-powercliconfiguration -defaultviservermode multiple -Confirm:$false -Scope Session | Out-Null
Connect-VIServer alnvcenter01.bakerbotts.net | Out-Null

Get-job | Remove-Job -Force

Write-Log "Performing pre-flight"

$servers = @(Invoke-PreFlight $servers | select -Unique)

Write-Log "Checking for SCCM patches"
Invoke-SCCM $servers

Write-Log "Checking for VMTools updates"
Invoke-VMToolsCheck $servers

Write-Log "Checking for WindowsUpdate patches"
Invoke-WindowsUpdate $servers

Write-Log "Performing post-patch actions"
Invoke-PostPatches $servers


foreach ($server in ($global:failedsystems | sort -unique)){
    write-log "$server failed to be patched." -ForegroundColor Red -MsgType 2
}
foreach ($server in ($global:skippedsystems | sort -unique)){
    write-log "$server was skipped." -ForegroundColor Yellow -MsgType 3
}
foreach ($server in ($global:succeededsystems | sort -unique)){
    write-log "$server was successfully patched." -ForegroundColor Green
}
