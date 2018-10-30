<#
    This utility scans the network and verifies the expiration date of installed digital certificates
    CAUTION: Since this effectively does a network scan, check with your organization first if running this script is allowed.

    Version: 1.0
#>

############################################## VARIABLE Definition ###################################################
# The line below is no longer needed. The script was created using PSv2, where $PSScriptRoot didn't exist yet
# $scriptPath = split-path -parent $MyInvocation.MyCommand.Definition

# Program variables
# DO NOT change anything here
$global:certObjCol = @() 
$global:ipAddress = ""
$global:netMask = ""
$global:IPList = @()

# User variables
# No need to change, but feel free to do so
$global:timeOutMax = 20 # In seconds; time before a remote process times out and errors out
$global:checkInterval = 50 # In milliseconds; time interval to poll for remote processes and check task completion status
$global:LOGPATH = $PSScriptRoot + "\Log\" + ("expiring_certificates_LOG_" + (Get-Date -Format "yyyyMMddhhmmss") + ".log")
$global:REPORTPATH = $PSScriptRoot + "\Report\" + ("expiring_certificates_REPORT_" + (Get-Date -Format "yyyyMMddhhmmss") + ".html")

# Styling HTML header for report
# Change this as needed, depending on your taste
$headingstyle = "<style>"
$headingstyle = $headingstyle + "H1{font-family:Tahoma;font-size:18px;margin-bottom:0px;margin-top:-15px}"
$headingstyle = $headingstyle + "H2{font-family:Tahoma;font-size:16px;padding-bottom:0px;margin:0}" 
$headingstyle = $headingstyle + "BODY{background-color:white;font-family:Tahoma;font-size:14px}"
$headingstyle = $headingstyle + "TABLE{border-width: 1px;border-style: solid;border-color: black;border-collapse: collapse;}"
$headingstyle = $headingstyle + "TH{border-width: 1px;padding-left: 10px;padding-right: 10px;border-style: solid;border-color: black;background-color:midnightblue;white-space: pre-wrap;font-family:Tahoma;color:white}"
$headingstyle = $headingstyle + "TD{border-width: 1px;padding-left: 10px;padding-right: 10px;border-style: solid;border-color: black;background-color:white;white-space: pre-wrap}"
$headingstyle = $headingstyle + "Table.courier TD{border-width: 1px;padding-left: 10px;padding-right: 10px;border-style: solid;border-color: black;background-color:white;white-space: pre-wrap; font-family: courier new}"
$headingstyle = $headingstyle + "</style>"
###################################################################################################################

############################################## HELPER functions definition #############################################
# Read config.ini and set defined variables
function Set-Config {
    $configFile = "$PSScriptRoot\config.ini"
    if ((Test-Path $configFile) -eq $true) {
        $configData = Get-Content $configFile
        foreach ($line in $configData) {
            if ($line -ne "" -and $line -ne "#*") {
                if ($line -like "*certIssuer*") {
                    $global:issuer = $line.Split('=')[1]
                }
                if ($line -like "*expireThreshold*") {
                    $global:expireThreshold = $line.Split('=')[1]
                }
                if ($line -like "*netinterface*") {
                    $global:netinterface = $line.Split('=')[1]
                }
                if ($line -like "*logHistory*") {
                    $global:logHistory = $line.Split('=')[1]
                }
                if ($line -like "*reportHistory*") {
                    $global:reportHistory = $line.Split('=')[1]
                }
                if ($line -like "*reportHeading*") {
                    $global:reportHeading = $line.Split('=')[1]
                }
                if ($line -like "*reportSubHeading*") {
                    $global:reportSubHeading += $line.Split('=')[1] -replace '<cert_issuer>',$global:issuer
                }
                if ($line -like "*emailrecipients*") {
                    $global:emailrecipients = $line.Split('=')[1]
                }
                if ($line -like "*emailsender*") {
                    $global:emailsender = $line.Split('=')[1]
                }
                if ($line -like "*smtpserver*") {
                    $global:smtpserver = $line.Split('=')[1]
                }
                if ($line -like "*smtpport*") {
                    $global:smtpport = $line.Split('=')[1]
                }
                if ($line -like "*emailsubject*") {
                    $global:emailsubject = $line.Split('=')[1]
                }
            }
        }
    }
}

# Get all installed digital certificates
function Get-CertsFromIssuer {
    [CmdletBinding()]
    param(
        [Parameter(Position=1)]
        [String]$server,
        [Parameter(Position=2)]
        [String]$issuer = $global:issuer
    )

    $timeout = $false
    try {
        # Build temporary script to execute on remote server
        $scriptTempFile = 'C:\scripttemp.ps1'
        $scriptTempFileRemoteUNC = "\\$server\c$\scripttempcopied.ps1"
        $scriptTempFileRemote = 'C:\scripttempcopied.ps1'
        Write-Output "Get-ChildItem -Path Cert:\ -recurse | where-object {`$_.issuer -like `"*$issuer*`"} | Select-Object -ExpandProperty PSPath > c:\cert_query.txt; `$? > c:\cert_result.txt" >> $scriptTempFile
        
        # Copy temporary script file to target server
        Copy-Item -Path $scriptTempFile -Destination $scriptTempFileRemoteUNC -Force
        
        # Execute remote script
        $processId = (Invoke-WmiMethod -Path "Win32_Process" -ComputerName $server  -Name Create -ArgumentList "powershell.exe -windowstyle hidden $scriptTempFileRemote" -ErrorAction Stop).processID
        if ($processId -eq $null) {
            return "Failed to invoke remote process; Execution Policy may be set to restricted"
        }

        # Wait for remote script to complete
        Out-Message "Waiting for remote process to complete..."
        New-Item -Path "c:\cert_result_copied.txt" -ItemType "File" -ErrorAction SilentlyContinue > $null
        Copy-Item -Path "\\$server\c$\cert_result.txt" -Destination "C:\cert_result_copied.txt" -ErrorAction "SilentlyContinue" > $null
        $timeoutCounter = 0
        $Result = Get-Content "C:\cert_result_copied.txt"
        while (((Get-WmiObject -class "win32_process" -Filter "ProcessID=$processId" -ComputerName $server) -ne $null -or $Result -eq $null) -and $timeoutCounter -lt ($global:timeOutMax * $global:checkInterval))
        {
            write-host -NoNewline "#"
            Start-Sleep -Milliseconds $global:checkInterval
            $timeoutCounter++
            Copy-Item -Path "\\$server\c$\cert_result.txt" -Destination "C:\cert_result_copied.txt" -ErrorAction "SilentlyContinue" > $null
            $Result = Get-Content "C:\cert_result_copied.txt"
        }

        # Get final script output when remote script completes
        Copy-Item -Path "\\$server\c$\cert_result.txt" -Destination "C:\cert_result_copied.txt" -ErrorAction "SilentlyContinue" > $null
        $Result = Get-Content "C:\cert_result_copied.txt"
        New-Item -Path "c:\cert_query_copied.txt" -ItemType "File" -ErrorAction SilentlyContinue > $null
        $queryResult = ""
        if (Test-Path "\\$server\c$\cert_query.txt") {
                Copy-Item -Path "\\$server\c$\cert_query.txt" -Destination "C:\cert_query_copied.txt" -ErrorAction "SilentlyContinue" > $null
                $queryResult = Get-Content "c:\cert_query_copied.txt"
        }

        # Perform cleanup
        try {
            if (Test-Path "\\$server\c$\cert_result.txt") {
                Remove-Item -Path "\\$server\c$\cert_result.txt" -Force -ErrorAction Stop > $null
            }
            if (Test-Path "C:\cert_result_copied.txt") {
                Remove-Item -Path "C:\cert_result_copied.txt" -Force -ErrorAction Stop > $null
            }
            if (Test-Path "\\$server\c$\cert_query.txt") {
                Remove-Item -Path "\\$server\c$\cert_query.txt" -Force -ErrorAction Stop > $null
            }
            if (Test-Path "C:\cert_query_copied.txt") {
                Remove-Item -Path "C:\cert_query_copied.txt" -Force -ErrorAction Stop > $null
            }
            if (Test-Path $scriptTempFile) {
                Remove-Item -Path $scriptTempFile -Force -ErrorAction Stop > $null
            }
            if (Test-Path $scriptTempFileRemoteUNC) {
                Remove-Item -Path $scriptTempFileRemoteUNC -Force -ErrorAction Stop > $null
            }
        }
        catch [Exception] {
            Out-Message -Yellow "[WARNING]: Removing temporary files failed on $server"
            Out-Message -Silent "[Remove Error]: $_"
        }

        # Parse Result
        if ($timeoutCounter -ge ($global:timeOutMax * $global:checkInterval)) {
            $timeout = $True
        }
        if ($timeout -eq $false) {
            write-host "... Complete!"
            Out-Message "Remote process execution completed on $server. Acquiring result..."
            Out-Message "Copying result file from $server"
            Out-Message "Temporary file copied"
            if ($Result -like "*True*")
            {
                Out-Message "Certificate stores in $server has been successfully queried for certificates issued by $global:issuer"
                Out-Message "Obtaining query results"
                $global:certsFromIssuer = $queryResult
                Out-Message "Results obtained for further processing"
                return $True
            }
            elseif ($Result -like "*False*")
            {
                return "Remote server returned an operation failure response"
            }
            else {
                return "Remote query process failed to execute on $server"
            }
        }
        else {
            return "TIMEOUT has been encountered while waiting for remote process to complete"
        }
    }
    catch [Exception] {
        return $_    
    }
}

# Get details of all detected certificates from a target server
function Get-CertDetails {
    [CmdletBinding()]
    param(
        [Parameter(Position=1)]
        [String]$server,
        [Parameter(Position=2)]
        [String[]]$certPath = $global:certsFromIssuer,
        [Parameter(Position=3)]
        [String]$platform
    )

    $obtainError = $false
    $timeout = $false
    try {
        foreach ($psPath in $certPath) {

            # Build temporary script
            $scriptTempFile = 'C:\scripttemp.ps1'
            $scriptTempFileRemoteUNC = "\\$server\c$\scripttempcopied.ps1"
            $scriptTempFileRemote = 'C:\scripttempcopied.ps1'
            Write-Output "`$certDetails = Get-ChildItem -Path Cert:\ -recurse | Where-object {`$_.pspath -eq `'$psPath`'} | Select-Object -Property Subject,issuer,NotAfter,FriendlyName" > $scriptTempFile
            Write-Output "`$? > c:\cert_result.txt" >> $scriptTempFile
            Write-Output "New-Item -Path `"C:\cert_details.txt`" -ItemType File -Force -ErrorAction SilentlyContinue > `$null" >> $scriptTempFile
            Write-Output "`$Subject=`$certDetails.subject;Write-Output `"Subject;`$Subject`" > C:\cert_details.txt" >> $scriptTempFile
            Write-Output "`$Issuer=`$certDetails.issuer;Write-Output `"Issuer;`$Issuer`" >> C:\cert_details.txt" >> $scriptTempFile
            Write-Output "`$Expiration=(Get-Date -Date `$certDetails.NotAfter -Format {g});Write-Output `"Expiration;`$Expiration`" >> C:\cert_details.txt" >> $scriptTempFile
            Write-Output "`$FriendlyName=`$certDetails.friendlyname;Write-Output `"FriendlyName;`$FriendlyName`" >> C:\cert_details.txt" >> $scriptTempFile
            Start-Sleep -Seconds 1

            # Copy temporary script file to target server
            Copy-Item -Path $scriptTempFile -Destination $scriptTempFileRemoteUNC -Force
        
            # Execute script on remote server
            $processId = (Invoke-WmiMethod -Path "Win32_Process" -ComputerName $server  -Name Create -ArgumentList "powershell.exe -windowstyle hidden $scriptTempFileRemote" -ErrorAction Stop).processID
            if ($processId -eq $null) {
                return "Failed to invoke remote process; Execution Policy may be set to restricted"
            }

            # Wait for remote process to complete
            Out-Message "Waiting for remote process to complete..."
            New-Item -Path "c:\cert_result_copied.txt" -ItemType "File" -ErrorAction SilentlyContinue > $null
            Copy-Item -Path "\\$server\c$\cert_result.txt" -Destination "C:\cert_result_copied.txt" -ErrorAction "SilentlyContinue" > $null
            $timeoutCounter = 0
            $Result = Get-Content "C:\cert_result_copied.txt"
            while (((Get-WmiObject -class "win32_process" -Filter "ProcessID=$processId" -ComputerName $server) -ne $null -or $Result -eq $null) -and $timeoutCounter -lt ($global:timeOutMax * $global:checkInterval))
            {
                write-host -NoNewline "#"
                Start-Sleep -Milliseconds $global:checkInterval
                $timeoutCounter++
                Copy-Item -Path "\\$server\c$\cert_result.txt" -Destination "C:\cert_result_copied.txt" -ErrorAction "SilentlyContinue" > $null
                $Result = Get-Content "C:\cert_result_copied.txt"
            }

            # Copy script output when remote script completes
            Copy-Item -Path "\\$server\c$\cert_result.txt" -Destination "C:\cert_result_copied.txt" -ErrorAction "SilentlyContinue" > $null
            $Result = Get-Content "C:\cert_result_copied.txt"
            New-Item -Path "c:\cert_details_copied.txt" -ItemType "File" -ErrorAction SilentlyContinue > $null
            $queryResult = ""
            if (Test-Path "\\$server\c$\cert_details.txt") {
                    Copy-Item -Path "\\$server\c$\cert_details.txt" -Destination "C:\cert_details_copied.txt" -ErrorAction "SilentlyContinue" > $null
                    $queryResult = Get-Content "c:\cert_details_copied.txt"
            }

            # Perform cleanup
            try {
                if (Test-Path "\\$server\c$\cert_result.txt") {
                    Remove-Item -Path "\\$server\c$\cert_result.txt" -Force -ErrorAction Stop > $null
                }
                if (Test-Path "C:\cert_result_copied.txt") {
                    Remove-Item -Path "C:\cert_result_copied.txt" -Force -ErrorAction Stop > $null
                }
                if (Test-Path "\\$server\c$\cert_details.txt") {
                    Remove-Item -Path "\\$server\c$\cert_details.txt" -Force -ErrorAction Stop > $null
                }
                if (Test-Path "c:\cert_details_copied.txt") {
                    Remove-Item -Path "c:\cert_details_copied.txt" -Force -ErrorAction Stop > $null
                }
                if (Test-Path $scriptTempFile) {
                    Remove-Item -Path $scriptTempFile -Force -ErrorAction Stop > $null
                }
                if (Test-Path $scriptTempFileRemoteUNC) {
                    Remove-Item -Path $scriptTempFileRemoteUNC -Force -ErrorAction Stop > $null
                }
            }
            catch [Exception] {
                Out-Message -Yellow "[WARNING]: Removing temporary files failed on $server"
                Out-Message -Silent "[Remove Error]: $_"
            }

            # Parse Result
            if ($timeoutCounter -ge ($global:timeOutMax * $global:checkInterval)) {
                $timeout = $True
            }
            if ($timeout -eq $false) {
                write-host "...Complete!"
                Out-Message "Remote process execution completed on $server. Acquiring result..."
                Out-Message "Copying result file from $server"
                Out-Message "Temporary file copied"
                if ($Result -like "*True*")
                {
                    Out-Message "Certificate details of $psPath in $server has been successfully obtained"
                    Out-Message "Obtaining results"
                    $obtainError = $false
                }
                elseif ($Result -like "*False*")
                {
                    $obtainError = $True
                    return "Remote server returned an operation failure response"
                }
                else {
                    $obtainError = $True
                    return "Remote query process failed to execute on $server"
                }
            }
            else {
                $obtainError = $True
                return "TIMEOUT has been encountered while waiting for remote process to complete"
            }

            # Build certificate details properties
            if ($obtainError -eq $false) {
                foreach ($line in $queryResult) {
                    if ($line -like "*Subject;*") {
                        $certSubjectRaw = $line.Split(';')[1]
                        $certSubject = ""
                        foreach ($item in ($certSubjectRaw -Split  ', ')) {
                            $certSubject += $item
                            if ($item -ne ($certSubjectRaw -Split  ', ')[($certSubjectRaw -Split  ', ').Count -1]) {
                                $certSubject += "`n"
                            }
                        }
                        $certSubject = $certSubject.Trim()
                    }
                    if ($line -like "*Issuer;*") {
                        $certIssuedByRaw = $line.Split(';')[1]
                        $certIssuedBy = (($certIssuedByRaw -Split  ', ')[0]).Split('=')[1] -replace "`"",''
                    }
                    if ($line -like "*Expiration;*") {
                        $certExpiration = $line.Split(';')[1]
                    }
                    if ($line -like "*FriendlyName;*") {
                        $certFN = $line.Split(';')[1]
                        if ($certFN -eq "" -or $certFN -eq $null) {
                            $certFN = '<not set>'
                        }
                    }
                }
                # Get certificate scope and store
                $certScope = ($psPath.Split(':')[2]).Split('`\')[0]
                $certStore = ($psPath.Split(':')[2]).Split('`\')[1]
                if ($certScope -eq "LocalMachine") {
                    $certScope = "Local Computer"
                }
                if ($certScope -eq "CurrentUser") {
                    $certScope = "Current User ($env:USERNAME)"
                }
                if ($certStore -eq "My") {
                    $certStore = "Personal"
                }
                if ($certStore -eq "AuthRoot") {
                    $certStore = "Third Party Root Certification Authority"
                }
                if ($certStore -eq "CA") {
                    $certStore = "Intermediate Certification Authorities"
                }
                if ($certStore -eq "Root") {
                    $certStore = "Trusted Root Certification Authorities"
                }
                if ($certStore -eq "Trust") {
                    $certStore = "Enterprise Trust"
                }
                if ($certStore -eq "TrustedDevices") {
                    $certStore = "Trusted Devices"
                }
                if ($certStore -eq "TrustedPublisher") {
                    $certStore = "Trusted Publisher"
                }
                if ($certStore -eq "TrustedPeople") {
                    $certStore = "Trusted People"
                }
                if ($certStore -eq "SmartCardRoot") {
                    $certStore = "Smart Card Trusted Root"
                }

                # Get days before certificate expires
                $certDaystoExpire = ((Get-Date -Date $certExpiration) - (date)).Days
                if ($certDaystoExpire -lt 0) {
                    $certDaystoExpire = '<td style="background-color: Red;">' + "EXPIRED" + '</td>'
                    $certExpireValue=1
                }
                elseif ($certDaystoExpire -le $global:expireThreshold) {
                    $certDaystoExpire = '<td style="background-color: Red;">' + $certDaystoExpire + '</td>'
                }
                else {
                    $certExpireValue=2
                }
                $certObjProps = @{'Server'=$server;
                                  'Windows OS'=$platform;
                                  'Certificate Path'="\$certScope\$certStore";
                                  'Friendly Name'=$certFN;
                                  'Subject'=$certSubject;
                                  'Issued By'=$certIssuedBy;
                                  'Expiration'=$certExpiration;
                                  'Days to Expire'=$certDaystoExpire;
                                  'ExpireValue'=$expireValue;}
                $certObj = New-Object -TypeName psobject -Property $certObjProps
                $global:certObjCol += $certObj
            }
        }
        return $True
    }
    catch [Exception] {
        return $_  
    }
}

# Get all installed digital certificates and their details for servers earlier than Windows 2008 R2
function Get-CertsFromIssuerNonR2 {
    [CmdletBinding()]
    param(
        [Parameter(Position=1)]
        [String]$server,
        [Parameter(Position=2)]
        [String]$issuer = $global:issuer,
        [Parameter(Position=3)]
        [String]$platform
    )

    $global:certsFromIssuer = @()
    try {
        # Define all certificate stores
        $scope = "LocalMachine"
        $Stores = @(
        "My",
        "Trust",
        "TrustedPeople",
        "AuthRoot",
        "CA",
        "SmartCardRoot",
        "Disallowed",
        "Root",
        "Remote Desktop",
        "TrustedDevices",
        "TrustedPublisher")
        $certCol = @()
        foreach ($store in $Stores) {
            try {
                $remoteStore = New-Object System.Security.Cryptography.X509Certificates.X509Store("\\$server\$store","$scope")
                $remoteStore.Open("ReadOnly")
                $certificates = $remoteStore.Certificates
                $certCol = $certificates | Where-Object {$_.issuer -like "*$issuer*"}

                if ($certCol -ne $null) {
                    Out-Message "Processing certificates issued by $issuer found in \$scope\$store of $server"
                    foreach ($cert in $certCol) {
                        # Build certificate details properties
                        # Get Subject 
                        $certSubjectRaw = $cert.Subject
                        $certSubject = ""
                        foreach ($item in ($certSubjectRaw -Split  ', ')) {
                            $certSubject += $item
                            if ($item -ne ($certSubjectRaw -Split  ', ')[($certSubjectRaw -Split  ', ').Count -1]) {
                                $certSubject += "`n"
                            }
                        }
                        $certSubject = $certSubject.Trim()

                        # Get Issuer
                        $certIssuedByRaw = $cert.Issuer
                        $certIssuedBy = (($certIssuedByRaw -Split  ', ')[0]).Split('=')[1] -replace "`"",''
                
                        # Expiration
                        $certExpiration = $cert.NotAfter

                        # Friendly Name
                        $certFN = $cert.FriendlyName
                        if ($certFN -eq "" -or $certFN -eq $null) {
                            $certFN = '<not set>'
                        }

                        # Get certificate scope and store
                        $certScope = $scope
                        $certStore = $store
                        if ($certScope -eq "LocalMachine") {
                            $certScope = "Local Computer"
                        }
                        if ($certScope -eq "CurrentUser") {
                            $certScope = "Current User ($env:USERNAME)"
                        }
                        if ($certStore -eq "My") {
                            $certStore = "Personal"
                        }
                        if ($certStore -eq "AuthRoot") {
                            $certStore = "Third Party Root Certification Authority"
                        }
                        if ($certStore -eq "CA") {
                            $certStore = "Intermediate Certification Authorities"
                        }
                        if ($certStore -eq "Root") {
                            $certStore = "Trusted Root Certification Authorities"
                        }
                        if ($certStore -eq "Trust") {
                            $certStore = "Enterprise Trust"
                        }
                        if ($certStore -eq "TrustedDevices") {
                            $certStore = "Trusted Devices"
                        }
                        if ($certStore -eq "TrustedPublisher") {
                            $certStore = "Trusted Publisher"
                        }
                        if ($certStore -eq "TrustedPeople") {
                            $certStore = "Trusted People"
                        }
                        if ($certStore -eq "SmartCardRoot") {
                            $certStore = "Smart Card Trusted Root"
                        }

                        # Get days to expire
                        $certDaystoExpire = ((Get-Date -Date $certExpiration) - (date)).Days
                        if ($certDaystoExpire -lt 0) {
                            $certDaystoExpire = '<td style="background-color: Red;">' + "EXPIRED" + '</td>'
                            $certExpireValue=1
                        }
                        elseif ($certDaystoExpire -le $global:expireThreshold) {
                            $certDaystoExpire = '<td style="background-color: Red;">' + $certDaystoExpire + '</td>'
                        }
                        else {
                            $certExpireValue=2
                        }

                        # Build certificate object
                        Out-Message "Certificate object is being created"
                        $certObjProps = @{'Server'=$server;
                                          'Windows OS'=$platform;
                                          'Certificate Path'="\$certScope\$certStore";
                                          'Friendly Name'=$certFN;
                                          'Subject'=$certSubject;
                                          'Issued By'=$certIssuedBy;
                                          'Expiration'=$certExpiration;
                                          'Days to Expire'=$certDaystoExpire;
                                          'ExpireValue'=$expireValue;}
                        $certObj = New-Object -TypeName psobject -Property $certObjProps
                        $global:certObjCol += $certObj
                        Out-Message "Certificate object has been created and added to certificate pool"
                    }
                }
                else {
                    Out-Message "No certificate issued by $issuer are found in \$scope\$store of $server"
                }
            }
            catch [Exception] {
                Out-Message -Red "Unable to obtain certificates in \$scope\$store of $server"
                Out-Message -Red "[ERROR]: $_"
            }
        }
        Out-Message "Certificates in $server issued by $issuer have been successfully queried and obtained"
        return $true
    }
    catch [Exception] {
        return $_
    }
}

# Generate HTML report from detected certificates on servers within the current network
function Set-HTMLReport {
    $tableOrder = @()
    $tableOrder += 'Server'
    $tableOrder += 'Windows OS'
    $tableOrder += 'Certificate Path'
    $tableOrder += 'Friendly Name'
    $tableOrder += 'Subject'
    $tableOrder += 'Issued By'
    $tableOrder += 'Expiration'
    $tableOrder += 'Days to Expire'
    $props = @{'TableEntry'=$global:certObjCol;
               'Order'=$tableOrder;
               'HTMLFile'=$global:REPORTPATH;
               'Heading'=$global:reportHeading;
               'subHeading'=$global:reportSubHeading;}
    Set-HTMLTable @props
}

# Generate the HTML tables in the report; used by Set-HTMLReport
function Set-HTMLTable {
    [CmdletBinding()]
    param(
        [Parameter(Position=1)]
        [PSObject[]]$TableEntry = @(),
        [Parameter(Position=2)]
        [String[]]$Order = @(),
        [Parameter(Position=3)]
        [String]$HTMLFile,
        [Parameter(Position=4)]
        [String]$Heading,
        [Parameter(Position=5)]
        [String]$subHeading
    )

    # Create HTML table representing object
    $reportraw = (Write-Output $TableEntry | Sort-Object 'ExpireValue','Days to Expire','Server' | Select-Object $Order | ConvertTo-HTML -Head (Set-HTMLHeader $Heading $subHeading))
    $reportraw = $reportraw -replace '&lt;br&gt;','<br>'
    $reportraw = $reportraw -replace '&lt;/td&gt;</td>','</td>'
    $reportraw = $reportraw -replace '<td>&lt;td style=&quot;background-color: red;&quot;&gt;','<td style="background-color: red;">'

    $reportraw | Out-File -Append $HTMLFile
    $output_report = $HTMLFile
    & $output_report

}

# Sets the HTML header, which determines the style of the report; used by Set-HTMLTable
function Set-HTMLHeader {
    param(
        [parameter(Position =1,Mandatory = $True)]
        [string]$header,
        [parameter(Position =2)]
        [string]$subheader
    )

    $displaydate = Get-Date -Format {g}
    $datestamp = "Report generation date:<b>$displaydate</b>"
    $strHeader = $global:headingstyle + "<p style=`"text-align:center`"><img src=`'cid:logo.png`' alt=`'LOGO`' align=`"center`"></p>"
    $strHeader = $strHeader + "<H1 style=`"color:midnightblue;text-align:center;`">" + "Certificate Expiration Report" + "</H1><br>"
    $strHeader = $strHeader + "<H2 style=`"color:black;`">" + $header + "</H2>"
    if ($PSBoundParameters.ContainsKey('subheader')) {
        $strHeader = $strHeader + '<p style="margin-top:5px;padding:0px;color:black;font-family:calibri;font-size:12;line-height:14px">' + $subheader + '<br>'
        $strHeader = $strHeader + ($datestamp + '</p>')
    }
    else {
        $strHeader = $strHeader + '<p style="margin-top:5px;padding:0px;color:black;font-family:calibri;font-size:12;line-height:14px">' + $datestamp + '</p>'
    }
    $strHeader
}

# Helper function to print output to screen and to log file
function Out-Message {
    [CmdletBinding()]
    param(
        [Parameter(Position=1)]
        [String]$Message,
        [Parameter(Position=2)]
        [String]$Path = $global:LOGPATH,
        [Parameter(Position=3)]
        [switch]$Green,
        [Parameter(Position=4)]
        [switch]$Yellow,
        [Parameter(Position=5)]
        [switch]$Red,
        [Parameter(Position=6)]
        [switch]$Silent
    )

    # Print to screen
    if (($PSBoundParameters.ContainsKey('Silent')) -ne $true) {
        if ($PSBoundParameters.ContainsKey('Green')) {
            Write-Host -ForegroundColor Green $Message
        }
        elseif ($PSBoundParameters.ContainsKey('Yellow')) {
            Write-Host -ForegroundColor Yellow $Message 
        }
        elseif ($PSBoundParameters.ContainsKey('Red')) {
            Write-Host -ForegroundColor Red $Message
        }
        else { 
            Write-Host $Message
        }
    }

    # Output to log file
    $datedisplay = date -F {MM/dd/yyy hh:mm:ss:}
    [IO.File]::AppendAllText($Path,"$datedisplay $Message`r`n")
}

# Get IP Address
function Get-IPAddress {
    [cmdletbinding()]
    param(
        [Parameter(Position=1)]
        [Alias('Hostname')]
        [string]$interfaceName = $global:netinterface
    )

    try {
        $macaddress = Get-WmiObject -class win32_networkadapter | Where-Object {$_.netconnectionid -eq $interfaceName} | Select-Object -ExpandProperty macaddress
        $ipaddress = Get-WmiObject win32_networkadapterconfiguration | where-object {$_.macaddress -eq $macaddress} | select-object -ExpandProperty ipaddress
        if ($ipaddress.Count -gt 1) {
            return $ipaddress[0]
        }
        else {
            return $ipaddress
        }
    }
    catch {
        return $_
    }
}

# Get Subnet Mask
function Get-NetMask {
    [cmdletbinding()]
    param(
        [Parameter(Position=1)]
        [Alias('Hostname')]
        [string]$interfaceName = $global:netinterface
    )

    try {
        $macaddress = Get-WmiObject -class win32_networkadapter | Where-Object {$_.netconnectionid -eq $interfaceName} | Select-Object -ExpandProperty macaddress
        $netmask = Get-WmiObject win32_networkadapterconfiguration | where-object {$_.macaddress -eq $macaddress} | select-object -ExpandProperty ipsubnet
        foreach ($item in $netmask)
        {
            if ($netmask -like "*.*")
            {
                return $item
            }
        }
    }
    catch {
        return $_
    }
}

# Get the Operating System version
function Get-OSVersion {
    param(
    [Parameter()]
        [string]$server
    )

    try {
        return (Get-WmiObject -class "win32_operatingsystem" -ComputerName "$server" -ErrorAction Stop | Select-Object -ExpandProperty Caption)
    }
    catch {
        return "unknown"
    }
}

# Remove old reports older than the set reports history
function Remove-OldReports {
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$History = $global:reportHistory
    )

    $reportsList = get-childitem -Path "$PSScriptRoot\Report" | Sort-Object -Property 'LastWriteTime' -Descending | Select-Object -ExpandProperty Name
    if ($reportsList.Count -ge $History) {
        $reportCounter = 1
        foreach ($report in $reportsList) {
            if ($reportCounter -gt $History) {
                Remove-Item -Path "$PSScriptRoot\Report\$report" -Force > $null
            }
            $reportCounter++
        }
    }
}

# Remove old logs older than the set log history
function Remove-OldLogs {
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$History = $global:logHistory
    )
    $logsList = get-childitem -Path "$PSScriptRoot\Log" | Sort-Object -Property 'LastWriteTime' -Descending | Select-Object -ExpandProperty Name
    if ($logsList.Count -ge $History) {
        $logCounter = 1
        foreach ($log in $logsList) {
            if ($logCounter -gt $History) {
                Remove-Item -Path "$PSScriptRoot\Log\$log" -Force > $null
            }
            $logCounter++
        }
    }
}

# Send Html report as inline email
function Send-Report {
    [CmdletBinding()]
    param(
        [Parameter(Position=1)]
        [string[]]$To = $global:emailrecipients,
        [Parameter(Position=2)]
        [string[]]$From = $global:emailsender,
        [Parameter(Position=3)]
        [string]$SMTPServer = $global:smtpserver,
        [Parameter(Position=4)]
        [string]$SMTPPort = $global:smtpport,
        [Parameter(Position=5)]
        [string]$Subject = $global:emailsubject
    )

    # Create SMTP message
    $SMTPmessage = New-Object Net.Mail.MailMessage($From,$To)
    $SMTPmessage.Subject = $Subject
    $SMTPmessage.IsBodyHtml = $true
    $SMTPmessage.Body = Get-Content "$global:REPORTPATH"

    #Attachments
    $attachment = New-Object System.Net.Mail.Attachment("$PSScriptRoot\img\logo.png")
    $attachment.ContentDisposition.Inline = $true
    $attachment.ContentDisposition.DispositionType = "Inline"
    $attachment.ContentType = "image/png"
    $attachment.ContentId = "logo.png"
    $SMTPmessage.attachments.Add($attachment)

    # Send the email
    $SMTPClient = New-Object Net.Mail.SmtpClient($SMTPServer,$SMTPPort)
    try {
        Out-Message "Sending email message..."
        $SMTPClient.Send($SMTPmessage)
        Out-Message "Email sent!"
        return $true
    }
    catch {
        return $_
    }

    # Cleanup
    $attachment.Dispose()
    $SMTPmessage.Dispose()

}
########################################################################################################################

############################################## H3RD PARTY helper functions #############################################
# The following functions were obtained from: http://www.indented.co.uk/2010/01/23/powershell-subnet-math/
# Sadly the site is already down :( These functions are used to obtain the network range of the host executing this script
function Get-NetworkRange ([String]$IP, [String]$Mask) {
  if ($IP.Contains("/")) {
    $Temp = $IP.Split("/")
    $IP = $Temp[0]
    $Mask = $Temp[1]
  }
 
  if (!$Mask.Contains(".")) {
    $Mask = ConvertTo-Mask $Mask
  }
 
  $DecimalIP = ConvertTo-DecimalIP $IP
  $DecimalMask = ConvertTo-DecimalIP $Mask
  
  $Network = $DecimalIP -band $DecimalMask
  $Broadcast = $DecimalIP -bor ((-bnot $DecimalMask) -band [UInt32]::MaxValue)
 
  for ($i = $($Network + 1); $i -lt $Broadcast; $i++) {
    $global:IPList += (ConvertTo-DottedDecimalIP $i)
  }
}

function ConvertTo-Mask {
  <#
    .Synopsis
      Returns a dotted decimal subnet mask from a mask length.
    .Description
      ConvertTo-Mask returns a subnet mask in dotted decimal format from an integer value ranging
      between 0 and 32. ConvertTo-Mask first creates a binary string from the length, converts
      that to an unsigned 32-bit integer then calls ConvertTo-DottedDecimalIP to complete the operation.
    .Parameter MaskLength
      The number of bits which must be masked.
  #>
  
  [CmdLetBinding()]
  param(
    [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
    [Alias("Length")]
    [ValidateRange(0, 32)]
    $MaskLength
  )
  
  Process {
    return ConvertTo-DottedDecimalIP ([Convert]::ToUInt32($(("1" * $MaskLength).PadRight(32, "0")), 2))
  }
}

function ConvertTo-DottedDecimalIP {
  <#
    .Synopsis
      Returns a dotted decimal IP address from either an unsigned 32-bit integer or a dotted binary string.
    .Description
      ConvertTo-DottedDecimalIP uses a regular expression match on the input string to convert to an IP address.
    .Parameter IPAddress
      A string representation of an IP address from either UInt32 or dotted binary.
  #>
 
  [CmdLetBinding()]
  param(
    [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
    [String]$IPAddress
  )
  
  process {
    Switch -RegEx ($IPAddress) {
      "([01]{8}.){3}[01]{8}" {
        return [String]::Join('.', $( $IPAddress.Split('.') | ForEach-Object { [Convert]::ToUInt32($_, 2) } ))
      }
      "\d" {
        $IPAddress = [UInt32]$IPAddress
        $DottedIP = $( For ($i = 3; $i -gt -1; $i--) {
          $Remainder = $IPAddress % [Math]::Pow(256, $i)
          ($IPAddress - $Remainder) / [Math]::Pow(256, $i)
          $IPAddress = $Remainder
         } )
      
        return [String]::Join('.', $DottedIP)
      }
      default {
        Write-Error "Cannot convert this format"
      }
    }
  }
}

function ConvertTo-DecimalIP {
  <#
    .Synopsis
      Converts a Decimal IP address into a 32-bit unsigned integer.
    .Description
      ConvertTo-DecimalIP takes a decimal IP, uses a shift-like operation on each octet and returns a single UInt32 value.
    .Parameter IPAddress
      An IP Address to convert.
  #>
  
  [CmdLetBinding()]
  param(
    [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
    [Net.IPAddress]$IPAddress
  )
 
  process {
    $i = 3; $DecimalIP = 0;
    $IPAddress.GetAddressBytes() | ForEach-Object { $DecimalIP += $_ * [Math]::Pow(256, $i); $i-- }
 
    return [UInt32]$DecimalIP
  }
}
########################################################################################################################

##################################################### MAIN PROGRAM #####################################################
# Get config
Set-Config

# Get list of servers in the network
$global:ipAddress = Get-IPAddress
$global:netMask = Get-NetMask
Get-NetworkRange -IP $global:ipAddress -Mask $global:netMask

# Get certificate from all target servers
foreach ($ip_address in $global:IPList) {

    # Check if server is online
    Out-Message "Beginning discovery on $ip_address"
    Out-Message "Performing ping test to verify active node in $ip_address"
    if (Test-Connection -Quiet -Count 1 -ComputerName $ip_address) {
        # Determine version of remote Windows Operating System
        Out-Message "Ping successful on $ip_address; Certificate Expiration Discovery will proceed on $ip_address"
        Out-Message "Obtaining OS platform version of $ip_address"
        $osCheckResult = Get-OSVersion -server $ip_address
        $osCheckResultFiltered = $osCheckResult -replace 'Microsoft Windows Server ',''
        $osCheckResultFiltered = $osCheckResultFiltered -replace 'Microsoft� Windows Server� ',''
        $osCheckResultFiltered = $osCheckResultFiltered -replace 'Microsoft(R) Windows(R) Server ',''
        if ($osCheckResultFiltered -like "*2003*") {
            $osCheckResultFiltered = "2003"
        }

        # Server 2008 R2, 2012+, or 2016+
        if (($osCheckResult -like "*2008 R2*" -or $osCheckResult -like "*2012*" -or $osCheckResult -like "*2016*")) {
            Out-Message "Server is running $osCheckResult"
            Out-Message "Obtaining hostname of $ip_address"
            try {
                $server = [System.Net.Dns]::GetHostbyaddress($ip_address) | Select-Object -ExpandProperty Hostname
                $server = $server.Split('.')[0]
            }
            catch [Exception] {
                Out-Message -Yellow "[WARNING]: Unable to determine hostname of $ip_address"
                Out-Message -Yellow "Certificate Expiration Discovery will use $ip_address as hostname"
                $server = $ip_address
            }
            Out-Message "Obtaining certificates matching ISSUER $global:issuer in $server"
            $getCertsResult = Get-CertsFromIssuer -server $server
            if ($getCertsResult -eq $true) {
                Out-Message "Certificates mathcing search filter have been obtained"
                Out-Message "Processing result to get certificate information"
                $getCertDetails = Get-CertDetails -server $server -platform $osCheckResultFiltered
                if ($getCertDetails -eq $true) {
                    Out-Message "Certificate details have been obtained from $server"
                }
                else {
                    Out-Message -Red "Unable to obtain certificate information from certificate stored of $server"
                    Out-Message -Red "[ERROR]: $getCertDetails"
                }
            }
            else {
                Out-Message -Red "Unable to obtain certificates from ISSUER $global:issuer"
                Out-Message -Red "[ERROR]: $getCertsResult"
            }
        }

        # Server 2008 (Non-R2) and 2003
        elseif ($osCheckResult -like "*2008*" -or $osCheckResult -like "*2003*") {
            Out-Message "Server is running $osCheckResult"
            Out-Message -Yellow "[WARNING]: This OS version is only partially supported"
            Out-Message -Yellow "Only certificates in the Local Computer scope can be quieried; Certificates specific to the current user will not be queried"
            Out-Message "Obtaining hostname of $ip_address"l
            try {
                $server = [System.Net.Dns]::GetHostbyaddress($ip_address) | Select-Object -ExpandProperty Hostname
                $server = $server.Split('.')[0]
            }
            catch [Exception] {
                Out-Message -Yellow "[WARNING]: Unable to determine hostname of $ip_address"
                Out-Message -Yellow "Certificate Expiration Discovery will use $ip_address as hostname"
                $server = $ip_address
            }
            Out-Message "Obtaining certificates matching ISSUER $global:issuer in $server"
            $getCertsResultNonR2 = Get-CertsFromIssuerNonR2 -server $server -platform $osCheckResultFiltered
            if ($getCertsResultNonR2 -eq $true) {
                Out-Message "Certificate details have been obtained"
            }
            else {
                Out-Message -Red "Unable to obtain certificates from ISSUER $global:issuer"
                Out-Message -Red "[ERROR]: $getCertsResultNonR2"
            }
        }

        # Unsupported OS
        else {
            if ($osCheckResult -ne $null) {
                Out-Message "$ip_address is running $osCheckResult"
            }
            Out-Message -Yellow "Unsupported OS detected on $ip_address; this program will only execute on servers running Windows 2008 or later"
            Out-Message "Discovery terminated for address $ip_address"
        }
    }
    else {
        Out-Message "Target server $ip_address is offline"
        Out-Message "Discovery terminated for address $ip_address"
    }
}

# Generate HTML report
Set-HTMLReport

# Send Report via Email
try {
    Out-Message "Sending Report to $global:emailrecipients"
    $emailSendResult = Send-Report
    if ($emailSendResult -eq $true) {
        Out-Message -Green "Report has been successfully sent to $global:emailrecipients"
    }
    else {
            Out-Message -Red "Unable to send email to $global:emailrecipients"
        Out-Message -Red "[ERROR]: $emailSendResult"
    }
}
catch [Exception] {
    Out-Message -Red "Unable to send email to $global:emailrecipients"
    Out-Message -Red "[ERROR]: $_"
}

# Perform cleanup
Out-Message "Performing cleanup of old logs and reports"
try {
    Remove-OldLogs
    Remove-OldReports
    Out-Message "Cleanup complete"
}
catch [Exception] {
    Out-Message -Yellow "[WARNING]: Failed to complete cleanup of old logs and reports"
    Out-Message -Yellow "Please do manual cleanup as needed"
    Out-Message -Silent "[Return Message]: $_"
}
##################################################### END OF PROGRAM ###################################################
