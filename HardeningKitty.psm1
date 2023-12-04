Function Invoke-HardeningKitty {

    <#
    .SYNOPSIS

        Invoke-HardeningKitty - Checks and hardens your Windows configuration


         =^._.^=
        _(      )/  HardeningKitty


        Author:  Michael Schneider
        License: MIT
        Required Dependencies: None
        Optional Dependencies: None


    .DESCRIPTION

        HardeningKitty supports hardening of a Windows system. The configuration of the system is
        retrieved and assessed using a finding list. In addition, the system can be hardened according
        to predefined values. HardeningKitty reads settings from the registry and uses other modules
        to read configurations outside the registry.


    .PARAMETER FileFindingList

        Path to a finding list in CSV format. HardeningKitty has one list each for machine and user settings.


    .PARAMETER Mode

        The mode Config only retrieves the settings, while the mode Audit performs an assessment of the settings.
        The mode HailMary hardens the system according to recommendations of the HardeningKitty list.


    .PARAMETER EmojiSupport

        The use of emoji is activated. The terminal should support this accordingly. Windows Terminal
        offers full support.


    .PARAMETER Log

        The logging function is activated. The script output is additionally logged in a file. The file
        name is assigned by HardeningKitty itself and the file is stored in the same directory as the script.


    .PARAMETER LogFile

        The name and location of the log file can be defined by the user.


    .PARAMETER Report

        The retrieved settings and their assessment result are stored in CSV format in a machine-readable format.
        The file name is assigned by HardeningKitty itself and the file is stored in the same directory as the script.


    .PARAMETER ReportFile

        The name and location of the report file can be defined by the user.

    .PARAMETER Backup

        The retrieved settings and their assessment result are stored in CSV format in a machine-readable format with all value to backup your previous config.

    .PARAMETER SkipMachineInformation

        Information about the system is not queried and displayed. This may be useful while debugging or
        using multiple lists on the same system.

    .PARAMETER SkipUserInformation

        Information about the user is not queried and displayed. This may be useful while debugging or
        using multiple lists on the same system.

    .PARAMETER SkipLanguageWarning

        Do not show the language warning on an no-english Windows system.

    .PARAMETER SkipRestorePoint

        Do not create a System Restore Point in HailMary mode. HardeningKitty strongly recommends to backup your system before running Hail Mary. However,
        creating can be skipped, for example, if HailMary is executed several times in a row. By default, Windows allows a restore point every 24 hours.
        Another reason is when HardeningKitty is run as a user and thus lacks privileges.

    .PARAMETER Filter

        The Filter parameter can be used to filter the hardening list. For this purpose the PowerShell ScriptBlock syntax must be used, for example { $_.ID -eq 4505 }.
        The following elements are useful for filtering: ID, Category, Name, Method, and Severity.

    .EXAMPLE
        Invoke-HardeningKitty -Mode Audit -Log -Report

        HardeningKitty performs an audit, saves the results and creates a log file

    .EXAMPLE
        Invoke-HardeningKitty -FileFindingList finding_list_0x6d69636b_user.csv -SkipMachineInformation

        HardeningKitty performs an audit with a specific list and does not show machine information

    .EXAMPLE
        Invoke-HardeningKitty -Mode Config -Report -ReportFile C:\tmp\my_hardeningkitty_report.csv

        HardeningKitty uses the default list, and saves the results in a specific file

    .EXAMPLE
        Invoke-HardeningKitty -Filter { $_.Severity -eq "Medium" }

        HardeningKitty uses the default list, and checks only tests with the severity Medium
    #>

    [CmdletBinding()]
    Param (

        # Definition of the finding list, default is machine setting list
        [String]
        $FileFindingList,

        # Choose mode, read system config, audit system config, harden system config
        [ValidateSet("Audit", "Config", "HailMary", "GPO")]
        [String]
        $Mode = "Audit",

        # Activate emoji support for Windows Terminal
        [Switch]
        $EmojiSupport,

        # Create a log file
        [Switch]
        $Log,

        # Skip machine information, useful when debugging
        [Switch]
        $SkipMachineInformation,

        # Skip user information, useful when debugging
        [Switch]
        $SkipUserInformation,

        # Skip language warning, if you understand the risk
        [Switch]
        $SkipLanguageWarning,

        # Skip creating a System Restore Point during Hail Mary mode
        [Switch]
        $SkipRestorePoint,

        # Define name and path of the log file
        [String]
        $LogFile,

        # Create a report file in CSV format
        [Switch]
        $Report,

        # Define name and path of the report file
        [String]
        $ReportFile,

        # Create a backup config file in CSV format
        [Switch]
        $Backup,

        # Define name and path of the backup file
        [String]
        $BackupFile,

        # Use PowerShell ScriptBlock syntax to filter the finding list
        [scriptblock]
        $Filter,

         # Define name of the GPO name
        [String]
        $GPOname
    )

    Function Write-ProtocolEntry {

        <#
        .SYNOPSIS

            Output of an event with timestamp and different formatting
            depending on the level. If the Log parameter is set, the
            output is also stored in a file.
        #>

        [CmdletBinding()]
        Param (

            [String]
            $Text,

            [String]
            $LogLevel
        )

        $Time = Get-Date -Format G

        Switch ($LogLevel) {
            "Info"    { $Message = "[*] $Time - $Text"; Write-Host $Message; Break }
            "Debug"   { $Message = "[-] $Time - $Text"; Write-Host -ForegroundColor Cyan $Message; Break }
            "Warning" { $Message = "[?] $Time - $Text"; Write-Host -ForegroundColor Yellow $Message; Break }
            "Error"   { $Message = "[!] $Time - $Text"; Write-Host -ForegroundColor Red $Message; Break }
            "Success" { $Message = "[$] $Time - $Text"; Write-Host -ForegroundColor Green $Message; Break }
            "Notime"  { $Message = "[*] $Text"; Write-Host -ForegroundColor Gray $Message; Break }
            Default   { $Message = "[*] $Time - $Text"; Write-Host $Message; }
        }

        If ($Log) {
            Add-MessageToFile -Text $Message -File $LogFile
        }
    }

    Function Add-MessageToFile {

        <#
        .SYNOPSIS

            Write message to a file, this function can be used for logs,
            reports, backups and more.
        #>

        [CmdletBinding()]
        Param (

            [String]
            $Text,

            [String]
            $File
        )

        try {
            Add-Content -Path $File -Value $Text -ErrorAction Stop
        } catch {
            Write-ProtocolEntry -Text "Error while writing log entries into $File. Aborting..." -LogLevel "Error"
            Break
        }

    }

    Function Write-ResultEntry {

        <#
        .SYNOPSIS

            Output of the assessment result with different formatting
            depending on the severity level. If emoji support is enabled,
            a suitable symbol is used for the severity rating.
        #>

        [CmdletBinding()]
        Param (

            [String]
            $Text,

            [String]
            $SeverityLevel
        )

        If ($EmojiSupport) {

            Switch ($SeverityLevel) {

                "Passed" { $Emoji = [char]::ConvertFromUtf32(0x1F63A); $Message = "[$Emoji] $Text"; Write-Host -ForegroundColor Gray $Message; Break }
                "Low"    { $Emoji = [char]::ConvertFromUtf32(0x1F63C); $Message = "[$Emoji] $Text"; Write-Host -ForegroundColor Cyan $Message; Break }
                "Medium" { $Emoji = [char]::ConvertFromUtf32(0x1F63F); $Message = "[$Emoji] $Text"; Write-Host -ForegroundColor Yellow $Message; Break }
                "High"   { $Emoji = [char]::ConvertFromUtf32(0x1F640); $Message = "[$Emoji] $Text"; Write-Host -ForegroundColor Red $Message; Break }
                Default  { $Message = "[*] $Text"; Write-Host $Message; }
            }

        } Else {

            Switch ($SeverityLevel) {

                "Passed" { $Message = "[+] $Text"; Write-Host -ForegroundColor Gray $Message; Break }
                "Low"    { $Message = "[-] $Text"; Write-Host -ForegroundColor Cyan $Message; Break }
                "Medium" { $Message = "[$] $Text"; Write-Host -ForegroundColor Yellow $Message; Break }
                "High"   { $Message = "[!] $Text"; Write-Host -ForegroundColor Red $Message; Break }
                Default  { $Message = "[*] $Text"; Write-Host $Message; }
            }
        }
    }

    Function Get-IniContent ($filePath) {

        <#
        .SYNOPSIS

            Read a .ini file into a tree of hashtables

        .NOTES

            Original source see https://devblogs.microsoft.com/scripting/use-powershell-to-work-with-any-ini-file/
        #>

        $ini = @{}
        switch -regex -file $FilePath {
            "^\[(.+)\]" {
                # Section
                $section = $matches[1]
                $ini[$section] = @{}
                $CommentCount = 0
            }
            "^(;.*)$" {
                # Comment
                $value = $matches[1]
                $CommentCount = $CommentCount + 1
                $name = "Comment" + $CommentCount
                $ini[$section][$name] = $value
            }
            "(.+?)\s*=(.*)" {
                # Key
                $name, $value = $matches[1..2]
                $ini[$section][$name] = $value
            }
        }

        return $ini
    }

    Function Out-IniFile($InputObject, $FilePath, $Encoding) {

        <#
            .SYNOPSIS

                Write a hashtable out to a .ini file

            .NOTES

                Original source see https://devblogs.microsoft.com/scripting/use-powershell-to-work-with-any-ini-file/
        #>

        $outFile = New-Item -Force -ItemType file -Path $Filepath

        foreach ($i in $InputObject.keys) {
            if (!($($InputObject[$i].GetType().Name) -eq "Hashtable")) {
                #No Sections
                Add-Content -Encoding $Encoding -Path $outFile -Value "$i=$($InputObject[$i])"
            } else {
                #Sections
                Add-Content -Encoding $Encoding -Path $outFile -Value "[$i]"
                Foreach ($j in ($InputObject[$i].keys | Sort-Object)) {
                    if ($j -match "^Comment[\d]+") {
                        Add-Content -Encoding $Encoding -Path $outFile -Value "$($InputObject[$i][$j])"
                    } else {
                        Add-Content -Encoding $Encoding -Path $outFile -Value "$j=$($InputObject[$i][$j])"
                    }
                }
                Add-Content -Encoding $Encoding -Path $outFile -Value ""
            }
        }
    }

    Function Get-HashtableValueDeep {

        <#
            .SYNOPSIS

                Get a value from a tree of hashtables
        #>

        [CmdletBinding()]
        Param (

            [Hashtable]
            $Table,

            [String]
            $Path
        )

        $Key = $Path.Split('\', 2)

        $Entry = $Table[$Key[0]]

        if ($Entry -is [hashtable] -and $Key.Length -eq 1) {
            throw "Path is incomplete (expected a leaf but still on a branch)"
        }

        if ($Entry -is [hashtable]) {
            return Get-HashtableValueDeep $Entry $Key[1];
        } else {
            if ($Key.Length -eq 1) {
                return $Entry
            } else {
                throw "Path is too long (expected a branch but arrived at a leaf before the end of the path)"
            }
        }
    }

    Function Set-HashtableValueDeep {

        <#
            .SYNOPSIS

                Set a value in a tree of hashtables, using recursion.
        #>

        [CmdletBinding()]
        Param (

            [Hashtable]
            $Table,

            [String]
            $Path,

            [String]
            $Value
        )

        $Key = $Path.Split('\', 2)

        $Entry = $Table[$Key[0]]

        if ($Key.Length -eq 2) {
            if ($null -eq $Entry) {
                $Table[$Key[0]] = @{}
            } elseif ($Entry -isnot [hashtable]) {
                throw "Not hashtable"
            }

            return Set-HashtableValueDeep -Table $Table[$Key[0]] -Path $Key[1] -Value $Value;
        } elseif ($Key.Length -eq 1) {
            $Table[$Key[0]] = $Value;
        }
    }

    Function Get-SidFromAccount {

        <#
            .SYNOPSIS

                Translate the account name (user or group) into the Security Identifier (SID)
        #>

        [CmdletBinding()]
        Param (

            [String]
            $AccountName
        )

        try {

            $AccountObject = New-Object System.Security.Principal.NTAccount($AccountName)
            $AccountSid = $AccountObject.Translate([System.Security.Principal.SecurityIdentifier]).Value

        } catch {

            # If translation fails, return account name
            $AccountSid = $AccountName
        }

        Return $AccountSid
    }

    Function Get-AccountFromSid {

        <#
            .SYNOPSIS

                Translate the Security Identifier (SID) into the account name (user or group)
        #>

        [CmdletBinding()]
        Param (

            [String]
            $AccountSid
        )

        try {

            $AccountObject = New-Object System.Security.Principal.SecurityIdentifier ($AccountSid)
            $AccountName = $AccountObject.Translate([System.Security.Principal.NTAccount]).Value

        } catch {

            # If translation fails, return account SID
            $AccountName = $AccountSid
        }

        Return $AccountName
    }

    Function Translate-SidFromWellkownAccount {

        <#
            .SYNOPSIS

                Translate the well-known account name (user or group) into the Security Identifier (SID)
                No attempt is made to get a Computer SID or Domain SID to identify groups such as Domain Admins,
                as the possibility for false positives is too great. In this case the account name is returned.
        #>

        [CmdletBinding()]
        Param (

            [String]
            $AccountName
        )

        Switch ($AccountName) {

            "BUILTIN\Account Operators" { $AccountSid = "S-1-5-32-548"; Break }
            "BUILTIN\Administrators" { $AccountSid = "S-1-5-32-544"; Break }
            "BUILTIN\Backup Operators" { $AccountSid = "S-1-5-32-551"; Break }
            "BUILTIN\Guests" { $AccountSid = "S-1-5-32-546"; Break }
            "BUILTIN\Power Users" { $AccountSid = "S-1-5-32-547"; Break }
            "BUILTIN\Print Operators" { $AccountSid = "S-1-5-32-550"; Break }
            "BUILTIN\Remote Desktop Users" { $AccountSid = "S-1-5-32-555"; Break }
            "BUILTIN\Server Operators" { $AccountSid = "S-1-5-32-549"; Break }
            "BUILTIN\Users" { $AccountSid = "S-1-5-32-545"; Break }
            "Everyone" { $AccountSid = "S-1-1-0"; Break }
            "NT AUTHORITY\ANONYMOUS LOGON" { $AccountSid = "S-1-5-7"; Break }
            "NT AUTHORITY\Authenticated Users" { $AccountSid = "S-1-5-11"; Break }
            "NT AUTHORITY\ENTERPRISE DOMAIN CONTROLLERS" { $AccountSid = "S-1-5-9"; Break }
            "NT AUTHORITY\IUSR" { $AccountSid = "S-1-5-17"; Break }
            "NT AUTHORITY\Local account and member of Administrators group" { $AccountSid = "S-1-5-114"; Break }
            "NT AUTHORITY\Local account" { $AccountSid = "S-1-5-113"; Break }
            "NT AUTHORITY\LOCAL SERVICE" { $AccountSid = "S-1-5-19"; Break }
            "NT AUTHORITY\NETWORK SERVICE" { $AccountSid = "S-1-5-20"; Break }
            "NT AUTHORITY\SERVICE" { $AccountSid = "S-1-5-6"; Break }
            "NT AUTHORITY\SYSTEM" { $AccountSid = "S-1-5-18"; Break }
            "NT SERVICE\WdiServiceHost" { $AccountSid = "S-1-5-80-3139157870-2983391045-3678747466-658725712-1809340420"; Break }
            "NT VIRTUAL MACHINE\Virtual Machines" { $AccountSid = "S-1-5-83-0"; Break }
            "Window Manager\Window Manager Group" { $AccountSid = "S-1-5-90-0"; Break }
            Default { $AccountSid = $AccountName }
        }

        Return $AccountSid
    }

    function Write-NotAdminError {
        [CmdletBinding()]
        param (
            [String]
            $FindingID,
            [String]
            $FindingName,
            [string]
            $FindingMethod
        )

        $Script:StatsError++
        $Message = "ID " + $FindingID + ", " + $FindingName + ", Method " + $FindingMethod + " requires admin privileges. Test skipped."
        Write-ProtocolEntry -Text $Message -LogLevel "Error"
    }

    function Write-BinaryError {
        [CmdletBinding()]
        param (
            [String]
            $Binary,
            [String]
            $FindingID,
            [String]
            $FindingName,
            [string]
            $FindingMethod
        )
        $Script:StatsError++
        $Message = "ID " + $FindingID + ", " + $FindingName + ", Method " + $FindingMethod + " requires $Binary and it was not found. Test skipped."
        Write-ProtocolEntry -Text $Message -LogLevel "Error"
    }

    function ConvertToInt {
        [CmdletBinding()]
        Param (

            [String]
            $string
        )
        $int64 = $null
        $int32 = $null

        # Attempt to parse the string as an Int32
        if ([Int32]::TryParse($string, [ref]$int32)) {
            return $int32
        }

        # Attempt to parse the string as an Int64
        if ([Int64]::TryParse($string, [ref]$int64)) {
            return $int64
        }

        # If the string cannot be parsed as either an Int32 or an Int64, throw an error
        throw "Cannot convert string '$string' to an integer."
    }

    #
    # Binary Locations
    #
    $BinarySecedit  = "C:\Windows\System32\secedit.exe"
    $BinaryAuditpol = "C:\Windows\System32\auditpol.exe"
    $BinaryNet      = "C:\Windows\System32\net.exe"
    $BinaryBcdedit  = "C:\Windows\System32\bcdedit.exe"

    #
    # Start Main
    #
    $HardeningKittyVersion = "0.9.2-1690255284"

    #
    # Log, report and backup file
    #
    $Hostname = $env:COMPUTERNAME.ToLower()
    $FileDate = Get-Date -Format yyyyMMdd-HHmmss
    $WinSystemLocale = Get-WinSystemLocale
    $PowerShellVersion = "$($PSVersionTable.PSVersion.Major).$($PSVersionTable.PSVersion.Minor)"

    If ($FileFindingList.Length -eq 0) {
        $ListName = "finding_list_0x6d69636b_machine"
    } Else {
        $ListName = [System.IO.Path]::GetFileNameWithoutExtension($FileFindingList)
    }

    If ($Log -and $LogFile.Length -eq 0) {
        $LogFile = "hardeningkitty_log_" + $Hostname + "_" + $ListName + "-$FileDate.log"
    }
    If ($Report -and $ReportFile.Length -eq 0) {
        $ReportFile = "hardeningkitty_report_" + $Hostname + "_" + $ListName + "-$FileDate.csv"
    }
    If ($Backup -and $BackupFile.Length -eq 0) {
        $BackupFile = "hardeningkitty_backup_" + $Hostname + "_" + $ListName + "-$FileDate.csv"
    }
    $ReportAllResults = @()
    $BackupAllResults = @()

    #
    # Statistics
    #
    $StatsPassed = 0
    $StatsLow = 0
    $StatsMedium = 0
    $StatsHigh = 0
    $StatsTotal = 0
    $Script:StatsError = 0

    #
    # Header
    #
    Write-Output "`n"
    Write-Output "      =^._.^="
    Write-Output "     _(      )/  HardeningKitty $HardeningKittyVersion"
    Write-Output "`n"
    Write-ProtocolEntry -Text "Starting HardeningKitty" -LogLevel "Info"

    #
    # Machine information
    #
    If (-not($SkipMachineInformation)) {

        Write-Output "`n"
        Write-ProtocolEntry -Text "Getting machine information" -LogLevel "Info"

        #
        # The Get-ComputerInfo cmdlet gets a consolidated object of system
        # and operating system properties. This cmdlet was introduced in Windows PowerShell 5.1.
        #
        If ($PowerShellVersion -le 5.0) {

            try {

                $OperatingSystem = Get-CimInstance Win32_operatingsystem
                $ComputerSystem = Get-CimInstance Win32_ComputerSystem
                Switch ($ComputerSystem.domainrole) {
                    "0" { $Domainrole = "Standalone Workstation"; Break }
                    "1" { $Domainrole = "Member Workstation"; Break }
                    "2" { $Domainrole = "Standalone Server"; Break }
                    "3" { $Domainrole = "Member Server"; Break }
                    "4" { $Domainrole = "Backup Domain Controller"; Break }
                    "5" { $Domainrole = "Primary Domain Controller"; Break }
                }
                $Uptime = (Get-Date) - $OperatingSystem.LastBootUpTime

                $Message = "Hostname: " + $OperatingSystem.CSName
                Write-ProtocolEntry -Text $Message -LogLevel "Notime"
                $Message = "Domain: " + $ComputerSystem.Domain
                Write-ProtocolEntry -Text $Message -LogLevel "Notime"
                $Message = "Domain role: " + $Domainrole
                Write-ProtocolEntry -Text $Message -LogLevel "Notime"
                $Message = "Install date: " + $OperatingSystem.InstallDate
                Write-ProtocolEntry -Text $Message -LogLevel "Notime"
                $Message = "Last Boot Time: " + $OperatingSystem.LastBootUpTime
                Write-ProtocolEntry -Text $Message -LogLevel "Notime"
                $Message = "Uptime: " + $Uptime
                Write-ProtocolEntry -Text $Message -LogLevel "Notime"
                $Message = "Windows: " + $OperatingSystem.Caption
                Write-ProtocolEntry -Text $Message -LogLevel "Notime"
                $Message = "Windows version: " + $OperatingSystem.Version
                Write-ProtocolEntry -Text $Message -LogLevel "Notime"
                $Message = "Windows build: " + $OperatingSystem.BuildNumber
                Write-ProtocolEntry -Text $Message -LogLevel "Notime"
                $Message = "System-locale: " + $WinSystemLocale.Name
                Write-ProtocolEntry -Text $Message -LogLevel "Notime"
                $Message = "Powershell Version: " + $PowerShellVersion
                Write-ProtocolEntry -Text $Message -LogLevel "Notime"
            } catch {
                Write-ProtocolEntry -Text "Getting machine information failed." -LogLevel "Warning"
            }
        } Else {

            $MachineInformation = Get-ComputerInfo
            $Message = "Hostname: " + $MachineInformation.CsDNSHostName
            Write-ProtocolEntry -Text $Message -LogLevel "Notime"
            $Message = "Domain: " + $MachineInformation.CsDomain
            Write-ProtocolEntry -Text $Message -LogLevel "Notime"
            $Message = "Domain role: " + $MachineInformation.CsDomainRole
            Write-ProtocolEntry -Text $Message -LogLevel "Notime"
            $Message = "Install date: " + $MachineInformation.OsInstallDate
            Write-ProtocolEntry -Text $Message -LogLevel "Notime"
            $Message = "Last Boot Time: " + $MachineInformation.OsLastBootUpTime
            Write-ProtocolEntry -Text $Message -LogLevel "Notime"
            $Message = "Uptime: " + $MachineInformation.OsUptime
            Write-ProtocolEntry -Text $Message -LogLevel "Notime"
            $Message = "Windows: " + $MachineInformation.OsName
            Write-ProtocolEntry -Text $Message -LogLevel "Notime"
            $Message = "Windows edition: " + $MachineInformation.WindowsEditionId
            Write-ProtocolEntry -Text $Message -LogLevel "Notime"
            $Message = "Windows version: " + $MachineInformation.WindowsVersion
            Write-ProtocolEntry -Text $Message -LogLevel "Notime"
            $Message = "Windows build: " + $MachineInformation.WindowsBuildLabEx
            Write-ProtocolEntry -Text $Message -LogLevel "Notime"
            $Message = "System-locale: " + $WinSystemLocale.Name
            Write-ProtocolEntry -Text $Message -LogLevel "Notime"
            $Message = "Powershell Version: " + $PowerShellVersion
            Write-ProtocolEntry -Text $Message -LogLevel "Notime"
        }
    }

    #
    # Warning for non-english systems
    #
    If ($WinSystemLocale.Name -ne "en-US" -and -not($SkipLanguageWarning)) {
        Write-Output "`n"
        Write-ProtocolEntry -Text "Language warning" -LogLevel "Info"
        $Message = "HardeningKitty was developed for the system language 'en-US'. This system uses '" + $WinSystemLocale.Name + "' Language-dependent analyses can sometimes produce false results. Please create an issue if this occurs."
        Write-ProtocolEntry -Text $Message -LogLevel "Warning"
    }

    #
    # User information
    #
    If (-not($SkipUserInformation)) {
        Write-Output "`n"
        Write-ProtocolEntry -Text "Getting user information" -LogLevel "Info"

        $Message = "Username: " + [Security.Principal.WindowsIdentity]::GetCurrent().Name
        Write-ProtocolEntry -Text $Message -LogLevel "Notime"
        $IsAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
        $Message = "Is Admin: " + $IsAdmin
        Write-ProtocolEntry -Text $Message -LogLevel "Notime"
    } Else {
        $IsAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
    }

    #
    # Start Config/Audit mode
    # The processing is done per category of the finding list.
    # The finding list defines which module is used and the arguments and recommended values for the test.
    #
    If ($Mode -eq "Audit" -or $Mode -eq "Config") {

        # A CSV finding list is imported. HardeningKitty has one machine and one user list.
        If ($FileFindingList.Length -eq 0) {

            $CurrentLocation = $PSScriptRoot
            $DefaultList = "$CurrentLocation\lists\finding_list_0x6d69636b_machine.csv"

            If (Test-Path -Path $DefaultList) {
                $FileFindingList = $DefaultList
            } Else {
                $Message = "The finding list $DefaultList was not found."
                Write-ProtocolEntry -Text $Message -LogLevel "Error"
                Continue
            }
        }

        $FindingList = Import-Csv -Path $FileFindingList -Delimiter ","
        If ($Filter) {
            $FindingList = $FindingList | Where-Object -FilterScript $Filter
            If ($FindingList.Length -eq 0) {
                $Message = "Your filter did not return any results, please adjust the filter so that HardeningKitty has something to work with."
                Write-ProtocolEntry -Text $Message -LogLevel "Error"
                Break
            }
        }
        $LastCategory = ""

        ForEach ($Finding in $FindingList) {

            #
            # Reset
            #
            $Result = ""

            #
            # Category
            #
            If ($LastCategory -ne $Finding.Category) {

                $Message = "Starting Category " + $Finding.Category
                Write-Output "`n"
                Write-ProtocolEntry -Text $Message -LogLevel "Info"
                $LastCategory = $Finding.Category
            }

            #
            # Get Registry Item
            # Registry entries can be read with a native PowerShell function. The retrieved value is evaluated later.
            # If the registry entry is not available, a default value is used. This must be specified in the finding list.
            #
            If ($Finding.Method -eq 'Registry') {

                If (Test-Path -Path $Finding.RegistryPath) {

                    try {
                        $Result = Get-ItemPropertyValue -Path $Finding.RegistryPath -Name $Finding.RegistryItem
                        # Join the result with ";" character if result is an array
                        if ($Result -is [system.array] -and ($Finding.RegistryItem -eq "Machine" -Or $Finding.RegistryItem -eq "EccCurves" -Or $Finding.RegistryItem -eq "NullSessionPipes")){
                            $Result = $Result -join ";"
                        }
                    } catch {
                        If ($Backup) {
                            # If an error occurs and the backup mode is enabled, we consider that this policy does not exist
                            # and put "-NODATA-" as result to identify it as non-existing policy
                            $Result = "-NODATA-"
                        } Else {
                            $Result = $Finding.DefaultValue
                        }
                    }
                } Else {
                    If ($Backup) {
                        # If this policy does not exist and the backup mode is enabled, we
                        # put "-NODATA-" as result to identify it as non-existing policy
                        $Result = "-NODATA-"
                    } Else {
                        $Result = $Finding.DefaultValue
                        # Multiline Registry Keys need a semicolon instead of a space
                        If ($Finding.RegistryItem -eq "Machine") {
                            $Result = $Result.Replace(";", " ")
                        }
                    }
                }
            }

            #
            # Get secedit policy
            # Secedit configures and analyzes system security, results are written
            # to a file, which means HardeningKitty must create a temporary file
            # and afterwards delete it. HardeningKitty is very orderly.
            #
            ElseIf ($Finding.Method -eq 'secedit') {

                # Check if Secedit binary is available, skip test if not
                If (-Not (Test-Path $BinarySecedit)) {
                    Write-BinaryError -Binary $BinarySecedit -FindingID $Finding.ID -FindingName $Finding.Name -FindingMethod $Finding.Method
                    Continue
                }

                # Check if the user has admin rights, skip test if not
                If (-not($IsAdmin)) {
                    Write-NotAdminError -FindingID $Finding.ID -FindingName $Finding.Name -FindingMethod $Finding.Method
                    Continue
                }

                $TempFileName = [System.IO.Path]::GetTempFileName()

                $Area = "";

                Switch ($Finding.Category) {
                    "Account Policies" { $Area = "SECURITYPOLICY"; Break }
                    "Security Options" { $Area = "SECURITYPOLICY"; Break }
                }

                &$BinarySecedit /export /cfg $TempFileName /areas $Area | Out-Null

                $Data = Get-IniContent $TempFileName

                $Value = Get-HashtableValueDeep $Data $Finding.MethodArgument

                if ($null -eq $Value) {
                    $Result = $null
                } else {
                    $Result = $Value -as [int]
                }

                Remove-Item $TempFileName
            }

            #
            # Get Registry List and search for item
            # Depending on the registry structure, the value cannot be accessed directly, but must be found within a data structure
            # If the registry entry is not available, a default value is used. This must be specified in the finding list.
            #
            ElseIf ($Finding.Method -eq 'RegistryList') {

                If (Test-Path -Path $Finding.RegistryPath) {

                    try {
                        $ResultList = Get-ItemProperty -Path $Finding.RegistryPath

                        If ($ResultList | Where-Object { $_ -like "*" + $Finding.RegistryItem + "*" }) {
                            $Result = $Finding.RegistryItem
                        } Else {
                            $Result = "-NODATA-"
                        }

                    } catch {
                        $Result = $Finding.DefaultValue
                    }
                } Else {
                    If ($Backup) {
                        # If this policy does not exist and the backup mode is enabled, we
                        # put "-NODATA-" as result to identify it as non-existing policy
                        $Result = "-NODATA-"
                    } Else {
                        $Result = $Finding.DefaultValue
                    }
                }
            }

            #
            # Get Audit Policy
            # The output of auditpol.exe is parsed and will be evaluated later.
            # The desired value is not output directly, some output lines can be ignored
            # and are therefore skipped. If the output changes, the parsing must be adjusted :(
            #
            ElseIf ($Finding.Method -eq 'auditpol') {

                # Check if Auditpol binary is available, skip test if not
                If (-Not (Test-Path $BinaryAuditpol)) {
                    Write-BinaryError -Binary $BinaryAuditpol -FindingID $Finding.ID -FindingName $Finding.Name -FindingMethod $Finding.Method
                    Continue
                }

                # Check if the user has admin rights, skip test if not
                If (-not($IsAdmin)) {
                    Write-NotAdminError -FindingID $Finding.ID -FindingName $Finding.Name -FindingMethod $Finding.Method
                    Continue
                }

                try {

                    $SubCategory = $Finding.MethodArgument

                    # auditpol.exe does not write a backup in an existing file, so we have to build a name instead of create one
                    $TempFileName = [System.IO.Path]::GetTempPath() + "HardeningKitty_auditpol-" + $(Get-Date -Format yyyyMMdd-HHmmss) + ".csv"
                    &$BinaryAuditpol /backup /file:$TempFileName > $null

                    $ResultOutputLoad = Get-Content $TempFileName
                    foreach ($line in $ResultOutputLoad) {
                        $table = $line.Split(",")
                        if ($table[3] -eq $SubCategory) {

                            # Translate setting value (works only for English list, so this is workaround)
                            Switch ($table[6]) {
                                "0" { $Result = "No Auditing"; Break }
                                "1" { $Result = "Success"; Break }
                                "2" { $Result = "Failure"; Break }
                                "3" { $Result = "Success and Failure"; Break }
                            }
                        }
                    }

                    # House cleaning
                    Remove-Item $TempFileName
                    Clear-Variable -Name ("ResultOutputLoad", "table")

                } catch {
                    $Result = $Finding.DefaultValue
                }
            }

            #
            # Get Account Policy
            # The output of net.exe is parsed and will be evaluated later.
            # It may be necessary to use the /domain parameter when calling net.exe.
            # The values of the user executing the script are read out. These may not match the password policy.
            #
            ElseIf ($Finding.Method -eq 'accountpolicy') {

                # Check if net binary is available, skip test if not
                If (-Not (Test-Path $BinaryNet)) {
                    Write-BinaryError -Binary $BinaryNet -FindingID $Finding.ID -FindingName $Finding.Name -FindingMethod $Finding.Method
                    Continue
                }

                try {

                    $ResultOutput = &$BinaryNet accounts

                    # "Parse" account policy
                    Switch ($Finding.Name) {
                        "Force user logoff how long after time expires" { $ResultOutput[0] -match '([a-zA-Z:, /-]+)  ([a-z0-9, ]+)' | Out-Null; $Result = $Matches[2]; Break }
                        "Network security: Force logoff when logon hours expires" { $ResultOutput[0] -match '([a-zA-Z:, /-]+)  ([a-z0-9, ]+)' | Out-Null; $Result = $Matches[2]; Break }
                        "Minimum password age" { $ResultOutput[1] -match '([a-zA-Z:, /-]+)  ([a-z0-9, ]+)' | Out-Null; $Result = $Matches[2]; Break }
                        "Maximum password age" { $ResultOutput[2] -match '([a-zA-Z:, /-]+)  ([a-z0-9, ]+)' | Out-Null; $Result = $Matches[2]; Break }
                        "Minimum password length" { $ResultOutput[3] -match '([a-zA-Z:, /-]+)  ([a-z0-9, ]+)' | Out-Null; $Result = $Matches[2]; Break }
                        "Length of password history maintained" { $ResultOutput[4] -match '([a-zA-Z:, /-]+)  ([a-z0-9, ]+)' | Out-Null; $Result = $Matches[2]; Break }
                        "Account lockout threshold" { $ResultOutput[5] -match '([a-zA-Z:, /-]+)  ([a-z0-9, ]+)' | Out-Null; $Result = $Matches[2]; Break }
                        "Account lockout duration" { $ResultOutput[6] -match '([a-zA-Z:, /-]+)  ([a-z0-9, ]+)' | Out-Null; $Result = $Matches[2]; Break }
                        "Reset account lockout counter" { $ResultOutput[7] -match '([a-zA-Z:, /-]+)  ([a-z0-9, ]+)' | Out-Null; $Result = $Matches[2]; Break }
                    }

                } catch {
                    $Result = $Finding.DefaultValue
                }
            }

            #
            # Get Local Account Information
            # The PowerShell function Get-LocalUser is used for this.
            # In order to get the correct user, the query is made via the SID,
            # the base value of the computer must first be retrieved.
            #
            ElseIf ($Finding.Method -eq 'localaccount') {

                try {

                    # Get Computer SID
                    $ComputerSid = ((Get-LocalUser | Select-Object -First 1).SID).AccountDomainSID.ToString()

                    # Get User Status
                    $Sid = $ComputerSid + "-" + $Finding.MethodArgument
                    $ResultOutput = Get-LocalUser -SID $Sid

                    If ($Finding.Name.Contains("account status")) {
                        $Result = $ResultOutput.Enabled
                    } ElseIf ($Finding.Name.Contains("Rename")) {
                        $Result = $ResultOutput.Name
                    } Else {
                        $Result = $Finding.DefaultValue
                    }

                } catch {
                    $Result = $Finding.DefaultValue
                }
            }

            #
            # User Rights Assignment
            # This method was first developed with the tool accessck.exe, hence the name.
            # Due to compatibility problems in languages other than English, secedit.exe is
            # now used to read the User Rights Assignments.
            #
            # Secedit configures and analyzes system security, results are written
            # to a file, which means HardeningKitty must create a temporary file
            # and afterwards delete it. HardeningKitty is very orderly.
            #
            ElseIf ($Finding.Method -eq 'accesschk') {

                # Check if Secedit binary is available, skip test if not
                If (-Not (Test-Path $BinarySecedit)) {
                    Write-BinaryError -Binary $BinarySecedit -FindingID $Finding.ID -FindingName $Finding.Name -FindingMethod $Finding.Method
                    Continue
                }

                # Check if the user has admin rights, skip test if not
                If (-not($IsAdmin)) {
                    Write-NotAdminError -FindingID $Finding.ID -FindingName $Finding.Name -FindingMethod $Finding.Method
                    Continue
                }

                $TempFileName = [System.IO.Path]::GetTempFileName()

                try {

                    &$BinarySecedit /export /cfg $TempFileName /areas USER_RIGHTS | Out-Null
                    $ResultOutputRaw = Get-Content -Encoding unicode $TempFileName | Select-String $Finding.MethodArgument

                    If ($null -eq $ResultOutputRaw) {
                        $Result = ""
                    } Else {
                        $ResultOutputList = $ResultOutputRaw.ToString().split("=").Trim()
                        $Result = $ResultOutputList[1] -Replace "\*", ""
                        $Result = $Result -Replace ",", ";"
                    }

                } catch {
                    # If secedit did not work, throw an error instead of using the DefaultValue
                    $Script:StatsError++
                    $Message = "ID " + $Finding.ID + ", " + $Finding.Name + ", secedit.exe could not read the configuration. Test skipped."
                    Write-ProtocolEntry -Text $Message -LogLevel "Error"
                    Continue
                }

                Remove-Item $TempFileName
            }

            #
            # Windows Optional Feature
            # Yay, a native PowerShell function! The status of the feature can easily be read out directly.
            #
            ElseIf ($Finding.Method -eq 'WindowsOptionalFeature') {

                # Check if the user has admin rights, skip test if not
                If (-not($IsAdmin)) {
                    Write-NotAdminError -FindingID $Finding.ID -FindingName $Finding.Name -FindingMethod $Finding.Method
                    Continue
                }

                try {

                    $ResultOutput = Get-WindowsOptionalFeature -Online -FeatureName $Finding.MethodArgument
                    $Result = $ResultOutput.State

                } catch {
                    $Result = $Finding.DefaultValue
                }
            }

            #
            # Get CimInstance and search for item
            # Via a CIM instance classes can be read from the CIM server.
            # Afterwards, you have to search for the correct property within the class.
            #
            ElseIf ($Finding.Method -eq 'CimInstance') {

                try {

                    $ResultList = Get-CimInstance -ClassName $Finding.ClassName -Namespace $Finding.Namespace
                    $Property = $Finding.Property

                    If ($ResultList.$Property | Where-Object { $_ -like "*" + $Finding.RecommendedValue + "*" }) {
                        $Result = $Finding.RecommendedValue
                    } Else {
                        $Result = "Not available"
                    }

                } catch {
                    $Result = $Finding.DefaultValue
                }
            }

            #
            # BitLocker Drive Encryption
            # The values are saved from a PowerShell function into an object.
            # The desired arguments can be accessed directly.
            #
            ElseIf ($Finding.Method -eq 'BitLockerVolume') {

                # Check if the user has admin rights, skip test if not
                If (-not($IsAdmin)) {
                    Write-NotAdminError -FindingID $Finding.ID -FindingName $Finding.Name -FindingMethod $Finding.Method
                    Continue
                }

                try {

                    $ResultOutput = Get-BitLockerVolume -MountPoint $Env:SystemDrive
                    If ($ResultOutput.VolumeType -eq 'OperatingSystem') {
                        $ResultArgument = $Finding.MethodArgument
                        $Result = $ResultOutput.$ResultArgument
                    } Else {
                        $Result = "Manual check required"
                    }

                } catch {
                    $Result = $Finding.DefaultValue
                }
            }

            #
            # PowerShell Language Mode
            # This is a single purpose function, the desired configuration is output directly.
            #
            ElseIf ($Finding.Method -eq 'LanguageMode') {

                try {

                    $ResultOutput = $ExecutionContext.SessionState.LanguageMode
                    $Result = $ResultOutput

                } catch {
                    $Result = $Finding.DefaultValue
                }
            }

            #
            # Microsoft Defender Status
            # The values are saved from a PowerShell function into an object.
            # The desired arguments can be accessed directly.
            #
            ElseIf ($Finding.Method -eq 'MpComputerStatus') {

                try {

                    $ResultOutput = Get-MpComputerStatus
                    $ResultArgument = $Finding.MethodArgument
                    $Result = $ResultOutput.$ResultArgument

                } catch {
                    $Result = $Finding.DefaultValue
                }
            }

            #
            # Microsoft Defender Preferences
            # The values are saved from a PowerShell function into an object.
            # The desired arguments can be accessed directly.
            #
            ElseIf ($Finding.Method -eq 'MpPreference') {

                try {

                    $ResultOutput = Get-MpPreference
                    $ResultArgument = $Finding.MethodArgument
                    $Result = $ResultOutput.$ResultArgument

                } catch {
                    $Result = $Finding.DefaultValue
                }
            }

            #
            # Microsoft Defender Preferences - Attack surface reduction rules (ASR rules)
            # The values are saved from a PowerShell function into an object.
            # The desired arguments can be accessed directly.
            #
            ElseIf ($Finding.Method -eq 'MpPreferenceAsr') {

                try {

                    $ResultOutput = Get-MpPreference
                    $ResultAsrIds = $ResultOutput.AttackSurfaceReductionRules_Ids
                    $ResultAsrActions = $ResultOutput.AttackSurfaceReductionRules_Actions
                    $Result = $Finding.DefaultValue
                    $Counter = 0

                    ForEach ($AsrRule in $ResultAsrIds) {

                        If ($AsrRule -eq $Finding.MethodArgument) {
                            $Result = $ResultAsrActions[$Counter]
                            Continue
                        }
                        $Counter++
                    }

                } catch {
                    $Result = $Finding.DefaultValue
                }
            }

            #
            # Microsoft Defender Preferences - Exclusion lists
            # The values are saved from a PowerShell function into an object.
            # The desired arguments can be accessed directly.
            #
            ElseIf ($Finding.Method -eq 'MpPreferenceExclusion') {

                # Check if the user has admin rights, skip test if not
                # Normal users are not allowed to get exclusions
                If (-not($IsAdmin)) {
                    Write-NotAdminError -FindingID $Finding.ID -FindingName $Finding.Name -FindingMethod $Finding.Method
                    Continue
                }

                try {

                    $ResultOutput = Get-MpPreference
                    $ExclusionType = $Finding.MethodArgument
                    $ResultExclusions = $ResultOutput.$ExclusionType

                    ForEach ($Exclusion in $ResultExclusions) {
                        $Result += $Exclusion + ";"
                    }
                    # Remove last character
                    $Result = $Result -replace ".$"

                } catch {
                    $Result = $Finding.DefaultValue
                }
            }

            #
            # Exploit protection (System)
            # The values are saved from a PowerShell function into an object.
            # The desired arguments can be accessed directly.
            # Since the object has several dimensions and there is only one dimension
            # in the finding list (lazy) a workaround with split must be done...
            #
            ElseIf ($Finding.Method -eq 'Processmitigation') {

                try {

                    $ResultOutput = Get-ProcessMitigation -System
                    $ResultArgumentArray = $Finding.MethodArgument.Split(".")
                    $ResultArgument0 = $ResultArgumentArray[0]
                    $ResultArgument1 = $ResultArgumentArray[1]
                    $Result = $ResultOutput.$ResultArgument0.$ResultArgument1

                } catch {
                    $Result = $Finding.DefaultValue
                }
            }

            #
            # Exploit protection (Application)
            # The values are saved from a PowerShell function into an object.
            # The desired arguments can be accessed directly.
            # Since the object has several dimensions and there is only one dimension
            # in the finding list (lazy) a workaround with split must be done...
            #
            ElseIf ($Finding.Method -eq 'ProcessmitigationApplication') {

                try {

                    $ResultArgumentArray = $Finding.MethodArgument.Split("/")
                    $ResultOutput = Get-ProcessMitigation -Name $ResultArgumentArray[0]
                    $ResultArgument0 = $ResultArgumentArray[1]
                    $ResultArgument1 = $ResultArgumentArray[2]
                    $Result = $ResultOutput.$ResultArgument0.$ResultArgument1

                } catch {
                    $Result = $Finding.DefaultValue
                }
            }

            #
            # bcdedit
            # Again, the output of a tool must be searched and parsed. Ugly...
            #
            ElseIf ($Finding.Method -eq 'bcdedit') {

                # Check if the user has admin rights, skip test if not
                If (-not($IsAdmin)) {
                    Write-NotAdminError -FindingID $Finding.ID -FindingName $Finding.Name -FindingMethod $Finding.Method
                    Continue
                }

                # Check if Bcdedit binary is available, skip test if not
                If (-Not (Test-Path $BinaryBcdedit)) {
                    Write-BinaryError -Binary $BinaryBcdedit -FindingID $Finding.ID -FindingName $Finding.Name -FindingMethod $Finding.Method
                    Continue
                }

                try {

                    $ResultOutput = &$BinaryBcdedit
                    $ResultOutput = $ResultOutput | Where-Object { $_ -like "*" + $Finding.RecommendedValue + "*" }

                    If ($ResultOutput -match ' ([a-z,A-Z]+)') {
                        $Result = $Matches[1]
                    } Else {
                        $Result = $Finding.DefaultValue
                    }

                } catch {
                    $Result = $Finding.DefaultValue
                }
            }

            #
            # FirewallRule
            # Search for a specific firewall rule with a given name
            #
            ElseIf ($Finding.Method -eq 'FirewallRule') {

                try {

                    $ResultOutput = Get-NetFirewallRule -PolicyStore ActiveStore -DisplayName $Finding.Name 2> $null
                    $Result = $ResultOutput.Enabled

                } catch {
                    $Result = $Finding.DefaultValue
                }
            }

            #
            # Service
            # Check the status of a service
            #
            ElseIf ($Finding.Method -eq 'service') {

                try {

                    $ResultOutput = Get-Service -Name $Finding.MethodArgument 2> $null
                    $Result = $ResultOutput.StartType

                } catch {
                    $Result = $Finding.DefaultValue
                }
            }

            #
            # Scheduled Task
            # Check the status of a scheduled task
            #
            ElseIf ($Finding.Method -eq 'ScheduledTask') {

                try {

                    $ResultOutput = Get-ScheduledTask -TaskName $Finding.MethodArgument 2> $null
                    $Result = $ResultOutput.State

                } catch {
                    $Result = $Finding.DefaultValue
                }
            }

            #
            # Compare result value and recommendation
            # The finding list specifies the test, as well as the recommended values.
            # There are two output formats, one for command line output and one for the CSV file.
            #
            If ($Mode -eq "Audit") {

                #
                # User Right Assignment
                # For multilingual support, a SID translation takes place and then the known SID values are compared with each other.
                # The results are already available as SID (from secedit) and therefore the specifications are now also translated and still sorted.
                #
                If ($Finding.Method -eq 'accesschk') {

                    $SaveRecommendedValue = $Finding.RecommendedValue

                    If ($Result -ne '') {

                        $ListRecommended = $Finding.RecommendedValue.Split(";")
                        $ListRecommendedSid = @()

                        # SID Translation
                        ForEach ($AccountName in $ListRecommended) {
                            $AccountSid = Translate-SidFromWellkownAccount -AccountName $AccountName
                            $ListRecommendedSid += $AccountSid
                        }
                        # Sort SID List
                        $ListRecommendedSid = $ListRecommendedSid | Sort-Object

                        # Build String
                        ForEach ($AccountName in $ListRecommendedSid) {
                            [String] $RecommendedValueSid += $AccountName + ";"
                        }

                        $RecommendedValueSid = $RecommendedValueSid -replace ".$"
                        $Finding.RecommendedValue = $RecommendedValueSid
                        Clear-Variable -Name ("RecommendedValueSid")
                    }
                }

                #
                # Exception handling for special registry keys
                # Machine => Network access: Remotely accessible registry paths
                # Hardened UNC Paths => Remove spaces in result and recommendation only if result is not null or empty
                #
                If ($Finding.Method -eq 'Registry' -and $Finding.RegistryItem -eq "Machine") {
                    # $Finding.RecommendedValue = $Finding.RecommendedValue.Replace(";", " ")
                } ElseIf ($Finding.Method -eq 'Registry' -and $Finding.RegistryPath -eq "HKLM:\Software\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths") {
                    If (![string]::IsNullOrEmpty($Result)) {
                        $Result = $Result.Replace(" ", "")
                    }
                    $Finding.RecommendedValue = $Finding.RecommendedValue.Replace(" ", "")
                }

                #
                # Handling for registry keys with an "advanced" format
                #
                If ($Finding.Method -eq 'Registry' -and $Finding.RegistryItem -eq "ASRRules") {

                    try {
                        $ResultAsr = $Result.Split("|")
                        ForEach ($AsrRow in $ResultAsr) {
                            $AsrRule = $AsrRow.Split("=")
                            If ($AsrRule[0] -eq $Finding.MethodArgument) {
                                $Result = $AsrRule[1]
                                Break
                            } Else {
                            $Result = $Finding.DefaultValue
                            }
                        }
                    } catch {
                        $Result = $Finding.DefaultValue
                    }
                }

                $ResultPassed = $false
                Switch ($Finding.Operator) {

                    "="  { If ([string] $Result -eq $Finding.RecommendedValue) { $ResultPassed = $true }; Break }
                    "<=" { try { If ([int]$Result -le [int]$Finding.RecommendedValue) { $ResultPassed = $true } } catch { $ResultPassed = $false }; Break }
                    "<=!0" { try { If ([int]$Result -le [int]$Finding.RecommendedValue -and [int]$Result -ne 0) { $ResultPassed = $true } } catch { $ResultPassed = $false }; Break }
                    ">=" { try { If ([int]$Result -ge [int]$Finding.RecommendedValue) { $ResultPassed = $true } } catch { $ResultPassed = $false }; Break }
                    "contains" { If ($Result.ToString().Contains($Finding.RecommendedValue)) { $ResultPassed = $true }; Break }
                    "!="  { If ([string] $Result -ne $Finding.RecommendedValue) { $ResultPassed = $true }; Break }
                    "=|0" { try { If ([string]$Result -eq $Finding.RecommendedValue -or $Result.Length -eq 0) { $ResultPassed = $true } } catch { $ResultPassed = $false }; Break }
                }

                #
                # Restore Result after SID translation
                # The results are already available as SID, for better readability they are translated into their names
                #
                If ($Finding.Method -eq 'accesschk') {

                    If ($Result -ne "") {

                        $ListResult = $Result.Split(";")
                        ForEach ($AccountSid in $ListResult) {
                            $AccountName = Get-AccountFromSid -AccountSid $AccountSid
                            [String] $ResultName += $AccountName.Trim() + ";"
                        }
                        $ResultName = $ResultName -replace ".$"
                        $Result = $ResultName
                        Clear-Variable -Name ("ResultName")
                    }

                    $Finding.RecommendedValue = $SaveRecommendedValue
                }

                If ($ResultPassed) {

                    # Passed
                    $TestResult = "Passed"
                    $Message = "ID " + $Finding.ID + ", " + $Finding.Name + ", Result=$Result, Recommended=" + $Finding.RecommendedValue + ", Severity=Passed"
                    Write-ResultEntry -Text $Message -SeverityLevel "Passed"

                    If ($Log) {
                        Add-MessageToFile -Text $Message -File $LogFile
                    }

                    If ($Report) {
                        $ReportResult = [ordered] @{
                            ID = $Finding.ID
                            Category = $Finding.Category
                            Name = $Finding.Name
                            Severity = "Passed"
                            Result = $Result
                            Recommended = $Finding.RecommendedValue
                            TestResult = $TestResult
                            SeverityFinding = $Finding.Severity
                        }
                        $ReportAllResults += $ReportResult
                    }

                    # Increment Counter
                    $StatsPassed++

                } Else {

                    # Failed
                    $TestResult = "Failed"
                    If ($Finding.Operator -eq "!=") {
                        $Message = "ID " + $Finding.ID + ", " + $Finding.Name + ", Result=$Result, Recommended=Not " + $Finding.RecommendedValue + ", Severity=" + $Finding.Severity
                    } Else {
                        $Message = "ID " + $Finding.ID + ", " + $Finding.Name + ", Result=$Result, Recommended=" + $Finding.RecommendedValue + ", Severity=" + $Finding.Severity
                    }

                    Write-ResultEntry -Text $Message -SeverityLevel $Finding.Severity

                    If ($Log) {
                        Add-MessageToFile -Text $Message -File $LogFile
                    }

                    If ($Report) {
                        $ReportResult = [ordered] @{
                            ID = $Finding.ID
                            Category = $Finding.Category
                            Name = $Finding.Name
                            Severity = $Finding.Severity
                            Result = $Result
                            Recommended = $Finding.RecommendedValue
                            TestResult = $TestResult
                            SeverityFinding = $Finding.Severity
                        }
                        $ReportAllResults += $ReportResult
                    }

                    # Increment Counter
                    Switch ($Finding.Severity) {

                        "Low"    { $StatsLow++; Break }
                        "Medium" { $StatsMedium++; Break }
                        "High"   { $StatsHigh++; Break }
                    }
                }

            #
            # Only return received value
            #
            } Elseif ($Mode -eq "Config") {

                $Message = "ID " + $Finding.ID + "; " + $Finding.Name + "; Result=$Result"
                Write-ResultEntry -Text $Message

                If ($Log) {
                    Add-MessageToFile -Text $Message -File $LogFile
                }
                If ($Report) {
                    $ReportResult = [ordered] @{
                        ID = $Finding.ID
                        Category = $Finding.Category
                        Name = $Finding.Name
                        Severity = ""
                        Result = $Result
                        Recommended = $Finding.RecommendedValue
                        TestResult = ""
                        SeverityFinding = ""
                    }
                    $ReportAllResults += $ReportResult
                }
                If ($Backup) {

                    # Do not save Firewall rules in the backup file, if they are not set
                    If ( $Finding.Method -eq "FirewallRule" -and !$Result ) {
                        Continue
                    }

                    $BackupResult = [ordered] @{
                        ID = $Finding.ID
                        Category = $Finding.Category
                        Name = $Finding.Name
                        Method = $Finding.Method
                        MethodArgument = $Finding.MethodArgument
                        RegistryPath = $Finding.RegistryPath
                        RegistryItem = $Finding.RegistryItem
                        ClassName =$Finding.ClassName
                        Namespace = $Finding.Namespace
                        Property = $Finding.Property
                        DefaultValue = $Finding.DefaultValue
                        RecommendedValue = $Result
                        Operator = $Finding.Operator
                        Severity = $Finding.Severity
                    }
                    $BackupAllResults += $BackupResult
                }
            }
        }
    }

    #
    # Start HailMary mode
    # HardeningKitty configures all settings in a finding list file.
    # Even though HardeningKitty works very carefully, please only
    # use HailyMary if you know what you are doing.
    #
    Elseif ($Mode -eq "HailMary") {

        # A CSV finding list is imported
        If ($FileFindingList.Length -eq 0) {

            # No fallback to a default list anymore, just show an error message
            # $CurrentLocation = $PSScriptRoot
            # $DefaultList = "$CurrentLocation\lists\finding_list_0x6d69636b_machine.csv"
            $Message = "No finding list has been specified - I'm sorry Dave, I'm afraid I can't do that. Please select a suitable list and specify it with the FileFindingList parameter. Select the finding list wisely and check beforehand whether the settings can affect the stability or the function of your system."
            Write-ProtocolEntry -Text $Message -LogLevel "Error"
            Continue

            If (Test-Path -Path $DefaultList) {
                $FileFindingList = $DefaultList
            } Else {
                $Message = "The finding list $DefaultList was not found."
                Write-ProtocolEntry -Text $Message -LogLevel "Error"
                Continue
            }
        }

        $FindingList = Import-Csv -Path $FileFindingList -Delimiter ","
        $LastCategory = ""
        $ProcessmitigationEnableArray = @()
        $ProcessmitigationDisableArray = @()

        #
        # Create a System Restore Point
        #

        If (-not($SkipRestorePoint)) {

            $Message = "Creating a system restore point"
            Write-Output "`n"
            Write-ProtocolEntry -Text $Message -LogLevel "Info"

            # Check if the user has admin rights, skip test if not
            If (-not($IsAdmin)) {
                Write-NotAdminError -FindingID "42" -FindingName "System Restore Point" -FindingMethod "Checkpoint-Computer"
                Continue
            }

            Try {
                Enable-ComputerRestore -Drive $Env:SystemDrive
                Checkpoint-Computer -Description 'HardeningKitty' -RestorePointType 'MODIFY_SETTINGS' -ErrorAction Stop -WarningAction Stop
            } catch {

                $Message = "Creating a system restore point failed. Use -SkipRestorePoint to run HailMary anyway. Be careful!"
                Write-ResultEntry -Text $Message -SeverityLevel "High"
                If ($Log) {
                    Add-MessageToFile -Text $Message -File $LogFile
                }
                Break
            }

            $Message = "Creating a system restore point was successful"
            Write-ResultEntry -Text $Message -SeverityLevel "Passed"
            If ($Log) {
                Add-MessageToFile -Text $Message -File $LogFile
            }
        }

        ForEach ($Finding in $FindingList) {

            #
            # Category
            #
            If ($LastCategory -ne $Finding.Category) {

                $Message = "Starting Category " + $Finding.Category
                Write-Output "`n"
                Write-ProtocolEntry -Text $Message -LogLevel "Info"
                $LastCategory = $Finding.Category
            }

            #
            # Registry
            # Create or modify a registry value.
            #
            If ($Finding.Method -eq 'Registry' -or $Finding.Method -eq 'RegistryList') {

                # Check if the user has admin rights, skip test if not
                If (-not($IsAdmin) -and -not($Finding.RegistryPath.StartsWith("HKCU:\"))) {
                    Write-NotAdminError -FindingID $Finding.ID -FindingName $Finding.Name -FindingMethod $Finding.Method
                    Continue
                }

                #
                # Do not set/configure certain registry
                # ASR rules configured with Intune (ASRRules, ASROnlyExclusions)
                # Defender expections configured with Intune (ExcludedExtensions, ExcludedPaths, ExcludedProcesses)
                #
                If ($Finding.RegistryItem -eq "ASRRules" -Or $Finding.RegistryItem -eq "ASROnlyExclusions" -Or $Finding.RegistryItem -eq "ExcludedExtensions" -Or $Finding.RegistryItem -eq "ExcludedPaths" -Or $Finding.RegistryItem -eq "ExcludedProcesses") {
                    $ResultText = "This setting is not configured by HardeningKitty"
                    $Message = "ID " + $Finding.ID + ", " + $Finding.RegistryPath + ", " + $Finding.RegistryItem + ", " + $ResultText
                    $MessageSeverity = "Passed"
                    $TestResult = "Passed"
                    Write-ResultEntry -Text $Message -SeverityLevel $MessageSeverity
                    If ($Log) {
                        Add-MessageToFile -Text $Message -File $LogFile
                    }
                    If ($Report) {
                        $ReportResult = [ordered] @{
                            ID = $Finding.ID
                            Category = $Finding.Category
                            Name = $Finding.Name
                            Severity = $MessageSeverity
                            Result = $ResultText
                            Recommended = ""
                            TestResult = $TestResult
                            SeverityFinding = ""
                        }
                        $ReportAllResults += $ReportResult
                    }
                    Continue
                }

                $RegType = "String"

                #
                # Basically this is true, but there is an exception for the finding "MitigationOptions_FontBocking",
                # the value "10000000000" is written to the registry as a string...
                #
                # ... and more exceptions are added over time:
                #
                # MitigationOptions_FontBocking => Mitigation Options: Untrusted Font Blocking
                # Machine => Network access: Remotely accessible registry paths
                # Retention => Event Log Service: *: Control Event Log behavior when the log file reaches its maximum size
                # AllocateDASD => Devices: Allowed to format and eject removable media
                # ScRemoveOption => Interactive logon: Smart card removal behavior
                # AutoAdminLogon => MSS: (AutoAdminLogon) Enable Automatic Logon (not recommended)
                #
                If ($Finding.RegistryItem -eq "MitigationOptions_FontBocking" -Or $Finding.RegistryItem -eq "Retention" -Or $Finding.RegistryItem -eq "AllocateDASD" -Or $Finding.RegistryItem -eq "ScRemoveOption" -Or $Finding.RegistryItem -eq "AutoAdminLogon") {
                    $RegType = "String"
                } ElseIf ($Finding.RegistryItem -eq "Machine" -Or $Finding.RegistryItem -eq "EccCurves" -Or $Finding.RegistryItem -eq "NullSessionPipes") {
                    $RegType = "MultiString"
                    $Finding.RecommendedValue = $Finding.RecommendedValue -split ";"
                } ElseIf ($Finding.RecommendedValue -match "^\d+$") {
                    $RegType = "DWord"
                }

                If (!(Test-Path $Finding.RegistryPath)) {

                    $Result = New-Item $Finding.RegistryPath -Force;

                    If ($Result) {
                        $ResultText = "Registry key created"
                        $Message = "ID " + $Finding.ID + ", " + $Finding.RegistryPath + ", " + $Finding.RegistryItem + ", " + $ResultText
                        $MessageSeverity = "Passed"
                        $TestResult = "Passed"
                        Write-ResultEntry -Text $Message -SeverityLevel $MessageSeverity
                        If ($Log) {
                            Add-MessageToFile -Text $Message -File $LogFile
                        }
                        If ($Report) {
                            $ReportResult = [ordered] @{
                                ID = $Finding.ID
                                Category = $Finding.Category
                                Name = $Finding.Name
                                Severity = $MessageSeverity
                                Result = $ResultText
                                Recommended = ""
                                TestResult = $TestResult
                                SeverityFinding = ""
                            }
                            $ReportAllResults += $ReportResult
                        }
                    } Else {
                        $ResultText = "Failed to create registry key"
                        $Message = "ID " + $Finding.ID + ", " + $Finding.RegistryPath + ", " + $Finding.RegistryItem + ", " + $ResultText
                        $MessageSeverity = "High"
                        $TestResult = "Failed"
                        Write-ResultEntry -Text $Message -SeverityLevel $MessageSeverity
                        If ($Log) {
                            Add-MessageToFile -Text $Message -File $LogFile
                        }
                        If ($Report) {
                            $ReportResult = [ordered] @{
                                ID = $Finding.ID
                                Category = $Finding.Category
                                Name = $Finding.Name
                                Severity = $MessageSeverity
                                Result = $ResultText
                                Recommended = ""
                                TestResult = $TestResult
                                SeverityFinding = ""
                            }
                            $ReportAllResults += $ReportResult
                        }
                        Continue
                    }
                }

                #
                # The method RegistryList needs a separate handling, because the name of the registry key is dynamic, usually incremented.
                # Therefore, it is searched whether the value already exists or not. If the value does not exist, it counts how many
                # other values are already there in order to set the next higher value and not overwrite existing keys.
                #
                If ($Finding.Method -eq 'RegistryList') {
                    $RegistryItemFound = $false
                    $ListPolicies = $Finding.RegistryPath
                    $ResultList = Get-ItemProperty -Path $Finding.RegistryPath
                    $ResultListCounter = 0
                    If ($ResultList | Where-Object { $_ -like "*" + $Finding.RegistryItem + "*" }) {
                        $ResultList.PSObject.Properties | ForEach-Object {
                            If ($_.Value -eq $Finding.RegistryItem) {
                                $Finding.RegistryItem = $_.Name
                                $RegistryItemFound = $true
                            }
                        }
                    } Else {
                        $ResultList.PSObject.Properties | ForEach-Object {
                            $ResultListCounter++
                        }
                    }
                    # Check if registryItem (key name) has been found or not
                    If ($RegistryItemFound -eq $false) {
                        If ($ResultListCounter -eq 0) {
                            $Finding.RegistryItem = 1
                        } Else {
                            # Check if key is already used and can be used
                            $KeyAlreadyExists = $true
                            $Finding.RegistryItem = 1
                            while ($KeyAlreadyExists){
                                try {
                                    # This key exists and should be incremented
                                    $Result = Get-ItemPropertyValue -Path $Finding.RegistryPath -Name $Finding.RegistryItem
                                    $Finding.RegistryItem=$Finding.RegistryItem+1
                                    $KeyAlreadyExists = $true;
                                } catch {
                                    # This key does not exist and it can be used
                                    $KeyAlreadyExists = $false;
                                }
                            }
                        }
                    }
                }
                $ResultText = ""
                # Remove this policy if it should not exists
                If ($Finding.RecommendedValue -eq '-NODATA-') {

                    # Check if the key (item) already exists
                    $keyExists = $true;
                    try {
                        # This key exists
                        $Result = Get-ItemPropertyValue -Path $Finding.RegistryPath -Name $Finding.RegistryItem
                    } catch {
                        # This key does not exist
                        $keyExists = $false;
                    }

                    If ($keyExists) {
                        # key exists
                        try {
                            Remove-ItemProperty -Path $Finding.RegistryPath -Name $Finding.RegistryItem
                            $ResultText = "Registry key removed"
                            $Message = "ID " + $Finding.ID + ", " + $Finding.RegistryPath + ", " + $Finding.RegistryItem + ", " + $ResultText
                            $MessageSeverity = "Passed"
                            $TestResult = "Passed"
                        } catch {
                            $ResultText = "Failed to remove registry key"
                            $Message = "ID " + $Finding.ID + ", " + $Finding.RegistryPath + ", " + $Finding.RegistryItem + ", " + $ResultText
                            $MessageSeverity = "High"
                            $TestResult = "Failed"
                        }
                    } Else {
                        # key does not exists

                        If ($Finding.Method -eq 'RegistryList') {
                            # Don't show incorrect item
                            $ResultText = "This value does not already exists in list policy"
                            $Message = "ID " + $Finding.ID + ", " + $Finding.RegistryPath + ", " + $ResultText
                        } Else {
                            $ResultText = "This key policy does not already exists"
                            $Message = "ID " + $Finding.ID + ", " + $Finding.RegistryPath + ", " + $Finding.RegistryItem + ", " + $ResultText
                        }
                        $MessageSeverity = "Low"
                        $TestResult = "Passed"
                    }


                } Else {
                    $Result = Set-ItemProperty -PassThru -Path $Finding.RegistryPath -Name $Finding.RegistryItem -Type $RegType -Value $Finding.RecommendedValue

                    if ($Result) {
                        $ResultText = "Registry value created/modified"
                        $Message = "ID " + $Finding.ID + ", " + $Finding.RegistryPath + ", " + $Finding.RegistryItem + ", " + $ResultText
                        $MessageSeverity = "Passed"
                        $TestResult = "Passed"
                    } else {
                        $ResultText = "Failed to create registry value"
                        $Message = "ID " + $Finding.ID + ", " + $Finding.RegistryPath + ", " + $Finding.RegistryItem + ", " + $ResultText
                        $MessageSeverity = "High"
                        $TestResult = "Failed"
                    }
                }

                Write-ResultEntry -Text $Message -SeverityLevel $MessageSeverity
                If ($Log) {
                    Add-MessageToFile -Text $Message -File $LogFile
                }
                If ($Report) {
                    $ReportResult = [ordered] @{
                        ID = $Finding.ID
                        Category = $Finding.Category
                        Name = $Finding.Name
                        Severity = $MessageSeverity
                        Result = $ResultText
                        Recommended = ""
                        TestResult = $TestResult
                        SeverityFinding = ""
                    }
                    $ReportAllResults += $ReportResult
                }
            }

            #
            # secedit
            # Set a security policy
            #
            If ($Finding.Method -eq 'secedit') {

                # Check if Secedit binary is available, skip test if not
                If (-Not (Test-Path $BinarySecedit)) {
                    Write-BinaryError -Binary $BinarySecedit -FindingID $Finding.ID -FindingName $Finding.Name -FindingMethod $Finding.Method
                    Continue
                }

                # Check if the user has admin rights, skip test if not
                If (-not($IsAdmin)) {
                    Write-NotAdminError -FindingID $Finding.ID -FindingName $Finding.Name -FindingMethod $Finding.Method
                    Continue
                }

                $Area = "";

                Switch ($Finding.Category) {
                    "Account Policies" { $Area = "SECURITYPOLICY"; Break }
                    "Security Options" { $Area = "SECURITYPOLICY"; Break }
                }

                $TempFileName = [System.IO.Path]::GetTempFileName()
                $TempDbFileName = [System.IO.Path]::GetTempFileName()

                &$BinarySecedit /export /cfg $TempFileName /areas $Area | Out-Null

                $Data = Get-IniContent $TempFileName

                Set-HashtableValueDeep -Table $Data -Path $Finding.MethodArgument -Value $Finding.RecommendedValue

                Out-IniFile -InputObject $Data -FilePath $TempFileName -Encoding Unicode

                &$BinarySecedit /import /cfg $TempFileName /overwrite /areas $Area /db $TempDbFileName /quiet | Out-Null

                if ($LastExitCode -ne 0) {
                    $ResultText = "Failed to import security policy into temporary database"
                    $Message = "ID " + $Finding.ID + ", " + $Finding.MethodArgument + ", " + $Finding.RecommendedValue + ", " + $ResultText
                    $MessageSeverity = "High"
                    $TestResult = "Failed"
                    Write-ResultEntry -Text $Message -SeverityLevel $MessageSeverity
                    If ($Log) {
                        Add-MessageToFile -Text $Message -File $LogFile
                    }
                    If ($Report) {
                        $ReportResult = [ordered] @{
                            ID = $Finding.ID
                            Category = $Finding.Category
                            Name = $Finding.Name
                            Severity = $MessageSeverity
                            Result = $ResultText
                            Recommended = ""
                            TestResult = $TestResult
                            SeverityFinding = ""
                        }
                        $ReportAllResults += $ReportResult
                    }
                    Remove-Item $TempFileName
                    Remove-Item $TempDbFileName
                    Continue
                }

                $ResultText = "Imported security policy into temporary database"
                $Message = "ID " + $Finding.ID + ", " + $Finding.MethodArgument + ", " + $Finding.RecommendedValue + ", " + $ResultText
                $MessageSeverity = "Passed"
                $TestResult = "Passed"

                Write-ResultEntry -Text $Message -SeverityLevel $MessageSeverity
                If ($Log) {
                    Add-MessageToFile -Text $Message -File $LogFile
                }
                If ($Report) {
                    $ReportResult = [ordered] @{
                        ID = $Finding.ID
                        Category = $Finding.Category
                        Name = $Finding.Name
                        Severity = $MessageSeverity
                        Result = $ResultText
                        Recommended = ""
                        TestResult = $TestResult
                        SeverityFinding = ""
                    }
                    $ReportAllResults += $ReportResult
                }

                &$BinarySecedit /configure /db $TempDbFileName /overwrite /areas SECURITYPOLICY /quiet | Out-Null

                if ($LastExitCode -ne 0) {
                    $ResultText = "Failed to configure security policy"
                    $Message = "ID " + $Finding.ID + ", " + $Finding.MethodArgument + ", " + $Finding.RecommendedValue + ", " + $ResultText
                    $MessageSeverity = "High"
                    $TestResult = "Failed"
                    Write-ResultEntry -Text $Message -SeverityLevel $MessageSeverity
                    If ($Log) {
                        Add-MessageToFile -Text $Message -File $LogFile
                    }
                    If ($Report) {
                        $ReportResult = [ordered] @{
                            ID = $Finding.ID
                            Category = $Finding.Category
                            Name = $Finding.Name
                            Severity = $MessageSeverity
                            Result = $ResultText
                            Recommended = ""
                            TestResult = $TestResult
                            SeverityFinding = ""
                        }
                        $ReportAllResults += $ReportResult
                    }
                    Remove-Item $TempFileName
                    Remove-Item $TempDbFileName
                    Continue
                }

                $ResultText = "Configured security policy"
                $Message = "ID " + $Finding.ID + ", " + $Finding.MethodArgument + ", " + $Finding.RecommendedValue + ", " + $ResultText
                $MessageSeverity = "Passed"
                $TestResult = "Passed"

                Write-ResultEntry -Text $Message -SeverityLevel $MessageSeverity
                If ($Log) {
                    Add-MessageToFile -Text $Message -File $LogFile
                }
                If ($Report) {
                    $ReportResult = [ordered] @{
                        ID = $Finding.ID
                        Category = $Finding.Category
                        Name = $Finding.Name
                        Severity = $MessageSeverity
                        Result = $ResultText
                        Recommended = ""
                        TestResult = $TestResult
                        SeverityFinding = ""
                    }
                    $ReportAllResults += $ReportResult
                }

                Remove-Item $TempFileName
                Remove-Item $TempDbFileName
            }

            #
            # auditpol
            # Set an audit policy
            #
            If ($Finding.Method -eq 'auditpol') {

                # Check if Auditpol binary is available, skip test if not
                If (-Not (Test-Path $BinaryAuditpol)) {
                    Write-BinaryError -Binary $BinaryAuditpol -FindingID $Finding.ID -FindingName $Finding.Name -FindingMethod $Finding.Method
                    Continue
                }

                # Check if the user has admin rights, skip test if not
                If (-not($IsAdmin)) {
                    Write-NotAdminError -FindingID $Finding.ID -FindingName $Finding.Name -FindingMethod $Finding.Method
                    Continue
                }

                $Success = if ($Finding.RecommendedValue -ilike "*success*") { "enable" } else { "disable" }
                $Failure = if ($Finding.RecommendedValue -ilike "*failure*") { "enable" } else { "disable" }

                $SubCategory = $Finding.MethodArgument

                &$BinaryAuditpol /set /subcategory:"$($SubCategory)" /success:$($Success) /failure:$($Failure) | Out-Null

                if ($LastExitCode -eq 0) {
                    $ResultText = "Audit policy set"
                    $Message = "ID " + $Finding.ID + ", " + $Finding.Name + ", " + $Finding.RecommendedValue + ", " + $ResultText
                    $MessageSeverity = "Passed"
                    $TestResult = "Passed"
                } else {
                    $ResultText = "Failed to set audit policy"
                    $Message = "ID " + $Finding.ID + ", " + $Finding.Name + ", " + $Finding.RecommendedValue + ", " + $ResultText
                    $MessageSeverity = "High"
                    $TestResult = "Failed"
                }

                Write-ResultEntry -Text $Message -SeverityLevel $MessageSeverity
                If ($Log) {
                    Add-MessageToFile -Text $Message -File $LogFile
                }
                If ($Report) {
                    $ReportResult = [ordered] @{
                        ID = $Finding.ID
                        Category = $Finding.Category
                        Name = $Finding.Name
                        Severity = $MessageSeverity
                        Result = $ResultText
                        Recommended = ""
                        TestResult = $TestResult
                        SeverityFinding = ""
                    }
                    $ReportAllResults += $ReportResult
                }
            }

            #
            # accountpolicy
            # Set a user account policy
            #
            If ($Finding.Method -eq 'accountpolicy') {

                # Check if the user has admin rights, skip test if not
                If (-not($IsAdmin)) {
                    Write-NotAdminError -FindingID $Finding.ID -FindingName $Finding.Name -FindingMethod $Finding.Method
                    Continue
                }

                # Check if net binary is available, skip test if not
                If (-Not (Test-Path $BinaryNet)) {
                    Write-BinaryError -Binary $BinaryNet -FindingID $Finding.ID -FindingName $Finding.Name -FindingMethod $Finding.Method
                    Continue
                }

                $Sw = "";

                Switch ($Finding.Name) {
                    "Force user logoff how long after time expires" { $Sw = "/FORCELOGOFF:$($Finding.RecommendedValue)"; Break }
                    "Minimum password age" { $Sw = "/MINPWAGE:$($Finding.RecommendedValue)"; Break }
                    "Maximum password age" { $Sw = "/MAXPWAGE:$($Finding.RecommendedValue)"; Break }
                    "Minimum password length" { $Sw = "/MINPWLEN:$($Finding.RecommendedValue)"; Break }
                    "Length of password history maintained" { $Sw = "/UNIQUEPW:$($Finding.RecommendedValue)"; Break }
                    "Account lockout threshold" { $Sw = "/lockoutthreshold:$($Finding.RecommendedValue)"; Break; }
                    "Account lockout duration" { $Sw = @("/lockoutwindow:$($Finding.RecommendedValue)", "/lockoutduration:$($Finding.RecommendedValue)"); Break }
                    "Reset account lockout counter" { $Sw = "/lockoutwindow:$($Finding.RecommendedValue)"; Break }
                }

                &$BinaryNet accounts $Sw | Out-Null

                if ($LastExitCode -eq 0) {
                    $ResultText = "Account policy set"
                    $Message = "ID " + $Finding.ID + ", " + $Finding.Name + ", " + $Finding.RecommendedValue + ", " + $ResultText
                    $MessageSeverity = "Passed"
                    $TestResult = "Passed"
                } else {
                    $ResultText = "Failed to set account policy"
                    $Message = "ID " + $Finding.ID + ", " + $Finding.Name + ", " + $Finding.RecommendedValue + ", " + $ResultText
                    $MessageSeverity = "High"
                    $TestResult = "Failed"
                }

                Write-ResultEntry -Text $Message -SeverityLevel $MessageSeverity
                If ($Log) {
                    Add-MessageToFile -Text $Message -File $LogFile
                }
                If ($Report) {
                    $ReportResult = [ordered] @{
                        ID = $Finding.ID
                        Category = $Finding.Category
                        Name = $Finding.Name
                        Severity = $MessageSeverity
                        Result = $ResultText
                        Recommended = ""
                        TestResult = $TestResult
                        SeverityFinding = ""
                    }
                    $ReportAllResults += $ReportResult
                }
            }

            #
            # accesschk
            # For the audit mode, accesschk is used, but the rights are set with secedit.
            #
            If ($Finding.Method -eq 'accesschk') {

                # Check if Secedit binary is available, skip test if not
                If (-Not (Test-Path $BinarySecedit)) {
                    Write-BinaryError -Binary $BinarySecedit -FindingID $Finding.ID -FindingName $Finding.Name -FindingMethod $Finding.Method
                    Continue
                }

                # Check if the user has admin rights, skip test if not
                If (-not($IsAdmin)) {
                    Write-NotAdminError -FindingID $Finding.ID -FindingName $Finding.Name -FindingMethod $Finding.Method
                    Continue
                }

                $TempFileName = [System.IO.Path]::GetTempFileName()
                $TempDbFileName = [System.IO.Path]::GetTempFileName()

                &$BinarySecedit /export /cfg $TempFileName /areas USER_RIGHTS | Out-Null

                if ($Finding.RecommendedValue -eq "") {
                    (Get-Content -Encoding unicode $TempFileName) -replace "$($Finding.MethodArgument).*", "$($Finding.MethodArgument) = " | Out-File $TempFileName
                } else {
                    $ListTranslated = @()
                    $Finding.RecommendedValue -split ';' | Where-Object {
                        # Get SID to translate the account name
                        $AccountSid = Translate-SidFromWellkownAccount -AccountName $_
                        # Get account name from system with SID (local translation)
                        $AccountName = Get-AccountFromSid -AccountSid $AccountSid
                        $ListTranslated += $AccountName
                    }

                    # If User Right Assignment exists, replace values
                    If ( ((Get-Content -Encoding unicode $TempFileName) | Select-String $($Finding.MethodArgument)).Count -gt 0 ) {
                        (Get-Content -Encoding unicode $TempFileName) -replace "$($Finding.MethodArgument).*", "$($Finding.MethodArgument) = $($ListTranslated -join ',')" | Out-File $TempFileName
                    }
                    # If it does not exist, add a new entry into the file at the right position
                    Else {
                        $TempFileContent = Get-Content -Encoding unicode $TempFileName
                        $LineNumber = $TempFileContent.Count
                        $TempFileContent[$LineNumber - 3] = "$($Finding.MethodArgument) = $($ListTranslated -join ',')"
                        $TempFileContent[$LineNumber - 2] = "[Version]"
                        $TempFileContent[$LineNumber - 1] = 'signature="$CHICAGO$"'
                        $TempFileContent += "Revision=1"
                        $TempFileContent | Set-Content -Encoding unicode $TempFileName
                    }
                }

                &$BinarySecedit /import /cfg $TempFileName /overwrite /areas USER_RIGHTS /db $TempDbFileName /quiet | Out-Null

                if ($LastExitCode -ne 0) {
                    $ResultText = "Failed to import user right assignment into temporary database"
                    $Message = "ID " + $Finding.ID + ", " + $Finding.MethodArgument + ", " + $Finding.RecommendedValue + ", " + $ResultText
                    $MessageSeverity = "High"
                    Write-ResultEntry -Text $Message -SeverityLevel $MessageSeverity
                    Remove-Item $TempFileName
                    Remove-Item $TempDbFileName
                    Continue
                }

                $ResultText = "Imported user right assignment into temporary database"
                $Message = "ID " + $Finding.ID + ", " + $Finding.MethodArgument + ", " + $Finding.RecommendedValue + ", " + $ResultText
                $MessageSeverity = "Passed"
                $TestResult = "Passed"

                Write-ResultEntry -Text $Message -SeverityLevel $MessageSeverity
                If ($Log) {
                    Add-MessageToFile -Text $Message -File $LogFile
                }
                If ($Report) {
                    $ReportResult = [ordered] @{
                        ID = $Finding.ID
                        Category = $Finding.Category
                        Name = $Finding.Name
                        Severity = $MessageSeverity
                        Result = $ResultText
                        Recommended = ""
                        TestResult = $TestResult
                        SeverityFinding = ""
                    }
                    $ReportAllResults += $ReportResult
                }

                &$BinarySecedit /configure /db $TempDbFileName /overwrite /areas USER_RIGHTS /quiet | Out-Null

                if ($LastExitCode -ne 0) {
                    $ResultText = "Failed to configure system user right assignment"
                    $Message = "ID " + $Finding.ID + ", " + $Finding.MethodArgument + ", " + $Finding.RecommendedValue + ", " + $ResultText
                    $MessageSeverity = "High"
                    $TestResult = "Failed"
                    Write-ResultEntry -Text $Message -SeverityLevel $MessageSeverity
                    If ($Log) {
                        Add-MessageToFile -Text $Message -File $LogFile
                    }
                    If ($Report) {
                       $ReportResult = [ordered] @{
                            ID = $Finding.ID
                            Category = $Finding.Category
                            Name = $Finding.Name
                            Severity = $MessageSeverity
                            Result = $ResultText
                            Recommended = ""
                            TestResult = $TestResult
                            SeverityFinding = ""
                        }
                        $ReportAllResults += $ReportResult
                    }
                    Remove-Item $TempFileName
                    Remove-Item $TempDbFileName
                    Continue
                }

                $ResultText = "Configured system user right assignment"
                $Message = "ID " + $Finding.ID + ", " + $Finding.MethodArgument + ", " + $Finding.RecommendedValue + ", " + $ResultText
                $MessageSeverity = "Passed"
                $TestResult = "Passed"

                Write-ResultEntry -Text $Message -SeverityLevel $MessageSeverity
                If ($Log) {
                    Add-MessageToFile -Text $Message -File $LogFile
                }
                If ($Report) {
                    $ReportResult = [ordered] @{
                        ID = $Finding.ID
                        Category = $Finding.Category
                        Name = $Finding.Name
                        Severity = $MessageSeverity
                        Result = $ResultText
                        Recommended = ""
                        TestResult = $TestResult
                        SeverityFinding = ""
                    }
                    $ReportAllResults += $ReportResult
                }

                Remove-Item $TempFileName
                Remove-Item $TempDbFileName
            }

            #
            # WindowsOptionalFeature
            # Install / Remove a Windows feature
            #
            If ($Finding.Method -eq 'WindowsOptionalFeature') {

                # Check if the user has admin rights, skip test if not
                If (-not($IsAdmin)) {
                    Write-NotAdminError -FindingID $Finding.ID -FindingName $Finding.Name -FindingMethod $Finding.Method
                    Continue
                }

                #
                # Check if feature is installed and should be removed, or
                # it is missing and should be installed
                #
                try {
                    $ResultOutput = Get-WindowsOptionalFeature -Online -FeatureName $Finding.MethodArgument
                    $Result = $ResultOutput.State
                } catch {
                    $ResultText = "Could not check status"
                    $Message = "ID " + $Finding.ID + ", " + $Finding.Name + ", " + $ResultText
                    $MessageSeverity = "High"
                    $TestResult = "Failed"
                    Write-ResultEntry -Text $Message -SeverityLevel $MessageSeverity
                    If ($Log) {
                        Add-MessageToFile -Text $Message -File $LogFile
                    }
                    If ($Report) {
                        $ReportResult = [ordered] @{
                            ID = $Finding.ID
                            Category = $Finding.Category
                            Name = $Finding.Name
                            Severity = $MessageSeverity
                            Result = $ResultText
                            Recommended = ""
                            TestResult = $TestResult
                            SeverityFinding = ""
                        }
                        $ReportAllResults += $ReportResult
                    }
                    Continue
                }

                # Feature will be removed, a reboot will be suppressed
                If ($Result -eq "Enabled" -and $Finding.RecommendedValue -eq "Disabled") {

                    try {
                        $Result = Disable-WindowsOptionalFeature -NoRestart -Online -FeatureName $Finding.MethodArgument
                    } catch {
                        $ResultText = "Could not be removed"
                        $Message = "ID " + $Finding.ID + ", " + $Finding.Name + ", " + $ResultText
                        $MessageSeverity = "High"
                        $TestResult = "Failed"
                        Write-ResultEntry -Text $Message -SeverityLevel $MessageSeverity
                        If ($Log) {
                            Add-MessageToFile -Text $Message -File $LogFile
                        }
                        If ($Report) {
                            $ReportResult = [ordered] @{
                                ID = $Finding.ID
                                Category = $Finding.Category
                                Name = $Finding.Name
                                Severity = $MessageSeverity
                                Result = $ResultText
                                Recommended = ""
                                TestResult = $TestResult
                                SeverityFinding = ""
                            }
                            $ReportAllResults += $ReportResult
                        }
                        Continue
                    }

                    $ResultText = "Feature removed"
                    $Message = "ID " + $Finding.ID + ", " + $Finding.Name + ", " + $ResultText
                    $MessageSeverity = "Passed"
                }
                # No changes required
                ElseIf ($Result -eq "Disabled" -and $Finding.RecommendedValue -eq "Disabled") {
                    $ResultText = "Feature is not installed"
                    $Message = "ID " + $Finding.ID + ", " + $Finding.Name + ", " + $ResultText
                    $MessageSeverity = "Passed"
                }
                # Feature will be installed, a reboot will be suppressed
                ElseIf ($Result -eq "Disabled" -and $Finding.RecommendedValue -eq "Enabled") {

                    try {
                        $Result = Enable-WindowsOptionalFeature -NoRestart -Online -FeatureName $Finding.MethodArgument
                    } catch {
                        $ResultText = "Could not be installed"
                        $Message = "ID " + $Finding.ID + ", " + $Finding.Name + ", " + $ResultText
                        $MessageSeverity = "High"
                        $TestResult = "Failed"
                        Write-ResultEntry -Text $Message -SeverityLevel $MessageSeverity
                        If ($Log) {
                            Add-MessageToFile -Text $Message -File $LogFile
                        }
                        If ($Report) {
                            $ReportResult = [ordered] @{
                                ID = $Finding.ID
                                Category = $Finding.Category
                                Name = $Finding.Name
                                Severity = $MessageSeverity
                                Result = $ResultText
                                Recommended = ""
                                TestResult = $TestResult
                                SeverityFinding = ""
                            }
                            $ReportAllResults += $ReportResult
                        }
                        Continue
                    }

                    $ResultText = "Feature installed"
                    $Message = "ID " + $Finding.ID + ", " + $Finding.Name + ", " + $ResultText
                    $MessageSeverity = "Passed"
                    $TestResult = "Passed"
                }
                # No changes required
                ElseIf ($Result -eq "Enabled" -and $Finding.RecommendedValue -eq "Enabled") {
                    $ResultText = "Feature is already installed"
                    $Message = "ID " + $Finding.ID + ", " + $Finding.Name + ", " + $ResultText
                    $MessageSeverity = "Passed"
                    $TestResult = "Passed"
                }

                Write-ResultEntry -Text $Message -SeverityLevel $MessageSeverity
                If ($Log) {
                    Add-MessageToFile -Text $Message -File $LogFile
                }
                If ($Report) {
                    $ReportResult = [ordered] @{
                        ID = $Finding.ID
                        Category = $Finding.Category
                        Name = $Finding.Name
                        Severity = $MessageSeverity
                        Result = $ResultText
                        Recommended = ""
                        TestResult = $TestResult
                        SeverityFinding = ""
                    }
                    $ReportAllResults += $ReportResult
                }
            }

            #
            # MpPreference
            # Set a Windows Defender policy
            #
            If ($Finding.Method -eq 'MpPreference') {

                # Check if the user has admin rights, skip test if not
                If (-not($IsAdmin)) {
                    Write-NotAdminError -FindingID $Finding.ID -FindingName $Finding.Name -FindingMethod $Finding.Method
                    Continue
                }

                $ResultMethodArgument = $Finding.MethodArgument
                $ResultRecommendedValue = $Finding.RecommendedValue

                Switch ($ResultRecommendedValue) {
                    "True" { $ResultRecommendedValue = 1; Break }
                    "False" { $ResultRecommendedValue = 0; Break }
                }

                # Build a hashtable MpPreferenceArgs for splatting arguments to Set-MpPreference. See https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_splatting
                $MpPreferenceArgs = @{
                    $ResultMethodArgument = $ResultRecommendedValue
                }

                Set-MpPreference @MpPreferenceArgs

                if ($?) {
                    $ResultText = "Method value modified"
                    $Message = "ID " + $Finding.ID + ", " + $Finding.MethodArgument + ", " + $ResultText
                    $MessageSeverity = "Passed"
                    $TestResult = "Passed"
                } else {
                    $ResultText = "Failed to change Method value"
                    $Message = "ID " + $Finding.ID + ", " + $Finding.MethodArgument + ", " + $ResultText
                    $MessageSeverity = "High"
                    $TestResult = "Passed"
                }

                Write-ResultEntry -Text $Message -SeverityLevel $MessageSeverity
                If ($Log) {
                    Add-MessageToFile -Text $Message -File $LogFile
                }
                If ($Report) {
                    $ReportResult = [ordered] @{
                        ID = $Finding.ID
                        Category = $Finding.Category
                        Name = $Finding.Name
                        Severity = $MessageSeverity
                        Result = $ResultText
                        Recommended = ""
                        TestResult = $TestResult
                        SeverityFinding = ""
                    }
                    $ReportAllResults += $ReportResult
                }
            }

            #
            # Microsoft Defender Preferences - Attack surface reduction rules (ASR rules)
            # The values are saved from a PowerShell function into an object.
            # The desired arguments can be accessed directly.
            #
            If ($Finding.Method -eq 'MpPreferenceAsr') {

                # Check if the user has admin rights, skip test if not
                If (-not($IsAdmin)) {
                    Write-NotAdminError -FindingID $Finding.ID -FindingName $Finding.Name -FindingMethod $Finding.Method
                    Continue
                }

                $ResultMethodArgument = $Finding.MethodArgument
                $ResultRecommendedValue = $Finding.RecommendedValue

                Switch ($ResultRecommendedValue) {
                    "True" { $ResultRecommendedValue = 1; Break }
                    "False" { $ResultRecommendedValue = 0; Break }
                }

                # Build a hashtable MpPreferenceArgs for splatting arguments to Set-MpPreference. See https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_splatting
                $MpPreferenceArgs = @{
                    AttackSurfaceReductionRules_Ids     = $ResultMethodArgument
                    AttackSurfaceReductionRules_Actions = $ResultRecommendedValue
                }

                Add-MpPreference @MpPreferenceArgs

                if ($?) {
                    $ResultText = "ASR rule added to list"
                    $Message = "ID " + $Finding.ID + ", " + $Finding.Name + ", " + $Finding.MethodArgument + ", " + $ResultText
                    $MessageSeverity = "Passed"
                    $TestResult = "Passed"
                } else {
                    $ResultText = "Failed to add ASR rule"
                    $Message = "ID " + $Finding.ID + ", " + $Finding.Name + ", " + $Finding.MethodArgument + ", " + $ResultText
                    $MessageSeverity = "High"
                    $TestResult = "Failed"
                }

                Write-ResultEntry -Text $Message -SeverityLevel $MessageSeverity
                If ($Log) {
                    Add-MessageToFile -Text $Message -File $LogFile
                }
                If ($Report) {
                    $ReportResult = [ordered] @{
                        ID = $Finding.ID
                        Category = $Finding.Category
                        Name = $Finding.Name
                        Severity = $MessageSeverity
                        Result = $ResultText
                        Recommended = ""
                        TestResult = $TestResult
                        SeverityFinding = ""
                    }
                    $ReportAllResults += $ReportResult
                }
            }

            #
            # Exploit protection
            # Set exploit protection values
            #
            # I noticed irregularities when the process mitigations were set individually,
            # in some cases settings that had already been set were then reset. Therefore,
            # the settings are collected in an array and finally set at the end of the processing.
            #
            If ($Finding.Method -eq 'Processmitigation') {

                # Check if the user has admin rights, skip test if not
                If (-not($IsAdmin)) {
                    Write-NotAdminError -FindingID $Finding.ID -FindingName $Finding.Name -FindingMethod $Finding.Method
                    Continue
                }

                $SettingArgumentArray = $Finding.MethodArgument.Split(".")

                If ( $Finding.RecommendedValue -eq "ON") {

                    If ( $SettingArgumentArray[1] -eq "Enable" ) {
                        $ProcessmitigationEnableArray += $SettingArgumentArray[0]
                    } Else {
                        $ProcessmitigationEnableArray += $SettingArgumentArray[1]
                    }
                } ElseIf ( $Finding.RecommendedValue -eq "OFF") {

                    If ($SettingArgumentArray[1] -eq "TelemetryOnly") {
                        $ProcessmitigationDisableArray += "SEHOPTelemetry"
                    } ElseIf ( $SettingArgumentArray[1] -eq "Enable" ) {
                        $ProcessmitigationDisableArray += $SettingArgumentArray[0]
                    } Else {
                        $ProcessmitigationDisableArray += $SettingArgumentArray[1]
                    }
                }
                $ResultText = "setting added to list"
                $Message = "ID " + $Finding.ID + ", " + $Finding.Name + ", " + $ResultText
                $MessageSeverity = "Passed"
                $TestResult = "Passed"
                Write-ResultEntry -Text $Message -SeverityLevel $MessageSeverity
                If ($Log) {
                    Add-MessageToFile -Text $Message -File $LogFile
                }
                If ($Report) {
                    $ReportResult = [ordered] @{
                        ID = $Finding.ID
                        Category = $Finding.Category
                        Name = $Finding.Name
                        Severity = $MessageSeverity
                        Result = $ResultText
                        Recommended = ""
                        TestResult = $TestResult
                        SeverityFinding = ""
                    }
                    $ReportAllResults += $ReportResult
                }
            }

            #
            # bcdedit
            # Force use of Data Execution Prevention, if it is not already set
            #
            If ($Finding.Method -eq 'bcdedit') {

                # Check if the user has admin rights, skip test if not
                If (-not($IsAdmin)) {
                    Write-NotAdminError -FindingID $Finding.ID -FindingName $Finding.Name -FindingMethod $Finding.Method
                    Continue
                }

                # Check if Bcdedit binary is available, skip test if not
                If (-Not (Test-Path $BinaryBcdedit)) {
                    Write-BinaryError -Binary $BinaryBcdedit -FindingID $Finding.ID -FindingName $Finding.Name -FindingMethod $Finding.Method
                    Continue
                }

                try {

                    $ResultOutput = &$BinaryBcdedit
                    $ResultOutput = $ResultOutput | Where-Object { $_ -like "*" + $Finding.RecommendedValue + "*" }

                    If ($ResultOutput -match ' ([a-z,A-Z]+)') {
                        $Result = $Matches[1]
                    } Else {
                        $Result = $Finding.DefaultValue
                    }

                } catch {
                    $Result = $Finding.DefaultValue
                }

                If ($Result -ne $Finding.RecommendedValue) {

                    try {

                        $ResultOutput = &$BinaryBcdedit "/set" $Finding.MethodArgument $Finding.RecommendedValue

                    } catch {

                        $ResultText = "Setting could not be enabled"
                        $Message = "ID " + $Finding.ID + ", " + $Finding.Name + ", " + $ResultText
                        $MessageSeverity = "High"
                        $TestResult = "Failed"
                    }

                    $ResultText = "Setting enabled. Please restart the system to activate it"
                    $Message = "ID " + $Finding.ID + ", " + $Finding.Name + ", " + $ResultText
                    $MessageSeverity = "Passed"
                    $TestResult = "Passed"
                } Else {

                    $ResultText = "Setting is already set correct"
                    $Message = "ID " + $Finding.ID + ", " + $Finding.Name + ", " + $ResultText
                    $MessageSeverity = "Passed"
                    $TestResult = "Passed"
                }

                Write-ResultEntry -Text $Message -SeverityLevel $MessageSeverity
                If ($Log) {
                    Add-MessageToFile -Text $Message -File $LogFile
                }
                If ($Report) {
                    $ReportResult = [ordered] @{
                        ID = $Finding.ID
                        Category = $Finding.Category
                        Name = $Finding.Name
                        Severity = $MessageSeverity
                        Result = $ResultText
                        Recommended = ""
                        TestResult = $TestResult
                        SeverityFinding = ""
                    }
                    $ReportAllResults += $ReportResult
                }
            }

            #
            # FirewallRule
            # Create a firewall rule. First it will be checked if the rule already exists
            #
            If ($Finding.Method -eq 'FirewallRule') {

                # Check if the user has admin rights, skip test if not
                If (-not($IsAdmin)) {
                    Write-NotAdminError -FindingID $Finding.ID -FindingName $Finding.Name -FindingMethod $Finding.Method
                    Continue
                }

                $FwRule = $Finding.MethodArgument
                $FwRuleArray = $FwRule.Split("|")

                $FwDisplayName = $Finding.Name
                $FwProfile = $FwRuleArray[0]
                $FwDirection = $FwRuleArray[1]
                $FwAction = $FwRuleArray[2]
                $FwProtocol = $FwRuleArray[3]
                $FwLocalPort = @($FwRuleArray[4]).Split(",")
                $FwProgram = $FwRuleArray[5]

                # Check if rule already exists
                try {

                    $ResultOutput = Get-NetFirewallRule -PolicyStore ActiveStore -DisplayName $FwDisplayName 2> $null
                    $Result = $ResultOutput.Enabled

                } catch {
                    $Result = $Finding.DefaultValue
                }

                # Go on if rule not exists
                If (-Not $Result) {

                    If ($FwProgram -eq "") {
                        $ResultRule = New-NetFirewallRule -DisplayName $FwDisplayName -Profile $FwProfile -Direction $FwDirection -Action $FwAction -Protocol $FwProtocol -LocalPort $FwLocalPort
                    } Else {
                        $ResultRule = New-NetFirewallRule -DisplayName $FwDisplayName -Profile $FwProfile -Direction $FwDirection -Action $FwAction -Program "$FwProgram"
                    }

                    If ($ResultRule.PrimaryStatus -eq "OK") {

                        # Excellent
                        $ResultText = "Rule created"
                        $Message = "ID " + $Finding.ID + ", " + $Finding.Name + ", " + $ResultText
                        $MessageSeverity = "Passed"
                        $TestResult = "Passed"
                    } Else {
                        # Bogus
                        $ResultText = "Rule not created"
                        $Message = "ID " + $Finding.ID + ", " + $Finding.Name + ", " + $ResultText
                        $MessageSeverity = "High"
                        $TestResult = "Failed"
                    }
                } Else {
                    # Excellent
                    $ResultText = "Rule already exists"
                    $Message = "ID " + $Finding.ID + ", " + $Finding.Name + ", " + $ResultText
                    $MessageSeverity = "Passed"
                    $TestResult = "Passed"
                }

                Write-ResultEntry -Text $Message -SeverityLevel $MessageSeverity

                If ($Log) {
                    Add-MessageToFile -Text $Message -File $LogFile
                }

                If ($Report) {
                    $ReportResult = [ordered] @{
                        ID = $Finding.ID
                        Category = $Finding.Category
                        Name = $Finding.Name
                        Severity = $MessageSeverity
                        Result = $ResultText
                        Recommended = ""
                        TestResult = $TestResult
                        SeverityFinding = ""
                    }
                    $ReportAllResults += $ReportResult
                }
            }

            #
            # Scheduled Task
            # Edit a scheduled task. First it will be checked if a modification is required
            #
            If ($Finding.Method -eq 'ScheduledTask') {

                # Check if the user has admin rights, skip test if not
                If (-not($IsAdmin)) {
                    Write-NotAdminError -FindingID $Finding.ID -FindingName $Finding.Name -FindingMethod $Finding.Method
                    Continue
                }

                # Check the state of the scheduled task
                try {
                    $ResultOutput = Get-ScheduledTask -TaskName $Finding.MethodArgument 2> $null
                    $Result = $ResultOutput.State

                } catch {
                    $Result = $Finding.DefaultValue
                }

                # Check if a modification is requried
                If ($Result -eq $Finding.RecommendedValue) {

                    # Excellent
                    $ResultText = "Scheduled Task has alredy the recommended state"
                    $Message = "ID " + $Finding.ID + ", " + $Finding.Name + ", " + $ResultText
                    $MessageSeverity = "Passed"
                    $TestResult = "Passed"

                } Else {

                    If ($Finding.RecommendedValue -eq "Disabled") {

                        $Result = Get-ScheduledTask -TaskName $Finding.MethodArgument | Disable-ScheduledTask

                        $ResultText = "Scheduled Task was disabled"
                        $Message = "ID " + $Finding.ID + ", " + $Finding.Name + ", " + $ResultText
                        $MessageSeverity = "Passed"
                        $TestResult = "Passed"

                    } ElseIf ($Finding.RecommendedValue -eq "Ready") {

                        $Result = Get-ScheduledTask -TaskName $Finding.MethodArgument | Enable-ScheduledTask

                        $ResultText = "Scheduled Task was enabled"
                        $Message = "ID " + $Finding.ID + ", " + $Finding.Name + ", " + $ResultText
                        $MessageSeverity = "Passed"
                        $TestResult = "Passed"
                    }
                }

                Write-ResultEntry -Text $Message -SeverityLevel $MessageSeverity

                If ($Log) {
                    Add-MessageToFile -Text $Message -File $LogFile
                }

                If ($Report) {
                    $ReportResult = [ordered] @{
                        ID = $Finding.ID
                        Category = $Finding.Category
                        Name = $Finding.Name
                        Severity = $MessageSeverity
                        Result = $ResultText
                        Recommended = ""
                        TestResult = $TestResult
                        SeverityFinding = ""
                    }
                    $ReportAllResults += $ReportResult
                }
            }
        }

        #
        # After all items of the checklist have been run through, the process mitigation settings can now be set...
        #
        If ( $ProcessmitigationEnableArray.Count -gt 0 -and $ProcessmitigationDisableArray.Count -gt 0) {

            $ResultText = "Process mitigation settings set"
            $MessageSeverity = "Passed"
            $TestResult = "Passed"

            try {
                $Result = Set-ProcessMitigation -System -Enable $ProcessmitigationEnableArray -Disable $ProcessmitigationDisableArray
            } catch {
                $ResultText = "Failed to set process mitigation settings"
                $MessageSeverity = "High"
                $TestResult = "Failed"
            }

            $Message = "Starting Category Microsoft Defender Exploit Guard"
            Write-Output "`n"
            Write-ProtocolEntry -Text $Message -LogLevel "Info"

            $Message = $ResultText
            Write-ResultEntry -Text $Message -SeverityLevel $MessageSeverity
            If ($Log) {
                Add-MessageToFile -Text $Message -File $LogFile
            }
            If ($Report) {
                $ReportResult = [ordered] @{
                    ID = $Finding.ID
                    Category = $Finding.Category
                    Name = $Finding.Name
                    Severity = $MessageSeverity
                    Result = $ResultText
                    Recommended = ""
                    TestResult = $TestResult
                    SeverityFinding = ""
                }
                $ReportAllResults += $ReportResult
            }
        } ElseIf ($ProcessmitigationEnableArray.Count -gt 0 -and $ProcessmitigationDisableArray.Count -eq 0) {
            $ResultText = "Process mitigation settings set"
            $MessageSeverity = "Passed"
            $TestResult = "Passed"

            try {
                $Result = Set-ProcessMitigation -System -Enable $ProcessmitigationEnableArray
            } catch {
                $ResultText = "Failed to set process mitigation settings"
                $MessageSeverity = "High"
                $TestResult = "Failed"
            }

            $Message = "Starting Category Microsoft Defender Exploit Guard"
            Write-Output "`n"
            Write-ProtocolEntry -Text $Message -LogLevel "Info"

            $Message = $ResultText
            Write-ResultEntry -Text $Message -SeverityLevel $MessageSeverity
            If ($Log) {
                Add-MessageToFile -Text $Message -File $LogFile
            }
            If ($Report) {
                $ReportResult = [ordered] @{
                    ID = $Finding.ID
                    Category = $Finding.Category
                    Name = $Finding.Name
                    Severity = $MessageSeverity
                    Result = $ResultText
                    Recommended = ""
                    TestResult = $TestResult
                    SeverityFinding = ""
                }
                $ReportAllResults += $ReportResult
            }
        } ElseIf ($ProcessmitigationEnableArray.Count -eq 0 -and $ProcessmitigationDisableArray.Count -gt 0) {
            $ResultText = "Process mitigation settings set"
            $MessageSeverity = "Passed"
            $TestResult = "Passed"

            try {
                $Result = Set-ProcessMitigation -System -Disable $ProcessmitigationDisableArray
            } catch {
                $ResultText = "Failed to set process mitigation settings"
                $MessageSeverity = "High"
                $TestResult = "Failed"
            }

            $Message = "Starting Category Microsoft Defender Exploit Guard"
            Write-Output "`n"
            Write-ProtocolEntry -Text $Message -LogLevel "Info"

            $Message = $ResultText
            Write-ResultEntry -Text $Message -SeverityLevel $MessageSeverity
            If ($Log) {
                Add-MessageToFile -Text $Message -File $LogFile
            }
            If ($Report) {
                $ReportResult = [ordered] @{
                    ID = $Finding.ID
                    Category = $Finding.Category
                    Name = $Finding.Name
                    Severity = $MessageSeverity
                    Result = $ResultText
                    Recommended = ""
                    TestResult = $TestResult
                    SeverityFinding = ""
                }
                $ReportAllResults += $ReportResult
            }
        }
    }


    #
    # Start GPO mode
    # HardeningKitty configures all settings in a finding list file.
    # Even though HardeningKitty works very carefully.
    # The GPO mode create a GPO containing every registry method remediation.
    #
    Elseif ($Mode -eq "GPO") {

        Write-Output "`n"
        If ($GPOname.Length -eq 0) {
            # Control if a GPO name is given
            $Message = "The GPO Name $GPOname was not found."
            Write-ProtocolEntry -Text $Message -LogLevel "Error"
            Break
        }
        If ($FileFindingList.Length -eq 0) {
            # Control if a Finding list is given
            $CurrentLocation = $PSScriptRoot
            $DefaultList = "$CurrentLocation\lists\finding_list_0x6d69636b_machine.csv"

            If (Test-Path -Path $DefaultList) {
                $FileFindingList = $DefaultList
            } Else {
                $Message = "The finding list $DefaultList was not found."
                Write-ProtocolEntry -Text $Message -LogLevel "Error"
                Break
            }
        }

        # Check if the user has admin rights, skip test if not
        If (-not($IsAdmin)) {
            Write-NotAdminError -FindingID "0" -FindingName "GPO Mode" -FindingMethod "Create a GPO"
            Continue
        }

        # Check if the New-GPO cmdlet is available
        try {
            $CheckRsatStatus = Get-Command New-GPO -ErrorAction Stop
        } catch {
            Write-BinaryError -Binary "Group Policy Management PowerShell Module" -FindingID "0" -FindingName "GPO Mode" -FindingMethod "Create a GPO"
            Continue
        }

        # Should check if user is domain admin
        try {
            New-GPO -Name $GPOname -ErrorAction Stop | Out-Null
        }
        catch [System.ArgumentException] {
            # Control if the Name of the GPO is ok
            Write-ProtocolEntry -Text $_.Exception.Message -LogLevel "Error"
            Break
        }

        # Iterrate over finding list
        $FindingList = Import-Csv -Path $FileFindingList -Delimiter ","
        ForEach ($Finding in $FindingList) {
            #
            # Only Registry Method Policies
            #
            If ($Finding.Method -eq "Registry") {
                $RegType = "String"

                #
                # Basically this is true, but there is an exception for the finding "MitigationOptions_FontBocking",
                # the value "10000000000" is written to the registry as a string...
                #
                # ... and more exceptions are added over time:
                #
                # MitigationOptions_FontBocking => Mitigation Options: Untrusted Font Blocking
                # Machine => Network access: Remotely accessible registry paths
                # Retention => Event Log Service: *: Control Event Log behavior when the log file reaches its maximum size
                # AllocateDASD => Devices: Allowed to format and eject removable media
                # ScRemoveOption => Interactive logon: Smart card removal behavior
                # AutoAdminLogon => MSS: (AutoAdminLogon) Enable Automatic Logon (not recommended)
                #
                If ($Finding.RegistryItem -eq "MitigationOptions_FontBocking" -Or $Finding.RegistryItem -eq "Retention" -Or $Finding.RegistryItem -eq "AllocateDASD" -Or $Finding.RegistryItem -eq "ScRemoveOption" -Or $Finding.RegistryItem -eq "AutoAdminLogon") {
                    $RegType = "String"
                } ElseIf ($Finding.RegistryItem -eq "Machine") {
                    $RegType = "MultiString"
                    $Finding.RecommendedValue = $Finding.RecommendedValue -split ";"
                } ElseIf ($Finding.RecommendedValue -match "^\d+$") {
                    $RegType = "DWord"
                    $Finding.RecommendedValue = ConvertToInt -string $Finding.RecommendedValue
                }
                $RegPath = $Finding.RegistryPath.Replace(":","")
                $RegItem = $Finding.RegistryItem

                try {
                    Set-GPRegistryValue -Name $GPOname -Key $RegPath -ValueName $RegItem -Type $RegType -Value $Finding.RecommendedValue | Out-Null
                    $ResultText = "Registry value added successfully"
                    $Message = "ID " + $Finding.ID + ", " + $Finding.RegistryPath + ", " + $Finding.RegistryItem + ", " + $ResultText
                    $MessageSeverity = "Passed"
                    $TestResult = "Passed"
                } catch {
                    $ResultText = "Failed to add registry key"
                    $Message = "ID " + $Finding.ID + ", " + $Finding.RegistryPath + ", " + $ResultText
                    $MessageSeverity = "High"
                    $TestResult = "Failed"

                } finally {
                    Write-ResultEntry -Text $Message -SeverityLevel $MessageSeverity
                    If ($Log) {
                        Add-MessageToFile -Text $Message -File $LogFile
                    }
                }
            }
        }
     }

    Write-Output "`n"
    Write-ProtocolEntry -Text "HardeningKitty is done" -LogLevel "Info"

    # Write report file
    If ($Report) {
        ForEach ($ReportResult in $ReportAllResults) {
            $ResultObject = [pscustomobject] $ReportResult
            $ResultObject | Export-Csv -Path $ReportFile -Delimiter "," -NoTypeInformation -Append
        }
    }

    # Write backup file
    If ($Backup) {
        ForEach ($BackupResult in $BackupAllResults) {
            $BackupObject = [pscustomobject] $BackupResult
            $BackupObject | Export-Csv -Path $BackupFile -Delimiter "," -NoTypeInformation -Append
        }
    }

    If ($Mode -eq "Audit") {

        # HardeningKitty Score
        $StatsTotal = $StatsPassed + $StatsLow + $StatsMedium + $StatsHigh
        $ScoreTotal = $StatsTotal * 4
        $ScoreAchived = $StatsPassed * 4 + $StatsLow * 2 + $StatsMedium
        If ($ScoreTotal -ne 0 ) {
            $HardeningKittyScore = ([int] $ScoreAchived / [int] $ScoreTotal) * 5 + 1
        }
        $HardeningKittyScoreRounded = [math]::round($HardeningKittyScore, 2)

        # Overwrite HardeningKitty Score if no finding is passed
        If ($StatsPassed -eq 0 ) {
            $HardeningKittyScoreRounded = 1.00
        }

        If ($Script:StatsError -gt 0) {
            Write-ProtocolEntry -Text "During the execution of HardeningKitty errors occurred due to missing admin rights or tools. For a complete result, these errors should be resolved. Total errors: $Script:StatsError" -LogLevel "Error"
        }

        Write-ProtocolEntry -Text "Your HardeningKitty score is: $HardeningKittyScoreRounded. HardeningKitty Statistics: Total checks: $StatsTotal - Passed: $StatsPassed, Low: $StatsLow, Medium: $StatsMedium, High: $StatsHigh." -LogLevel "Info"
    }
    Write-Output "`n"
}

Export-ModuleMember -Function Invoke-HardeningKitty

# SIG # Begin signature block
# MIInLwYJKoZIhvcNAQcCoIInIDCCJxwCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUYYl8xktEXR9Y0nRaPDQT+6UQ
# 4H+ggiA+MIIFbzCCBFegAwIBAgIQSPyTtGBVlI02p8mKidaUFjANBgkqhkiG9w0B
# AQwFADB7MQswCQYDVQQGEwJHQjEbMBkGA1UECAwSR3JlYXRlciBNYW5jaGVzdGVy
# MRAwDgYDVQQHDAdTYWxmb3JkMRowGAYDVQQKDBFDb21vZG8gQ0EgTGltaXRlZDEh
# MB8GA1UEAwwYQUFBIENlcnRpZmljYXRlIFNlcnZpY2VzMB4XDTIxMDUyNTAwMDAw
# MFoXDTI4MTIzMTIzNTk1OVowVjELMAkGA1UEBhMCR0IxGDAWBgNVBAoTD1NlY3Rp
# Z28gTGltaXRlZDEtMCsGA1UEAxMkU2VjdGlnbyBQdWJsaWMgQ29kZSBTaWduaW5n
# IFJvb3QgUjQ2MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAjeeUEiIE
# JHQu/xYjApKKtq42haxH1CORKz7cfeIxoFFvrISR41KKteKW3tCHYySJiv/vEpM7
# fbu2ir29BX8nm2tl06UMabG8STma8W1uquSggyfamg0rUOlLW7O4ZDakfko9qXGr
# YbNzszwLDO/bM1flvjQ345cbXf0fEj2CA3bm+z9m0pQxafptszSswXp43JJQ8mTH
# qi0Eq8Nq6uAvp6fcbtfo/9ohq0C/ue4NnsbZnpnvxt4fqQx2sycgoda6/YDnAdLv
# 64IplXCN/7sVz/7RDzaiLk8ykHRGa0c1E3cFM09jLrgt4b9lpwRrGNhx+swI8m2J
# mRCxrds+LOSqGLDGBwF1Z95t6WNjHjZ/aYm+qkU+blpfj6Fby50whjDoA7NAxg0P
# OM1nqFOI+rgwZfpvx+cdsYN0aT6sxGg7seZnM5q2COCABUhA7vaCZEao9XOwBpXy
# bGWfv1VbHJxXGsd4RnxwqpQbghesh+m2yQ6BHEDWFhcp/FycGCvqRfXvvdVnTyhe
# Be6QTHrnxvTQ/PrNPjJGEyA2igTqt6oHRpwNkzoJZplYXCmjuQymMDg80EY2NXyc
# uu7D1fkKdvp+BRtAypI16dV60bV/AK6pkKrFfwGcELEW/MxuGNxvYv6mUKe4e7id
# FT/+IAx1yCJaE5UZkADpGtXChvHjjuxf9OUCAwEAAaOCARIwggEOMB8GA1UdIwQY
# MBaAFKARCiM+lvEH7OKvKe+CpX/QMKS0MB0GA1UdDgQWBBQy65Ka/zWWSC8oQEJw
# IDaRXBeF5jAOBgNVHQ8BAf8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zATBgNVHSUE
# DDAKBggrBgEFBQcDAzAbBgNVHSAEFDASMAYGBFUdIAAwCAYGZ4EMAQQBMEMGA1Ud
# HwQ8MDowOKA2oDSGMmh0dHA6Ly9jcmwuY29tb2RvY2EuY29tL0FBQUNlcnRpZmlj
# YXRlU2VydmljZXMuY3JsMDQGCCsGAQUFBwEBBCgwJjAkBggrBgEFBQcwAYYYaHR0
# cDovL29jc3AuY29tb2RvY2EuY29tMA0GCSqGSIb3DQEBDAUAA4IBAQASv6Hvi3Sa
# mES4aUa1qyQKDKSKZ7g6gb9Fin1SB6iNH04hhTmja14tIIa/ELiueTtTzbT72ES+
# BtlcY2fUQBaHRIZyKtYyFfUSg8L54V0RQGf2QidyxSPiAjgaTCDi2wH3zUZPJqJ8
# ZsBRNraJAlTH/Fj7bADu/pimLpWhDFMpH2/YGaZPnvesCepdgsaLr4CnvYFIUoQx
# 2jLsFeSmTD1sOXPUC4U5IOCFGmjhp0g4qdE2JXfBjRkWxYhMZn0vY86Y6GnfrDyo
# XZ3JHFuu2PMvdM+4fvbXg50RlmKarkUT2n/cR/vfw1Kf5gZV6Z2M8jpiUbzsJA8p
# 1FiAhORFe1rYMIIGHDCCBASgAwIBAgIQM9cIqJFAUxnipbvTObmtbjANBgkqhkiG
# 9w0BAQwFADBWMQswCQYDVQQGEwJHQjEYMBYGA1UEChMPU2VjdGlnbyBMaW1pdGVk
# MS0wKwYDVQQDEyRTZWN0aWdvIFB1YmxpYyBDb2RlIFNpZ25pbmcgUm9vdCBSNDYw
# HhcNMjEwMzIyMDAwMDAwWhcNMzYwMzIxMjM1OTU5WjBXMQswCQYDVQQGEwJHQjEY
# MBYGA1UEChMPU2VjdGlnbyBMaW1pdGVkMS4wLAYDVQQDEyVTZWN0aWdvIFB1Ymxp
# YyBDb2RlIFNpZ25pbmcgQ0EgRVYgUjM2MIIBojANBgkqhkiG9w0BAQEFAAOCAY8A
# MIIBigKCAYEAu9H+HrdCW3j1kKeuLIPxjSHTMIaFe9/TzdkWS6yFxbsBz+KMKBFy
# BHYsgcWrEnpASsUQ6IEUORtfTwf2MDAwfzUl5cBzPUAJlOio+Os5C1XVtgyLHif4
# 3j4iwb/vZe5z7mXdKN27H32bMn+3mVUXqrJJqDwQajrDIbKZqEPXO4KoGWG1Pmpa
# Xbi8nhPQCp71W49pOGjqpR9byiPuC+280B5DQ26wU4zCcypEMW6+j7jGAva7ggQV
# eQxSIOiYJ3Fh7y/k+AL7M1m19MNV59/2CCKuttEJWewBn3OJt0NP1fLZvVZZCd23
# F/bEdIC6h0asBtvbBA3VTrrujAk0GZUb5nATBCXfj7jXhDOMbKYM62i6lU98ROjU
# aY0lecMh8TV3+E+2ElWV0FboGALV7nnIhqFp8RtOlBNqB2Lw0GuZpZdQnhwzoR7u
# YYsFaByO9e4mkIPW/nGFp5ryDRQ+NrUSrXd1esznRjZqkFPLxpRx3gc6IfnWMmfg
# nG5UhqBkoIPLAgMBAAGjggFjMIIBXzAfBgNVHSMEGDAWgBQy65Ka/zWWSC8oQEJw
# IDaRXBeF5jAdBgNVHQ4EFgQUgTKSQSsozUbIxKLGKjkS7EipPxQwDgYDVR0PAQH/
# BAQDAgGGMBIGA1UdEwEB/wQIMAYBAf8CAQAwEwYDVR0lBAwwCgYIKwYBBQUHAwMw
# GgYDVR0gBBMwETAGBgRVHSAAMAcGBWeBDAEDMEsGA1UdHwREMEIwQKA+oDyGOmh0
# dHA6Ly9jcmwuc2VjdGlnby5jb20vU2VjdGlnb1B1YmxpY0NvZGVTaWduaW5nUm9v
# dFI0Ni5jcmwwewYIKwYBBQUHAQEEbzBtMEYGCCsGAQUFBzAChjpodHRwOi8vY3J0
# LnNlY3RpZ28uY29tL1NlY3RpZ29QdWJsaWNDb2RlU2lnbmluZ1Jvb3RSNDYucDdj
# MCMGCCsGAQUFBzABhhdodHRwOi8vb2NzcC5zZWN0aWdvLmNvbTANBgkqhkiG9w0B
# AQwFAAOCAgEAXzas+/n2cloUt/ALHd7Y/ZcB0v0B7pkthuj2t/A5/9aBSlqnQkoK
# LRWd5pT9xWlKstdL8RYSTPa+kGZliy101KsI92oRAwh3fL5p4bDbnySJA9beXKTg
# sta0z+M41bltzCfWzmQR6BBydtP54OksielJ07OXlgYK4fYKyEGakV2B2DZ3mMqA
# QZeo+JE/Y5+qzVRUS4Dq9Rdm05Rx/Z79RzHj6RqGHdO+INI/sVJfspO9jJUJmHKP
# lQH0mEOlSvsUJqqdNr9ysPzcvYQN7O00qF6VKzgWYwV12fYxLhVr4pSyKtJ0NbWY
# mqP++CsvthdLJ2xa5rl2XtqG3atk1mrqgxiIGzGC9YizlCXAIS8IaQLjTLtMKhEw
# 64F5BuFBlSrUIPYLk+R8dgydHSZrX4QB9iqZza/ex/DkGKJOmy8qDGamknUmvtlA
# NRNvrqY3GnrorRxRYwcqVgZs7X4Y9uPsZHOmbQg2i68Pma51axcrwk1qw1FGQVbp
# j8KN/xNxm9rtntOfq+VFphLFFFpSQZejBgAIxeYc6ieCPDvb5kbE7y0ANRPNNn2d
# 5aonCAXMzsA2DksZT9Bjmm2/xSlTMSLbdVB3htDy+GruawYbPoUjK5fIfnqZQQzd
# WH8OqMMSPTo1m+CdLIwXgVREqHodmJ2Wf1lYplRl/1FCC/hH68/45b8wgga+MIIF
# JqADAgECAhBY1/j+ACGVk7Nfk2EAZ7N7MA0GCSqGSIb3DQEBCwUAMFcxCzAJBgNV
# BAYTAkdCMRgwFgYDVQQKEw9TZWN0aWdvIExpbWl0ZWQxLjAsBgNVBAMTJVNlY3Rp
# Z28gUHVibGljIENvZGUgU2lnbmluZyBDQSBFViBSMzYwHhcNMjMwODIxMDAwMDAw
# WhcNMjYwODIwMjM1OTU5WjCBkTEYMBYGA1UEBRMPQ0hFLTEwOS44MDQuMzgyMRMw
# EQYLKwYBBAGCNzwCAQMTAkNIMR0wGwYDVQQPExRQcml2YXRlIE9yZ2FuaXphdGlv
# bjELMAkGA1UEBhMCQ0gxEDAOBgNVBAgMB1rDvHJpY2gxEDAOBgNVBAoMB3NjaXAg
# YWcxEDAOBgNVBAMMB3NjaXAgYWcwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIK
# AoICAQCzQ6oCVeUUYjACeXvIhnAvENhDTMoRQ3l5uChhnt76mVcpy3mnMrwexqqL
# J9xvoXx4N95BXiloBbpa8OGc/c1O4pasVFP56Xiqf0IaaUwHqaTWoM2LdpEUo3Wj
# ULGcNxxRoQC3Ui4UTtHOVlixHU5uPoxVp5EaMb3iW8ybFGjcoYRd1Tvoe+tl4818
# KnAWrnqnyoFVc5P1ofh93n8ZIb9kL79c2uz94PiYMVCZvGQi6vVTytZSLItYpxsP
# 41B8q2qX9acmVKhB4VTweP6J/G2Y8BG8DbLJGuNEuCTKRLj4o7hDEpYI7NKstJyY
# f3AIAQT9zB4BNLlj37q6YqX9/uZ4dYdydBJl3hix5u3I7hCbrE3FbZkfi5t8BYK3
# v/1+Wt9C6+uooUmcLRdos8mYSB4IusKRI4nnupCYC/2blAUCQSyp5jLsOJexdgal
# VdKe7Aj8md62lBRGca2ajCCzGEpk5iAMfq43EnKcaoiY4ajsRniDfKDRgkJ1JUWV
# CiCwiI/UTuLav2ilQkc3BzPrv3LXQQM68dAeR6Er0Pz46iSJ/b3sgIbQonvfPCi3
# xrSvaxfVueO8IZgZ+oY5M4fYE3peYI1UFDSuvjhmpFln/OlVq6SgaKe2wigOunuf
# R3eDOu+Ltq8Ht6X4Rv5LSrU/BjENRhPsp27fyWADiJpZ7ru3AQIDAQABo4IByTCC
# AcUwHwYDVR0jBBgwFoAUgTKSQSsozUbIxKLGKjkS7EipPxQwHQYDVR0OBBYEFPlP
# y5ch4ih7wuj28WV5r6p7U6ITMA4GA1UdDwEB/wQEAwIHgDAMBgNVHRMBAf8EAjAA
# MBMGA1UdJQQMMAoGCCsGAQUFBwMDMEkGA1UdIARCMEAwNQYMKwYBBAGyMQECAQYB
# MCUwIwYIKwYBBQUHAgEWF2h0dHBzOi8vc2VjdGlnby5jb20vQ1BTMAcGBWeBDAED
# MEsGA1UdHwREMEIwQKA+oDyGOmh0dHA6Ly9jcmwuc2VjdGlnby5jb20vU2VjdGln
# b1B1YmxpY0NvZGVTaWduaW5nQ0FFVlIzNi5jcmwwewYIKwYBBQUHAQEEbzBtMEYG
# CCsGAQUFBzAChjpodHRwOi8vY3J0LnNlY3RpZ28uY29tL1NlY3RpZ29QdWJsaWND
# b2RlU2lnbmluZ0NBRVZSMzYuY3J0MCMGCCsGAQUFBzABhhdodHRwOi8vb2NzcC5z
# ZWN0aWdvLmNvbTA7BgNVHREENDAyoCIGCCsGAQUFBwgDoBYwFAwSQ0gtQ0hFLTEw
# OS44MDQuMzgygQxtaXNjQHNjaXAuY2gwDQYJKoZIhvcNAQELBQADggGBAIPzM0vd
# +ZHVmIl+VseC1DVUkkukcEW7UG+bopOaTw/nqr6dMzqglpCMTnDuYK3zSl3ptTlW
# Cnok1EGjFNssPfr8uoFsgooblOZpEgolbc45pNvT0ERSP/85MOvTJqVH1kfJhWDA
# KG9BxJkhkhlc9bE98MgvrlEJ/q/wx+lXH739Zeerwvs2Y/MMUeSqZPmTuc2YkhiL
# TpmpIT9KXcvjYaFQB2mKHRerQTpmLGgu2tzo7yoJJrBcGp2trQH+68dWTiywsME7
# glrrSKkJTB+87UmiSTdETx2H2pGOh65He3/NQe/+vcI2SBB0CXStw2AhhReemj/w
# 6INi2FYkhO1Sag9inF/1K62w//gZsSR/YB8dlG0+MAsNaPJaCXnciPP5fG2XIZsQ
# caKd8dT9Y+wtBEigoNX0Js0NmMWwvygL33pGwjzIc9td3k7KkO3gJeO9VI5oqp7R
# PIAew0HTB5PyWS1C0BXNVMLoONdinpBGTXp0P8DH2YYsHBQqPgmIgUeVNzCCBuww
# ggTUoAMCAQICEDAPb6zdZph0fKlGNqd4LbkwDQYJKoZIhvcNAQEMBQAwgYgxCzAJ
# BgNVBAYTAlVTMRMwEQYDVQQIEwpOZXcgSmVyc2V5MRQwEgYDVQQHEwtKZXJzZXkg
# Q2l0eTEeMBwGA1UEChMVVGhlIFVTRVJUUlVTVCBOZXR3b3JrMS4wLAYDVQQDEyVV
# U0VSVHJ1c3QgUlNBIENlcnRpZmljYXRpb24gQXV0aG9yaXR5MB4XDTE5MDUwMjAw
# MDAwMFoXDTM4MDExODIzNTk1OVowfTELMAkGA1UEBhMCR0IxGzAZBgNVBAgTEkdy
# ZWF0ZXIgTWFuY2hlc3RlcjEQMA4GA1UEBxMHU2FsZm9yZDEYMBYGA1UEChMPU2Vj
# dGlnbyBMaW1pdGVkMSUwIwYDVQQDExxTZWN0aWdvIFJTQSBUaW1lIFN0YW1waW5n
# IENBMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAyBsBr9ksfoiZfQGY
# PyCQvZyAIVSTuc+gPlPvs1rAdtYaBKXOR4O168TMSTTL80VlufmnZBYmCfvVMlJ5
# LsljwhObtoY/AQWSZm8hq9VxEHmH9EYqzcRaydvXXUlNclYP3MnjU5g6Kh78zlhJ
# 07/zObu5pCNCrNAVw3+eolzXOPEWsnDTo8Tfs8VyrC4Kd/wNlFK3/B+VcyQ9ASi8
# Dw1Ps5EBjm6dJ3VV0Rc7NCF7lwGUr3+Az9ERCleEyX9W4L1GnIK+lJ2/tCCwYH64
# TfUNP9vQ6oWMilZx0S2UTMiMPNMUopy9Jv/TUyDHYGmbWApU9AXn/TGs+ciFF8e4
# KRmkKS9G493bkV+fPzY+DjBnK0a3Na+WvtpMYMyou58NFNQYxDCYdIIhz2JWtSFz
# Eh79qsoIWId3pBXrGVX/0DlULSbuRRo6b83XhPDX8CjFT2SDAtT74t7xvAIo9G3a
# J4oG0paH3uhrDvBbfel2aZMgHEqXLHcZK5OVmJyXnuuOwXhWxkQl3wYSmgYtnwNe
# /YOiU2fKsfqNoWTJiJJZy6hGwMnypv99V9sSdvqKQSTUG/xypRSi1K1DHKRJi0E5
# FAMeKfobpSKupcNNgtCN2mu32/cYQFdz8HGj+0p9RTbB942C+rnJDVOAffq2OVgy
# 728YUInXT50zvRq1naHelUF6p4MCAwEAAaOCAVowggFWMB8GA1UdIwQYMBaAFFN5
# v1qqK0rPVIDh2JvAnfKyA2bLMB0GA1UdDgQWBBQaofhhGSAPw0F3RSiO0TVfBhIE
# VTAOBgNVHQ8BAf8EBAMCAYYwEgYDVR0TAQH/BAgwBgEB/wIBADATBgNVHSUEDDAK
# BggrBgEFBQcDCDARBgNVHSAECjAIMAYGBFUdIAAwUAYDVR0fBEkwRzBFoEOgQYY/
# aHR0cDovL2NybC51c2VydHJ1c3QuY29tL1VTRVJUcnVzdFJTQUNlcnRpZmljYXRp
# b25BdXRob3JpdHkuY3JsMHYGCCsGAQUFBwEBBGowaDA/BggrBgEFBQcwAoYzaHR0
# cDovL2NydC51c2VydHJ1c3QuY29tL1VTRVJUcnVzdFJTQUFkZFRydXN0Q0EuY3J0
# MCUGCCsGAQUFBzABhhlodHRwOi8vb2NzcC51c2VydHJ1c3QuY29tMA0GCSqGSIb3
# DQEBDAUAA4ICAQBtVIGlM10W4bVTgZF13wN6MgstJYQRsrDbKn0qBfW8Oyf0WqC5
# SVmQKWxhy7VQ2+J9+Z8A70DDrdPi5Fb5WEHP8ULlEH3/sHQfj8ZcCfkzXuqgHCZY
# XPO0EQ/V1cPivNVYeL9IduFEZ22PsEMQD43k+ThivxMBxYWjTMXMslMwlaTW9JZW
# CLjNXH8Blr5yUmo7Qjd8Fng5k5OUm7Hcsm1BbWfNyW+QPX9FcsEbI9bCVYRm5LPF
# Zgb289ZLXq2jK0KKIZL+qG9aJXBigXNjXqC72NzXStM9r4MGOBIdJIct5PwC1j53
# BLwENrXnd8ucLo0jGLmjwkcd8F3WoXNXBWiap8k3ZR2+6rzYQoNDBaWLpgn/0aGU
# pk6qPQn1BWy30mRa2Coiwkud8TleTN5IPZs0lpoJX47997FSkc4/ifYcobWpdR9x
# v1tDXWU9UIFuq/DQ0/yysx+2mZYm9Dx5i1xkzM3uJ5rloMAMcofBbk1a0x7q8ETm
# Mm8c6xdOlMN4ZSA7D0GqH+mhQZ3+sbigZSo04N6o+TzmwTC7wKBjLPxcFgCo0MR/
# 6hGdHgbGpm0yXbQ4CStJB6r97DDa8acvz7f9+tCjhNknnvsBZne5VhDhIG7GrrH5
# trrINV0zdo7xfCAMKneutaIChrop7rRaALGMq+P5CslUXdS5anSevUiumDCCBvUw
# ggTdoAMCAQICEDlMJeF8oG0nqGXiO9kdItQwDQYJKoZIhvcNAQEMBQAwfTELMAkG
# A1UEBhMCR0IxGzAZBgNVBAgTEkdyZWF0ZXIgTWFuY2hlc3RlcjEQMA4GA1UEBxMH
# U2FsZm9yZDEYMBYGA1UEChMPU2VjdGlnbyBMaW1pdGVkMSUwIwYDVQQDExxTZWN0
# aWdvIFJTQSBUaW1lIFN0YW1waW5nIENBMB4XDTIzMDUwMzAwMDAwMFoXDTM0MDgw
# MjIzNTk1OVowajELMAkGA1UEBhMCR0IxEzARBgNVBAgTCk1hbmNoZXN0ZXIxGDAW
# BgNVBAoTD1NlY3RpZ28gTGltaXRlZDEsMCoGA1UEAwwjU2VjdGlnbyBSU0EgVGlt
# ZSBTdGFtcGluZyBTaWduZXIgIzQwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIK
# AoICAQCkkyhSS88nh3akKRyZOMDnDtTRHOxoywFk5IrNd7BxZYK8n/yLu7uVmPsl
# EY5aiAlmERRYsroiW+b2MvFdLcB6og7g4FZk7aHlgSByIGRBbMfDCPrzfV3vIZrC
# ftcsw7oRmB780yAIQrNfv3+IWDKrMLPYjHqWShkTXKz856vpHBYusLA4lUrPhVCr
# ZwMlobs46Q9vqVqakSgTNbkf8z3hJMhrsZnoDe+7TeU9jFQDkdD8Lc9VMzh6CRwH
# 0SLgY4anvv3Sg3MSFJuaTAlGvTS84UtQe3LgW/0Zux88ahl7brstRCq+PEzMrIoE
# k8ZXhqBzNiuBl/obm36Ih9hSeYn+bnc317tQn/oYJU8T8l58qbEgWimro0KHd+D0
# TAJI3VilU6ajoO0ZlmUVKcXtMzAl5paDgZr2YGaQWAeAzUJ1rPu0kdDF3QFAarao
# EO72jXq3nnWv06VLGKEMn1ewXiVHkXTNdRLRnG/kXg2b7HUm7v7T9ZIvUoXo2kRR
# KqLMAMqHZkOjGwDvorWWnWKtJwvyG0rJw5RCN4gghKiHrsO6I3J7+FTv+GsnsIX1
# p0OF2Cs5dNtadwLRpPr1zZw9zB+uUdB7bNgdLRFCU3F0wuU1qi1SEtklz/DT0JFD
# EtcyfZhs43dByP8fJFTvbq3GPlV78VyHOmTxYEsFT++5L+wJEwIDAQABo4IBgjCC
# AX4wHwYDVR0jBBgwFoAUGqH4YRkgD8NBd0UojtE1XwYSBFUwHQYDVR0OBBYEFAMP
# MciRKpO9Y/PRXU2kNA/SlQEYMA4GA1UdDwEB/wQEAwIGwDAMBgNVHRMBAf8EAjAA
# MBYGA1UdJQEB/wQMMAoGCCsGAQUFBwMIMEoGA1UdIARDMEEwNQYMKwYBBAGyMQEC
# AQMIMCUwIwYIKwYBBQUHAgEWF2h0dHBzOi8vc2VjdGlnby5jb20vQ1BTMAgGBmeB
# DAEEAjBEBgNVHR8EPTA7MDmgN6A1hjNodHRwOi8vY3JsLnNlY3RpZ28uY29tL1Nl
# Y3RpZ29SU0FUaW1lU3RhbXBpbmdDQS5jcmwwdAYIKwYBBQUHAQEEaDBmMD8GCCsG
# AQUFBzAChjNodHRwOi8vY3J0LnNlY3RpZ28uY29tL1NlY3RpZ29SU0FUaW1lU3Rh
# bXBpbmdDQS5jcnQwIwYIKwYBBQUHMAGGF2h0dHA6Ly9vY3NwLnNlY3RpZ28uY29t
# MA0GCSqGSIb3DQEBDAUAA4ICAQBMm2VY+uB5z+8VwzJt3jOR63dY4uu9y0o8dd5+
# lG3DIscEld9laWETDPYMnvWJIF7Bh8cDJMrHpfAm3/j4MWUN4OttUVemjIRSCEYc
# KsLe8tqKRfO+9/YuxH7t+O1ov3pWSOlh5Zo5d7y+upFkiHX/XYUWNCfSKcv/7S3a
# /76TDOxtog3Mw/FuvSGRGiMAUq2X1GJ4KoR5qNc9rCGPcMMkeTqX8Q2jo1tT2KsA
# ulj7NYBPXyhxbBlewoNykK7gxtjymfvqtJJlfAd8NUQdrVgYa2L73mzECqls0yFG
# cNwvjXVMI8JB0HqWO8NL3c2SJnR2XDegmiSeTl9O048P5RNPWURlS0Nkz0j4Z2e5
# Tb/MDbE6MNChPUitemXk7N/gAfCzKko5rMGk+al9NdAyQKCxGSoYIbLIfQVxGksn
# NqrgmByDdefHfkuEQ81D+5CXdioSrEDBcFuZCkD6gG2UYXvIbrnIZ2ckXFCNASDe
# B/cB1PguEc2dg+X4yiUcRD0n5bCGRyoLG4R2fXtoT4239xO07aAt7nMP2RC6nZks
# fNd1H48QxJTmfiTllUqIjCfWhWYd+a5kdpHoSP7IVQrtKcMf3jimwBT7Mj34qYNi
# NsjDvgCHHKv6SkIciQPc9Vx8cNldeE7un14g5glqfCsIo0j1FfwET9/NIRx65fWO
# GtS5QDGCBlswggZXAgEBMGswVzELMAkGA1UEBhMCR0IxGDAWBgNVBAoTD1NlY3Rp
# Z28gTGltaXRlZDEuMCwGA1UEAxMlU2VjdGlnbyBQdWJsaWMgQ29kZSBTaWduaW5n
# IENBIEVWIFIzNgIQWNf4/gAhlZOzX5NhAGezezAJBgUrDgMCGgUAoHgwGAYKKwYB
# BAGCNwIBDDEKMAigAoAAoQKAADAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAc
# BgorBgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAjBgkqhkiG9w0BCQQxFgQU206j
# DzUW5RPPcSPIWC8bqKcHIfowDQYJKoZIhvcNAQEBBQAEggIAiel1Lb5Luk8RsAz7
# Tbs5/rJzNKTLHkp52QuJfp92pGuthQ8QTFIv6l7NaVmmCzSObJzKkbTF/bqc9r4S
# Ny1fb5wraqDRVmHEkLa+RGfH2oGqXwBYPQLrVu5l5UsLCyWG/m+larPcOz/hNEd+
# vcyh8Rh/jTxxsQDDzgt4wFHPPDFWtQPRcajGM3RFrapx1piPp1DTKnYzRkOFHNdZ
# qz8liEErwy9KS0F3bBKg84q872JpXOYlvEbMpkX/zUQJ+wjCJmysVrYYzng8pQaj
# uCOhGF1D7++TYy+mBv/Fmz0jGLVEek06jOKXCEmmVZV9R0+r4u4Ghp8JAXqMwbBq
# vsT0dfnoc1ih7sHzosb6W5HSKfqG/HxK1OYjhCZgkMFJc5unO8SBdAT5lvgC11mT
# kkeDzafvtPhzcAtFXO9F3qdILhdZrtVTXdynsu5yQQrk7FsIRDTXgaaFtL3dMyt1
# hN2w/tyl8RJva7Ffeg5ut5hePx0ialZ2Fe9imat1AjdLY0AnMVvw3vX5GMOYoynf
# TmGX0OUT/zBmgu62j+h6zMAQGWFx+BJllXFSO8uMRxYdhrU5AYrhVWSRTQc8vN03
# IbR+BOr11Ad1hgDSvcjHvPNKcNva3ISeI6j51Dm+PZldg7oJexd9+woNP3KQ4W5l
# lycatUyrBwPm3VMIFnJqH7jAubShggNLMIIDRwYJKoZIhvcNAQkGMYIDODCCAzQC
# AQEwgZEwfTELMAkGA1UEBhMCR0IxGzAZBgNVBAgTEkdyZWF0ZXIgTWFuY2hlc3Rl
# cjEQMA4GA1UEBxMHU2FsZm9yZDEYMBYGA1UEChMPU2VjdGlnbyBMaW1pdGVkMSUw
# IwYDVQQDExxTZWN0aWdvIFJTQSBUaW1lIFN0YW1waW5nIENBAhA5TCXhfKBtJ6hl
# 4jvZHSLUMA0GCWCGSAFlAwQCAgUAoHkwGAYJKoZIhvcNAQkDMQsGCSqGSIb3DQEH
# ATAcBgkqhkiG9w0BCQUxDxcNMjMxMjA0MTIzMDU1WjA/BgkqhkiG9w0BCQQxMgQw
# rg3WKLqHhwpq69PyYD7PJVcbL+IV07vU+bc8IyuYhomFn7mH9JhtFZCvOhAmZDMj
# MA0GCSqGSIb3DQEBAQUABIICAHqdVMYZPocCYaTlvgsq8AAGGzu10LGstdE5jSiy
# HJQ3qrlqlsiTHtEEdEWJJWSzir1p/cYIukog45R9rYDhYNEJM5Q5+vInPDUxowKV
# 8gghFeB8Yec7dyBbzDxkvGkhrOQkrJeh212yrvJwqvw5mqrIa4LjF8e53uXwOQky
# sXSkAbJbW7lHh1rH6a4gqzs0NjCrLdcWS2QCJXprb18Vgt4Gij1gzZ9hksWdv64R
# WHweZC7JZ5y1QLa/3kz38GSXesMOfGJ11ElMytxSG44VP9fTbKoaDyGVNadT0hwJ
# 4JJx2I1bmUZ4AxlCyUdvI9DccN2cEn/1uS7sXS1VgitQxUhBXX/lHMm/gldki2JL
# IQU+JwF3XxrUo1z5rnxRTGIm9z+i/il/afTTpTuRbNG+fZJT3zPc1LDzyahy5OTp
# wzLvtXUxCKfwfaigx8T7BjzRYojNciXyGIelk7fzBXb4ENh4f3QZYtSstSGUr/ND
# l9o0YbBu030OI0nE+et3dQAvBy2R38Ws5nxwu1glpnuWqRDgwbVJn3sLK79ArKew
# kTDQjMxJSl3kJSxxxlQ5LFGVHpqACdvtLRi4HynpYDSa96GdtvKToGISZ8iTO9t/
# mJz4WGaVtXnhG9CcEr3wstIpvwn4eI1RsAT7Rj1SWPgztD2+LnM9hHPiwnDf11R8
# DtYk
# SIG # End signature block
