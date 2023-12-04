# HardeningKitty

This is the stable version of _HardeningKitty_ from the [Windows Hardening Project by Michael Schneider](https://github.com/0x6d69636b/windows_hardening). The stable version of _HardeningKitty_ is signed with the code signing certificate of _scip AG_. **Since this is the stable version, we do not accept pull requests in this repo, please send them to the [development repo](https://github.com/0x6d69636b/windows_hardening)**. 

_HardeningKitty_ supports hardening of a Windows system. The configuration of the system is retrieved and assessed using a finding list. In addition, the system can be hardened according to predefined values. _HardeningKitty_ reads settings from the registry and uses other modules to read configurations outside the registry.

The script was developed for English systems. It is possible that in other languages the analysis is incorrect. Please create an issue if this occurs.

## How to Run

Run the script with administrative privileges to access machine settings. For the user settings it is better to execute them with a normal user account. Ideally, the user account is used for daily work.

Download _HardeningKitty_ and copy it to the target system (script and lists). Then HardeningKitty can be imported and executed:

```powershell
PS C:\tmp> Import-Module .\HardeningKitty.psm1
PS C:\tmp> Invoke-HardeningKitty -EmojiSupport


         =^._.^=
        _(      )/  HardeningKitty 0.9.0-1662273740


[*] 9/4/2022 8:54:12 AM - Starting HardeningKitty


[*] 9/4/2022 8:54:12 AM - Getting user information
[*] Hostname: DESKTOP-DG83TOD
[*] Domain: WORKGROUP

...

[*] [*] 9/4/2022 8:54:12 AM - Starting Category Account Policies
[😺] ID 1103, Store passwords using reversible encryption, Result=0, Severity=Passed
[😺] ID 1100, Account lockout threshold, Result=10, Severity=Passed
[😺] ID 1101, Account lockout duration, Result=30, Severity=Passed

...

[*] 9/4/2022 8:54:12 AM - Starting Category User Rights Assignment
[😿] ID 1200, Access this computer from the network, Result=BUILTIN\Administrators;BUILTIN\Users, Recommended=BUILTIN\Administrators, Severity=Medium

...

[*] 9/4/2022 8:54:14 AM - Starting Category Administrative Templates: Printer
[🙀] ID 1764, Point and Print Restrictions: When installing drivers for a new connection (CVE-2021-34527), Result=1, Recommended=0, Severity=High
[🙀] ID 1765, Point and Print Restrictions: When updating drivers for an existing connection (CVE-2021-34527), Result=2, Recommended=0, Severity=High

...

[*] 9/4/2022 8:54:19 AM - Starting Category MS Security Guide
[😿] ID 2200, LSA Protection, Result=, Recommended=1, Severity=Medium
[😼] ID 2201, Lsass.exe audit mode, Result=, Recommended=8, Severity=Low

...

[*] 9/4/2022 8:54:25 AM - HardeningKitty is done
[*] 9/4/2022 8:54:25 AM - Your HardeningKitty score is: 4.82. HardeningKitty Statistics: Total checks: 325 - Passed: 213, Low: 33, Medium: 76, High: 3.
```

## How To Install

First create the directory *HardeningKitty* and for every version a sub directory like *0.9.2* in a path listed in the *PSModulePath* environment variable.

Copy the module *HardeningKitty.psm1*, *HardeningKitty.psd1*, and the *lists* directory to this new directory.

```powershell
PS C:\tmp> $Version = "0.9.2"
PS C:\tmp> New-Item -Path $Env:ProgramFiles\WindowsPowerShell\Modules\HardeningKitty\$Version -ItemType Directory
PS C:\tmp> Copy-Item -Path .\HardeningKitty.psd1,.\HardeningKitty.psm1,.\lists\ -Destination $Env:ProgramFiles\WindowsPowerShell\Modules\HardeningKitty\$Version\ -Recurse
```

For more information see Microsoft's article [Installing a PowerShell Module](https://docs.microsoft.com/en-us/powershell/scripting/developer/module/installing-a-powershell-module).

### How to Automatically Download and Install the Latest Release

You can use the script below to download and install the latest release of *HardeningKitty*.

```powershell
Function InstallHardeningKitty() {
    $Version = (((Invoke-WebRequest "https://api.github.com/repos/scipag/HardeningKitty/releases/latest" -UseBasicParsing) | ConvertFrom-Json).Name).SubString(2)
    $HardeningKittyLatestVersionDownloadLink = ((Invoke-WebRequest "https://api.github.com/repos/scipag/HardeningKitty/releases/latest" -UseBasicParsing) | ConvertFrom-Json).zipball_url
    $ProgressPreference = 'SilentlyContinue'
    Invoke-WebRequest $HardeningKittyLatestVersionDownloadLink -Out HardeningKitty$Version.zip
    Expand-Archive -Path ".\HardeningKitty$Version.zip" -Destination ".\HardeningKitty$Version" -Force
    $Folder = Get-ChildItem .\HardeningKitty$Version | Select-Object Name -ExpandProperty Name
    Move-Item ".\HardeningKitty$Version\$Folder\*" ".\HardeningKitty$Version\"
    Remove-Item ".\HardeningKitty$Version\$Folder\"
    New-Item -Path $Env:ProgramFiles\WindowsPowerShell\Modules\HardeningKitty\$Version -ItemType Directory
    Set-Location .\HardeningKitty$Version
    Copy-Item -Path .\HardeningKitty.psd1,.\HardeningKitty.psm1,.\lists\ -Destination $Env:ProgramFiles\WindowsPowerShell\Modules\HardeningKitty\$Version\ -Recurse
    Import-Module "$Env:ProgramFiles\WindowsPowerShell\Modules\HardeningKitty\$Version\HardeningKitty.psm1"
}
InstallHardeningKitty
```

### Examples

#### Audit

The default mode is _audit_. HardeningKitty performs an audit, saves the results to a CSV file and creates a log file. The files are automatically named and receive a timestamp. Using the parameters _ReportFile_ or _LogFile_, it is also possible to assign your own name and path.

The _Filter_ parameter can be used to filter the hardening list. For this purpose the PowerShell ScriptBlock syntax must be used, for example `{ $_.ID -eq 4505 }`. The following elements are useful for filtering: ID, Category, Name, Method, and Severity.

```powershell
Invoke-HardeningKitty -Mode Audit -Log -Report
```

HardeningKitty can be executed with a specific list defined by the parameter _FileFindingList_. If HardeningKitty is run several times on the same system, it may be useful to hide the machine information. The parameter _SkipMachineInformation_ is used for this purpose.

```powershell
Invoke-HardeningKitty -FileFindingList .\lists\finding_list_0x6d69636b_user.csv -SkipMachineInformation
```

HardeningKitty uses the default list, and checks only tests with the severity Medium.

```powershell
Invoke-HardeningKitty -Filter { $_.Severity -eq "Medium" }
```

#### Config

The mode _config_ retrives all current settings of a system. If a setting has not been configured, HardeningKitty will use a default value stored in the finding list. This mode can be combined with other functions, for example to create a backup.

HardeningKitty gets the current settings and stores them in a report:

```powershell
Invoke-HardeningKitty -Mode Config -Report -ReportFile C:\tmp\my_hardeningkitty_report.csv
```

#### Backup

Backups are important. Really important. Therefore, HardeningKitty also has a function to retrieve the current configuration and save it in a form that can be partially restored.

**Disclaimer:** HardeningKitty tries to restore the original configuration. This works quite well with registry keys and Hardening Kitty really tries its best. But the backup function is not a snapshot and does not replace a real system backup. It is not possible to restore the system 1:1 with HardeningKitty alone after HailMary. If this is a requirement, create an image or system backup and restore it.

The _Backup_ switch specifies that the file is written in form of a finding list and can thus be used for the _HailMary_ mode. The name and path of the backup can be specified with the parameter _BackupFile_.

```powershell
Invoke-HardeningKitty -Mode Config -Backup
```

Please test this function to see if it really works properly on the target system before making any serious changes. A Schrödinger's backup is dangerous.

##### Non-Default Finding List

Note that if _-FileFindingList_ is not specified, the backup is referred to the default finding list. Before deploying a _specific_ list in _HailMary_ mode, always create a backup _referred to that specific list_.

```powershell
Invoke-HardeningKitty -Mode Config -Backup -BackupFile ".\myBackup.csv" -FileFindingList ".\list\{list}.csv"
```

##### Restoring a Backup

The _Backup_ switch creates a file in form of a finding list, to restore the backup load it in _HailMary_ mode like any find list:

```powershell
Invoke-HardeningKitty -Mode HailMary -Log -Report -FileFindingList ".\myBackup.csv"
```

#### HailMary

The _HailMary_ method is very powerful. It can be used to deploy a finding list on a system. All findings are set on this system as recommended in the list. With power comes responsibility. Please use this mode only if you know what you are doing. Be sure to have a backup of the system.

```powershell
Invoke-HardeningKitty -Mode HailMary -Log -Report -FileFindingList .\lists\finding_list_0x6d69636b_machine.csv
```

Before HailMary is run, a finding list must be picked. It is important to check whether the settings have an influence on the stability and functionality of the system. Before running HailMary, a backup should be made.

#### Create a Group Policy (experimental)

Thanks to [@gderybel](https://github.com/gderybel), HardeningKitty can convert a finding list into a group policy. At the moment only registry settings can be converted and not everything has been tested yet. A new policy is created, as long as it is not assigned to an object, no change is made to the system. Use it with care.

```powershell
Invoke-HardeningKitty -Mode GPO -FileFindingList .\lists\finding_list_0x6d69636b_machine.csv -GPOName HardeningKitty-Machine-01
```

## HardeningKitty Score

Each Passed finding gives 4 points, a Low finding gives 2 points, a Medium finding gives 1 point and a High Finding gives 0 points.

The formula for the HardeningKitty Score is _(Points achieved / Maximum points) * 5 + 1_.

### Rating

| Score | Rating Casual | Rating Professional |
| :---- | :------------ | :------------------ |
| 6 | 😹 Excellent | Excellent |
| 5 | 😺 Well done | Good |
| 4 | 😼 Sufficient | Sufficient |
| 3 | 😿 You should do better | Insufficient |
| 2 | 🙀 Weak | Insufficient |
| 1 | 😾 Bogus | Insufficient |

## HardeningKitty Interface

[ataumo](https://github.com/ataumo) build a web based interface for HardeningKitty. The tool can be used to create your own lists and provides additional information on the hardening settings. The [source code](https://github.com/ataumo/policies_hardening_interface) is under AGPL license and there is a [demo site](https://phi.cryptonit.fr/policies_hardening_interface/).

### Last Update

HardeningKitty can be used to audit systems against the following baselines / benchmarks:

| Name | System Version    | Version  |
| :--- | :---------------- | :------  |
| 0x6d69636b Windows 10 (Machine) | 22H2 | |
| 0x6d69636b Windows 10 (User) | 22H2 | |
| BSI SiSyPHuS Windows 10 hoher Schutzbedarf Domänenmitglied (Machine) | 1809 | 1.0 |
| BSI SiSyPHuS Windows 10 hoher Schutzbedarf Domänenmitglied (User) | 1809| 1.0
| BSI SiSyPHuS Windows 10 normaler Schutzbedarf Domänenmitglied (Machine) | 1809| 1.0 |
| BSI SiSyPHuS Windows 10 normaler Schutzbedarf Domänenmitglied (User) | 1809| 1.0 |
| BSI SiSyPHuS Windows 10 normaler Schutzbedarf Einzelrechner (Machine) | 1809| 1.0 |
| BSI SiSyPHuS Windows 10 normaler Schutzbedarf Einzelrechner (User) | 1809 | 1.0 |
| CIS Microsoft Windows 10 Enterprise (Machine) | 1809 | 1.6.1 |
| CIS Microsoft Windows 10 Enterprise (User) | 1809 | 1.6.1 |
| CIS Microsoft Windows 10 Enterprise (Machine) | 1903 | 1.7.1 |
| CIS Microsoft Windows 10 Enterprise (User) | 1903 | 1.7.1 |
| CIS Microsoft Windows 10 Enterprise (Machine) | 1909 | 1.8.1 |
| CIS Microsoft Windows 10 Enterprise (User) | 1909 | 1.8.1 |
| CIS Microsoft Windows 10 Enterprise (Machine) | 2004 | 1.9.1 |
| CIS Microsoft Windows 10 Enterprise (User) | 2004 | 1.9.1 |
| CIS Microsoft Windows 10 Enterprise (Machine) | 20H2 | 1.10.1 |
| CIS Microsoft Windows 10 Enterprise (User) | 20H2 | 1.10.1 |
| CIS Microsoft Windows 10 Enterprise (Machine) | 21H1 | 1.11.0 |
| CIS Microsoft Windows 10 Enterprise (User) | 21H1 | 1.11.0 |
| CIS Microsoft Windows 10 Enterprise (Machine) | 21H2 | 1.12.0 |
| CIS Microsoft Windows 10 Enterprise (User) | 21H2 | 1.12.0 |
| CIS Microsoft Windows 10 Enterprise (Machine) | 22H2 | 2.0.0 |
| CIS Microsoft Windows 10 Enterprise (User) | 22H2 | 2.0.0 |
| CIS Microsoft Windows 11 Enterprise (Machine) | 21H2 | 1.0.0 |
| CIS Microsoft Windows 11 Enterprise (User) | 21H2 | 1.0.0 |
| CIS Microsoft Windows 11 Enterprise (Machine) | 22H2 | 2.0.0 |
| CIS Microsoft Windows 11 Enterprise (User) | 22H2 | 2.0.0 |
| CIS Microsoft Windows Server 2012 R2 (Machine) | R2 | 2.4.0 |
| CIS Microsoft Windows Server 2012 R2 (User) | R2 | 2.4.0 |
| CIS Microsoft Windows Server 2012 R2 (Machine) | R2 | 2.6.0 |
| CIS Microsoft Windows Server 2012 R2 (User) | R2 | 2.6.0 |
| CIS Microsoft Windows Server 2016 (Machine) | 1607 | 1.2.0 |
| CIS Microsoft Windows Server 2016 (User) | 1607 | 1.2.0 |
| CIS Microsoft Windows Server 2016 (Machine) | 1607 | 1.3.0 |
| CIS Microsoft Windows Server 2016 (User) | 1607 | 1.3.0 |
| CIS Microsoft Windows Server 2016 (Machine) | 1607 | 2.0.0 |
| CIS Microsoft Windows Server 2016 (User) | 1607 | 2.0.0 |
| CIS Microsoft Windows Server 2019 (Machine) | 1809 | 1.1.0 |
| CIS Microsoft Windows Server 2019 (User) | 1809 | 1.1.0 |
| CIS Microsoft Windows Server 2019 (Machine) | 1809 | 1.2.1 |
| CIS Microsoft Windows Server 2019 (User) | 1809 | 1.2.1 |
| CIS Microsoft Windows Server 2019 (Machine) | 1809 | 2.0.0 |
| CIS Microsoft Windows Server 2019 (User) | 1809 | 2.0.0 |
| CIS Microsoft Windows Server 2022 (Machine) | 21H2 | 1.0.0 |
| CIS Microsoft Windows Server 2022 (User) | 21H2 | 1.0.0 |
| CIS Microsoft Windows Server 2022 (Machine) | 22H2 | 2.0.0 |
| CIS Microsoft Windows Server 2022 (User) | 22H2 | 2.0.0 |
| DoD Microsoft Windows 10 STIG (Machine) | 20H2 | v2r1 |
| DoD Microsoft Windows 10 STIG (User) | 20H2 | v2r1 |
| DoD Windows Server 2019 Domain Controller STIG (Machine) | 20H2 | v2r1 |
| DoD Windows Server 2019 Domain Controller STIG (User) | 20H2 | v2r1 |
| DoD Windows Server 2019 Member Server STIG (Machine) | 20H2 | v2r1 |
| DoD Windows Server 2019 Member Server STIG (User) | 20H2 | v2r1 |
| DoD Windows Defender Antivirus STIG | 20H2 | v2r1 |
| DoD Windows Firewall STIG | 20H2 | v1r7 |
| Microsoft Security baseline for Microsoft Edge | 87 | Final |
| Microsoft Security baseline for Microsoft Edge | 88, 89, 90, 91 | Final |
| Microsoft Security baseline for Microsoft Edge | 92 | Final |
| Microsoft Security baseline for Microsoft Edge | 93, 94 | Final |
| Microsoft Security baseline for Microsoft Edge | 95 | Final |
| Microsoft Security baseline for Microsoft Edge | 96 | Final |
| Microsoft Security baseline for Microsoft Edge | 97 | Final |
| Microsoft Security baseline for Microsoft Edge | 98, 99, 100, 101, 102, 103, 104, 105, 106 | Final |
| Microsoft Security baseline for Microsoft Edge | 107, 108, 109, 110, 111 | Final |
| Microsoft Security baseline for Microsoft Edge | 112, 113 | Final |
| Microsoft Security baseline for Microsoft Edge | 114, 115, 116 | Final |
| Microsoft Security baseline for Microsoft Edge | 117, 118, 119 | Final |
| Microsoft Security baseline for Windows 10 | 2004 | Final |
| Microsoft Security baseline for Windows 10 | 20H2, 21H1 | Final |
| Microsoft Security baseline for Windows 10 | 21H2 | Final |
| Microsoft Security baseline for Windows 10 (Machine) | 22H2 | Final |
| Microsoft Security baseline for Windows 10 (User) | 22H2 | Final |
| Microsoft Security baseline for Windows 11 | 21H2 | Final |
| Microsoft Security baseline for Windows 11 (Machine) | 22H2 | Final |
| Microsoft Security baseline for Windows 11 (User) | 22H2 | Final |
| Microsoft Security baseline for Windows 11 (Machine) | 23H2 | Final |
| Microsoft Security baseline for Windows 11 (User) | 23H2 | Final |
| Microsoft Security baseline for Windows Server (DC) | 2004 | Final |
| Microsoft Security baseline for Windows Server (Member) | 2004 | Final |
| Microsoft Security baseline for Windows Server (DC) | 20H2 | Final |
| Microsoft Security baseline for Windows Server (Member) | 20H2 | Final |
| Microsoft Security baseline for Windows Server 2022 (DC) | 21H2 | Final |
| Microsoft Security baseline for Windows Server 2022 (Member) | 21H2 | Final |
| Microsoft Security baseline for Office 365 ProPlus (Machine) | Sept 2019 | Final |
| Microsoft Security baseline for Office 365 ProPlus (User) | Sept 2019 | Final |
| Microsoft Security Baseline for Microsoft 365 Apps for enterprise (Machine) | v2104, v2106 | Final |
| Microsoft Security Baseline for Microsoft 365 Apps for enterprise (User) | v2104, v2106 | Final |
| Microsoft Security Baseline for Microsoft 365 Apps for enterprise (Machine) | v2112 | Final |
| Microsoft Security Baseline for Microsoft 365 Apps for enterprise (User) | v2112 | Final |
| Microsoft Security Baseline for Microsoft 365 Apps for enterprise (Machine) | v2206 | Final |
| Microsoft Security Baseline for Microsoft 365 Apps for enterprise (User) | v2206 | Final |
| Microsoft Security Baseline for Microsoft 365 Apps for enterprise (Machine) | v2306 | Final |
| Microsoft Security Baseline for Microsoft 365 Apps for enterprise (User) | v2306 | Final |
| Microsoft Windows Server TLS Settings | 1809 | 1.0 |
| Microsoft Windows Server TLS Settings (Future Use with TLSv1.3) | 1903 | 1.0 |
