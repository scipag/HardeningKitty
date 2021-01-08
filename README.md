# HardeningKitty

This is the stable version of Hardening Kitty from the [Windows Hardening Project by Michael Schneider](https://github.com/0x6d69636b/windows_hardening).

_HardeningKitty_ supports hardening of a Windows system. The configuration of the system is retrieved and assessed using a finding list. In addition, the system can be hardened according to predefined values. _HardeningKitty_ reads settings from the registry and uses other modules to read configurations outside the registry.

**Attention**: HardeningKitty has a dependency for the tool AccessChk by Mark Russinovich. This must be present on the computer and defined in the script accordingly.

The script was developed for English systems. It is possible that in other languages the analysis is incorrect. Please create an issue if this occurs.

## How to run

Run the script with administrative privileges to access machine settings. For the user settings it is better to execute them with a normal user account. Ideally, the user account is used for daily work.

Download _HardeningKitty_ and copy it to the target system (script and lists). Additionally, [AccessChk](https://docs.microsoft.com/en-us/sysinternals/downloads/accesschk) (tested with version 1.6.2) must be available on the target system. The path of the variable _$BinaryAccesschk_ must be modified accordingly. After that HardeningKitty can be imported and executed:

```powershell
PS C:\> Import-Module Invoke-HardeningKitty.ps1
PS C:\> Invoke-HardeningKitty -EmojiSupport


         =^._.^=
        _(      )/  HardeningKitty


[*] 5/28/2020 4:39:16 PM - Starting HardeningKitty


[*] 5/28/2020 4:39:16 PM - Getting machine information
[*] Hostname: w10
[*] Domain: WORKGROUP

...

[*] 5/28/2020 4:39:21 PM - Starting Category Account Policies
[😺] ID 1100, Account lockout duration, Result=30, Severity=Passed
[😺] ID 1101, Account lockout threshold, Result=5, Severity=Passed
[😺] ID 1102, Reset account lockout counter, Result=30, Severity=Passed

...

[*] 5/28/2020 4:39:23 PM - Starting Category Advanced Audit Policy Configuration
[😼] ID 1513, Kernel Object, Result=, Recommended=Success and Failure, Severity=Low

...

[*] 5/28/2020 4:39:24 PM - Starting Category System
[😿] ID 1614, Device Guard: Virtualization Based Security Status, Result=Not available, Recommended=2, Severity=Medium

...

[*] 5/28/2020 4:39:25 PM - Starting Category Windows Components
[🙀] ID 1708, BitLocker Drive Encryption: Volume status, Result=FullyDecrypted, Recommended=FullyEncrypted, Severity=High

...

[*] 5/28/2020 4:39:34 PM - HardeningKitty is done
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

## Last Update

HardeningKitty can be used to audit systems against the following baselines / benchmarks:

| Name | System Version    | Version  |
| :--- | :---------------- | :------  |
| 0x6d69636b (Machine) | 2009 | |
| 0x6d69636b (User) | 2009 | |
| CIS Microsoft Windows 10 Enterprise (Machine) | 2004 | 1.9.1 |
| CIS Microsoft Windows 10 Enterprise (User) | 2004 | 1.9.1 |
| CIS Microsoft Windows Server 2019 (Machine) | 1809 | 1.1.0 |
| CIS Microsoft Windows Server 2019 (User) | 1809 | 1.1.0 |
| Microsoft Security baseline for Microsoft Edge | 87 | Final |
| Microsoft Security baseline for Windows 10 version 2004 | 2004 | Final |
| Microsoft Security baseline for Windows 10 version 2009 | 2009 | Final |
| Microsoft Security baseline for Windows Server version 2004 (DC) | 2004 | Final |
| Microsoft Security baseline for Windows Server version 2004 (Member) | 2004 | Final |
| Microsoft Security baseline for Windows Server 10 version 2009 (DC) | 2009 | Final |
| Microsoft Security baseline for Windows Server 10 version 2009 (Member) | 2009 | Final |
| Microsoft Security baseline for Office 365 ProPlus (Machine) | Sept 2019 | Final |
| Microsoft Security baseline for Office 365 ProPlus (User) | Sept 2019 | Final |