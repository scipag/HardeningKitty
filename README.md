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

## Last Update

The lists were last updated/checked against the following Microsoft Security Baseline or other frameworks:

* Hardening list Windows 10
	- Security baseline for Windows 10 and Windows Server, version 2004
	- Security baseline for Office 365 ProPlus, version 1908
* finding\_list\_0x6d69636b\_machine and finding\_list\_0x6d69636b\_user
	- Security baseline for Windows 10 and Windows Server, version 2004
	- Security baseline for Office 365 ProPlus, version 1908
	- 0x6d69636b own knowledge 
* finding\_list\_msft\_security\_baseline\_edge\_machine
	- Security baseline for Microsoft Edge, version 85
* finding\_list\_msft\_security\_baseline\_windows\_10\_machine
	- Security baseline for Windows 10 and Windows Server, version 2004
* finding\_list\_msft\_security\_baseline\_windows\_server\_dc\_machine
	- Security baseline for Windows 10 and Windows Server, version 2004
* finding\_list\_msft\_security\_baseline\_windows\_server\_member\_machine
	- Security baseline for Windows 10 and Windows Server, version 2004

