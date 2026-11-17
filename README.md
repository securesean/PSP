# Personal Security Product

Sean Pierce

As normal computer user, I've always been a little miffed that I don't have a basic awareness of who is remotely accessing/scanning/attacking my machine. So I created this program to simply notify me of the most obvious events I would want to know about. I'm making/testing this as I go along and I add things when something jumps out to me as an attacker. I'm not implementing a stig checker / attack surface analyzer but I will list remote access oriented things such as LocalAccountTokenFilterPolicy. Everything here is just a PoC; When I get serious I will re-implement it as a service, with a real installer and updater.

## Download
[Latest Version Here](https://github.com/securesean/PSP/releases)

## Features:
- Can be installed as a persistent Windows Service (`-install` / `-uninstall`) running as `SYSTEM` (`PSPService`) with a separate user-mode notification agent (`PSP_Notifier.exe`) that displays Toast notifications in the interactive user session
- Structured rule engine (`RuleEngine` & `%ProgramData%\PSP_Logs\rules_config.json`) for evaluating logon exclusions, process filters, and well-known group SIDs
- Built-in self-performance and memory bloat monitor (`SelfPerformanceMonitor`) that tracks Working Set, Private Memory, Managed Heap, Handles, and Thread counts, bounded event caching, and automatic GC reclamation
- Real-time system state monitoring (`SystemStateMonitor`): alerts if `LocalAccountTokenFilterPolicy` registry value is modified, if Windows Firewall is disabled on any profile, if an inbound allow Firewall rule is added, or if a Windows Service starts listening on a new TCP port; also supports automatically downloading and installing Sysmon (`-sysmon`)
- Listens on common ports (`80`, `443`, `22`) to detect and alert on attempted port scanning / unauthorized connections, and automatically performs reverse DNS hostname resolution and a basic TCP port scan against the connecting host
- When something attempts to remotely accessing/scanning/attacking my machine a toast notification will notify the user
- Full details are writen to `%ProgramData%\PSP_Logs` (with explicit `yyyy-MM-dd HH:mm:ss` timestamps and dedicated crash/exception diagnostics in `PSP_CrashLog.txt`)
- Toast on-click event opens the xml log, and Toast notifications include custom notification sound, app & button icons, a **"Never show this again"** button, and contextual default response actions (**Block IP**, **Kill Service**, **Check VT for Exe**, **Scan YARA / Watch**, **Logoff & Reset Pass**, and **Launch Autoruns**)
- Includes and displays a Basic License & EULA (`LICENSE.txt` and `--license` / `--eula` flag, plus automatic first-run display)
- `--test` runs real (non-simulated) end-to-end self-tests (creating real test accounts, performing real network/explicit-credential logons, and installing a real temporary Windows Service) and automatically enables missing Windows Audit Policy subcategories (such as `Security System Extension` via `auditpol.exe`) when events like `4697` are not yet enabled
- Supported Events:
   - 4624 - Logon Success 
   - 4625 - Logon Failed 
   - 4697 - Service Installed
   - 1102 - Security Log Cleared
   - 4798 - Local User Group Membership Enumerated
   - 4799 - Security-Enabled Local Group Membership Enumerated
   - 4726 - User Deleted
   - 4720 - User Created
   - 4722 - User Enabled
   - 4732 - User Added To Group
   - 4622 - Lsass Loaded Package
   - 4614 - Notifcation Package Loaded
   - 4611 - Lsass Logon
   - 4610 - Lsass Loaded Auth Package
   - 4648 - User Logon With Creds
   - 4724 - Password Reset
   - 4656 / 4663 - Securable Object Accessed (SAM, LSASS, or configured SACL canary keys)
   - 4672 / 4673 / 4674 - Sensitive Privilege Assignment & Use (`SeDebugPrivilege`, `SeLoadDriverPrivilege`, `SeTakeOwnershipPrivilege`)
   - 4688 - Suspicious Process Creation (DeepBlueCLI / BST command-line indicators)
   - 4728 / 4756 - User Added to Global / Universal Security Group
   - System Log: 104 (Log Cleared), 7030 (Interactive Service), 7036 (Security Service Stopped), 7040 (Service Start Type Changed), 7045 (New Service Installed)
   - Application Log: 2, 1033, 1107 (Suspicious installer / application events)
   - AppLocker: 8003, 8004, 8006, 8007 (Blocked EXE, DLL, MSI, or Script execution)
   - PowerShell Operational: 4103, 4104 (Suspicious PowerShell Script Block / Module execution)
   - WinRM Operational: 91 (Remote WSMan Shell creation)
   - Sysmon Operational: 1 (Process Creation), 7 (Image Loaded)

![RemoteLogon](assets/RemoteLogon.png)

![ServiceInstall](assets/ServiceInstall.png)

![ServiceInstall](assets/AddedToGroup.png)

## How to Install
- Run `PSP_Console.exe -install` from an Administrator prompt to install and start the `PSPService` Windows Service and register the user-mode toast agent (`PSP_Notifier.exe`) to run at user logon (use `PSP_Console.exe -uninstall` to remove)
- Or double click `PSP_Console.exe` to run interactively in console mode (it will pop a UAC prompt and launch `PSP_Notifier.exe` in user mode)
- Enable "Security System Extension" to support these events: https://www.windows-security.org/b355febe2c7a2ae1eaba46c4470d6d4a/security-system-extension . See if your machine is already collecting them with the command: `AuditPol /get /category:* | grep "Security System Extension"` By default it will say, "No Auditing". We (probably) need it to say, "Success"
 - Inspired based on: https://www.stigviewer.com/stig/windows_7/2017-12-01/finding/V-26556 Fix Text (F-29805r1_fix)
 - GUI - secpol.msc  https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/how-to-configure-security-policy-settings enable "Audit Security System Extension" . C# - https://docs.microsoft.com/en-us/dotnet/api/system.security.accesscontrol.filesystemauditrule?view=net-6.0
 - GUI - gpedit.msc: Computer Configuration\Windows Settings\Advanced Audit Policy Configuration\System -> "Audit Security System Extension"
WARNING: I am not a Windows Logging expert and I have observed that making these changes via the GUI will supress other events


## How to Compile:
- Right click on the project in the "Solution Explorer" and choose, "Manage NuGet Packages" and install, "Microsoft.Toolkit.Uwp.Notifications"
- Click Build Solution

## TODO - Add a "-SecurityEvaluation" option 
- Do basic security checks such as WinRm/RDP is enabled, Guest is enabled and is in groups, the Admin account is enabled with default name. Look at stigs for inspiration . 
- Print basic information such as "X number of users can access this computer remotely via RDP, SMB/RPC/DCOM, WinRM"
- Check local token filter policy  
- Download and execute autoruns for the user
- Make a 'Lockdown' mode that will stop WinRM,LanMan,RDP,SSH and start listening on those ports instead to block them
- The valuation mode will also:
   - list all users/groups in local admin groups
   - resursively lookup domain groups and users in admin groups
   - list weird services
   - list and programs listening on any ports
   - list the services running on those ports 
   - detect if "System Security Extention" is enabled

# TODO - Possible Future
- Subscribe to events on a remote computer: https://docs.microsoft.com/en-us/previous-versions/bb671202(v=vs.90)?redirectedfrom=MSDN
- Support self-installing on a remote system
- Send toast notications to a remote computer
- Perhaps look at implementing good basic perodic execution rules? (Example: High Entropy file names, single letter executables, known malicious exe names, known malicious pipe names, or rundll32 without any arguements, etc.)
- Other periodic checks (pre-fetch files deleted)
- Vaccine capabilitiy - launch known analysis tool file names, mutex's
- Perhaps look at what a local sigma instance might look like?
- Pull down public domain/ip known malicious ip's/domains and alert if nework detections happen to them. Could leverage intel from https://strontic.github.io/xcyclopedia/


## Credits
Icon from: https://icon-icons.com/download/127074/ICO/512/
