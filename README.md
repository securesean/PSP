# Personal Security Product

Sean Pierce

As normal computer user, I've always been a little miffed that I don't have a basic awareness of who is remotely accessing/scanning/attacking my machine. So I created this program to simply notify me of the most obvious events I would want to know about. I'm making/testing this as I go along and I add things when something jumps out to me as an attacker. I'm not implementing a stig checker / attack surface analyzer but I will list remote access oriented things such as LocalAccountTokenFilterPolicy. Everything here is just a PoC; When I get serious I will re-implement it as a service, with a real installer and updater.

## Download
[Latest Version Here](https://github.com/securesean/PSP/releases)

## Features:
- When something attempts to remotely accessing/scanning/attacking my machine a toast notification will notify the user
- Full details are writen to %Programdata%\PSP_Logs
- Toast on-click event opens the xml log 
- `--test` will test about half the events to verify end-to-end functionality 
- Supported Events:
   - 4624 - Logon Success 
   - 4625 - Logon Failed 
   - 4697 - Service Installed
   - 1102 - Security Log Cleared
   - 4798 - Local Group Enum (a little noisy sometimes)
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

![RemoteLogon](assets/RemoteLogon.png)

![ServiceInstall](assets/ServiceInstall.png)

![ServiceInstall](assets/AddedToGroup.png)

## How to Install
- Double click and it should pop a UAC prompt
- Enable "Security System Extension" to support these events: https://www.windows-security.org/b355febe2c7a2ae1eaba46c4470d6d4a/security-system-extension . See if your machine is already collecting them with the command: `AuditPol /get /category:* | grep "Security System Extension"` By default it will say, "No Auditing". We (probably) need it to say, "Success"
 - Inspired based on: https://www.stigviewer.com/stig/windows_7/2017-12-01/finding/V-26556 Fix Text (F-29805r1_fix)
 - GUI - secpol.msc  https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/how-to-configure-security-policy-settings enable "Audit Security System Extension" . C# - https://docs.microsoft.com/en-us/dotnet/api/system.security.accesscontrol.filesystemauditrule?view=net-6.0
 - GUI - gpedit.msc: Computer Configuration\Windows Settings\Advanced Audit Policy Configuration\System -> "Audit Security System Extension"
WARNING: I am not a Windows Logging expert and I have observed that making these changes via the GUI will supress other events


## How to Compile:
- Right click on the project in the "Solution Explorer" and choose, "Manage NuGet Packages" and install, "Microsoft.Toolkit.Uwp.Notifications"
- Click Build Solution

## TODO:
- Update to support being installed as a Windows Service that will have a user mode component to still show alerts as they are detected
- Make better rule logic flow (instead of messy if statements before every toast notification)
- Make better self tests - try not to simulate anything. For example, create a real service to test service detection.
- After self testing, and finding that some events are not enabled, see if I can't automatiaclly enable them (such as service installed events). Look at  https://github.com/rkovar/PowerShell/blob/master/audit.bat
- Add seconds to log output
- Add button to "never show this message again" for common events
- Include/Display Basic License with EULA 
- Better logging on the reason for a crash
- Alert on attempted port scanning. Listen on some common ports (80, 443, 22) and alert if anyone trying to connect to them. Automatically do some basic port scanning and name resolution of the host that attempted the connection. 
- Alert on Windows Security Log Event ID 4799: https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4799
- Alert on Windows Security Log Event ID 4798: https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4798
- Alert on securable objects being accessed: https://github.com/OTRF/Set-AuditRule
- Download and install sysmon if not already running on the system
- Look at 7030, 7036, 7045, 7040, 104, 4688, 4672, 4720, 4728, 4732, "4756", "4625", "4673", "4674", "4648", "1102", App - 2, AppLocker - "8003", "8004", "8006", "8007", PowerShell - "4103", "4104", SysMon "1", "7", Test Event Number "1033", "1107" from https://github.com/ManuelBerrueta/BST/blob/main/Windows/Search_EVTX_LogEvents.ps1 and https://github.com/sans-blue-team/DeepBlueCLI
- Alert on malicious looking WinRM commands under Microsoft-Windows-WinRM/Operational (Event ID 91).
- Alert if local token filter policy is changed (the reg key)
- Alert if FireWall is disabled
- Alert if FireWall rule has been added so a process can start listening
- Alert if a service starts listening on a port
- Automatically enable additional logging such as "(Audit) System Security Extention" to start producing events such as 4697 (Service Installed)
- Add default actions to the Toast notifications ('Block IP', 'Start watching for new processes as that user/Service', 'scan for yara sigs', 'Check VT for Exe', 'Launch Autoruns', 'Kill Service', 'Log off user and reset password', etc.)
- Add a better sound for the Toast Notification
- Add icons for the Toast Notification
- Add icons for the Toast Notification buttons - https://docs.microsoft.com/en-us/windows/apps/design/shell/tiles-and-notifications/adaptive-interactive-toasts?tabs=builder-syntax
- Monitor for self-performance - primiarly to monitor for memory leak / memory bloat

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
