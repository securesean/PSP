using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.IO;
using System.Security.AccessControl;
using System.Security.Principal;

namespace PSP_Console
{
    public class MultiChannelEventMonitor
    {
        private readonly List<EventLogWatcher> _watchers = new List<EventLogWatcher>();
        private static readonly string[] SuspiciousIndicators = new[]
        {
            "-enc", "-encodedcommand", "frombase64string", "downloadstring", "downloadfile",
            "net.webclient", "invoke-expression", "iex(", "iex ", "mimikatz", "sekurlsa",
            "lsadump", "vssadmin delete shadows", "shadowcopy delete", "bcdedit /set",
            "certutil -urlcache", "bitsadmin /transfer", "reg save hklm\\sam",
            "reg save hklm\\system", "reg save hklm\\security", "ntds.dit", "amsiutils",
            "amsiinitfailed", "virtualalloc", "createthread", "comsvcs.dll", "minidump"
        };

        public void Start()
        {
            ConfigureCanarySecurableObjectAuditRule();

            // 1. Additional Security Log Events (4656, 4663, 4672, 4673, 4674, 4688, 4728, 4756)
            TrySubscribeChannel(
                "Security",
                "*[System[EventID=4656 or EventID=4663 or EventID=4672 or EventID=4673 or EventID=4674 or EventID=4688 or EventID=4728 or EventID=4756]]",
                OnSecurityEventWritten);

            // 2. System Log Events (104, 7030, 7036, 7040, 7045)
            TrySubscribeChannel(
                "System",
                "*[System[EventID=104 or EventID=7030 or EventID=7036 or EventID=7040 or EventID=7045]]",
                OnSystemEventWritten);

            // 3. Application Log Events (2, 1033, 1107)
            TrySubscribeChannel(
                "Application",
                "*[System[EventID=2 or EventID=1033 or EventID=1107]]",
                OnApplicationEventWritten);

            // 4. PowerShell Operational Log (4103, 4104)
            TrySubscribeChannel(
                "Microsoft-Windows-PowerShell/Operational",
                "*[System[EventID=4103 or EventID=4104]]",
                OnPowerShellEventWritten);

            // 5. WinRM Operational Log (Event ID 91 - shell creation / remote WinRM command execution)
            TrySubscribeChannel(
                "Microsoft-Windows-WinRM/Operational",
                "*[System[EventID=91]]",
                OnWinRmEventWritten);

            // 6. AppLocker Logs (8003, 8004, 8006, 8007)
            TrySubscribeChannel(
                "Microsoft-Windows-AppLocker/EXE and DLL",
                "*[System[EventID=8003 or EventID=8004]]",
                OnAppLockerEventWritten);
            TrySubscribeChannel(
                "Microsoft-Windows-AppLocker/MSI and Script",
                "*[System[EventID=8006 or EventID=8007]]",
                OnAppLockerEventWritten);

            // 7. Sysmon Operational Log (Event ID 1 and 7, if Sysmon is installed)
            TrySubscribeChannel(
                "Microsoft-Windows-Sysmon/Operational",
                "*[System[EventID=1 or EventID=7]]",
                OnSysmonEventWritten);
        }

        public void Stop()
        {
            foreach (EventLogWatcher watcher in _watchers)
            {
                try
                {
                    watcher.Enabled = false;
                    watcher.Dispose();
                }
                catch
                {
                }
            }
            _watchers.Clear();
        }

        private void TrySubscribeChannel(string channelName, string xpathQuery, EventHandler<EventRecordWrittenEventArgs> handler)
        {
            try
            {
                EventLogQuery query = new EventLogQuery(channelName, PathType.LogName, xpathQuery);
                EventLogWatcher watcher = new EventLogWatcher(query);
                watcher.EventRecordWritten += handler;
                watcher.Enabled = true;
                _watchers.Add(watcher);
                Helper.WriteToLog("Subscribed to additional event channel: " + channelName);
            }
            catch (EventLogNotFoundException)
            {
                Helper.WriteToLog("Event channel not present on system (skipping): " + channelName);
            }
            catch (Exception ex)
            {
                Helper.WriteToLog("Could not subscribe to channel '" + channelName + "': " + ex.Message, "ERROR");
            }
        }

        public static readonly List<string> DeployedCanaryFilePaths = new List<string>();

        private static readonly string[] CanaryIndicators = new[]
        {
            "PSP_Canary",
            @"\Bitcoin\wallet.dat",
            @"\Ethereum\keystore\",
            @"\Electrum\wallets\",
            @"\Exodus\exodus.wallet\",
            @"\atomic\Local Storage\leveldb\",
            @"\Coinomi\Coinomi\wallets\",
            @"\Monero\wallets\",
            @"\Vivaldi\User Data\",
            @"\Helium\User Data\"
        };

        // Inspired by https://github.com/OTRF/Set-AuditRule - configures SACL on HKLM\SOFTWARE\PSP_Canary,
        // common cryptocurrency wallet canary files, and Vivaldi / Helium browser cookie files
        // and enables Object Access auditing so accessing them generates Event 4656/4663
        private static void ConfigureCanarySecurableObjectAuditRule()
        {
            try
            {
                AuditPolicyManager.EnableSubcategory("Registry", true, true);
                AuditPolicyManager.EnableSubcategory("File System", true, true);
                AuditPolicyManager.EnableSubcategory("SAM", true, true);

                using (RegistryKey key = Registry.LocalMachine.CreateSubKey(@"SOFTWARE\PSP_Canary"))
                {
                    if (key != null)
                    {
                        RegistrySecurity security = key.GetAccessControl();
                        SecurityIdentifier everyone = new SecurityIdentifier(WellKnownSidType.WorldSid, null);
                        RegistryAuditRule auditRule = new RegistryAuditRule(
                            everyone,
                            RegistryRights.QueryValues | RegistryRights.SetValue | RegistryRights.Delete,
                            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                            PropagationFlags.None,
                            AuditFlags.Success | AuditFlags.Failure);
                        security.AddAuditRule(auditRule);
                        key.SetAccessControl(security);
                    }
                }

                DeployUserCanaryFilesAndAuditRules();
            }
            catch (Exception ex)
            {
                Helper.WriteToLog("Failed to configure canary audit rules: " + ex.Message, "ERROR");
            }
        }

        private static void DeployUserCanaryFilesAndAuditRules()
        {
            string usersRoot = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), @"..\Users");
            try
            {
                usersRoot = Path.GetFullPath(usersRoot);
            }
            catch
            {
                usersRoot = @"C:\Users";
            }

            if (!Directory.Exists(usersRoot))
            {
                return;
            }

            string[] excludedProfiles = new[] { "Public", "Default", "Default User", "All Users" };

            foreach (string userDir in Directory.GetDirectories(usersRoot))
            {
                string folderName = Path.GetFileName(userDir);
                bool skip = false;
                foreach (string excl in excludedProfiles)
                {
                    if (string.Equals(folderName, excl, StringComparison.OrdinalIgnoreCase))
                    {
                        skip = true;
                        break;
                    }
                }
                if (skip) continue;

                string roaming = Path.Combine(userDir, "AppData", "Roaming");
                string local = Path.Combine(userDir, "AppData", "Local");
                string documents = Path.Combine(userDir, "Documents");

                if (!Directory.Exists(roaming) && !Directory.Exists(local))
                {
                    continue;
                }

                string[] canaryFiles = new[]
                {
                    // Common Cryptocurrency Wallet Canary Files
                    Path.Combine(roaming, "Bitcoin", "wallet.dat"),
                    Path.Combine(roaming, "Ethereum", "keystore", "UTC--2026-01-01T00-00-00.000Z--0000000000000000000000000000000000000000"),
                    Path.Combine(roaming, "Electrum", "wallets", "default_wallet"),
                    Path.Combine(roaming, "Exodus", "exodus.wallet", "seed.seco"),
                    Path.Combine(roaming, "Exodus", "exodus.wallet", "passphrase.json"),
                    Path.Combine(roaming, "atomic", "Local Storage", "leveldb", "000001.ldb"),
                    Path.Combine(local, "Coinomi", "Coinomi", "wallets", "default.wallet"),
                    Path.Combine(documents, "Monero", "wallets", "default", "default.keys"),

                    // Vivaldi Browser Cookie Files
                    Path.Combine(local, "Vivaldi", "User Data", "Default", "Network", "Cookies"),
                    Path.Combine(local, "Vivaldi", "User Data", "Default", "Cookies"),

                    // Helium Browser Cookie Files
                    Path.Combine(local, "Helium", "User Data", "Default", "Network", "Cookies"),
                    Path.Combine(local, "Helium", "User Data", "Default", "Cookies")
                };

                foreach (string filePath in canaryFiles)
                {
                    CreateAndAuditCanaryFile(filePath);
                }
            }
        }

        private static void CreateAndAuditCanaryFile(string filePath)
        {
            try
            {
                string dir = Path.GetDirectoryName(filePath);
                if (!Directory.Exists(dir))
                {
                    Directory.CreateDirectory(dir);
                }

                if (!File.Exists(filePath))
                {
                    string dummyContent = filePath.EndsWith("Cookies", StringComparison.OrdinalIgnoreCase)
                        ? "SQLite format 3\0PSP_CANARY_COOKIE_DB"
                        : "{\"psp_canary\":true,\"type\":\"wallet_canary\",\"warning\":\"Unauthorized access monitored by PSP\"}";
                    File.WriteAllText(filePath, dummyContent);
                }

                FileSecurity fileSecurity = File.GetAccessControl(filePath);
                SecurityIdentifier everyone = new SecurityIdentifier(WellKnownSidType.WorldSid, null);
                FileSystemAuditRule auditRule = new FileSystemAuditRule(
                    everyone,
                    FileSystemRights.ReadData | FileSystemRights.Write | FileSystemRights.Delete | FileSystemRights.ReadAttributes,
                    InheritanceFlags.None,
                    PropagationFlags.None,
                    AuditFlags.Success | AuditFlags.Failure);
                fileSecurity.AddAuditRule(auditRule);
                File.SetAccessControl(filePath, fileSecurity);

                if (!DeployedCanaryFilePaths.Contains(filePath))
                {
                    DeployedCanaryFilePaths.Add(filePath);
                }
            }
            catch
            {
            }
        }

        private static string SaveRecordXml(EventRecord record)
        {
            string recordId = (record.RecordId ?? DateTime.UtcNow.Ticks).ToString();
            try
            {
                if (!Directory.Exists(Helper.path))
                {
                    Directory.CreateDirectory(Helper.path);
                }
                File.WriteAllText(Path.Combine(Helper.path, recordId + ".xml"), record.ToXml());
            }
            catch
            {
            }
            return recordId;
        }

        private static bool ContainsSuspiciousIndicator(string text, out string matchedIndicator)
        {
            matchedIndicator = null;
            if (string.IsNullOrEmpty(text))
            {
                return false;
            }
            string lower = text.ToLowerInvariant();
            foreach (string indicator in SuspiciousIndicators)
            {
                if (lower.Contains(indicator))
                {
                    matchedIndicator = indicator;
                    return true;
                }
            }
            return false;
        }

        private void OnSecurityEventWritten(object sender, EventRecordWrittenEventArgs e)
        {
            if (e == null || e.EventRecord == null) return;
            try
            {
                int id = e.EventRecord.Id;
                string xml = e.EventRecord.ToXml();

                if (id == 4656 || id == 4663)
                {
                    string matchedCanary = null;
                    foreach (string indicator in CanaryIndicators)
                    {
                        if (xml.IndexOf(indicator, StringComparison.OrdinalIgnoreCase) >= 0)
                        {
                            matchedCanary = indicator;
                            break;
                        }
                    }

                    // Securable Object Access: alert on Crypto Wallet / Vivaldi / Helium canary files, PSP_Canary, SAM, or LSASS
                    if (matchedCanary != null ||
                        xml.IndexOf(@"\SAM", StringComparison.OrdinalIgnoreCase) >= 0 ||
                        xml.IndexOf("lsass.exe", StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        if (xml.IndexOf("PSP_Console.exe", StringComparison.OrdinalIgnoreCase) >= 0 ||
                            xml.IndexOf("MsMpEng.exe", StringComparison.OrdinalIgnoreCase) >= 0 ||
                            xml.IndexOf("SearchIndexer.exe", StringComparison.OrdinalIgnoreCase) >= 0 ||
                            xml.IndexOf("SearchProtocolHost.exe", StringComparison.OrdinalIgnoreCase) >= 0)
                        {
                            return;
                        }

                        string subjectUser = "";
                        string objectName = "";
                        string processName = "";
                        string processId = "";
                        try
                        {
                            string[] xPaths = new[]
                            {
                                "Event/EventData/Data[@Name='SubjectUserName']",
                                "Event/EventData/Data[@Name='ObjectName']",
                                "Event/EventData/Data[@Name='ProcessName']",
                                "Event/EventData/Data[@Name='ProcessId']"
                            };
                            using (EventLogPropertySelector selector = new EventLogPropertySelector(xPaths))
                            {
                                IList<object> props = ((EventLogRecord)e.EventRecord).GetPropertyValues(selector);
                                if (props.Count > 0 && props[0] != null) subjectUser = props[0].ToString();
                                if (props.Count > 1 && props[1] != null) objectName = props[1].ToString();
                                if (props.Count > 2 && props[2] != null) processName = props[2].ToString();
                                if (props.Count > 3 && props[3] != null) processId = props[3].ToString();
                            }
                        }
                        catch
                        {
                        }

                        string recordId = SaveRecordXml(e.EventRecord);
                        string title = matchedCanary != null
                            ? "Canary File / Object Accessed! (" + matchedCanary.Trim('\\') + ")"
                            : "Securable Object Accessed (Event " + id + ")";

                        Helper.WriteToLog(title + " | Object: " + objectName + " | Process: " + processName + " (PID: " + processId + ") | User: " + subjectUser, "OUTPUT");

                        List<string> toastLines = new List<string> { title };
                        if (!string.IsNullOrEmpty(objectName))
                        {
                            toastLines.Add("Target: " + objectName);
                        }
                        if (!string.IsNullOrEmpty(processName))
                        {
                            toastLines.Add("Process: " + processName + " (PID: " + processId + ", User: " + subjectUser + ")");
                        }

                        List<ToastButtonItem> customButtons = null;
                        if (matchedCanary != null)
                        {
                            ToastActionHandler.EnsureIconsGenerated();
                            customButtons = new List<ToastButtonItem>
                            {
                                new ToastButtonItem
                                {
                                    Content = "Kill Process",
                                    Arguments = "action=kill_process&pid=" + Uri.EscapeDataString(processId ?? "") + "&path=" + Uri.EscapeDataString(processName ?? ""),
                                    IconUri = File.Exists(ToastActionHandler.KillServiceIconPath) ? new Uri(ToastActionHandler.KillServiceIconPath).AbsoluteUri : null
                                },
                                new ToastButtonItem
                                {
                                    Content = "Disconnect Network",
                                    Arguments = "action=disconnect_network",
                                    IconUri = File.Exists(ToastActionHandler.BlockIpIconPath) ? new Uri(ToastActionHandler.BlockIpIconPath).AbsoluteUri : null
                                }
                            };

                            if (!string.IsNullOrEmpty(processName))
                            {
                                customButtons.Add(new ToastButtonItem
                                {
                                    Content = "VT",
                                    Arguments = "action=check_vt&path=" + Uri.EscapeDataString(processName),
                                    IconUri = File.Exists(ToastActionHandler.CheckVtIconPath) ? new Uri(ToastActionHandler.CheckVtIconPath).AbsoluteUri : null
                                });
                            }
                        }

                        ToastHelper.ShowToast(id, recordId, toastLines, customButtons);
                    }
                }
                else if (id == 4688)
                {
                    string matched;
                    if (ContainsSuspiciousIndicator(xml, out matched))
                    {
                        string recordId = SaveRecordXml(e.EventRecord);
                        Helper.WriteToLog("Suspicious Process Creation (Event 4688 - matched '" + matched + "'):\n" + xml, "OUTPUT");
                        ToastHelper.ShowToast(
                            4688,
                            recordId,
                            new List<string>
                            {
                                "Suspicious Process Created (Event 4688)",
                                "Matched indicator: " + matched
                            });
                    }
                }
                else if (id == 4728 || id == 4756)
                {
                    string recordId = SaveRecordXml(e.EventRecord);
                    string groupType = id == 4728 ? "Global Group" : "Universal Group";
                    Helper.WriteToLog("User added to Security-Enabled " + groupType + " (Event " + id + "):\n" + xml, "OUTPUT");
                    ToastHelper.ShowToast(
                        id,
                        recordId,
                        new List<string>
                        {
                            "User Added to " + groupType + " (Event " + id + ")",
                            "Click to view full XML event details"
                        });
                }
                else if (id == 4673 || id == 4674)
                {
                    if (xml.IndexOf("SeDebugPrivilege", StringComparison.OrdinalIgnoreCase) >= 0 ||
                        xml.IndexOf("SeLoadDriverPrivilege", StringComparison.OrdinalIgnoreCase) >= 0 ||
                        xml.IndexOf("SeTakeOwnershipPrivilege", StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        if (xml.IndexOf("PSP_Console.exe", StringComparison.OrdinalIgnoreCase) < 0 &&
                            xml.IndexOf(@"C:\Windows\System32\svchost.exe", StringComparison.OrdinalIgnoreCase) < 0)
                        {
                            string recordId = SaveRecordXml(e.EventRecord);
                            Helper.WriteToLog("Sensitive Privilege Use Detected (Event " + id + "):\n" + xml, "OUTPUT");
                            ToastHelper.ShowToast(
                                id,
                                recordId,
                                new List<string>
                                {
                                    "Sensitive Privilege Used (Event " + id + ")",
                                    "SeDebugPrivilege / SeLoadDriverPrivilege / SeTakeOwnershipPrivilege"
                                });
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Helper.LogCrash("OnSecurityEventWritten", ex);
            }
        }

        private void OnSystemEventWritten(object sender, EventRecordWrittenEventArgs e)
        {
            if (e == null || e.EventRecord == null) return;
            try
            {
                int id = e.EventRecord.Id;
                string xml = e.EventRecord.ToXml();
                string desc = e.EventRecord.FormatDescription() ?? "";

                if (id == 104)
                {
                    string recordId = SaveRecordXml(e.EventRecord);
                    Helper.WriteToLog("System Event Log Cleared (Event 104)!\n" + desc, "OUTPUT");
                    ToastHelper.ShowToast(104, recordId, new List<string> { "System Event Log Cleared (Event 104)!", desc });
                }
                else if (id == 7030)
                {
                    string recordId = SaveRecordXml(e.EventRecord);
                    Helper.WriteToLog("Interactive Service Detected (Event 7030):\n" + desc, "OUTPUT");
                    ToastHelper.ShowToast(7030, recordId, new List<string> { "Service Marked Interactive (Event 7030)", desc });
                }
                else if (id == 7045)
                {
                    string recordId = SaveRecordXml(e.EventRecord);
                    Helper.WriteToLog("New Service Installed (System Event 7045):\n" + desc, "OUTPUT");
                    ToastHelper.ShowToast(7045, recordId, new List<string> { "New Service Installed (Event 7045)", desc });
                }
                else if (id == 7040)
                {
                    if (xml.IndexOf("WinDefend", StringComparison.OrdinalIgnoreCase) >= 0 ||
                        xml.IndexOf("MpsSvc", StringComparison.OrdinalIgnoreCase) >= 0 ||
                        xml.IndexOf("EventLog", StringComparison.OrdinalIgnoreCase) >= 0 ||
                        xml.IndexOf("RemoteRegistry", StringComparison.OrdinalIgnoreCase) >= 0 ||
                        xml.IndexOf("TermService", StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        string recordId = SaveRecordXml(e.EventRecord);
                        Helper.WriteToLog("Critical Service Start Type Changed (Event 7040):\n" + desc, "OUTPUT");
                        ToastHelper.ShowToast(7040, recordId, new List<string> { "Service Start Type Changed (Event 7040)", desc });
                    }
                }
                else if (id == 7036)
                {
                    if ((xml.IndexOf("WinDefend", StringComparison.OrdinalIgnoreCase) >= 0 ||
                         xml.IndexOf("MpsSvc", StringComparison.OrdinalIgnoreCase) >= 0 ||
                         xml.IndexOf("Sense", StringComparison.OrdinalIgnoreCase) >= 0 ||
                         xml.IndexOf("Sysmon", StringComparison.OrdinalIgnoreCase) >= 0) &&
                        desc.IndexOf("stopped", StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        string recordId = SaveRecordXml(e.EventRecord);
                        Helper.WriteToLog("Security Service Stopped (Event 7036):\n" + desc, "OUTPUT");
                        ToastHelper.ShowToast(7036, recordId, new List<string> { "Security Service Stopped (Event 7036)!", desc });
                    }
                }
            }
            catch (Exception ex)
            {
                Helper.LogCrash("OnSystemEventWritten", ex);
            }
        }

        private void OnApplicationEventWritten(object sender, EventRecordWrittenEventArgs e)
        {
            if (e == null || e.EventRecord == null) return;
            try
            {
                int id = e.EventRecord.Id;
                string xml = e.EventRecord.ToXml();
                string matched;
                if (ContainsSuspiciousIndicator(xml, out matched))
                {
                    string recordId = SaveRecordXml(e.EventRecord);
                    Helper.WriteToLog("Suspicious Application Event " + id + " (matched '" + matched + "'):\n" + xml, "OUTPUT");
                    ToastHelper.ShowToast(id, recordId, new List<string> { "Suspicious Application Event " + id, "Indicator: " + matched });
                }
            }
            catch (Exception ex)
            {
                Helper.LogCrash("OnApplicationEventWritten", ex);
            }
        }

        private void OnPowerShellEventWritten(object sender, EventRecordWrittenEventArgs e)
        {
            if (e == null || e.EventRecord == null) return;
            try
            {
                int id = e.EventRecord.Id;
                string xml = e.EventRecord.ToXml();
                string matched;
                if (ContainsSuspiciousIndicator(xml, out matched))
                {
                    string recordId = SaveRecordXml(e.EventRecord);
                    Helper.WriteToLog("Suspicious PowerShell Execution (Event " + id + " - matched '" + matched + "'):\n" + xml, "OUTPUT");
                    ToastHelper.ShowToast(
                        id,
                        recordId,
                        new List<string>
                        {
                            "Suspicious PowerShell Script Detected (Event " + id + ")",
                            "Matched indicator: " + matched
                        });
                }
            }
            catch (Exception ex)
            {
                Helper.LogCrash("OnPowerShellEventWritten", ex);
            }
        }

        private void OnWinRmEventWritten(object sender, EventRecordWrittenEventArgs e)
        {
            if (e == null || e.EventRecord == null) return;
            try
            {
                int id = e.EventRecord.Id;
                string xml = e.EventRecord.ToXml();
                string desc = e.EventRecord.FormatDescription() ?? "WinRM WSMan Shell created";
                string recordId = SaveRecordXml(e.EventRecord);

                Helper.WriteToLog("WinRM Remote Shell Activity Detected (Event " + id + "):\n" + desc + "\n" + xml, "OUTPUT");
                ToastHelper.ShowToast(
                    id,
                    recordId,
                    new List<string>
                    {
                        "WinRM Remote Shell Activity (Event " + id + ")",
                        desc
                    });
            }
            catch (Exception ex)
            {
                Helper.LogCrash("OnWinRmEventWritten", ex);
            }
        }

        private void OnAppLockerEventWritten(object sender, EventRecordWrittenEventArgs e)
        {
            if (e == null || e.EventRecord == null) return;
            try
            {
                int id = e.EventRecord.Id;
                string desc = e.EventRecord.FormatDescription() ?? e.EventRecord.ToXml();
                string recordId = SaveRecordXml(e.EventRecord);

                Helper.WriteToLog("AppLocker Policy Alert (Event " + id + "):\n" + desc, "OUTPUT");
                ToastHelper.ShowToast(
                    id,
                    recordId,
                    new List<string>
                    {
                        "AppLocker Alert (Event " + id + ")",
                        desc
                    });
            }
            catch (Exception ex)
            {
                Helper.LogCrash("OnAppLockerEventWritten", ex);
            }
        }

        private void OnSysmonEventWritten(object sender, EventRecordWrittenEventArgs e)
        {
            if (e == null || e.EventRecord == null) return;
            try
            {
                int id = e.EventRecord.Id;
                string xml = e.EventRecord.ToXml();
                string matched;
                if (ContainsSuspiciousIndicator(xml, out matched))
                {
                    string recordId = SaveRecordXml(e.EventRecord);
                    Helper.WriteToLog("Sysmon Suspicious Event " + id + " (matched '" + matched + "'):\n" + xml, "OUTPUT");
                    ToastHelper.ShowToast(
                        id,
                        recordId,
                        new List<string>
                        {
                            "Sysmon Alert (Event ID " + id + ")",
                            "Matched indicator: " + matched
                        });
                }
            }
            catch (Exception ex)
            {
                Helper.LogCrash("OnSysmonEventWritten", ex);
            }
        }
    }
}
