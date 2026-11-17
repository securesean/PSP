using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.DirectoryServices;
using System.DirectoryServices.AccountManagement;
using System.IO;
using System.Management;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Json;
using System.Security.Principal;
using System.ServiceProcess;
using System.Text;
using System.Threading;
using System.Xml;

namespace PSP_Console
{
    [DataContract]
    public class RemoteAccessServicesReport
    {
        [DataMember(Order = 1)] public bool RdpEnabled { get; set; }
        [DataMember(Order = 2)] public bool TermServiceRunning { get; set; }
        [DataMember(Order = 3)] public bool RdpRegistryAllowed { get; set; }
        [DataMember(Order = 4)] public bool WinRmRunning { get; set; }
        [DataMember(Order = 5)] public bool SmbLanmanServerRunning { get; set; }
        [DataMember(Order = 6)] public bool OpenSshRunning { get; set; }
    }

    [DataContract]
    public class BuiltInAccountsReport
    {
        [DataMember(Order = 1)] public string Rid500AdminName { get; set; }
        [DataMember(Order = 2)] public bool Rid500AdminEnabled { get; set; }
        [DataMember(Order = 3)] public bool Rid500UsesDefaultName { get; set; }
        [DataMember(Order = 4)] public string Rid501GuestName { get; set; }
        [DataMember(Order = 5)] public bool Rid501GuestEnabled { get; set; }
        [DataMember(Order = 6)] public List<string> Rid501GuestGroups { get; set; } = new List<string>();
        [DataMember(Order = 7)] public List<string> StigFindings { get; set; } = new List<string>();
    }

    [DataContract]
    public class TokenFilterPolicyReport
    {
        [DataMember(Order = 1)] public int? PolicyValue { get; set; }
        [DataMember(Order = 2)] public string Assessment { get; set; }
    }

    [DataContract]
    public class RemoteAccessGroupsReport
    {
        [DataMember(Order = 1)] public List<string> LocalAdminsDirect { get; set; } = new List<string>();
        [DataMember(Order = 2)] public List<string> LocalAdminsRecursive { get; set; } = new List<string>();
        [DataMember(Order = 3)] public List<string> RemoteDesktopUsersRecursive { get; set; } = new List<string>();
        [DataMember(Order = 4)] public List<string> DcomUsersRecursive { get; set; } = new List<string>();
        [DataMember(Order = 5)] public List<string> WinRmUsersRecursive { get; set; } = new List<string>();
        [DataMember(Order = 6)] public int TotalRdpAccessUsers { get; set; }
        [DataMember(Order = 7)] public int TotalSmbRpcDcomAccessUsers { get; set; }
        [DataMember(Order = 8)] public int TotalWinRmAccessUsers { get; set; }
        [DataMember(Order = 9)] public string Summary { get; set; }
    }

    [DataContract]
    public class WeirdServiceEntry
    {
        [DataMember(Order = 1)] public string Name { get; set; }
        [DataMember(Order = 2)] public string State { get; set; }
        [DataMember(Order = 3)] public string RunsAs { get; set; }
        [DataMember(Order = 4)] public string Reason { get; set; }
        [DataMember(Order = 5)] public string PathName { get; set; }
    }

    [DataContract]
    public class ListeningPortEntry
    {
        [DataMember(Order = 1)] public int ProcessId { get; set; }
        [DataMember(Order = 2)] public string ProcessName { get; set; }
        [DataMember(Order = 3)] public List<int> Ports { get; set; } = new List<int>();
        [DataMember(Order = 4)] public List<string> Services { get; set; } = new List<string>();
    }

    [DataContract]
    public class SecurityEvaluationReport
    {
        [DataMember(Order = 1)] public string Timestamp { get; set; }
        [DataMember(Order = 2)] public string ComputerName { get; set; }
        [DataMember(Order = 3)] public RemoteAccessServicesReport RemoteAccessServices { get; set; }
        [DataMember(Order = 4)] public BuiltInAccountsReport BuiltInAccounts { get; set; }
        [DataMember(Order = 5)] public TokenFilterPolicyReport LocalAccountTokenFilterPolicy { get; set; }
        [DataMember(Order = 6)] public RemoteAccessGroupsReport GroupMembershipsAndRemoteAccess { get; set; }
        [DataMember(Order = 7)] public List<WeirdServiceEntry> WeirdServices { get; set; } = new List<WeirdServiceEntry>();
        [DataMember(Order = 8)] public List<ListeningPortEntry> ListeningPortsAndServices { get; set; } = new List<ListeningPortEntry>();
        [DataMember(Order = 9)] public bool AuditSecuritySystemExtensionEnabled { get; set; }
    }

    public static class SecurityEvaluator
    {
        public static void RunSecurityEvaluation(bool launchAutoruns = false)
        {
            Helper.WriteToLog("===============================================================================", "OUTPUT");
            Helper.WriteToLog("                PERSONAL SECURITY PRODUCT - SECURITY EVALUATION                ", "OUTPUT");
            Helper.WriteToLog("===============================================================================", "OUTPUT");

            SecurityEvaluationReport report = new SecurityEvaluationReport
            {
                Timestamp = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"),
                ComputerName = Environment.MachineName
            };

            // 1. Check WinRM / RDP / SMB / SSH service & registry status
            report.RemoteAccessServices = EvaluateRemoteAccessServices();

            // 2. Check Guest account & Built-in RID 500 Administrator account (STIG V-63353 / V-63351)
            report.BuiltInAccounts = EvaluateBuiltInAccounts();

            // 3. Check LocalAccountTokenFilterPolicy
            report.LocalAccountTokenFilterPolicy = EvaluateLocalAccountTokenFilterPolicy();

            // 4. List all direct and recursive users/groups in Local Administrators and Remote Access groups,
            //    and print summary: "X number of users can access this computer remotely via RDP, SMB/RPC/DCOM, WinRM"
            report.GroupMembershipsAndRemoteAccess = EvaluateRemoteAccessUsersAndAdminGroups();

            // 5. List weird services (non-standard paths, unquoted service paths with spaces, writable locations)
            report.WeirdServices = EvaluateWeirdServices();

            // 6. List all programs and Windows Services listening on any TCP ports
            report.ListeningPortsAndServices = EvaluateListeningPortsAndServices();

            // 7. Detect if "(Audit) Security System Extension" is enabled
            report.AuditSecuritySystemExtensionEnabled = EvaluateAuditSecuritySystemExtension();

            // 8. Save pretty JSON report to Desktop
            SaveReportToDesktopJson(report);

            // 9. Optionally download and execute Sysinternals Autoruns
            if (launchAutoruns)
            {
                ToastActionHandler.LaunchOrDownloadAutoruns();
            }
            else
            {
                Helper.WriteToLog("[Info] Run with '-SecurityEvaluation -autoruns' to automatically download and launch Sysinternals Autoruns.");
            }

            Helper.WriteToLog("===============================================================================", "OUTPUT");
            Helper.WriteToLog("                        SECURITY EVALUATION COMPLETE                           ", "OUTPUT");
            Helper.WriteToLog("===============================================================================", "OUTPUT");
        }

        private static void SaveReportToDesktopJson(SecurityEvaluationReport report)
        {
            try
            {
                string desktopDir = Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);
                if (string.IsNullOrEmpty(desktopDir) || !Directory.Exists(desktopDir))
                {
                    desktopDir = Helper.path;
                }

                string jsonPath = Path.Combine(desktopDir, "PSP_SecurityEvaluation.json");
                using (MemoryStream ms = new MemoryStream())
                {
                    using (XmlDictionaryWriter writer = JsonReaderWriterFactory.CreateJsonWriter(ms, Encoding.UTF8, false, true, "  "))
                    {
                        DataContractJsonSerializer serializer = new DataContractJsonSerializer(typeof(SecurityEvaluationReport));
                        serializer.WriteObject(writer, report);
                        writer.Flush();
                    }
                    File.WriteAllText(jsonPath, Encoding.UTF8.GetString(ms.ToArray()), Encoding.UTF8);
                }

                Helper.WriteToLog("\n[Report] Saved pretty JSON Security Evaluation report to Desktop: " + jsonPath, "OUTPUT");
            }
            catch (Exception ex)
            {
                Helper.WriteToLog("Failed to write Security Evaluation JSON report to Desktop: " + ex.Message, "ERROR");
            }
        }

        private static RemoteAccessServicesReport EvaluateRemoteAccessServices()
        {
            Helper.WriteToLog("\n--- [1] Remote Access Service Checks (WinRM, RDP, SMB, SSH) ---", "OUTPUT");

            bool rdpDisabled = true;
            try
            {
                using (RegistryKey key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Terminal Server", false))
                {
                    if (key != null)
                    {
                        object fDeny = key.GetValue("fDenyTSConnections");
                        if (fDeny != null && Convert.ToInt32(fDeny) == 0)
                        {
                            rdpDisabled = false;
                        }
                    }
                }
            }
            catch
            {
            }

            bool termServiceRunning = IsServiceRunning("TermService");
            bool winRmRunning = IsServiceRunning("WinRM");
            bool lanmanRunning = IsServiceRunning("LanmanServer");
            bool sshRunning = IsServiceRunning("sshd");

            Helper.WriteToLog("RDP (Remote Desktop)   : " + ((!rdpDisabled || termServiceRunning) ? "ENABLED (Service Running=" + termServiceRunning + ", Registry Allowed=" + (!rdpDisabled) + ")" : "Disabled"), (!rdpDisabled || termServiceRunning) ? "ERROR" : "OUTPUT");
            Helper.WriteToLog("WinRM (WS-Management)  : " + (winRmRunning ? "ENABLED (Running)" : "Disabled / Stopped"), winRmRunning ? "ERROR" : "OUTPUT");
            Helper.WriteToLog("SMB (LanmanServer)     : " + (lanmanRunning ? "ENABLED (Running)" : "Disabled / Stopped"), lanmanRunning ? "OUTPUT" : "INFO");
            Helper.WriteToLog("OpenSSH Server (sshd)  : " + (sshRunning ? "ENABLED (Running)" : "Disabled / Stopped"), sshRunning ? "ERROR" : "OUTPUT");

            return new RemoteAccessServicesReport
            {
                RdpEnabled = !rdpDisabled || termServiceRunning,
                TermServiceRunning = termServiceRunning,
                RdpRegistryAllowed = !rdpDisabled,
                WinRmRunning = winRmRunning,
                SmbLanmanServerRunning = lanmanRunning,
                OpenSshRunning = sshRunning
            };
        }

        private static BuiltInAccountsReport EvaluateBuiltInAccounts()
        {
            Helper.WriteToLog("\n--- [2] Built-in Account STIG Checks (Guest & Default Administrator) ---", "OUTPUT");
            BuiltInAccountsReport result = new BuiltInAccountsReport();
            try
            {
                using (PrincipalContext ctx = new PrincipalContext(ContextType.Machine))
                {
                    using (UserPrincipal filter = new UserPrincipal(ctx))
                    using (PrincipalSearcher searcher = new PrincipalSearcher(filter))
                    {
                        foreach (Principal p in searcher.FindAll())
                        {
                            UserPrincipal user = p as UserPrincipal;
                            if (user == null || user.Sid == null) continue;
                            string sid = user.Sid.Value;

                            if (sid.EndsWith("-500"))
                            {
                                bool enabled = user.Enabled ?? false;
                                bool defaultName = string.Equals(user.Name, "Administrator", StringComparison.OrdinalIgnoreCase);
                                result.Rid500AdminName = user.Name;
                                result.Rid500AdminEnabled = enabled;
                                result.Rid500UsesDefaultName = defaultName;

                                Helper.WriteToLog(
                                    string.Format("RID 500 Built-in Admin : Name='{0}', Enabled={1}, UsesDefaultName={2}",
                                        user.Name, enabled, defaultName),
                                    (enabled && defaultName) ? "ERROR" : "OUTPUT");
                                if (enabled && defaultName)
                                {
                                    string finding = "[STIG Finding V-63351] Built-in Administrator account is enabled and still uses default name 'Administrator'!";
                                    result.StigFindings.Add(finding);
                                    Helper.WriteToLog("  " + finding, "ERROR");
                                }
                            }
                            else if (sid.EndsWith("-501"))
                            {
                                bool enabled = user.Enabled ?? false;
                                List<string> guestGroups = new List<string>();
                                try
                                {
                                    foreach (Principal grp in user.GetGroups())
                                    {
                                        guestGroups.Add(grp.Name);
                                    }
                                }
                                catch
                                {
                                }
                                result.Rid501GuestName = user.Name;
                                result.Rid501GuestEnabled = enabled;
                                result.Rid501GuestGroups = guestGroups;

                                Helper.WriteToLog(
                                    string.Format("RID 501 Guest Account  : Name='{0}', Enabled={1}, Groups=[{2}]",
                                        user.Name, enabled, string.Join(", ", guestGroups)),
                                    enabled ? "ERROR" : "OUTPUT");
                                if (enabled)
                                {
                                    string finding = "[STIG Finding V-63353] Guest account is ENABLED!";
                                    result.StigFindings.Add(finding);
                                    Helper.WriteToLog("  " + finding, "ERROR");
                                }
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Helper.WriteToLog("Failed to evaluate built-in accounts: " + ex.Message, "ERROR");
            }
            return result;
        }

        private static TokenFilterPolicyReport EvaluateLocalAccountTokenFilterPolicy()
        {
            Helper.WriteToLog("\n--- [3] LocalAccountTokenFilterPolicy Check ---", "OUTPUT");
            int? policy = SystemStateMonitor.GetLocalAccountTokenFilterPolicy();
            string assessment;
            if (policy == 1)
            {
                assessment = "VULNERABLE: Remote UAC administrative token filtering is DISABLED! Local admins can authenticate remotely over SMB/RPC/WinRM.";
                Helper.WriteToLog("LocalAccountTokenFilterPolicy = 1 (" + assessment + ")", "ERROR");
            }
            else if (policy.HasValue)
            {
                assessment = "Protected: Remote UAC token filtering is enforced.";
                Helper.WriteToLog("LocalAccountTokenFilterPolicy = " + policy.Value + " (" + assessment + ")", "OUTPUT");
            }
            else
            {
                assessment = "Default Protected: Remote UAC token filtering is enforced (<Not Set>).";
                Helper.WriteToLog("LocalAccountTokenFilterPolicy = <Not Set> (" + assessment + ")", "OUTPUT");
            }
            return new TokenFilterPolicyReport
            {
                PolicyValue = policy,
                Assessment = assessment
            };
        }

        private static RemoteAccessGroupsReport EvaluateRemoteAccessUsersAndAdminGroups()
        {
            Helper.WriteToLog("\n--- [4] Local Administrators & Remote Access Group Members (Direct & Recursive) ---", "OUTPUT");

            List<string> adminDirect = GetGroupMembers("S-1-5-32-544", false);
            List<string> adminRecursive = GetGroupMembers("S-1-5-32-544", true);
            List<string> rdpRecursive = GetGroupMembers("S-1-5-32-555", true);    // Remote Desktop Users
            List<string> dcomRecursive = GetGroupMembers("S-1-5-32-562", true);   // Distributed COM Users
            List<string> winRmRecursive = GetGroupMembers("S-1-5-32-580", true);  // Remote Management Users

            Helper.WriteToLog("Local Administrators Group (S-1-5-32-544) Direct Members (" + adminDirect.Count + "):", "OUTPUT");
            foreach (string m in adminDirect)
            {
                Helper.WriteToLog("  - " + m);
            }

            Helper.WriteToLog("Local Administrators Group (S-1-5-32-544) Recursive Resolved Users (" + adminRecursive.Count + "):", "OUTPUT");
            foreach (string m in adminRecursive)
            {
                Helper.WriteToLog("  - " + m);
            }

            HashSet<string> allRdpUsers = new HashSet<string>(adminRecursive, StringComparer.OrdinalIgnoreCase);
            foreach (string u in rdpRecursive) allRdpUsers.Add(u);

            HashSet<string> allSmbRpcDcomUsers = new HashSet<string>(adminRecursive, StringComparer.OrdinalIgnoreCase);
            foreach (string u in dcomRecursive) allSmbRpcDcomUsers.Add(u);

            HashSet<string> allWinRmUsers = new HashSet<string>(adminRecursive, StringComparer.OrdinalIgnoreCase);
            foreach (string u in winRmRecursive) allWinRmUsers.Add(u);

            string summary = string.Format("SUMMARY: {0} user(s) can access via RDP, {1} user(s) via SMB/RPC/DCOM, and {2} user(s) via WinRM.",
                allRdpUsers.Count, allSmbRpcDcomUsers.Count, allWinRmUsers.Count);
            Helper.WriteToLog(summary, "OUTPUT");

            return new RemoteAccessGroupsReport
            {
                LocalAdminsDirect = adminDirect,
                LocalAdminsRecursive = adminRecursive,
                RemoteDesktopUsersRecursive = rdpRecursive,
                DcomUsersRecursive = dcomRecursive,
                WinRmUsersRecursive = winRmRecursive,
                TotalRdpAccessUsers = allRdpUsers.Count,
                TotalSmbRpcDcomAccessUsers = allSmbRpcDcomUsers.Count,
                TotalWinRmAccessUsers = allWinRmUsers.Count,
                Summary = summary
            };
        }

        private static List<string> GetGroupMembers(string groupSid, bool recursive)
        {
            List<string> members = new List<string>();
            try
            {
                string accountName = new SecurityIdentifier(groupSid).Translate(typeof(NTAccount)).Value;
                int slashIdx = accountName.IndexOf('\\');
                string groupName = slashIdx >= 0 ? accountName.Substring(slashIdx + 1) : accountName;

                using (DirectoryEntry groupEntry = new DirectoryEntry("WinNT://./" + groupName + ",group"))
                {
                    object membersObj = groupEntry.Invoke("Members", null);
                    foreach (object memberObj in (System.Collections.IEnumerable)membersObj)
                    {
                        using (DirectoryEntry memberEntry = new DirectoryEntry(memberObj))
                        {
                            string name = memberEntry.Name;
                            string schemaClass = memberEntry.SchemaClassName;
                            string sidStr = "";
                            try
                            {
                                byte[] sidBytes = (byte[])memberEntry.Properties["objectSid"].Value;
                                if (sidBytes != null)
                                {
                                    sidStr = new SecurityIdentifier(sidBytes, 0).Value;
                                }
                            }
                            catch
                            {
                            }

                            members.Add(string.Format("{0} [{1}, SID={2}]", name, schemaClass, sidStr));
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Helper.WriteToLog("  (Note: Could not resolve all members for group " + groupSid + ": " + ex.Message + ")");
            }
            return members;
        }

        private static List<WeirdServiceEntry> EvaluateWeirdServices()
        {
            Helper.WriteToLog("\n--- [5] Weird / Suspicious Windows Services Audit ---", "OUTPUT");
            List<WeirdServiceEntry> weirdList = new List<WeirdServiceEntry>();
            try
            {
                using (ManagementObjectSearcher searcher = new ManagementObjectSearcher("SELECT Name, DisplayName, PathName, StartName, State, StartMode FROM Win32_Service"))
                using (ManagementObjectCollection results = searcher.Get())
                {
                    foreach (ManagementObject svc in results)
                    {
                        string name = Convert.ToString(svc["Name"]) ?? "";
                        string pathName = (Convert.ToString(svc["PathName"]) ?? "").Trim();
                        string startName = Convert.ToString(svc["StartName"]) ?? "";
                        string state = Convert.ToString(svc["State"]) ?? "";

                        if (string.IsNullOrEmpty(pathName)) continue;

                        bool isStandardWindows = pathName.IndexOf(@"C:\Windows\", StringComparison.OrdinalIgnoreCase) >= 0;
                        bool isProgramFiles = pathName.IndexOf(@"C:\Program Files", StringComparison.OrdinalIgnoreCase) >= 0;
                        bool isUnquotedWithSpaces = !pathName.StartsWith("\"") &&
                                                    pathName.IndexOf(".exe", StringComparison.OrdinalIgnoreCase) > 0 &&
                                                    pathName.Substring(0, pathName.IndexOf(".exe", StringComparison.OrdinalIgnoreCase)).Contains(" ");

                        if ((!isStandardWindows && !isProgramFiles) || isUnquotedWithSpaces)
                        {
                            string reason = isUnquotedWithSpaces ? "UNQUOTED PATH WITH SPACES" : "NON-STANDARD BINARY PATH";
                            weirdList.Add(new WeirdServiceEntry
                            {
                                Name = name,
                                State = state,
                                RunsAs = startName,
                                Reason = reason,
                                PathName = pathName
                            });
                            Helper.WriteToLog(
                                string.Format("  [Weird Service] {0} ({1}, RunsAs={2}) [{3}] -> {4}",
                                    name, state, startName, reason, pathName),
                                isUnquotedWithSpaces ? "ERROR" : "OUTPUT");
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Helper.WriteToLog("Failed to enumerate services: " + ex.Message, "ERROR");
            }

            if (weirdList.Count == 0)
            {
                Helper.WriteToLog("  No weird or unquoted-path services found.", "OUTPUT");
            }
            return weirdList;
        }

        private static List<ListeningPortEntry> EvaluateListeningPortsAndServices()
        {
            Helper.WriteToLog("\n--- [6] Programs and Services Listening on TCP Ports ---", "OUTPUT");
            List<ListeningPortEntry> entries = new List<ListeningPortEntry>();
            try
            {
                Dictionary<int, List<int>> portsByPid = SystemStateMonitor.GetListeningTcpPortsByPid();
                Dictionary<int, List<string>> servicesByPid = SystemStateMonitor.GetRunningServicesByPid();

                foreach (KeyValuePair<int, List<int>> kvp in portsByPid)
                {
                    int pid = kvp.Key;
                    string procName = "UnknownProcess";
                    try
                    {
                        using (Process p = Process.GetProcessById(pid))
                        {
                            procName = p.ProcessName + ".exe";
                        }
                    }
                    catch
                    {
                    }

                    List<string> svcList;
                    bool hasServices = servicesByPid.TryGetValue(pid, out svcList) && svcList.Count > 0;
                    string svcDisplay = hasServices
                        ? string.Join(", ", svcList)
                        : "(No associated Windows Service)";

                    kvp.Value.Sort();
                    entries.Add(new ListeningPortEntry
                    {
                        ProcessId = pid,
                        ProcessName = procName,
                        Ports = new List<int>(kvp.Value),
                        Services = hasServices ? new List<string>(svcList) : new List<string>()
                    });

                    Helper.WriteToLog(
                        string.Format("  PID {0,-6} | Process: {1,-24} | Ports: {2,-22} | Services: {3}",
                            pid, procName, string.Join(", ", kvp.Value), svcDisplay),
                        "OUTPUT");
                }
            }
            catch (Exception ex)
            {
                Helper.WriteToLog("Failed to list listening ports: " + ex.Message, "ERROR");
            }
            return entries;
        }

        private static bool EvaluateAuditSecuritySystemExtension()
        {
            Helper.WriteToLog("\n--- [7] Audit Security System Extension Status ---", "OUTPUT");
            bool enabled = AuditPolicyManager.IsSubcategoryEnabled("Security System Extension");
            if (enabled)
            {
                Helper.WriteToLog("Audit 'Security System Extension' is ENABLED (Event 4697 Service Installed & LSASS package events are collected).", "OUTPUT");
            }
            else
            {
                Helper.WriteToLog("Audit 'Security System Extension' is NOT ENABLED! Run PSP_Console normally or with --test to automatically enable it.", "ERROR");
            }
            return enabled;
        }

        private class ServiceOriginalState
        {
            public string ServiceName { get; set; }
            public ServiceControllerStatus Status { get; set; }
            public int? RegistryStartValue { get; set; }
        }

        public static void RunLockdownMode(ManualResetEvent stopEvent = null, bool waitForInteractiveInput = true)
        {
            Helper.WriteToLog("===============================================================================", "OUTPUT");
            Helper.WriteToLog("                     ENGAGING PSP LOCKDOWN MODE                                ", "OUTPUT");
            Helper.WriteToLog("===============================================================================", "OUTPUT");

            string[] targetServices = new[] { "WinRM", "LanmanServer", "TermService", "sshd" };
            List<ServiceOriginalState> originalStates = new List<ServiceOriginalState>();

            foreach (string svc in targetServices)
            {
                try
                {
                    using (ServiceController sc = new ServiceController(svc))
                    {
                        ServiceControllerStatus currentStatus = sc.Status;
                        int? regStart = null;
                        using (RegistryKey key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\" + svc, false))
                        {
                            if (key != null && key.GetValue("Start") != null)
                            {
                                regStart = Convert.ToInt32(key.GetValue("Start"));
                            }
                        }

                        originalStates.Add(new ServiceOriginalState
                        {
                            ServiceName = svc,
                            Status = currentStatus,
                            RegistryStartValue = regStart
                        });

                        Helper.WriteToLog(string.Format("Lockdown: Recorded original state for '{0}' (Status={1}, StartType={2})",
                            svc, currentStatus, regStart.HasValue ? regStart.Value.ToString() : "N/A"));

                        if (currentStatus == ServiceControllerStatus.Running || currentStatus == ServiceControllerStatus.StartPending)
                        {
                            Helper.WriteToLog("Lockdown: Stopping service '" + svc + "'...", "OUTPUT");
                            sc.Stop();
                            sc.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(10));
                            Helper.WriteToLog("Lockdown: Service '" + svc + "' stopped.", "OUTPUT");
                        }
                    }
                }
                catch (InvalidOperationException)
                {
                    // Service is not installed on this machine
                }
                catch (Exception ex)
                {
                    Helper.WriteToLog("Lockdown: Failed to stop " + svc + ": " + ex.Message, "ERROR");
                }
            }

            // Listen on WinRM (5985, 5986), SMB (445), RDP (3389), SSH (22), HTTP/HTTPS (80, 443) to block & alert on connection attempts
            int[] lockdownPorts = new[] { 22, 80, 443, 445, 3389, 5985, 5986 };
            PortScanDetector detector = new PortScanDetector(lockdownPorts);

            ConsoleCancelEventHandler cancelHandler = (sender, e) =>
            {
                e.Cancel = true;
                if (stopEvent != null)
                {
                    stopEvent.Set();
                }
            };

            try
            {
                Console.CancelKeyPress += cancelHandler;
                detector.Start();

                Helper.WriteToLog("Lockdown active. Listening on ports [" + string.Join(", ", detector.ActiveListeningPorts) + "] to block & alert on remote connections.", "OUTPUT");

                if (waitForInteractiveInput)
                {
                    Helper.WriteToLog("Press Any key (or Ctrl+C) to stop Lockdown mode and restore services to their original state...", "OUTPUT");
                    if (!Console.IsInputRedirected)
                    {
                        while (!Console.KeyAvailable && (stopEvent == null || !stopEvent.WaitOne(200)))
                        {
                        }
                        if (Console.KeyAvailable)
                        {
                            Console.ReadKey(true);
                        }
                    }
                    else
                    {
                        Console.ReadLine();
                    }
                }
                else if (stopEvent != null)
                {
                    stopEvent.WaitOne();
                }
            }
            finally
            {
                Console.CancelKeyPress -= cancelHandler;
                Helper.WriteToLog("Exiting Lockdown mode. Releasing blocked ports and restoring services to original state...", "OUTPUT");
                detector.Stop();
                RestoreServicesToOriginalState(originalStates);
                Helper.WriteToLog("Lockdown mode exited and services restored.", "OUTPUT");
            }
        }

        private static void RestoreServicesToOriginalState(List<ServiceOriginalState> originalStates)
        {
            if (originalStates == null) return;

            foreach (ServiceOriginalState state in originalStates)
            {
                try
                {
                    if (state.RegistryStartValue.HasValue)
                    {
                        using (RegistryKey key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\" + state.ServiceName, true))
                        {
                            if (key != null)
                            {
                                key.SetValue("Start", state.RegistryStartValue.Value, RegistryValueKind.DWord);
                            }
                        }
                    }

                    using (ServiceController sc = new ServiceController(state.ServiceName))
                    {
                        sc.Refresh();
                        if (state.Status == ServiceControllerStatus.Running && sc.Status != ServiceControllerStatus.Running)
                        {
                            Helper.WriteToLog("Lockdown Restore: Starting service '" + state.ServiceName + "' back to Running state...", "OUTPUT");
                            sc.Start();
                            sc.WaitForStatus(ServiceControllerStatus.Running, TimeSpan.FromSeconds(10));
                            Helper.WriteToLog("Lockdown Restore: Service '" + state.ServiceName + "' is now " + sc.Status + ".", "OUTPUT");
                        }
                        else if (state.Status == ServiceControllerStatus.Stopped && sc.Status != ServiceControllerStatus.Stopped)
                        {
                            sc.Stop();
                            sc.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(10));
                        }
                        else
                        {
                            Helper.WriteToLog("Lockdown Restore: Service '" + state.ServiceName + "' remained in original state (" + sc.Status + ").");
                        }
                    }
                }
                catch (Exception ex)
                {
                    Helper.WriteToLog("Lockdown Restore: Failed to restore service '" + state.ServiceName + "': " + ex.Message, "ERROR");
                }
            }
        }

        private static bool IsServiceRunning(string serviceName)
        {
            try
            {
                using (ServiceController sc = new ServiceController(serviceName))
                {
                    return sc.Status == ServiceControllerStatus.Running;
                }
            }
            catch
            {
                return false;
            }
        }
    }
}
