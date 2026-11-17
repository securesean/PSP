using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.DirectoryServices.AccountManagement;
using System.IO;
using System.Management;
using System.Net;
using System.Net.Sockets;
using System.ServiceProcess;
using System.Threading;

namespace PSP_Console
{
    public static class SecurityEvaluator
    {
        public static void RunSecurityEvaluation(bool launchAutoruns = false)
        {
            Helper.WriteToLog("===============================================================================", "OUTPUT");
            Helper.WriteToLog("                PERSONAL SECURITY PRODUCT - SECURITY EVALUATION                ", "OUTPUT");
            Helper.WriteToLog("===============================================================================", "OUTPUT");

            // 1. Check WinRM / RDP / SMB / SSH service & registry status
            EvaluateRemoteAccessServices();

            // 2. Check Guest account & Built-in RID 500 Administrator account (STIG V-63353 / V-63351)
            EvaluateBuiltInAccounts();

            // 3. Check LocalAccountTokenFilterPolicy
            EvaluateLocalAccountTokenFilterPolicy();

            // 4. List all direct and recursive users/groups in Local Administrators and Remote Access groups,
            //    and print summary: "X number of users can access this computer remotely via RDP, SMB/RPC/DCOM, WinRM"
            EvaluateRemoteAccessUsersAndAdminGroups();

            // 5. List weird services (non-standard paths, unquoted service paths with spaces, writable locations)
            EvaluateWeirdServices();

            // 6. List all programs and Windows Services listening on any TCP ports
            EvaluateListeningPortsAndServices();

            // 7. Detect if "(Audit) Security System Extension" is enabled
            EvaluateAuditSecuritySystemExtension();

            // 8. Optionally download and execute Sysinternals Autoruns
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

        private static void EvaluateRemoteAccessServices()
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
        }

        private static void EvaluateBuiltInAccounts()
        {
            Helper.WriteToLog("\n--- [2] Built-in Account STIG Checks (Guest & Default Administrator) ---", "OUTPUT");
            try
            {
                using (PrincipalContext ctx = new PrincipalContext(ContextType.Machine))
                {
                    // Check RID 500 Administrator (S-1-5-21-...-500) and RID 501 Guest (S-1-5-21-...-501)
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
                                Helper.WriteToLog(
                                    string.Format("RID 500 Built-in Admin : Name='{0}', Enabled={1}, UsesDefaultName={2}",
                                        user.Name, enabled, defaultName),
                                    (enabled && defaultName) ? "ERROR" : "OUTPUT");
                                if (enabled && defaultName)
                                {
                                    Helper.WriteToLog("  [STIG Finding V-63351] Built-in Administrator account is enabled and still uses default name 'Administrator'!", "ERROR");
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
                                Helper.WriteToLog(
                                    string.Format("RID 501 Guest Account  : Name='{0}', Enabled={1}, Groups=[{2}]",
                                        user.Name, enabled, string.Join(", ", guestGroups)),
                                    enabled ? "ERROR" : "OUTPUT");
                                if (enabled)
                                {
                                    Helper.WriteToLog("  [STIG Finding V-63353] Guest account is ENABLED!", "ERROR");
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
        }

        private static void EvaluateLocalAccountTokenFilterPolicy()
        {
            Helper.WriteToLog("\n--- [3] LocalAccountTokenFilterPolicy Check ---", "OUTPUT");
            int? policy = SystemStateMonitor.GetLocalAccountTokenFilterPolicy();
            if (policy == 1)
            {
                Helper.WriteToLog("LocalAccountTokenFilterPolicy = 1 (VULNERABLE: Remote UAC administrative token filtering is DISABLED! Local admins can authenticate remotely over SMB/RPC/WinRM.)", "ERROR");
            }
            else if (policy.HasValue)
            {
                Helper.WriteToLog("LocalAccountTokenFilterPolicy = " + policy.Value + " (Protected: Remote UAC token filtering is enforced.)", "OUTPUT");
            }
            else
            {
                Helper.WriteToLog("LocalAccountTokenFilterPolicy = <Not Set> (Default Protected: Remote UAC token filtering is enforced.)", "OUTPUT");
            }
        }

        private static void EvaluateRemoteAccessUsersAndAdminGroups()
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

            Helper.WriteToLog(
                string.Format("SUMMARY: {0} user(s) can access via RDP, {1} user(s) via SMB/RPC/DCOM, and {2} user(s) via WinRM.",
                    allRdpUsers.Count, allSmbRpcDcomUsers.Count, allWinRmUsers.Count),
                "OUTPUT");
        }

        private static List<string> GetGroupMembers(string groupSid, bool recursive)
        {
            List<string> members = new List<string>();
            try
            {
                System.Threading.Tasks.Task task = System.Threading.Tasks.Task.Run(() =>
                {
                    try
                    {
                        using (PrincipalContext ctx = new PrincipalContext(ContextType.Machine))
                        using (GroupPrincipal group = GroupPrincipal.FindByIdentity(ctx, IdentityType.Sid, groupSid))
                        {
                            if (group != null)
                            {
                                using (PrincipalSearchResult<Principal> searchResult = group.GetMembers(recursive))
                                {
                                    foreach (Principal member in searchResult)
                                    {
                                        string sid = member.Sid != null ? member.Sid.Value : "";
                                        string type = member is GroupPrincipal ? "Group" : "User";
                                        members.Add(string.Format("{0} [{1}, SID={2}]", member.Name, type, sid));
                                    }
                                }
                            }
                        }
                    }
                    catch
                    {
                    }
                });
                task.Wait(3000);
            }
            catch (Exception ex)
            {
                Helper.WriteToLog("  (Note: Could not resolve all members for group " + groupSid + ": " + ex.Message + ")");
            }
            return members;
        }

        private static void EvaluateWeirdServices()
        {
            Helper.WriteToLog("\n--- [5] Weird / Suspicious Windows Services Audit ---", "OUTPUT");
            int weirdCount = 0;
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
                            weirdCount++;
                            string reason = isUnquotedWithSpaces ? "UNQUOTED PATH WITH SPACES" : "NON-STANDARD BINARY PATH";
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

            if (weirdCount == 0)
            {
                Helper.WriteToLog("  No weird or unquoted-path services found.", "OUTPUT");
            }
        }

        private static void EvaluateListeningPortsAndServices()
        {
            Helper.WriteToLog("\n--- [6] Programs and Services Listening on TCP Ports ---", "OUTPUT");
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
                    string svcDisplay = servicesByPid.TryGetValue(pid, out svcList) && svcList.Count > 0
                        ? string.Join(", ", svcList)
                        : "(No associated Windows Service)";

                    kvp.Value.Sort();
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
        }

        private static void EvaluateAuditSecuritySystemExtension()
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
        }

        public static void RunLockdownMode(ManualResetEvent stopEvent = null)
        {
            Helper.WriteToLog("===============================================================================", "OUTPUT");
            Helper.WriteToLog("                     ENGAGING PSP LOCKDOWN MODE                                ", "OUTPUT");
            Helper.WriteToLog("===============================================================================", "OUTPUT");

            string[] servicesToStop = new[] { "WinRM", "LanmanServer", "TermService", "sshd" };
            foreach (string svc in servicesToStop)
            {
                try
                {
                    if (IsServiceRunning(svc))
                    {
                        Helper.WriteToLog("Lockdown: Stopping service '" + svc + "'...", "OUTPUT");
                        using (ServiceController sc = new ServiceController(svc))
                        {
                            sc.Stop();
                            sc.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(5));
                        }
                    }
                }
                catch (Exception ex)
                {
                    Helper.WriteToLog("Lockdown: Failed to stop " + svc + ": " + ex.Message, "ERROR");
                }
            }

            // Listen on WinRM (5985, 5986), SMB (445), RDP (3389), SSH (22), HTTP/HTTPS (80, 443) to block & alert on connection attempts
            int[] lockdownPorts = new[] { 22, 80, 443, 445, 3389, 5985, 5986 };
            PortScanDetector detector = new PortScanDetector(lockdownPorts);
            detector.Start();

            Helper.WriteToLog("Lockdown active. Listening on ports [" + string.Join(", ", detector.ActiveListeningPorts) + "] to block & alert on remote connections.", "OUTPUT");
            if (stopEvent != null)
            {
                stopEvent.WaitOne();
                detector.Stop();
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
