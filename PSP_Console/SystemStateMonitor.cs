using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.IO;
using System.IO.Compression;
using System.Management;
using System.Net;
using System.Runtime.InteropServices;
using System.Security;
using System.ServiceProcess;
using System.Threading;

namespace PSP_Console
{
    public class SystemStateMonitor
    {
        private Thread _monitorThread;
        private volatile bool _running = false;
        private EventLogWatcher _firewallWatcher;

        private int? _lastTokenFilterPolicy;
        private readonly Dictionary<string, bool> _lastFirewallProfiles = new Dictionary<string, bool>(StringComparer.OrdinalIgnoreCase);
        private HashSet<string> _knownInboundFirewallRules = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        private HashSet<string> _knownServiceListeningPorts = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        private const string SystemPoliciesRegPath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System";
        private const string TokenFilterValueName = "LocalAccountTokenFilterPolicy";
        private const string FirewallPolicyBaseRegPath = @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy";

        public void Start()
        {
            if (_running) return;
            _running = true;

            // Initialize baselines
            _lastTokenFilterPolicy = GetLocalAccountTokenFilterPolicy();
            if (_lastTokenFilterPolicy == 1)
            {
                Helper.WriteToLog("WARNING: LocalAccountTokenFilterPolicy is currently set to 1 (Remote UAC token filtering is disabled!)", "OUTPUT");
            }

            _lastFirewallProfiles["DomainProfile"] = IsFirewallProfileEnabled("DomainProfile");
            _lastFirewallProfiles["StandardProfile"] = IsFirewallProfileEnabled("StandardProfile");
            _lastFirewallProfiles["PublicProfile"] = IsFirewallProfileEnabled("PublicProfile");

            _knownInboundFirewallRules = GetCurrentInboundAllowFirewallRules();
            _knownServiceListeningPorts = GetCurrentServiceListeningPortKeys(out _);

            StartFirewallEventLogWatcher();

            _monitorThread = new Thread(MonitorLoop)
            {
                IsBackground = true,
                Name = "SystemStateMonitorThread"
            };
            _monitorThread.Start();
            Helper.WriteToLog("SystemStateMonitor started (monitoring LocalAccountTokenFilterPolicy, Firewall state/rules, and Service listening ports).");
        }

        public void Stop()
        {
            _running = false;
            if (_firewallWatcher != null)
            {
                try
                {
                    _firewallWatcher.Enabled = false;
                    _firewallWatcher.Dispose();
                }
                catch
                {
                }
                _firewallWatcher = null;
            }
        }

        private void StartFirewallEventLogWatcher()
        {
            try
            {
                // Event 2003: Profile setting changed; 2004/2097: Rule added; 2005/2099: Rule modified
                EventLogQuery query = new EventLogQuery(
                    "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall",
                    PathType.LogName,
                    "*[System[EventID=2003 or EventID=2004 or EventID=2005 or EventID=2097 or EventID=2099]]");
                _firewallWatcher = new EventLogWatcher(query);
                _firewallWatcher.EventRecordWritten += OnFirewallEventWritten;
                _firewallWatcher.Enabled = true;
            }
            catch (Exception ex)
            {
                Helper.WriteToLog("Could not subscribe to Firewall event log (using registry polling fallback): " + ex.Message);
            }
        }

        private void OnFirewallEventWritten(object sender, EventRecordWrittenEventArgs e)
        {
            if (e == null || e.EventRecord == null) return;
            try
            {
                // Trigger an immediate check of firewall profiles & rules
                CheckFirewallStateAndRules();
            }
            catch (Exception ex)
            {
                Helper.LogCrash("OnFirewallEventWritten", ex);
            }
        }

        private void MonitorLoop()
        {
            while (_running)
            {
                try
                {
                    CheckLocalAccountTokenFilterPolicy();
                    CheckFirewallStateAndRules();
                    CheckServiceListeningPorts();
                }
                catch (Exception ex)
                {
                    Helper.LogCrash("SystemStateMonitor.MonitorLoop", ex);
                }

                for (int i = 0; i < 4 && _running; i++)
                {
                    Thread.Sleep(1000);
                }
            }
        }

        public static int? GetLocalAccountTokenFilterPolicy()
        {
            try
            {
                using (RegistryKey key = Registry.LocalMachine.OpenSubKey(SystemPoliciesRegPath, false))
                {
                    if (key != null)
                    {
                        object val = key.GetValue(TokenFilterValueName);
                        if (val != null)
                        {
                            return Convert.ToInt32(val);
                        }
                    }
                }
            }
            catch
            {
            }
            return null;
        }

        private void CheckLocalAccountTokenFilterPolicy()
        {
            int? current = GetLocalAccountTokenFilterPolicy();
            if (current != _lastTokenFilterPolicy)
            {
                string prevStr = _lastTokenFilterPolicy.HasValue ? _lastTokenFilterPolicy.Value.ToString() : "<not set>";
                string currStr = current.HasValue ? current.Value.ToString() : "<not set>";
                _lastTokenFilterPolicy = current;

                string warning = current == 1
                    ? "DANGER: Remote UAC Token Filtering DISABLED (Pass-the-Hash / Remote Admin enabled!)"
                    : "LocalAccountTokenFilterPolicy changed from " + prevStr + " to " + currStr;

                Helper.WriteToLog("ALERT: Registry value HKLM\\" + SystemPoliciesRegPath + "\\" + TokenFilterValueName + " changed from " + prevStr + " to " + currStr + "! " + warning, "OUTPUT");

                string recordId = SaveCustomAlertXml("LocalAccountTokenFilterPolicyChanged",
                    "RegistryKey: HKLM\\" + SystemPoliciesRegPath + "\\" + TokenFilterValueName + "\n" +
                    "PreviousValue: " + prevStr + "\n" +
                    "NewValue: " + currStr + "\n" +
                    "Assessment: " + warning);

                ToastHelper.ShowToast(
                    recordId,
                    "LocalAccountTokenFilterPolicy Changed!",
                    "Value changed: " + prevStr + " -> " + currStr,
                    warning);
            }
        }

        public static bool IsFirewallProfileEnabled(string profileSubKeyName)
        {
            try
            {
                using (RegistryKey key = Registry.LocalMachine.OpenSubKey(FirewallPolicyBaseRegPath + "\\" + profileSubKeyName, false))
                {
                    if (key != null)
                    {
                        object val = key.GetValue("EnableFirewall");
                        if (val != null)
                        {
                            return Convert.ToInt32(val) != 0;
                        }
                    }
                }
            }
            catch
            {
            }
            return true;
        }

        private void CheckFirewallStateAndRules()
        {
            string[] profiles = new[] { "DomainProfile", "StandardProfile", "PublicProfile" };
            foreach (string profile in profiles)
            {
                bool enabled = IsFirewallProfileEnabled(profile);
                bool prevEnabled;
                if (!_lastFirewallProfiles.TryGetValue(profile, out prevEnabled))
                {
                    prevEnabled = true;
                }
                _lastFirewallProfiles[profile] = enabled;

                if (prevEnabled && !enabled)
                {
                    Helper.WriteToLog("ALERT: Windows Firewall DISABLED on profile: " + profile + "!", "OUTPUT");
                    string recordId = SaveCustomAlertXml("FirewallDisabled", "Profile: " + profile + "\nState: Disabled (EnableFirewall=0)");
                    ToastHelper.ShowToast(
                        recordId,
                        "Windows Firewall Disabled!",
                        "Profile disabled: " + profile);
                }
            }

            // Check for new inbound allow firewall rules
            HashSet<string> currentRules = GetCurrentInboundAllowFirewallRules();
            foreach (string rule in currentRules)
            {
                if (!_knownInboundFirewallRules.Contains(rule))
                {
                    _knownInboundFirewallRules.Add(rule);
                    string summary = FormatFirewallRuleSummary(rule);
                    Helper.WriteToLog("ALERT: New Inbound Allow Firewall Rule added: " + summary, "OUTPUT");
                    string recordId = SaveCustomAlertXml("FirewallRuleAdded", rule);
                    ToastHelper.ShowToast(
                        recordId,
                        "Inbound Firewall Rule Added!",
                        summary);
                }
            }
            _knownInboundFirewallRules = currentRules;
        }

        private static HashSet<string> GetCurrentInboundAllowFirewallRules()
        {
            HashSet<string> rules = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            try
            {
                using (RegistryKey key = Registry.LocalMachine.OpenSubKey(FirewallPolicyBaseRegPath + "\\FirewallRules", false))
                {
                    if (key != null)
                    {
                        foreach (string valueName in key.GetValueNames())
                        {
                            string ruleData = Convert.ToString(key.GetValue(valueName)) ?? "";
                            if (ruleData.IndexOf("Action=Allow", StringComparison.OrdinalIgnoreCase) >= 0 &&
                                ruleData.IndexOf("Dir=In", StringComparison.OrdinalIgnoreCase) >= 0 &&
                                ruleData.IndexOf("Active=TRUE", StringComparison.OrdinalIgnoreCase) >= 0)
                            {
                                rules.Add(valueName + "|" + ruleData);
                            }
                        }
                    }
                }
            }
            catch
            {
            }
            return rules;
        }

        private static string FormatFirewallRuleSummary(string rawRule)
        {
            string name = "";
            string app = "";
            string lport = "";
            string[] parts = rawRule.Split('|');
            foreach (string part in parts)
            {
                if (part.StartsWith("Name=", StringComparison.OrdinalIgnoreCase)) name = part.Substring(5);
                else if (part.StartsWith("App=", StringComparison.OrdinalIgnoreCase)) app = part.Substring(4);
                else if (part.StartsWith("LPort=", StringComparison.OrdinalIgnoreCase)) lport = part.Substring(6);
            }
            string summary = !string.IsNullOrEmpty(name) ? "Rule: " + name : "New Inbound Allow Rule";
            if (!string.IsNullOrEmpty(lport)) summary += " (Port: " + lport + ")";
            if (!string.IsNullOrEmpty(app)) summary += " App: " + app;
            return summary;
        }

        private void CheckServiceListeningPorts()
        {
            Dictionary<string, string> detailsByKey;
            HashSet<string> currentKeys = GetCurrentServiceListeningPortKeys(out detailsByKey);

            foreach (string key in currentKeys)
            {
                if (!_knownServiceListeningPorts.Contains(key))
                {
                    _knownServiceListeningPorts.Add(key);
                    string details = detailsByKey.ContainsKey(key) ? detailsByKey[key] : key;
                    if (details.IndexOf("PSPService", StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        continue;
                    }
                    Helper.WriteToLog("ALERT: Windows Service started listening on a TCP port: " + details, "OUTPUT");
                    string recordId = SaveCustomAlertXml("ServiceListeningOnPort", details);
                    ToastHelper.ShowToast(
                        recordId,
                        "Service Started Listening on Port!",
                        details);
                }
            }
        }

        public static HashSet<string> GetCurrentServiceListeningPortKeys(out Dictionary<string, string> detailsByKey)
        {
            HashSet<string> keys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            detailsByKey = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

            try
            {
                Dictionary<int, List<string>> servicesByPid = GetRunningServicesByPid();
                Dictionary<int, List<int>> listeningPortsByPid = GetListeningTcpPortsByPid();

                foreach (KeyValuePair<int, List<int>> kvp in listeningPortsByPid)
                {
                    int pid = kvp.Key;
                    List<string> serviceNames;
                    if (servicesByPid.TryGetValue(pid, out serviceNames))
                    {
                        string joinedServices = string.Join("/", serviceNames);
                        foreach (int port in kvp.Value)
                        {
                            string key = joinedServices + ":" + port;
                            keys.Add(key);
                            detailsByKey[key] = "Service: " + joinedServices + " (PID " + pid + ") listening on TCP Port " + port;
                        }
                    }
                }
            }
            catch
            {
            }

            return keys;
        }

        public static Dictionary<int, List<string>> GetRunningServicesByPid()
        {
            Dictionary<int, List<string>> map = new Dictionary<int, List<string>>();
            try
            {
                using (ManagementObjectSearcher searcher = new ManagementObjectSearcher("SELECT Name, ProcessId FROM Win32_Service WHERE ProcessId != 0 AND State = 'Running'"))
                using (ManagementObjectCollection results = searcher.Get())
                {
                    foreach (ManagementObject obj in results)
                    {
                        int pid = Convert.ToInt32(obj["ProcessId"]);
                        string name = Convert.ToString(obj["Name"]) ?? "UnknownService";
                        if (pid > 0)
                        {
                            List<string> list;
                            if (!map.TryGetValue(pid, out list))
                            {
                                list = new List<string>();
                                map[pid] = list;
                            }
                            list.Add(name);
                        }
                    }
                }
            }
            catch
            {
            }
            return map;
        }

        public static Dictionary<int, List<int>> GetListeningTcpPortsByPid()
        {
            Dictionary<int, List<int>> result = new Dictionary<int, List<int>>();
            int bufferSize = 0;
            uint ret = GetExtendedTcpTable(IntPtr.Zero, ref bufferSize, true, AF_INET, TCP_TABLE_OWNER_PID_LISTENER, 0);
            IntPtr tcpTablePtr = Marshal.AllocHGlobal(bufferSize);
            try
            {
                ret = GetExtendedTcpTable(tcpTablePtr, ref bufferSize, true, AF_INET, TCP_TABLE_OWNER_PID_LISTENER, 0);
                if (ret == 0)
                {
                    int rowCount = Marshal.ReadInt32(tcpTablePtr);
                    IntPtr rowPtr = (IntPtr)((long)tcpTablePtr + 4);
                    int rowSize = Marshal.SizeOf(typeof(MIB_TCPROW_OWNER_PID));
                    for (int i = 0; i < rowCount; i++)
                    {
                        MIB_TCPROW_OWNER_PID row = (MIB_TCPROW_OWNER_PID)Marshal.PtrToStructure(rowPtr, typeof(MIB_TCPROW_OWNER_PID));
                        int localPort = (int)(((row.localPort & 0xFF) << 8) | ((row.localPort >> 8) & 0xFF));
                        int pid = (int)row.owningPid;

                        List<int> ports;
                        if (!result.TryGetValue(pid, out ports))
                        {
                            ports = new List<int>();
                            result[pid] = ports;
                        }
                        if (!ports.Contains(localPort))
                        {
                            ports.Add(localPort);
                        }
                        rowPtr = (IntPtr)((long)rowPtr + rowSize);
                    }
                }
            }
            finally
            {
                Marshal.FreeHGlobal(tcpTablePtr);
            }
            return result;
        }

        private const int AF_INET = 2;
        private const int TCP_TABLE_OWNER_PID_LISTENER = 3;

        [StructLayout(LayoutKind.Sequential)]
        private struct MIB_TCPROW_OWNER_PID
        {
            public uint state;
            public uint localAddr;
            public uint localPort;
            public uint remoteAddr;
            public uint remotePort;
            public uint owningPid;
        }

        [DllImport("iphlpapi.dll", SetLastError = true)]
        private static extern uint GetExtendedTcpTable(
            IntPtr pTcpTable,
            ref int dwOutBufLen,
            bool sort,
            int ipVersion,
            int tblClass,
            uint reserved);

        public static bool IsSysmonRunning()
        {
            try
            {
                foreach (ServiceController sc in ServiceController.GetServices())
                {
                    if (sc.ServiceName.Equals("Sysmon", StringComparison.OrdinalIgnoreCase) ||
                        sc.ServiceName.Equals("Sysmon64", StringComparison.OrdinalIgnoreCase))
                    {
                        return sc.Status == ServiceControllerStatus.Running;
                    }
                }
            }
            catch
            {
            }
            return false;
        }

        public static bool EnsureSysmonInstalled()
        {
            try
            {
                if (IsSysmonRunning())
                {
                    Helper.WriteToLog("Sysmon is already installed and running on this system.", "OUTPUT");
                    return true;
                }

                string toolsDir = Path.Combine(Helper.path, "Tools", "Sysmon");
                if (!Directory.Exists(toolsDir))
                {
                    Directory.CreateDirectory(toolsDir);
                }

                string zipPath = Path.Combine(toolsDir, "Sysmon.zip");
                string exePath = Path.Combine(toolsDir, Environment.Is64BitOperatingSystem ? "Sysmon64.exe" : "Sysmon.exe");

                if (!File.Exists(exePath))
                {
                    Helper.WriteToLog("Sysmon not running. Downloading Sysmon from Microsoft Sysinternals...", "OUTPUT");
                    ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
                    using (WebClient wc = new WebClient())
                    {
                        wc.DownloadFile("https://download.sysinternals.com/files/Sysmon.zip", zipPath);
                    }
                    ZipFile.ExtractToDirectory(zipPath, toolsDir);
                }

                if (File.Exists(exePath))
                {
                    Helper.WriteToLog("Installing Sysmon service (" + exePath + " -accepteula -i)...", "OUTPUT");
                    Process p = new Process();
                    p.StartInfo.FileName = exePath;
                    p.StartInfo.Arguments = "-accepteula -i";
                    p.StartInfo.UseShellExecute = false;
                    p.StartInfo.RedirectStandardOutput = true;
                    p.StartInfo.RedirectStandardError = true;
                    p.StartInfo.CreateNoWindow = true;
                    p.Start();
                    string output = p.StandardOutput.ReadToEnd() + p.StandardError.ReadToEnd();
                    p.WaitForExit(30000);
                    Helper.WriteToLog("Sysmon installer result: " + output.Trim(), "OUTPUT");
                    return IsSysmonRunning();
                }
            }
            catch (Exception ex)
            {
                Helper.WriteToLog("Failed to download/install Sysmon: " + ex.Message, "ERROR");
            }
            return false;
        }

        private static string SaveCustomAlertXml(string alertType, string details)
        {
            string recordId = DateTime.UtcNow.Ticks.ToString();
            try
            {
                if (!Directory.Exists(Helper.path))
                {
                    Directory.CreateDirectory(Helper.path);
                }
                string xml =
                    "<SystemStateAlert>\n" +
                    "  <Timestamp>" + SecurityElement.Escape(DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss")) + "</Timestamp>\n" +
                    "  <AlertType>" + SecurityElement.Escape(alertType) + "</AlertType>\n" +
                    "  <Details>" + SecurityElement.Escape(details) + "</Details>\n" +
                    "</SystemStateAlert>";
                File.WriteAllText(Path.Combine(Helper.path, recordId + ".xml"), xml);
            }
            catch
            {
            }
            return recordId;
        }
    }
}
