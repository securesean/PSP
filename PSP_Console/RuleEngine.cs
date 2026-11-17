using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Json;

namespace PSP_Console
{
    [DataContract]
    public class RuleConfig
    {
        [DataMember]
        public List<int> ExcludedLogonTypes { get; set; } = new List<int> { 2, 5, 7, 11 };

        [DataMember]
        public List<string> ExcludedGroupEnumProcesses { get; set; } = new List<string>
        {
            @"C:\Windows\System32\wbem\WmiPrvSE.exe"
        };

        [DataMember]
        public List<string> ExcludedLsassLogonProcesses { get; set; } = new List<string>
        {
            "ConsentUI",
            "Secondary Logon Service",
            "UserManager"
        };

        [DataMember]
        public List<int> SuppressedEventIds { get; set; } = new List<int>();

        [DataMember]
        public List<string> SuppressedAlertSignatures { get; set; } = new List<string>();
    }

    public static class RuleEngine
    {
        private const string EventValueNotSet = "%%1793";
        public static readonly string ConfigFilePath = Path.Combine(Helper.path, "rules_config.json");
        private static RuleConfig _config;
        private static readonly object _configLock = new object();

        private static readonly Dictionary<string, string[]> GroupSidWarnings = new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase)
        {
            { "-544", new[] { "WARNING: User added to local Admin Group! " } },
            { "-546", new[] { "WARNING: User added to local Guest Group! " } },
            { "-547", new[] { "WARNING: User added to local Power Users Group! " } },
            { "-548", new[] { "WARNING: User added to local Account Operators Group! " } },
            { "-549", new[] { "WARNING: User added to local Server Operators Group! " } },
            { "-551", new[] { "WARNING: User added to local Backup Operators Group! " } },
            { "-552", new[] { "WARNING: User added to local Replicators Group! " } },
            { "-554", new[] { "WARNING: User added to backward compatibility group that allows read access on all users and groups in the domain! " } },
            { "-555", new[] { "WARNING: User added to local RDP Group! " } },
            { "-556", new[] { "WARNING: User added to Network Configuration Operators Group! " } },
            { "-557", new[] { "WARNING: User added to Incoming Forest Trust Builders Group! " } },
            { "-558", new[] { "WARNING: User added to Performance Monitor Users Group! " } },
            { "-559", new[] { "WARNING: User added to Performance Log Users Group! " } },
            { "-560", new[] { "WARNING: User added to Windows Authorization Access Group Group! " } },
            { "-561", new[] { "WARNING: User added to Terminal Server License Servers Group! " } },
            { "-562", new[] { "WARNING: User added to Distributed COM Users Group! " } },
            { "-569", new[] { "WARNING: User added to Cryptographic Operators Group! " } },
            { "-573", new[] { "WARNING: User added to Event Log Readers Group! " } },
            { "-574", new[] { "WARNING: User added to Certificate Service DCOM Access Group! " } },
            { "-575", new[] { "WARNING: User added to RDS Remote Access Servers Group! " } },
            { "-576", new[] { "WARNING: User added to RDS Endpoint Servers Group! " } },
            { "-577", new[] { "WARNING: User added to RDS Management Servers Group! " } },
            { "-578", new[] { "WARNING: Members of this group have complete and unrestricted access to all features of Hyper-V." } },
            { "-579", new[] { "WARNING: Members of this group can remotely query authorization attributes and permissions for resources on this computer." } },
            { "-580", new[] { "WARNING: Members of this group can access WMI resources over management protocols (such as WS-Management via the Windows Remote Management service). This applies only to WMI namespaces that grant access to the user." } },
            { "-10", new[] { "WARNING: User added to NTLM Authentication Group! ", "A SID that is used when the NTLM authentication package authenticated the client" } },
            { "-64-14", new[] { "WARNING: A SID that is used when the SChannel authentication package authenticated the client." } },
            { "-64-21", new[] { "WARNING: A SID that is used when the Digest authentication package authenticated the client." } },
            { "-5-80", new[] { "WARNING: A SID that is used as an NT Service account prefix." } },
            { "-80-0", new[] { "WARNING: A group that includes all service processes that are configured on the system. Membership is controlled by the operating system. SID S-1-5-80-0 equals NT SERVICES\\ALL SERVICES. " } },
            { "-83-0", new[] { "WARNING: User added to NT VIRTUAL MACHINE\\Virtual Machines Group! ", "The group is created when the Hyper-V role is installed. Membership in the group is maintained by the Hyper-V Management Service (VMMS). This group requires the Create Symbolic Links right (SeCreateSymbolicLinkPrivilege), and also the Log on as a Service right (SeServiceLogonRight)." } },
            { "-501", new[] { "WARNING: User added to DOMAIN_USER_RID_GUEST Group! ", "The guest-user account in a domain. Users who do not have an account can automatically sign in to this account." } },
            { "-513", new[] { "WARNING: User added to DOMAIN_GROUP_RID_USERS Group! ", "A group that contains all user accounts in a domain. All users are automatically added to this group." } },
            { "-514", new[] { "WARNING: User added to DOMAIN_GROUP_RID_GUESTS Group! ", "The group Guest account in a domain." } },
            { "-515", new[] { "WARNING: User added to DOMAIN_GROUP_RID_COMPUTERS Group! ", "The Domain Computer group. All computers in the domain are members of this group." } },
            { "-516", new[] { "WARNING: User added to DOMAIN_GROUP_RID_CONTROLLERS Group! ", "The Domain Controller group. All domain controllers in the domain are members of this group." } },
            { "-517", new[] { "WARNING: User added to DOMAIN_GROUP_RID_CERT_ADMINS Group! ", "The certificate publishers' group. Computers running Active Directory Certificate Services are members of this group." } },
            { "-518", new[] { "WARNING: User added to DOMAIN_GROUP_RID_SCHEMA_ADMINS Group! ", "The schema administrators' group. Members of this group can modify the Active Directory schema." } },
            { "-519", new[] { "WARNING: User added to DOMAIN_GROUP_RID_ENTERPRISE_ADMINS Group! ", "\tThe enterprise administrators' group. Members of this group have full access to all domains in the Active Directory forest. Enterprise administrators are responsible for forest-level operations such as adding or removing new domains." } },
            { "-520", new[] { "WARNING: User added to DOMAIN_GROUP_RID_POLICY_ADMINS Group! ", "The policy administrators' group." } }
        };

        public static RuleConfig GetConfig()
        {
            lock (_configLock)
            {
                if (_config != null)
                {
                    return _config;
                }

                try
                {
                    if (File.Exists(ConfigFilePath))
                    {
                        using (FileStream fs = new FileStream(ConfigFilePath, FileMode.Open, FileAccess.Read, FileShare.Read))
                        {
                            DataContractJsonSerializer serializer = new DataContractJsonSerializer(typeof(RuleConfig));
                            _config = (RuleConfig)serializer.ReadObject(fs);
                        }
                    }
                }
                catch (Exception ex)
                {
                    Helper.WriteToLog("Failed to read rules_config.json, using defaults: " + ex.Message, "ERROR");
                }

                if (_config == null)
                {
                    _config = new RuleConfig();
                    SaveConfig(_config);
                }

                return _config;
            }
        }

        public static void SaveConfig(RuleConfig config)
        {
            lock (_configLock)
            {
                _config = config;
                try
                {
                    if (!Directory.Exists(Helper.path))
                    {
                        Directory.CreateDirectory(Helper.path);
                    }
                    using (FileStream fs = new FileStream(ConfigFilePath, FileMode.Create, FileAccess.Write, FileShare.Read))
                    {
                        DataContractJsonSerializer serializer = new DataContractJsonSerializer(typeof(RuleConfig));
                        serializer.WriteObject(fs, config);
                    }
                }
                catch
                {
                }
            }
        }

        public static bool IsMachineAccount(string accountName)
        {
            if (string.IsNullOrEmpty(accountName))
            {
                return false;
            }
            return accountName.ToUpperInvariant().Contains(Environment.MachineName.ToUpperInvariant() + "$");
        }

        public static bool IsValidEventField(string value)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                return false;
            }
            string trimmed = value.Trim();
            return trimmed != "-" && trimmed != EventValueNotSet;
        }

        public static bool ShouldEvaluateLogonType(int logonType)
        {
            RuleConfig cfg = GetConfig();
            return cfg.ExcludedLogonTypes == null || !cfg.ExcludedLogonTypes.Contains(logonType);
        }

        public static bool IsKerberosMachineNoise(int logonType, string authPackageName, string targetUserName)
        {
            return logonType == 3 &&
                   string.Equals(authPackageName, "Kerberos", StringComparison.OrdinalIgnoreCase) &&
                   IsMachineAccount(targetUserName);
        }

        public static bool ShouldAlertExplicitCredsLogon(string subjectUserSid, string subjectUserName)
        {
            return subjectUserSid != "S-1-5-18" && !IsMachineAccount(subjectUserName);
        }

        public static bool ShouldAlertLocalGroupEnum(string subjectUserName, string callerProcessName, string callerProcessId)
        {
            if (string.IsNullOrEmpty(callerProcessName) || callerProcessName == "-" || callerProcessId == "0")
            {
                return false;
            }
            if (IsMachineAccount(subjectUserName))
            {
                return false;
            }
            RuleConfig cfg = GetConfig();
            if (cfg.ExcludedGroupEnumProcesses != null)
            {
                foreach (string excluded in cfg.ExcludedGroupEnumProcesses)
                {
                    if (string.Equals(callerProcessName, excluded, StringComparison.OrdinalIgnoreCase))
                    {
                        return false;
                    }
                }
            }
            return true;
        }

        public static bool ShouldAlertUserAddedToGroup(string targetGroupSid, string memberSid, ICollection<string> localAdminGroupList)
        {
            if (!string.IsNullOrEmpty(targetGroupSid) &&
                targetGroupSid.EndsWith("-544", StringComparison.OrdinalIgnoreCase) &&
                localAdminGroupList != null &&
                localAdminGroupList.Contains(memberSid))
            {
                return false;
            }
            return true;
        }

        public static bool ShouldAlertLsassLogon(string logonProcessName)
        {
            if (string.IsNullOrWhiteSpace(logonProcessName))
            {
                return false;
            }
            RuleConfig cfg = GetConfig();
            if (cfg.ExcludedLsassLogonProcesses != null)
            {
                foreach (string excluded in cfg.ExcludedLsassLogonProcesses)
                {
                    if (string.Equals(logonProcessName.Trim(), excluded, StringComparison.OrdinalIgnoreCase))
                    {
                        return false;
                    }
                }
            }
            return true;
        }

        public static List<string> GetGroupSidWarningLines(string targetSid)
        {
            List<string> result = new List<string>();
            if (!string.IsNullOrEmpty(targetSid))
            {
                foreach (KeyValuePair<string, string[]> kvp in GroupSidWarnings)
                {
                    if (targetSid.EndsWith(kvp.Key, StringComparison.OrdinalIgnoreCase))
                    {
                        result.AddRange(kvp.Value);
                        return result;
                    }
                }
            }
            result.Add("With a cumstom (Unknown) Group");
            return result;
        }

        public static string BuildUserCreatedSummary(
            string targetUserName,
            string samAccountName,
            string displayName,
            string userPrincipalName,
            string sidHistory,
            string allowedToDelegateTo)
        {
            string message = "";
            string targetTrimmed = (targetUserName ?? "").Trim();

            if (IsValidEventField(samAccountName) && !string.Equals(targetTrimmed, samAccountName.Trim(), StringComparison.OrdinalIgnoreCase))
            {
                message += "Sam Account Name: " + samAccountName + ".  ";
            }

            if (IsValidEventField(displayName) && !string.Equals(targetTrimmed, displayName.Trim(), StringComparison.OrdinalIgnoreCase))
            {
                message += "Display Name: " + displayName + ".  ";
            }

            if (IsValidEventField(userPrincipalName) && !string.Equals(targetTrimmed, userPrincipalName.Trim(), StringComparison.OrdinalIgnoreCase))
            {
                message += "UPN: " + userPrincipalName + ".  ";
            }

            if (IsValidEventField(sidHistory))
            {
                message += "Interesting SID History: " + sidHistory + ".  ";
                Helper.WriteToLog("Interesting SID History: " + sidHistory, "OUTPUT");
            }

            if (IsValidEventField(allowedToDelegateTo))
            {
                message += "Interesting Deligation Powers: " + allowedToDelegateTo + ".  ";
                Helper.WriteToLog("Interesting Deligation Powers: " + allowedToDelegateTo, "OUTPUT");
            }

            return message;
        }

        public static string GetExplicitCredsProcessHint(string processName)
        {
            if (string.IsNullOrEmpty(processName))
            {
                return null;
            }
            if (processName.IndexOf("svchost.exe", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                return "(svchost.exe usually means you usually just ran runas.exe)";
            }
            if (processName.IndexOf("lsass.exe", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                return "(lsass.exe usually means you just RDP'd)";
            }
            return null;
        }

        public static string GetLsassLogonProcessHint(string logonProcessName)
        {
            string upper = (logonProcessName ?? "").Trim().ToUpperInvariant();
            if (upper == "WINLOGON")
            {
                return "This might be RDP Traffic";
            }
            if (upper == "HTTP.SYS")
            {
                return "This might be WinRM being enabled";
            }
            return "The source probably needs to be added to the known-good list";
        }

        public static List<string> BuildLogonSuccessToastLines(
            int logonType,
            string targetDomainName,
            string targetUserName,
            string ip,
            string workstationName,
            string authPackageName,
            string lmPackageName)
        {
            List<string> lines = new List<string>
            {
                logonType == 10 ? "RDP Logon Success (Logon Type 10) " : "Logon Success Type: " + logonType
            };

            string details = "User: " + targetDomainName + "\\" + targetUserName;
            if (Helper.isRemoteIP(ip))
            {
                if (IsValidEventField(workstationName))
                {
                    details += "\nAttacker Hostname: " + workstationName;
                }
                details += "\nIP: " + ip;
            }

            if (IsValidEventField(authPackageName))
            {
                details += " Auth: " + authPackageName;
            }
            if (IsValidEventField(lmPackageName))
            {
                details += " Auth Package: " + lmPackageName;
            }

            lines.Add(details);
            return lines;
        }

        public static List<string> BuildLogonFailedToastLines(
            int logonType,
            string targetDomainName,
            string targetUserName,
            string ip,
            string subjectDomainName,
            string workstationName,
            string authPackageName,
            string lmPackageName)
        {
            List<string> lines = new List<string>
            {
                "Logon Failed Type: " + logonType
            };

            string details = "Attempted Username: " + targetDomainName + "\\" + targetUserName;
            if (Helper.isRemoteIP(ip))
            {
                details += "\nIP: " + ip;
            }
            if (IsValidEventField(subjectDomainName) && IsValidEventField(workstationName))
            {
                details += "\nAttacker Hostname: " + subjectDomainName + "\\" + workstationName;
            }
            if (IsValidEventField(authPackageName))
            {
                details += " Auth: " + authPackageName;
            }
            if (IsValidEventField(lmPackageName))
            {
                details += " Auth Package: " + lmPackageName;
            }

            lines.Add(details);
            return lines;
        }
    }
}
