using System;
using System.Collections.Generic;
using System.Diagnostics;

namespace PSP_Console
{
    public static class AuditPolicyManager
    {
        private static readonly Dictionary<int, string[]> EventToSubcategories = new Dictionary<int, string[]>
        {
            { 4697, new[] { "Security System Extension" } },
            { 4610, new[] { "Security System Extension" } },
            { 4611, new[] { "Security System Extension" } },
            { 4614, new[] { "Security System Extension" } },
            { 4622, new[] { "Security System Extension" } },
            { 4624, new[] { "Logon" } },
            { 4625, new[] { "Logon" } },
            { 4648, new[] { "Logon", "Special Logon" } },
            { 4720, new[] { "User Account Management" } },
            { 4722, new[] { "User Account Management" } },
            { 4724, new[] { "User Account Management" } },
            { 4726, new[] { "User Account Management" } },
            { 4798, new[] { "User Account Management" } },
            { 4732, new[] { "Security Group Management" } },
            { 4799, new[] { "Security Group Management" } },
            { 1102, new[] { "Audit Policy Change" } }
        };

        public static bool IsSubcategoryEnabled(string subcategory)
        {
            try
            {
                string output = RunAuditPol("/get /subcategory:\"" + subcategory + "\"");
                return output.IndexOf("Success", StringComparison.OrdinalIgnoreCase) >= 0;
            }
            catch
            {
                return false;
            }
        }

        public static bool EnableSubcategory(string subcategory, bool success = true, bool failure = true)
        {
            try
            {
                string args = "/set /subcategory:\"" + subcategory + "\" " +
                              "/success:" + (success ? "enable" : "disable") + " " +
                              "/failure:" + (failure ? "enable" : "disable");
                string output = RunAuditPol(args);
                bool ok = output.IndexOf("The command was successfully executed", StringComparison.OrdinalIgnoreCase) >= 0;
                if (ok)
                {
                    Helper.WriteToLog("Enabled Windows Audit Policy subcategory: '" + subcategory + "'", "OUTPUT");
                }
                else
                {
                    Helper.WriteToLog("AuditPol output for '" + subcategory + "': " + output.Trim(), "ERROR");
                }
                return ok;
            }
            catch (Exception ex)
            {
                Helper.WriteToLog("Failed to enable AuditPol subcategory '" + subcategory + "': " + ex.Message, "ERROR");
                return false;
            }
        }

        public static HashSet<string> EnableAuditPoliciesForEvents(IEnumerable<int> missingEventIds)
        {
            HashSet<string> enabledSubcategories = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (int eventId in missingEventIds)
            {
                string[] subcategories;
                if (EventToSubcategories.TryGetValue(eventId, out subcategories))
                {
                    foreach (string sub in subcategories)
                    {
                        if (!enabledSubcategories.Contains(sub))
                        {
                            if (EnableSubcategory(sub, true, true))
                            {
                                enabledSubcategories.Add(sub);
                            }
                        }
                    }
                }
            }
            return enabledSubcategories;
        }

        public static void EnsureRecommendedAuditPolicies()
        {
            string[] recommended = new[]
            {
                "Security System Extension",
                "Logon",
                "Special Logon",
                "User Account Management",
                "Security Group Management",
                "Security State Change",
                "Audit Policy Change",
                "Process Creation",
                "MPSSVC Rule-Level Policy Change",
                "Other Policy Change Events"
            };

            foreach (string sub in recommended)
            {
                if (!IsSubcategoryEnabled(sub))
                {
                    Helper.WriteToLog("Audit subcategory '" + sub + "' is not enabled. Enabling automatically...");
                    EnableSubcategory(sub, true, true);
                }
            }
        }

        private static string RunAuditPol(string arguments)
        {
            Process p = new Process();
            p.StartInfo.FileName = "auditpol.exe";
            p.StartInfo.Arguments = arguments;
            p.StartInfo.UseShellExecute = false;
            p.StartInfo.RedirectStandardOutput = true;
            p.StartInfo.RedirectStandardError = true;
            p.StartInfo.CreateNoWindow = true;
            p.Start();
            string output = p.StandardOutput.ReadToEnd() + p.StandardError.ReadToEnd();
            p.WaitForExit(10000);
            return output;
        }
    }
}
