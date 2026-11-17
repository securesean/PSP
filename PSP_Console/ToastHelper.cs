using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Json;
using System.Security.AccessControl;
using System.Security.Principal;

namespace PSP_Console
{
    [DataContract]
    public class ToastButtonItem
    {
        [DataMember]
        public string Content { get; set; }

        [DataMember]
        public string Arguments { get; set; }

        [DataMember]
        public string IconUri { get; set; }
    }

    [DataContract]
    public class ToastAlertPayload
    {
        [DataMember]
        public string EventRecordId { get; set; }

        [DataMember]
        public int EventId { get; set; }

        [DataMember]
        public List<string> Lines { get; set; }

        [DataMember]
        public List<ToastButtonItem> Buttons { get; set; }

        [DataMember]
        public string AppLogoPath { get; set; }

        [DataMember]
        public string AudioUri { get; set; }
    }

    public static class ToastHelper
    {
        public static readonly string AlertsDirectory = Path.Combine(Helper.path, "Alerts");
        private static bool _aclConfigured = false;

        public static void EnsureAlertDirectories()
        {
            try
            {
                if (!Directory.Exists(Helper.path))
                {
                    Directory.CreateDirectory(Helper.path);
                }
                if (!Directory.Exists(AlertsDirectory))
                {
                    Directory.CreateDirectory(AlertsDirectory);
                }

                if (!_aclConfigured)
                {
                    GrantUsersModifyAccess(Helper.path);
                    GrantUsersModifyAccess(AlertsDirectory);
                    _aclConfigured = true;
                }
            }
            catch (Exception ex)
            {
                Helper.WriteToLog("Failed to configure alert directories: " + ex.Message, "ERROR");
            }
        }

        private static void GrantUsersModifyAccess(string dirPath)
        {
            try
            {
                DirectoryInfo dInfo = new DirectoryInfo(dirPath);
                DirectorySecurity dSecurity = dInfo.GetAccessControl();
                SecurityIdentifier usersSid = new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null);
                dSecurity.AddAccessRule(new FileSystemAccessRule(
                    usersSid,
                    FileSystemRights.Modify | FileSystemRights.Synchronize,
                    InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                    PropagationFlags.None,
                    AccessControlType.Allow));
                dInfo.SetAccessControl(dSecurity);
            }
            catch
            {
            }
        }

        public static void ShowToast(string eventRecordId, params string[] lines)
        {
            ShowToast(0, eventRecordId, lines != null ? new List<string>(lines) : new List<string>(), null);
        }

        public static void ShowToast(int eventId, string eventRecordId, List<string> lines, List<ToastButtonItem> buttons = null, string appLogoPath = null, string audioUri = null)
        {
            try
            {
                EnsureAlertDirectories();

                List<string> safeLines = lines ?? new List<string>();
                if (RuleEngine.IsAlertSuppressed(eventId, safeLines))
                {
                    Helper.WriteToLog("Suppressed toast notification (user selected 'Never show this message again'): " + RuleEngine.GetAlertSignature(safeLines));
                    return;
                }

                List<ToastButtonItem> finalButtons = buttons != null && buttons.Count > 0
                    ? new List<ToastButtonItem>(buttons)
                    : ToastActionHandler.BuildDefaultActionButtons(safeLines, RuleEngine.GetAlertSignature(safeLines), eventId);

                ToastActionHandler.EnsureIconsGenerated();
                string effectiveLogo = !string.IsNullOrEmpty(appLogoPath) ? appLogoPath : ToastActionHandler.AppLogoPngPath;
                string effectiveSound = !string.IsNullOrEmpty(audioUri) ? audioUri : ToastActionHandler.DefaultToastSoundUri;

                ToastAlertPayload payload = new ToastAlertPayload
                {
                    EventId = eventId,
                    EventRecordId = eventRecordId ?? "",
                    Lines = safeLines,
                    Buttons = finalButtons,
                    AppLogoPath = effectiveLogo,
                    AudioUri = effectiveSound
                };

                string tempFile = Path.Combine(AlertsDirectory, "tmp_" + Guid.NewGuid().ToString("N") + ".tmp");
                string finalFile = Path.Combine(AlertsDirectory, "alert_" + DateTime.UtcNow.Ticks.ToString("D20") + "_" + Guid.NewGuid().ToString("N") + ".json");

                using (FileStream fs = new FileStream(tempFile, FileMode.Create, FileAccess.Write, FileShare.None))
                {
                    DataContractJsonSerializer serializer = new DataContractJsonSerializer(typeof(ToastAlertPayload));
                    serializer.WriteObject(fs, payload);
                }

                File.Move(tempFile, finalFile);

                // Ensure the user-mode toast agent is running to display the queued alert
                ServiceManager.EnsureUserModeNotifierRunning();
            }
            catch (Exception ex)
            {
                Helper.WriteToLog("Failed to queue toast notification: " + ex.Message, "ERROR");
            }
        }
    }
}
