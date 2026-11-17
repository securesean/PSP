using Microsoft.Toolkit.Uwp.Notifications;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Json;
using System.Security.Cryptography;
using System.Text;
using System.Threading;

namespace PSP_Notifier
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

    class Program
    {
        private static readonly string BasePath = Environment.GetEnvironmentVariable("PROGRAMDATA") + "\\PSP_Logs";
        private static readonly string AlertsPath = BasePath + "\\Alerts";
        private static readonly object LogLock = new object();

        static void Main(string[] args)
        {
            AppDomain.CurrentDomain.UnhandledException += (sender, e) =>
            {
                WriteNotifierLog("[CRASH] UnhandledException (IsTerminating=" + e.IsTerminating + "): " + e.ExceptionObject);
            };

            bool processOnce = false;
            foreach (string arg in args)
            {
                if (arg.Equals("--process-once", StringComparison.OrdinalIgnoreCase))
                {
                    processOnce = true;
                }
            }

            try
            {
                if (!Directory.Exists(BasePath))
                    Directory.CreateDirectory(BasePath);
                if (!Directory.Exists(AlertsPath))
                    Directory.CreateDirectory(AlertsPath);
            }
            catch
            {
            }

            ToastNotificationManagerCompat.OnActivated += OnToastActivated;

            if (processOnce)
            {
                ProcessPendingAlerts();
                return;
            }

            bool createdNew;
            using (Mutex mutex = new Mutex(true, @"Local\PSP_Notifier_Singleton", out createdNew))
            {
                if (!createdNew)
                {
                    // Another instance is already running in this user session; process pending and exit
                    ProcessPendingAlerts();
                    return;
                }

                WriteNotifierLog("PSP_Notifier user-mode agent started in session " + Process.GetCurrentProcess().SessionId);

                FileSystemWatcher watcher = null;
                try
                {
                    watcher = new FileSystemWatcher(AlertsPath, "*.json");
                    watcher.NotifyFilter = NotifyFilters.FileName | NotifyFilters.CreationTime | NotifyFilters.LastWrite;
                    watcher.Created += (s, e) => ProcessPendingAlerts();
                    watcher.EnableRaisingEvents = true;
                }
                catch (Exception ex)
                {
                    WriteNotifierLog("Failed to initialize FileSystemWatcher: " + ex.Message);
                }

                while (true)
                {
                    ProcessPendingAlerts();
                    Thread.Sleep(1000);
                }
            }
        }

        private static void OnToastActivated(ToastNotificationActivatedEventArgsCompat toastArgs)
        {
            try
            {
                WriteNotifierLog("Toast activated with arguments: " + toastArgs.Argument);
                ToastArguments parsed = ToastArguments.Parse(toastArgs.Argument);

                if (parsed.Contains("action"))
                {
                    // Write action request for service or handle user-mode action
                    string actionFile = Path.Combine(AlertsPath, "action_" + Guid.NewGuid().ToString("N") + ".cmd");
                    File.WriteAllText(actionFile, toastArgs.Argument, Encoding.UTF8);

                    if (parsed["action"].Equals("suppress", StringComparison.OrdinalIgnoreCase) && parsed.Contains("signature"))
                    {
                        string sig = Uri.UnescapeDataString(parsed["signature"]);
                        string suppressedFile = Path.Combine(BasePath, "suppressed_alerts.txt");
                        File.AppendAllText(suppressedFile, sig + Environment.NewLine, Encoding.UTF8);
                        WriteNotifierLog("Suppressed future alerts matching signature: " + sig);
                    }
                    else if (parsed["action"].Equals("check_vt", StringComparison.OrdinalIgnoreCase) && parsed.Contains("path"))
                    {
                        string filePath = Uri.UnescapeDataString(parsed["path"]).Trim('"');
                        if (File.Exists(filePath))
                        {
                            string sha256 = ComputeSha256(filePath);
                            string vtUrl = "https://www.virustotal.com/gui/file/" + sha256;
                            Process.Start(new ProcessStartInfo(vtUrl) { UseShellExecute = true });
                            string desktopPath = Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);
                            string destPath = Path.Combine(desktopPath, Path.GetFileName(filePath));
                            try { File.Copy(filePath, destPath, true); } catch { }
                            WriteNotifierLog("Opened VirusTotal in user session for " + filePath + " (" + sha256 + ")");
                        }
                    }
                    else if (parsed["action"].Equals("autoruns", StringComparison.OrdinalIgnoreCase))
                    {
                        string autorunsExe = Path.Combine(BasePath, "Tools", "Autoruns", Environment.Is64BitOperatingSystem ? "Autoruns64.exe" : "Autoruns.exe");
                        if (File.Exists(autorunsExe))
                        {
                            Process.Start(new ProcessStartInfo(autorunsExe) { UseShellExecute = true });
                        }
                    }
                }

                string eventRecordId = null;
                if (parsed.Contains("conversationId"))
                {
                    eventRecordId = parsed["conversationId"];
                }
                else if (toastArgs.Argument != null && toastArgs.Argument.StartsWith("conversationId="))
                {
                    eventRecordId = toastArgs.Argument.Substring(15);
                }

                if (!string.IsNullOrEmpty(eventRecordId))
                {
                    string xmlPath = Path.Combine(BasePath, eventRecordId + ".xml");
                    if (File.Exists(xmlPath))
                    {
                        ProcessStartInfo startInfo = new ProcessStartInfo(xmlPath)
                        {
                            UseShellExecute = true,
                            Verb = "open"
                        };
                        Process.Start(startInfo);
                    }
                    else
                    {
                        WriteNotifierLog("XML file not found for record ID: " + xmlPath);
                    }
                }
            }
            catch (Exception ex)
            {
                WriteNotifierLog("Error handling toast activation: " + ex.Message);
            }
        }

        private static readonly object ProcessLock = new object();

        private static void ProcessPendingAlerts()
        {
            if (!Monitor.TryEnter(ProcessLock))
                return;

            try
            {
                if (!Directory.Exists(AlertsPath))
                    return;

                string[] files = Directory.GetFiles(AlertsPath, "alert_*.json");
                Array.Sort(files, StringComparer.OrdinalIgnoreCase);

                foreach (string file in files)
                {
                    try
                    {
                        byte[] bytes = File.ReadAllBytes(file);
                        ToastAlertPayload payload;
                        using (MemoryStream ms = new MemoryStream(bytes))
                        {
                            DataContractJsonSerializer serializer = new DataContractJsonSerializer(typeof(ToastAlertPayload));
                            payload = (ToastAlertPayload)serializer.ReadObject(ms);
                        }

                        File.Delete(file);

                        if (payload != null)
                        {
                            DisplayToast(payload);
                        }
                    }
                    catch (IOException)
                    {
                        // File may still be being written; retry on next poll
                    }
                    catch (Exception ex)
                    {
                        WriteNotifierLog("Error processing alert file " + file + ": " + ex.Message);
                        try { File.Delete(file); } catch { }
                    }
                }
            }
            catch (Exception ex)
            {
                WriteNotifierLog("Error enumerating alerts directory: " + ex.Message);
            }
            finally
            {
                Monitor.Exit(ProcessLock);
            }
        }

        private static void DisplayToast(ToastAlertPayload payload)
        {
            try
            {
                ToastContentBuilder toast = new ToastContentBuilder();
                if (!string.IsNullOrEmpty(payload.EventRecordId))
                {
                    toast.AddArgument("conversationId", payload.EventRecordId);
                }

                if (payload.Lines != null)
                {
                    foreach (string line in payload.Lines)
                    {
                        if (!string.IsNullOrEmpty(line))
                        {
                            toast.AddText(line);
                        }
                    }
                }

                if (!string.IsNullOrEmpty(payload.AppLogoPath) && File.Exists(payload.AppLogoPath))
                {
                    toast.AddAppLogoOverride(new Uri(payload.AppLogoPath), ToastGenericAppLogoCrop.Default);
                }

                if (!string.IsNullOrEmpty(payload.AudioUri))
                {
                    try
                    {
                        toast.AddAudio(new Uri(payload.AudioUri));
                    }
                    catch
                    {
                    }
                }

                List<string> buttonLabels = new List<string>();
                if (payload.Buttons != null)
                {
                    foreach (ToastButtonItem btn in payload.Buttons)
                    {
                        if (btn != null && !string.IsNullOrEmpty(btn.Content) && !string.IsNullOrEmpty(btn.Arguments))
                        {
                            buttonLabels.Add(btn.Content);
                            var toastBtn = new ToastButton(btn.Content, btn.Arguments);
                            if (!string.IsNullOrEmpty(btn.IconUri))
                            {
                                toastBtn.SetImageUri(new Uri(btn.IconUri));
                            }
                            toast.AddButton(toastBtn);
                        }
                    }
                }

                string firstLine = (payload.Lines != null && payload.Lines.Count > 0) ? payload.Lines[0] : "(no text)";
                string btnInfo = buttonLabels.Count > 0 ? " [Buttons: " + string.Join(", ", buttonLabels) + "]" : "";
                WriteNotifierLog("Displaying toast [Record=" + payload.EventRecordId + "]: " + firstLine + btnInfo);

                toast.Show();
            }
            catch (Exception ex)
            {
                WriteNotifierLog("Failed to display toast notification: " + ex.Message);
            }
        }

        private static string ComputeSha256(string filePath)
        {
            using (FileStream fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
            using (SHA256 sha = SHA256.Create())
            {
                byte[] hash = sha.ComputeHash(fs);
                StringBuilder sb = new StringBuilder(hash.Length * 2);
                foreach (byte b in hash)
                {
                    sb.Append(b.ToString("x2"));
                }
                return sb.ToString();
            }
        }

        private static void WriteNotifierLog(string message)
        {
            try
            {
                string logFile = Path.Combine(BasePath, "PSP_Notifier_Log_" + DateTime.Now.Date.ToShortDateString().Replace('/', '_') + ".txt");
                string line = "[Notifier] " + DateTime.Now.ToString("HH:mm:ss") + ": " + message;
                lock (LogLock)
                {
                    File.AppendAllText(logFile, line + Environment.NewLine);
                }
            }
            catch
            {
            }
        }
    }
}
