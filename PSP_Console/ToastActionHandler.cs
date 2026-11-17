using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Drawing.Imaging;
using System.IO;
using System.IO.Compression;
using System.Management;
using System.Net;
using System.Security.Cryptography;
using System.ServiceProcess;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Win32;

namespace PSP_Console
{
    public static class ToastActionHandler
    {
        public static readonly string IconsDirectory = Path.Combine(Helper.path, "Icons");
        public const string DefaultToastSoundUri = "ms-winsoundevent:Notification.Reminder";
        private static bool _iconsInitialized = false;

        public static string AppLogoPngPath => Path.Combine(IconsDirectory, "psp_logo.png");
        public static string BlockIpIconPath => Path.Combine(IconsDirectory, "block_ip.png");
        public static string KillServiceIconPath => Path.Combine(IconsDirectory, "kill_service.png");
        public static string CheckVtIconPath => Path.Combine(IconsDirectory, "check_vt.png");
        public static string AutorunsIconPath => Path.Combine(IconsDirectory, "autoruns.png");
        public static string ResetUserIconPath => Path.Combine(IconsDirectory, "reset_user.png");
        public static string WatchProcIconPath => Path.Combine(IconsDirectory, "watch_proc.png");
        public static string MuteIconPath => Path.Combine(IconsDirectory, "mute.png");

        public static void EnsureIconsGenerated()
        {
            if (_iconsInitialized && File.Exists(AppLogoPngPath))
            {
                return;
            }

            try
            {
                if (!Directory.Exists(IconsDirectory))
                {
                    Directory.CreateDirectory(IconsDirectory);
                }

                // Extract associated application icon to psp_logo.png
                if (!File.Exists(AppLogoPngPath))
                {
                    try
                    {
                        string exePath = ServiceManager.GetConsoleExePath();
                        using (Icon appIcon = Icon.ExtractAssociatedIcon(exePath))
                        {
                            if (appIcon != null)
                            {
                                using (Bitmap bmp = appIcon.ToBitmap())
                                {
                                    bmp.Save(AppLogoPngPath, ImageFormat.Png);
                                }
                            }
                        }
                    }
                    catch
                    {
                        GenerateBadgeIcon(AppLogoPngPath, Color.FromArgb(30, 136, 229), "PSP");
                    }
                }

                GenerateBadgeIcon(BlockIpIconPath, Color.FromArgb(211, 47, 47), "IP");
                GenerateBadgeIcon(KillServiceIconPath, Color.FromArgb(198, 40, 40), "SVC");
                GenerateBadgeIcon(CheckVtIconPath, Color.FromArgb(25, 118, 210), "VT");
                GenerateBadgeIcon(AutorunsIconPath, Color.FromArgb(0, 121, 107), "AR");
                GenerateBadgeIcon(ResetUserIconPath, Color.FromArgb(245, 124, 0), "USR");
                GenerateBadgeIcon(WatchProcIconPath, Color.FromArgb(123, 31, 162), "YARA");
                GenerateBadgeIcon(MuteIconPath, Color.FromArgb(97, 97, 97), "MUTE");

                _iconsInitialized = true;
            }
            catch (Exception ex)
            {
                Helper.WriteToLog("Failed to generate toast icons: " + ex.Message, "ERROR");
            }
        }

        private static void GenerateBadgeIcon(string filePath, Color bgColor, string label)
        {
            if (File.Exists(filePath)) return;

            using (Bitmap bmp = new Bitmap(64, 64))
            using (Graphics g = Graphics.FromImage(bmp))
            {
                g.SmoothingMode = SmoothingMode.AntiAlias;
                g.Clear(Color.Transparent);
                using (Brush brush = new SolidBrush(bgColor))
                {
                    g.FillEllipse(brush, 2, 2, 60, 60);
                }
                using (Font font = new Font("Segoe UI", label.Length <= 2 ? 18 : 13, FontStyle.Bold, GraphicsUnit.Pixel))
                using (Brush textBrush = new SolidBrush(Color.White))
                {
                    SizeF size = g.MeasureString(label, font);
                    g.DrawString(label, font, textBrush, (64 - size.Width) / 2f, (64 - size.Height) / 2f);
                }
                bmp.Save(filePath, ImageFormat.Png);
            }
        }

        public static List<ToastButtonItem> BuildDefaultActionButtons(IList<string> lines, string signature, int eventId)
        {
            EnsureIconsGenerated();
            List<ToastButtonItem> buttons = new List<ToastButtonItem>();
            string combined = lines != null ? string.Join("\n", lines) : "";

            // 1. If IP is in alert (or Port Scan Source IP), add 'Block IP'
            Match ipMatch = Regex.Match(combined, @"Source IP:\s*([^\s(\r\n]+)|\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b");
            if (ipMatch.Success)
            {
                string ip = !string.IsNullOrEmpty(ipMatch.Groups[1].Value) ? ipMatch.Groups[1].Value : ipMatch.Groups[2].Value;
                if (!string.IsNullOrEmpty(ip) && (combined.IndexOf("Port Scan", StringComparison.OrdinalIgnoreCase) >= 0 || Helper.isRemoteIP(ip)))
                {
                    buttons.Add(new ToastButtonItem
                    {
                        Content = "Block IP",
                        Arguments = "action=block_ip&ip=" + Uri.EscapeDataString(ip),
                        IconUri = new Uri(BlockIpIconPath).AbsoluteUri
                    });
                }
            }

            // 2. If ServiceName is in alert, add 'Kill Service'
            Match svcMatch = Regex.Match(combined, @"Service(?:Name)?:\s*([^\r\n(]+)", RegexOptions.IgnoreCase);
            if (svcMatch.Success)
            {
                string svc = svcMatch.Groups[1].Value.Trim();
                if (!string.IsNullOrEmpty(svc) && buttons.Count < 4)
                {
                    buttons.Add(new ToastButtonItem
                    {
                        Content = "Kill: " + svc,
                        Arguments = "action=kill_service&service=" + Uri.EscapeDataString(svc),
                        IconUri = new Uri(KillServiceIconPath).AbsoluteUri
                    });
                }
            }

            // 3. If executable path is in alert, add 'Check VT for Exe' and 'Scan YARA / Watch'
            Match exeMatch = Regex.Match(combined, @"([A-Za-z]:\\[^\r\n""']*?\.(?:exe|dll|sys))", RegexOptions.IgnoreCase);
            if (exeMatch.Success)
            {
                string exePath = exeMatch.Groups[1].Value.Trim();
                if (buttons.Count < 4)
                {
                    buttons.Add(new ToastButtonItem
                    {
                        Content = "VT",
                        Arguments = "action=check_vt&path=" + Uri.EscapeDataString(exePath),
                        IconUri = new Uri(CheckVtIconPath).AbsoluteUri
                    });
                }
                if (buttons.Count < 4)
                {
                    buttons.Add(new ToastButtonItem
                    {
                        Content = "YARA",
                        Arguments = "action=yara_scan&path=" + Uri.EscapeDataString(exePath),
                        IconUri = new Uri(WatchProcIconPath).AbsoluteUri
                    });
                }
            }

            // 4. If user account is in alert, add 'Log off & Reset Pass'
            Match userMatch = Regex.Match(combined, @"(?:User:|local user|account:)\s*(?:[^\\\r\n]+\\)?([A-Za-z0-9_\-\.]+)", RegexOptions.IgnoreCase);
            

            // 5. Add 'Launch Autoruns' if space permits
            if (buttons.Count < 4)
            {
                buttons.Add(new ToastButtonItem
                {
                    Content = "Autoruns",
                    Arguments = "action=autoruns",
                    IconUri = new Uri(AutorunsIconPath).AbsoluteUri
                });
            }

            // 6. Always include 'Never show this again' button (max 5 buttons on Windows Toast)
            if (!string.IsNullOrEmpty(signature) && buttons.Count < 5)
            {
                buttons.Add(new ToastButtonItem
                {
                    Content = "Don't show",
                    Arguments = "action=suppress&signature=" + Uri.EscapeDataString(signature) + "&eventId=" + eventId,
                    IconUri = new Uri(MuteIconPath).AbsoluteUri
                });
            }

            return buttons;
        }

        public static void ExecuteAction(string action, Dictionary<string, string> parameters)
        {
            try
            {
                if (string.Equals(action, "block_ip", StringComparison.OrdinalIgnoreCase) && parameters.ContainsKey("ip"))
                {
                    string ip = parameters["ip"];
                    RunCmd("netsh.exe", "advfirewall firewall add rule name=\"PSP_Blocked_IP_" + ip + "\" dir=in action=block remoteip=" + ip);
                    RunCmd("netsh.exe", "advfirewall firewall add rule name=\"PSP_Blocked_IP_Out_" + ip + "\" dir=out action=block remoteip=" + ip);
                    Helper.WriteToLog("Toast Action Executed: Blocked IP " + ip + " in Windows Firewall.", "OUTPUT");
                }
                else if (string.Equals(action, "kill_service", StringComparison.OrdinalIgnoreCase) && parameters.ContainsKey("service"))
                {
                    string service = parameters["service"];
                    StopAndDisableServiceNative(service);
                }
                else if (string.Equals(action, "check_vt", StringComparison.OrdinalIgnoreCase) && parameters.ContainsKey("path"))
                {
                    string filePath = parameters["path"];
                    if (File.Exists(filePath))
                    {
                        string sha256 = ComputeSha256(filePath);
                        string vtUrl = "https://www.virustotal.com/gui/file/" + sha256;
                        Helper.WriteToLog("Toast Action Executed: Computed SHA-256 for " + filePath + " = " + sha256 + " -> " + vtUrl, "OUTPUT");
                        // Open the VT URL in the default browser
                        Process.Start(new ProcessStartInfo(vtUrl) { UseShellExecute = true });

                        // copy file to desktop for upload to VT if user wants to do manual upload, then notify user
                        string desktopPath = Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);
                        string destPath = Path.Combine(desktopPath, Path.GetFileName(filePath));
                        File.Copy(filePath, destPath, true);
                        Helper.WriteToLog("Copied file to Desktop for manual upload to VT: " + destPath, "OUTPUT");
                    } else
                    {
                        Helper.WriteToLog("Toast Action Executed: File not found for VT check: " + filePath, "ERROR");
                    }
                }
                else if (string.Equals(action, "yara_scan", StringComparison.OrdinalIgnoreCase) && parameters.ContainsKey("path"))
                {
                    string filePath = parameters["path"];
                    PerformBasicYaraAndProcessWatch(filePath);
                }
                else if (string.Equals(action, "reset_user", StringComparison.OrdinalIgnoreCase) && parameters.ContainsKey("user"))
                {
                    string user = parameters["user"];
                    string newPass = "PspReset!" + Guid.NewGuid().ToString("N").Substring(0, 12);
                    RunCmd("net.exe", "user \"" + user + "\" \"" + newPass + "\"");
                    Helper.WriteToLog("Toast Action Executed: Reset password for user '" + user + "'.", "OUTPUT");
                }
                else if (string.Equals(action, "autoruns", StringComparison.OrdinalIgnoreCase))
                {
                    LaunchOrDownloadAutoruns();
                }
            }
            catch (Exception ex)
            {
                Helper.LogCrash("ToastActionHandler.ExecuteAction (" + action + ")", ex);
            }
        }

        public static void StopAndDisableServiceNative(string serviceIdentifier)
        {
            string resolvedName = serviceIdentifier != null ? serviceIdentifier.Trim() : "";
            string stopResult = "Not attempted";
            string disableResult = "Not attempted";
            bool overallSuccess = false;

            try
            {
                if (string.IsNullOrEmpty(resolvedName))
                {
                    throw new ArgumentException("Service name was empty.");
                }

                // 1. Locate service by ServiceName or DisplayName via native ServiceController
                ServiceController targetService = null;
                foreach (ServiceController sc in ServiceController.GetServices())
                {
                    if (string.Equals(sc.ServiceName, resolvedName, StringComparison.OrdinalIgnoreCase) ||
                        string.Equals(sc.DisplayName, resolvedName, StringComparison.OrdinalIgnoreCase))
                    {
                        targetService = sc;
                        resolvedName = sc.ServiceName;
                        break;
                    }
                }

                if (targetService == null)
                {
                    stopResult = "Service not found";
                    disableResult = "Service not found";
                    Helper.WriteToLog("StopAndDisableServiceNative: Service '" + serviceIdentifier + "' was not found.", "ERROR");
                }
                else
                {
                    using (targetService)
                    {
                        // 2. Stop the service using ServiceController
                        try
                        {
                            targetService.Refresh();
                            if (targetService.Status == ServiceControllerStatus.Stopped)
                            {
                                stopResult = "Already Stopped";
                            }
                            else
                            {
                                if (targetService.Status != ServiceControllerStatus.StopPending)
                                {
                                    targetService.Stop();
                                }
                                targetService.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(15));
                                stopResult = "Stopped (" + targetService.Status + ")";
                            }
                        }
                        catch (Exception stopEx)
                        {
                            stopResult = "Stop failed: " + stopEx.Message;
                            Helper.WriteToLog("Failed to stop service '" + resolvedName + "': " + stopEx.Message, "ERROR");
                        }

                        // 3. Disable the service using native WMI (Win32_Service.ChangeStartMode) and Registry fallback
                        try
                        {
                            uint wmiReturn = 1;
                            using (ManagementObject wmiService = new ManagementObject("Win32_Service.Name='" + resolvedName.Replace("'", "\\'") + "'"))
                            {
                                wmiService.Get();
                                object resultObj = wmiService.InvokeMethod("ChangeStartMode", new object[] { "Disabled" });
                                if (resultObj != null)
                                {
                                    wmiReturn = Convert.ToUInt32(resultObj);
                                }
                            }

                            using (RegistryKey svcKey = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\" + resolvedName, true))
                            {
                                if (svcKey != null)
                                {
                                    svcKey.SetValue("Start", 4, RegistryValueKind.DWord); // 4 = SERVICE_DISABLED
                                }
                            }

                            disableResult = wmiReturn == 0 ? "Disabled" : "Disabled via Registry (WMI code " + wmiReturn + ")";
                            overallSuccess = stopResult.StartsWith("Stopped", StringComparison.OrdinalIgnoreCase) ||
                                             stopResult.StartsWith("Already Stopped", StringComparison.OrdinalIgnoreCase);
                        }
                        catch (Exception disableEx)
                        {
                            disableResult = "Disable failed: " + disableEx.Message;
                            Helper.WriteToLog("Failed to disable service '" + resolvedName + "': " + disableEx.Message, "ERROR");
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                stopResult = "Error: " + ex.Message;
                Helper.WriteToLog("Exception in StopAndDisableServiceNative('" + serviceIdentifier + "'): " + ex.Message, "ERROR");
            }

            string title = overallSuccess
                ? "Service Stopped & Disabled: " + resolvedName
                : "Kill Service Outcome: " + resolvedName;

            Helper.WriteToLog(title + " | Stop: " + stopResult + " | Startup: " + disableResult, overallSuccess ? "OUTPUT" : "ERROR");

            ToastHelper.ShowToast(
                0,
                DateTime.UtcNow.Ticks.ToString(),
                new List<string>
                {
                    title,
                    "Stop Status: " + stopResult,
                    "Startup Mode: " + disableResult
                },
                new List<ToastButtonItem>
                {
                    new ToastButtonItem
                    {
                        Content = "Don't show",
                        Arguments = "action=suppress&signature=" + Uri.EscapeDataString(title) + "&eventId=0",
                        IconUri = File.Exists(MuteIconPath) ? new Uri(MuteIconPath).AbsoluteUri : null
                    }
                });
        }

        public static string ComputeSha256(string filePath)
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

        private static void PerformBasicYaraAndProcessWatch(string filePath)
        {
            if (!File.Exists(filePath))
            {
                Helper.WriteToLog("YARA Scan target file not found: " + filePath, "ERROR");
                return;
            }
            string content = Encoding.ASCII.GetString(File.ReadAllBytes(filePath));
            string[] yaraPatterns = new[] { "mimikatz", "sekurlsa", "amsiInitFailed", "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "ReflectiveLoader", "powershell" };
            List<string> hits = new List<string>();
            foreach (string pat in yaraPatterns)
            {
                if (content.IndexOf(pat, StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    hits.Add(pat);
                }
            }
            Helper.WriteToLog("YARA Signature Scan on '" + filePath + "': " + (hits.Count > 0 ? "MATCHED: " + string.Join(", ", hits) : "No built-in YARA strings matched."), "OUTPUT");
        }

        public static string LaunchOrDownloadAutoruns()
        {
            try
            {
                string toolsDir = Path.Combine(Helper.path, "Tools", "Autoruns");
                if (!Directory.Exists(toolsDir))
                {
                    Directory.CreateDirectory(toolsDir);
                }
                string zipPath = Path.Combine(toolsDir, "Autoruns.zip");
                string exePath = Path.Combine(toolsDir, Environment.Is64BitOperatingSystem ? "Autoruns64.exe" : "Autoruns.exe");

                if (!File.Exists(exePath))
                {
                    Helper.WriteToLog("Downloading Sysinternals Autoruns from Microsoft...", "OUTPUT");
                    ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
                    using (WebClient wc = new WebClient())
                    {
                        wc.DownloadFile("https://download.sysinternals.com/files/Autoruns.zip", zipPath);
                        Helper.WriteToLog("Autoruns downloaded to: " + zipPath, "OUTPUT");
                    }
                    ZipFile.ExtractToDirectory(zipPath, toolsDir);
                    Helper.WriteToLog("Autoruns downloaded and extracted to: " + toolsDir, "OUTPUT");
                }

                if (File.Exists(exePath))
                {
                    Helper.WriteToLog("Autoruns available at: " + exePath, "OUTPUT");
                    if (Environment.UserInteractive)
                    {
                        Process.Start(new ProcessStartInfo(exePath) { UseShellExecute = true });
                    }
                    return exePath;
                } else {
                    Helper.WriteToLog("Autoruns executable not found after extraction.", "ERROR");
                }
            }
            catch (Exception ex)
            {
                Helper.WriteToLog("Failed to download/launch Autoruns: " + ex.Message, "ERROR");
            }
            return null;
        }

        private static string RunCmd(string fileName, string args)
        {
            Helper.WriteToLog("Executing command: " + fileName + " " + args, "OUTPUT");
            Process p = new Process();
            p.StartInfo.FileName = fileName;
            p.StartInfo.Arguments = args;
            p.StartInfo.UseShellExecute = false;
            p.StartInfo.RedirectStandardOutput = true;
            p.StartInfo.RedirectStandardError = true;
            p.StartInfo.CreateNoWindow = true;
            p.Start();
            string output = p.StandardOutput.ReadToEnd() + p.StandardError.ReadToEnd();
            p.WaitForExit(10000);
            Helper.WriteToLog("Executed command: " + fileName + " " + args + "\nOutput:\n" + output, "OUTPUT");
            return output;
        }
    }
}
