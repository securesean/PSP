using Microsoft.Win32;
using System;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.ServiceProcess;

namespace PSP_Console
{
    public static class ServiceManager
    {
        private const string RunRegistryPath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
        private const string RunValueName = "PSP_Notifier";

        public static string GetConsoleExePath()
        {
            return Assembly.GetExecutingAssembly().Location;
        }

        public static string GetNotifierExePath()
        {
            string baseDir = Path.GetDirectoryName(GetConsoleExePath());
            return Path.Combine(baseDir, "PSP_Notifier.exe");
        }

        public static bool InstallService()
        {
            try
            {
                ToastHelper.EnsureAlertDirectories();

                string exePath = GetConsoleExePath();
                string notifierPath = GetNotifierExePath();

                Helper.WriteToLog("Installing Windows Service '" + PSPService.ServiceNameConst + "'...");
                Helper.WriteToLog("Service executable: " + exePath);
                Helper.WriteToLog("User-mode notifier executable: " + notifierPath);

                // If service already exists, stop and delete it first so binPath updates cleanly
                if (IsServiceInstalled())
                {
                    Helper.WriteToLog("Existing service found. Stopping and updating configuration...");
                    RunScCommand("stop " + PSPService.ServiceNameConst);
                    System.Threading.Thread.Sleep(1500);
                    RunScCommand("delete " + PSPService.ServiceNameConst);
                    System.Threading.Thread.Sleep(1000);
                }

                string binPathArg = "\\\"" + exePath + "\\\" --service";
                string createOutput = RunScCommand("create " + PSPService.ServiceNameConst + " binPath= \"" + binPathArg + "\" start= auto DisplayName= \"" + PSPService.DisplayNameConst + "\"");
                Helper.WriteToLog("sc create: " + createOutput.Trim(), "OUTPUT");

                RunScCommand("description " + PSPService.ServiceNameConst + " \"Personal Security Product - Monitors Windows Security Event Logs and alerts on suspicious activity.\"");

                // Register user-mode toast agent in HKLM Run so it starts on logon for interactive users
                if (File.Exists(notifierPath))
                {
                    using (RegistryKey key = Registry.LocalMachine.OpenSubKey(RunRegistryPath, true))
                    {
                        if (key != null)
                        {
                            key.SetValue(RunValueName, "\"" + notifierPath + "\"", RegistryValueKind.String);
                            Helper.WriteToLog("Registered user-mode toast agent in HKLM\\" + RunRegistryPath + " -> " + notifierPath, "OUTPUT");
                        }
                    }
                }
                else
                {
                    Helper.WriteToLog("Warning: PSP_Notifier.exe was not found at " + notifierPath, "ERROR");
                }

                // Start the user-mode notifier right away
                EnsureUserModeNotifierRunning();

                // Start the Windows Service
                string startOutput = RunScCommand("start " + PSPService.ServiceNameConst);
                Helper.WriteToLog("sc start: " + startOutput.Trim(), "OUTPUT");

                return IsServiceInstalled();
            }
            catch (Exception ex)
            {
                Helper.WriteToLog("Failed to install service: " + ex.Message, "ERROR");
                return false;
            }
        }

        public static bool UninstallService()
        {
            try
            {
                Helper.WriteToLog("Uninstalling Windows Service '" + PSPService.ServiceNameConst + "'...");

                if (IsServiceInstalled())
                {
                    string stopOutput = RunScCommand("stop " + PSPService.ServiceNameConst);
                    Helper.WriteToLog("sc stop: " + stopOutput.Trim());
                    System.Threading.Thread.Sleep(1500);

                    string deleteOutput = RunScCommand("delete " + PSPService.ServiceNameConst);
                    Helper.WriteToLog("sc delete: " + deleteOutput.Trim(), "OUTPUT");
                }
                else
                {
                    Helper.WriteToLog("Service '" + PSPService.ServiceNameConst + "' is not currently installed.");
                }

                // Remove HKLM Run entry
                using (RegistryKey key = Registry.LocalMachine.OpenSubKey(RunRegistryPath, true))
                {
                    if (key != null && key.GetValue(RunValueName) != null)
                    {
                        key.DeleteValue(RunValueName, false);
                        Helper.WriteToLog("Removed user-mode toast agent from HKLM\\" + RunRegistryPath, "OUTPUT");
                    }
                }

                // Stop running PSP_Notifier processes
                foreach (Process proc in Process.GetProcessesByName("PSP_Notifier"))
                {
                    try
                    {
                        proc.Kill();
                    }
                    catch
                    {
                    }
                }

                return true;
            }
            catch (Exception ex)
            {
                Helper.WriteToLog("Failed to uninstall service: " + ex.Message, "ERROR");
                return false;
            }
        }

        public static bool IsServiceInstalled()
        {
            try
            {
                ServiceController[] services = ServiceController.GetServices();
                foreach (ServiceController service in services)
                {
                    if (string.Equals(service.ServiceName, PSPService.ServiceNameConst, StringComparison.OrdinalIgnoreCase))
                    {
                        return true;
                    }
                }
            }
            catch
            {
            }
            return false;
        }

        private static string RunScCommand(string arguments)
        {
            Process p = new Process();
            p.StartInfo.FileName = "sc.exe";
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

        public static void EnsureUserModeNotifierRunning()
        {
            try
            {
                string notifierPath = GetNotifierExePath();
                if (!File.Exists(notifierPath))
                {
                    return;
                }

                Process[] existing = Process.GetProcessesByName("PSP_Notifier");
                foreach (Process proc in existing)
                {
                    try
                    {
                        if (proc.SessionId > 0 && !proc.HasExited)
                        {
                            return; // Already running in an interactive user session
                        }
                    }
                    catch
                    {
                    }
                }

                if (Environment.UserInteractive && Process.GetCurrentProcess().SessionId > 0)
                {
                    ProcessStartInfo psi = new ProcessStartInfo(notifierPath)
                    {
                        UseShellExecute = false,
                        CreateNoWindow = true,
                        WorkingDirectory = Path.GetDirectoryName(notifierPath)
                    };
                    Process.Start(psi);
                }
                else
                {
                    // Running in Session 0 (Windows Service): spawn PSP_Notifier into active console user session
                    LaunchProcessInActiveUserSession(notifierPath);
                }
            }
            catch (Exception ex)
            {
                Helper.WriteToLog("Could not start user-mode notifier: " + ex.Message, "ERROR");
            }
        }

        #region Win32 Session 0 -> Interactive User Session Process Launch

        [DllImport("kernel32.dll")]
        private static extern uint WTSGetActiveConsoleSessionId();

        [DllImport("wtsapi32.dll", SetLastError = true)]
        private static extern bool WTSQueryUserToken(uint sessionId, out IntPtr Token);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool DuplicateTokenEx(
            IntPtr ExistingTokenHandle,
            uint dwDesiredAccess,
            IntPtr lpThreadAttributes,
            int TokenType,
            int ImpersonationLevel,
            out IntPtr DuplicateTokenHandle);

        [DllImport("userenv.dll", SetLastError = true)]
        private static extern bool CreateEnvironmentBlock(out IntPtr lpEnvironment, IntPtr hToken, bool bInherit);

        [DllImport("userenv.dll", SetLastError = true)]
        private static extern bool DestroyEnvironmentBlock(IntPtr lpEnvironment);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool CreateProcessAsUser(
            IntPtr hToken,
            string lpApplicationName,
            string lpCommandLine,
            IntPtr lpProcessAttributes,
            IntPtr lpThreadAttributes,
            bool bInheritHandles,
            uint dwCreationFlags,
            IntPtr lpEnvironment,
            string lpCurrentDirectory,
            ref STARTUPINFO lpStartupInfo,
            out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hSnapshot);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct STARTUPINFO
        {
            public int cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public int dwX;
            public int dwY;
            public int dwXSize;
            public int dwYSize;
            public int dwXCountChars;
            public int dwYCountChars;
            public int dwFillAttribute;
            public int dwFlags;
            public short wShowWindow;
            public short cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }

        private const uint MAXIMUM_ALLOWED = 0x02000000;
        private const int SecurityIdentification = 1;
        private const int TokenPrimary = 1;
        private const uint CREATE_UNICODE_ENVIRONMENT = 0x00000400;
        private const uint CREATE_NO_WINDOW = 0x08000000;

        private static void LaunchProcessInActiveUserSession(string exePath)
        {
            uint sessionId = WTSGetActiveConsoleSessionId();
            if (sessionId == 0xFFFFFFFF || sessionId == 0)
            {
                return;
            }

            IntPtr userToken = IntPtr.Zero;
            IntPtr primaryToken = IntPtr.Zero;
            IntPtr envBlock = IntPtr.Zero;

            try
            {
                if (!WTSQueryUserToken(sessionId, out userToken))
                {
                    return;
                }

                if (!DuplicateTokenEx(userToken, MAXIMUM_ALLOWED, IntPtr.Zero, SecurityIdentification, TokenPrimary, out primaryToken))
                {
                    return;
                }

                CreateEnvironmentBlock(out envBlock, primaryToken, false);

                STARTUPINFO si = new STARTUPINFO();
                si.cb = Marshal.SizeOf(typeof(STARTUPINFO));
                si.lpDesktop = @"winsta0\default";

                PROCESS_INFORMATION pi;
                uint flags = CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW;
                string cmdLine = "\"" + exePath + "\"";

                if (CreateProcessAsUser(
                    primaryToken,
                    exePath,
                    cmdLine,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    false,
                    flags,
                    envBlock,
                    Path.GetDirectoryName(exePath),
                    ref si,
                    out pi))
                {
                    if (pi.hProcess != IntPtr.Zero) CloseHandle(pi.hProcess);
                    if (pi.hThread != IntPtr.Zero) CloseHandle(pi.hThread);
                    Helper.WriteToLog("Launched PSP_Notifier.exe into active user session " + sessionId + " (PID " + pi.dwProcessId + ")");
                }
            }
            finally
            {
                if (envBlock != IntPtr.Zero) DestroyEnvironmentBlock(envBlock);
                if (primaryToken != IntPtr.Zero) CloseHandle(primaryToken);
                if (userToken != IntPtr.Zero) CloseHandle(userToken);
            }
        }

        #endregion
    }
}
