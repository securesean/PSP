using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.ServiceProcess;
using System.Threading;

/*
 * Sean Pierce
 * Started: Dec 2021
 * Personal Security Product
 * I wrote this while I was home sick so I'm sorry for the typo's, bad structure, and dumb logic
 * */
namespace PSP_Console
{
    class Program
    {
        static EventProcessor eventProcessor;
        static PortScanDetector portScanDetector;
        static MultiChannelEventMonitor multiChannelMonitor;
        static SystemStateMonitor systemStateMonitor;
        static SelfPerformanceMonitor selfPerformanceMonitor;
        private static bool testMode = false;
        private static bool serviceMode = false;
        private static bool noWait = false;
        private static List<int> supportedEventIDList = new List<int>();

        static void Main(string[] args)
        {
            Helper.RegisterGlobalCrashHandlers("PSP_Console");
            try
            {
                RunMain(args);
            }
            catch (Exception ex)
            {
                Helper.LogCrash("PSP_Console.Main Fatal Crash", ex);
                throw;
            }
        }

        private static void RunMain(string[] args)
        {
            bool doInstall = false;
            bool doUninstall = false;
            bool doSecurityEval = false;
            bool doLockdown = false;
            bool doAutoruns = false;

            foreach (string arg in args)
            {
                string lower = arg.ToLower();
                if (lower == "-h" || lower == "--help")
                {
                    printBanner();
                    return;
                }
                if (lower == "-license" || lower == "--license" || lower == "-eula" || lower == "--eula")
                {
                    LicenseManager.DisplayLicense();
                    return;
                }
                if (lower == "-sysmon" || lower == "--sysmon" || lower == "--install-sysmon")
                {
                    SystemStateMonitor.EnsureSysmonInstalled();
                    return;
                }
                if (lower == "-securityevaluation" || lower == "--securityevaluation" || lower == "--security-evaluation")
                {
                    doSecurityEval = true;
                }
                if (lower == "-lockdown" || lower == "--lockdown")
                {
                    doLockdown = true;
                }
                if (lower == "-autoruns" || lower == "--autoruns")
                {
                    doAutoruns = true;
                }
                if (lower == "-t" || lower == "--test")
                {
                    testMode = true;
                }
                if (lower == "-install" || lower == "--install")
                {
                    doInstall = true;
                }
                if (lower == "-uninstall" || lower == "--uninstall")
                {
                    doUninstall = true;
                }
                if (lower == "-service" || lower == "--service")
                {
                    serviceMode = true;
                }
                if (lower == "-nowait" || lower == "--no-wait")
                {
                    noWait = true;
                }
            }

            if (doSecurityEval)
            {
                SecurityEvaluator.RunSecurityEvaluation(doAutoruns);
                return;
            }

            if (doAutoruns)
            {
                ToastActionHandler.LaunchOrDownloadAutoruns();
                return;
            }

            if (doLockdown)
            {
                using (ManualResetEvent waitEvent = new ManualResetEvent(noWait))
                {
                    SecurityEvaluator.RunLockdownMode(waitEvent);
                }
                return;
            }

            if (doInstall)
            {
                ServiceManager.InstallService();
                return;
            }

            if (doUninstall)
            {
                ServiceManager.UninstallService();
                return;
            }

            if (serviceMode || (!Environment.UserInteractive && args.Length == 0))
            {
                ServiceBase.Run(new PSPService());
                return;
            }

            ToastHelper.EnsureAlertDirectories();
            LicenseManager.EnsureFirstRunLicenseShown();
            ServiceManager.EnsureUserModeNotifierRunning();
            if (!testMode)
            {
                AuditPolicyManager.EnsureRecommendedAuditPolicies();
            }

            eventProcessor = new EventProcessor();
            eventProcessor.TestMode = testMode;

            Helper.WriteToLog("Initiallizing EventProcessor. Starting Security Event Subscription");
            subscribe();

            if (!noWait && !Console.IsInputRedirected)
            {
                Helper.WriteToLog("Press Any key to exit");
                Console.ReadKey();
            }
        }

        private static void printBanner()
        {
            string help = "Supported parameters:\n" +
                          "  -install / --install        Install PSP as a Windows Service and register the user-mode toast notifier\n" +
                          "  -uninstall / --uninstall    Remove the PSP Windows Service and user-mode toast notifier\n" +
                          "  -SecurityEvaluation         Audit WinRM/RDP/SMB/SSH, Guest & Admin accounts, LocalAccountTokenFilterPolicy,\n" +
                          "                              recursive Admin/Remote groups, weird services, listening ports, and AuditPol\n" +
                          "  -Lockdown                   Stop WinRM/LanMan/RDP/SSH and listen on their ports to block & alert on connections\n" +
                          "  -sysmon                     Download and install Sysinternals Sysmon if not already running\n" +
                          "  -autoruns                   Download and launch Sysinternals Autoruns\n" +
                          "  -t / --test                 Trigger self-test security events to verify end-to-end functionality\n" +
                          "  -license / --eula           Display Basic License and End-User License Agreement (EULA)\n" +
                          "  -h / --help                 Show this help message";
            Console.WriteLine(help);
            Helper.WriteToLog(help);
        }

        public static void RunServiceSubscription(ManualResetEvent stopEvent)
        {
            AuditPolicyManager.EnsureRecommendedAuditPolicies();
            eventProcessor = new EventProcessor();
            eventProcessor.TestMode = false;
            Helper.WriteToLog("Initializing EventProcessor in Windows Service mode. Starting Security Event Subscription");
            subscribe(stopEvent);
        }

        public static void subscribe(ManualResetEvent stopEvent = null)
        {
            EventLogWatcher SecurityWatcher = null;
            EventLogWatcher SecurityAuditingWatcher = null;
            try
            {
                // If the query is too board and is slowing the system down too much then I could probably improve performance 
                // by scoping down the query: https://docs.microsoft.com/en-us/previous-versions/bb671202(v=vs.90)?redirectedfrom=MSDN
                EventLogQuery securityQuery = new EventLogQuery("Security", PathType.LogName,
                "*[System[" +
                // Logon success/failed
                "EventID=4624 or EventID=4625 or " +
                // User Logged on with creds
                "EventID=4648 or " +

                // Cleared Log
                "EventID=1102 or " +

                // User Group Enumerated - will probably remove this
                "EventID=4798 or EventID=4799 or " +

                // User Created
                // This is a great resource: https://ebookreading.net/view/book/EB9781119390640_12.html
                "EventID=4720 or " +
                "EventID=4722 or " + // 'user account was enabled"
                "EventID=4732 or " + // 'user was added to a local group - look for Admin Group SID"

                // User Deleted
                "EventID=4726 or " +

                // User Password Reset
                "EventID=4724 or " +

                // Security System Extention
                "EventID=4697 or " +    // Server Installed
                "EventID=4610 or EventID=4611 or EventID=4614 or EventID=4622" +    // Lsass Stuff

                "]]");

                supportedEventIDList.Clear();
                supportedEventIDList.Add(4624);
                supportedEventIDList.Add(4625);
                supportedEventIDList.Add(4648);
                supportedEventIDList.Add(1102);
                supportedEventIDList.Add(4798);
                supportedEventIDList.Add(4799);
                supportedEventIDList.Add(4720);
                supportedEventIDList.Add(4722);
                supportedEventIDList.Add(4732);
                supportedEventIDList.Add(4726);
                supportedEventIDList.Add(4724);
                supportedEventIDList.Add(4697);
                supportedEventIDList.Add(4610);
                supportedEventIDList.Add(4611);
                supportedEventIDList.Add(4614);
                supportedEventIDList.Add(4622);

                SecurityWatcher = new EventLogWatcher(securityQuery);
                SecurityWatcher.EventRecordWritten += new EventHandler<EventRecordWrittenEventArgs>(EventLogEventRead);
                SecurityWatcher.Enabled = true;

                portScanDetector = new PortScanDetector(new[] { 80, 443, 22 });
                portScanDetector.Start();

                multiChannelMonitor = new MultiChannelEventMonitor();
                multiChannelMonitor.Start();

                systemStateMonitor = new SystemStateMonitor();
                systemStateMonitor.Start();

                selfPerformanceMonitor = new SelfPerformanceMonitor(eventProcessor);
                selfPerformanceMonitor.Start();

                Helper.WriteToLog("Subscribed");
                while (stopEvent == null || !stopEvent.WaitOne(1000))
                {
                    if (testMode)
                    {
                        portScanDetector.TriggerSelfTestConnection();

                        // Natively Supported Events
                        eventProcessor.trigger_process4624_LogonSuccess();
                        eventProcessor.trigger_process4625_LogonFailed();
                        eventProcessor.trigger_process1102_SecuritytLogCleared();
                        eventProcessor.trigger_process4798_LocalGroupEnum();
                        eventProcessor.trigger_process4799_SecurityGroupEnum();
                        eventProcessor.trigger_process4726_UserDeleted();
                        eventProcessor.trigger_process4720_UserCreated();
                        eventProcessor.trigger_process4722_UserEnabled();
                        eventProcessor.trigger_process4732_UserAddedToGroup();
                        eventProcessor.trigger_process4648_UserLogonWithCreds();
                        eventProcessor.trigger_process4724_PasswordReset();

                        // Events supported by "Security System Extension"
                        eventProcessor.trigger_process4697_ServiceInstalled();
                        eventProcessor.trigger_process4622_LsassLoadedPackage();
                        eventProcessor.trigger_process4614_NotifcationPackageLoaded();
                        eventProcessor.trigger_process4611_LsassLogon();
                        eventProcessor.trigger_process4610_LsassLoadedAuthPackage();

                        // Wait for events to roll in
                        System.Threading.Thread.Sleep(5000);

                        List<int> missingEventIDs = new List<int>();
                        foreach (int eventID in supportedEventIDList)
                        {
                            if (!eventProcessor.TestTriggeredEventIDs.Contains(eventID))
                            {
                                missingEventIDs.Add(eventID);
                            }
                        }

                        if (missingEventIDs.Count > 0)
                        {
                            Helper.WriteToLog("Detected missing events during self-test. Attempting to automatically enable required Windows Audit Policies...", "OUTPUT");
                            HashSet<string> enabledPolicies = AuditPolicyManager.EnableAuditPoliciesForEvents(missingEventIDs);
                            if (enabledPolicies.Count > 0)
                            {
                                Helper.WriteToLog("Re-testing previously unsupported events after enabling Audit Policies...", "TEST");
                                if (missingEventIDs.Contains(4624)) eventProcessor.trigger_process4624_LogonSuccess();
                                if (missingEventIDs.Contains(4625)) eventProcessor.trigger_process4625_LogonFailed();
                                if (missingEventIDs.Contains(4648)) eventProcessor.trigger_process4648_UserLogonWithCreds();
                                if (missingEventIDs.Contains(4697)) eventProcessor.trigger_process4697_ServiceInstalled();
                                if (missingEventIDs.Contains(4720)) eventProcessor.trigger_process4720_UserCreated();
                                if (missingEventIDs.Contains(4722)) eventProcessor.trigger_process4722_UserEnabled();
                                if (missingEventIDs.Contains(4724)) eventProcessor.trigger_process4724_PasswordReset();
                                if (missingEventIDs.Contains(4726)) eventProcessor.trigger_process4726_UserDeleted();
                                if (missingEventIDs.Contains(4732)) eventProcessor.trigger_process4732_UserAddedToGroup();
                                if (missingEventIDs.Contains(4798)) eventProcessor.trigger_process4798_LocalGroupEnum();
                                if (missingEventIDs.Contains(4799)) eventProcessor.trigger_process4799_SecurityGroupEnum();
                                System.Threading.Thread.Sleep(5000);
                            }
                        }

                        foreach (int eventID in supportedEventIDList)
                        {
                            if (eventProcessor.TestTriggeredEventIDs.Contains(eventID))
                            {
                                Helper.WriteToLog("Event Supported " + eventID.ToString(), "OUTPUT");
                            }
                            else
                            {
                                Helper.WriteToLog("Event NOT Supported " + eventID.ToString(), "ERROR");
                            }
                        }

                        if (!noWait && !Console.IsInputRedirected)
                        {
                            Helper.WriteToLog("Press Any key to exit");
                            Console.ReadKey();
                        }
                        return;
                    }

                    if (stopEvent == null)
                    {
                        System.Threading.Thread.Sleep(10000);
                    }
                    else
                    {
                        ServiceManager.EnsureUserModeNotifierRunning();
                    }
                }
            }
            catch (EventLogReadingException e)
            {
                Helper.WriteToLog("Error reading the log: {0}" + e.Message, "ERROR");
            }
            catch (System.UnauthorizedAccessException e)
            {
                Helper.WriteToLog("Error reading the log (Access Denied - Try running as High intrgrity): " + e.Message, "ERROR");
            }
            finally
            {
                if (SecurityWatcher != null)
                {
                    SecurityWatcher.Enabled = false;
                    SecurityWatcher.Dispose();
                }
                if (SecurityAuditingWatcher != null)
                {
                    SecurityAuditingWatcher.Dispose();
                }
                if (selfPerformanceMonitor != null)
                {
                    selfPerformanceMonitor.Stop();
                }
                if (systemStateMonitor != null)
                {
                    systemStateMonitor.Stop();
                }
                if (multiChannelMonitor != null)
                {
                    multiChannelMonitor.Stop();
                }
                if (portScanDetector != null)
                {
                    portScanDetector.Stop();
                }
                if (eventProcessor != null)
                {
                    eventProcessor.Stop();
                }
            }
        }

        // Callback method that gets executed when an event is reported to the subscription.
        public static void EventLogEventRead(object obj, EventRecordWrittenEventArgs eventRecord)
        {
            if (eventRecord.EventRecord == null)
            {
                Helper.WriteToLog("The event instance was null.", "ERROR");
                return;
            }

            switch (eventRecord.EventRecord.Id)
            {
                // Natively Supported Events
                case 4624:
                    eventProcessor.process4624_LogonSuccess(eventRecord);
                    break;
                case 4625:
                    eventProcessor.process4625_LogonFailed(eventRecord);
                    break;
                case 1102:
                    eventProcessor.process1102_SecuritytLogCleared(eventRecord);
                    break;

                // User Related
                case 4798:
                    eventProcessor.process4798_LocalGroupEnum(eventRecord);
                    break;
                case 4799:
                    eventProcessor.process4799_SecurityGroupEnum(eventRecord);
                    break;
                case 4726:
                    eventProcessor.process4726_UserDeleted(eventRecord);
                    break;
                case 4720:
                    eventProcessor.process4720_UserCreated(eventRecord);
                    break;
                case 4722:
                    eventProcessor.process4722_UserEnabled(eventRecord);
                    break;
                case 4732:
                    eventProcessor.process4732_UserAddedToGroup(eventRecord);
                    break;
                case 4648:
                    eventProcessor.process4648_UserLogonWithCreds(eventRecord);
                    break;
                case 4724:
                    eventProcessor.process4724_PasswordReset(eventRecord);
                    break;

                // Events supported by "Security System Extension"
                case 4697:
                    eventProcessor.process4697_ServiceInstalled(eventRecord);
                    break;
                case 4622:
                    eventProcessor.process4622_LsassLoadedPackage(eventRecord);
                    break;
                case 4614:
                    eventProcessor.process4614_NotifcationPackageLoaded(eventRecord);
                    break;
                case 4611:
                    eventProcessor.process4611_LsassLogon(eventRecord);
                    break;
                case 4610:
                    eventProcessor.process4610_LsassLoadedAuthPackage(eventRecord);
                    break;

                default:
                    Helper.WriteToLog("Unsupported Log ID: " + eventRecord.EventRecord.Id, "ERROR");
                    break;
            }
        }
    }
}
