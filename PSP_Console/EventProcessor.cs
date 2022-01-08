using Microsoft.Toolkit.Uwp.Notifications;
using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

// I just made this to hold all the Event processing code so everything wouldn't be all in one big .cs file
namespace PSP_Console
{
    internal class EventProcessor
    {

        /*
         * Test with :
         * PS: Clear-EventLog Security
            cmd: wevtutil.exe cl Security
         * */
        internal static void process1102_SecuritytLogCleared(EventRecordWrittenEventArgs eventRecord)
        {
            String[] xPathArray = new[]
                {
                    "Event/UserData/LogFileCleared/SubjectUserName", // For when it's like <SubjectUserName>Admin</SubjectUserName>
                };

            using (var loginEventPropertySelector = new EventLogPropertySelector(xPathArray))
            {
                try
                {
                    IList<object> logEventProps = ((EventLogRecord)eventRecord.EventRecord).GetPropertyValues(loginEventPropertySelector);
                    Helper.WriteToLog("User who Cleared Security Log: " + logEventProps[0]);

                    Helper.WriteToLog("Description: \n" + eventRecord.EventRecord.FormatDescription());
                    Helper.WriteToLog("Description (XML): \n" + eventRecord.EventRecord.ToXml());



                    // Output to File, Console and Pop-up
                    Helper.WriteToLog("User who Cleared Security Log: " + logEventProps[0], "OUTPUT");

                    /*  ToDo: Test remote clearing of a log via RPC ( I don't even know if that's possible)
                    string ip = logEventProps[6].ToString();
                    string port = logEventProps[7].ToString();
                    if (isRemoteIP(ip))
                    {
                        Helper.WriteToLog("IP Address: " + ip, "OUTPUT");
                        Helper.WriteToLog("IP Port: " + port, "OUTPUT");
                    }
                    */

                    // Toast 
                    // From https://docs.microsoft.com/en-us/windows/apps/design/shell/tiles-and-notifications/adaptive-interactive-toasts?tabs=builder-syntax
                    ToastContentBuilder toast = new ToastContentBuilder()
                    .AddText(logEventProps[0] + " Cleared Security Log!");
                    toast.Show();



                    Helper.WriteToLog("---------------------------------------");

                }
                catch (System.ArgumentOutOfRangeException)
                {
                    Helper.WriteToLog("Tried to print a vaule outside of pre-prescribed XPath Array during Service Install alert", "ERROR");
                }
            }
        }

        // Test with: sc.exe create aService3 start= delayed-auto binpath= C:\a.exe
        public static void process4697_ServiceInstalled(EventRecordWrittenEventArgs eventRecord)
        {
            String[] xPathArray = new[]
                {
                    // (The XPath expression evaluates to null if no Data element exists with the specified name.)
                    "Event/EventData/Data[@Name='SubjectUserName']",
                    "Event/EventData/Data[@Name='ServiceName']",
                    "Event/EventData/Data[@Name='ServiceFileName']",
                };

            using (var loginEventPropertySelector = new EventLogPropertySelector(xPathArray))
            {
                try
                {
                    IList<object> logEventProps = ((EventLogRecord)eventRecord.EventRecord).GetPropertyValues(loginEventPropertySelector);
                    Helper.WriteToLog("User who installed Service: " + logEventProps[0]);
                    Helper.WriteToLog("ServiceName: " + logEventProps[1]);
                    Helper.WriteToLog("ServiceFileName: " + logEventProps[2]);

                    Helper.WriteToLog("Description: \n" + eventRecord.EventRecord.FormatDescription());



                    // Output to File, Console and Pop-up
                    Helper.WriteToLog("User who installed Service: " + logEventProps[0], "OUTPUT");
                    Helper.WriteToLog("ServiceName: " + logEventProps[1], "OUTPUT");
                    Helper.WriteToLog("ServiceFileName: " + logEventProps[2], "OUTPUT");

                    /*  ToDo: Test remove service installation via RPC
                    string ip = logEventProps[6].ToString();
                    string port = logEventProps[7].ToString();
                    if (isRemoteIP(ip))
                    {
                        Helper.WriteToLog("IP Address: " + ip, "OUTPUT");
                        Helper.WriteToLog("IP Port: " + port, "OUTPUT");
                    }
                    */

                    // Toast 
                    // From https://docs.microsoft.com/en-us/windows/apps/design/shell/tiles-and-notifications/adaptive-interactive-toasts?tabs=builder-syntax
                    ToastContentBuilder toast = new ToastContentBuilder()
                    .AddText("Service Installed by " + logEventProps[0])
                    .AddText("ServiceName: " + logEventProps[1])
                    .AddText("ServiceFileName: " + logEventProps[2]);
                    toast.Show();



                    Helper.WriteToLog("---------------------------------------");

                }
                catch (System.ArgumentOutOfRangeException)
                {
                    Helper.WriteToLog("Tried to print a vaule outside of pre-prescribed XPath Array during Service Install alert", "ERROR");
                }
            }
        } // end process4697_ServiceInstalled


        // Test with: runas /user:attacker cmd
        public static void process4625_LogonFailed(EventRecordWrittenEventArgs eventRecord)
        {
            String[] xPathArray = new[]
                {
                    // (The XPath expression evaluates to null if no Data element exists with the specified name.)
                    "Event/EventData/Data[@Name='TargetUserSid']",
                    "Event/EventData/Data[@Name='TargetLogonId']",
                    "Event/EventData/Data[@Name='LogonType']",
                    "Event/EventData/Data[@Name='ElevatedToken']",
                    "Event/EventData/Data[@Name='WorkstationName']",
                    "Event/EventData/Data[@Name='ProcessName']",
                    "Event/EventData/Data[@Name='IpAddress']",
                    "Event/EventData/Data[@Name='IpPort']",
                    "Event/EventData/Data[@Name='TargetDomainName']",   // The attempted domain
                    "Event/EventData/Data[@Name='TargetUserName']",   // The attempted username
                    "Event/EventData/Data[@Name='SubjectUserName']",   // I guess the user that is attempted the auth?
                    "Event/EventData/Data[@Name='SubjectDomainName']",  // WORKGROUP by defaultd
                    "Event/EventData/Data[@Name='AuthenticationPackageName']",  // auth
                    "Event/EventData/Data[@Name='LmPackageName']",  // auth package name
                };

            using (var loginEventPropertySelector = new EventLogPropertySelector(xPathArray))
            {
                try
                {
                    IList<object> logEventProps = ((EventLogRecord)eventRecord.EventRecord).GetPropertyValues(loginEventPropertySelector);
                    Helper.WriteToLog("SID: " + logEventProps[0]);
                    Helper.WriteToLog("Logon Id: " + logEventProps[1]);
                    Helper.WriteToLog("Logon Type: " + logEventProps[2]);
                    Helper.WriteToLog("Elevated Token: " + logEventProps[3]);
                    Helper.WriteToLog("Workstation Name: " + logEventProps[4]);
                    Helper.WriteToLog("Process Name: " + logEventProps[5]);
                    Helper.WriteToLog("IP Address: " + logEventProps[6]);
                    Helper.WriteToLog("IP Port: " + logEventProps[7]);
                    Helper.WriteToLog("Description: \n" + eventRecord.EventRecord.FormatDescription());

                    // Rule logic. TODO: Create a blacklist style JSON config file
                    // See https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventID=4624
                    int logonType = 0;
                    if (int.TryParse(logEventProps[2].ToString(), out logonType))
                    {
                        if (logonType != 5 && logonType != 11 && logonType != 7 && logonType != 2)
                        // Further testing needed but I'll probably want to exclude
                        // 4	Batch (i.e. scheduled task)
                        // 2	Interactive (logon at keyboard and screen of system)
                        {
                            // Output to File, Console and Pop-up
                            Helper.WriteToLog("Logon Failed: ", "OUTPUT");
                            Helper.WriteToLog("Logon Type: " + logEventProps[2], "OUTPUT");
                            Helper.WriteToLog("Username: " + logEventProps[8] + "\\" + logEventProps[9], "OUTPUT");
                            Helper.WriteToLog("Auth: " + logEventProps[12], "OUTPUT");
                            Helper.WriteToLog("Auth Package: " + logEventProps[13], "OUTPUT");

                            string ip = logEventProps[6].ToString();
                            string port = logEventProps[7].ToString();
                            if (Helper.isRemoteIP(ip))
                            {
                                Helper.WriteToLog("IP Address: " + ip, "OUTPUT");
                                Helper.WriteToLog("IP Port: " + port, "OUTPUT");
                            }

                            // Toast 
                            string message = "";
                            // From https://docs.microsoft.com/en-us/windows/apps/design/shell/tiles-and-notifications/adaptive-interactive-toasts?tabs=builder-syntax
                            ToastContentBuilder toast = new ToastContentBuilder()
                            //.AddText("Logon Failed")
                            .AddText("Logon Failed Type: " + logEventProps[2]);

                            message += "Attempted Username: " + logEventProps[8] + "\\" + logEventProps[9];
                            if (Helper.isRemoteIP(ip))
                            {
                                message += "\nAttacker Hostname: " + logEventProps[11] + "\\" + logEventProps[4];
                                message += "\nIP: " + ip;
                            }

                            // This is too many lines that toast will display (Max: 4)
                            if (logEventProps[12].ToString() != "" && logEventProps[12].ToString() != "-")
                            {
                                message += " Auth: " + logEventProps[12];
                            }
                            if (logEventProps[13].ToString() == "" && logEventProps[13].ToString() == "-")
                            {
                                message += " Auth Package: " + logEventProps[13];
                            }
                            toast.AddText(message);
                            toast.Show();
                        }
                    }
                    else
                    {
                        Helper.WriteToLog("Could not parse the Logon Type number: " + logEventProps[2], "ERROR");
                    }

                    Helper.WriteToLog("---------------------------------------");

                }
                catch (System.ArgumentOutOfRangeException)
                {
                    Helper.WriteToLog("Tried to print a vaule outside of pre-prescribed XPath Array", "ERROR");
                }
            }
        } // end process4625_LogonFailed

        // "An Auth Provider was loadead. Malicious ones are Rare but deadly. Possible to make a list of known valid ones"
        internal static void process4610_LsassLoadedAuthPackage(EventRecordWrittenEventArgs eventRecord)
        {
            String[] xPathArray = new[]
                {
                    "Event/EventData/Data[@Name='SubjectUserName']", // Don't know what the structure of the XML is so TODO: fill in later
                };

            using (var loginEventPropertySelector = new EventLogPropertySelector(xPathArray))
            {
                try
                {
                    IList<object> logEventProps = ((EventLogRecord)eventRecord.EventRecord).GetPropertyValues(loginEventPropertySelector);

                    Helper.WriteToLog("Description: \n" + eventRecord.EventRecord.FormatDescription());
                    Helper.WriteToLog("Description (XML): \n" + eventRecord.EventRecord.ToXml());



                    // Output to File, Console and Pop-up
                    Helper.WriteToLog("Dll was given a password due to password reset", "OUTPUT");

                    // Toast 
                    ToastContentBuilder toast = new ToastContentBuilder()
                    .AddText("An Auth Provider was loadead")
                    .AddText("The source probably needs to be added to the known-good list");
                    toast.Show();

                    Helper.WriteToLog("---------------------------------------");

                }
                catch (System.ArgumentOutOfRangeException)
                {
                    Helper.WriteToLog("Tried to print a vaule outside of pre-prescribed XPath Array during Service Install alert", "ERROR");
                }
            }
        }

        // 4611 is logged at startup and occasionally afterwards for each logon process on the system. Possible to make a list of known valid ones
        internal static void process4611_LsassLogon(EventRecordWrittenEventArgs eventRecord)
        {
            String[] xPathArray = new[]
                {
                    "Event/EventData/Data[@Name='SubjectUserName']", // Don't know what the structure of the XML is so TODO: fill in later
                };

            using (var loginEventPropertySelector = new EventLogPropertySelector(xPathArray))
            {
                try
                {
                    IList<object> logEventProps = ((EventLogRecord)eventRecord.EventRecord).GetPropertyValues(loginEventPropertySelector);

                    Helper.WriteToLog("Description: \n" + eventRecord.EventRecord.FormatDescription());
                    Helper.WriteToLog("Description (XML): \n" + eventRecord.EventRecord.ToXml());



                    // Output to File, Console and Pop-up
                    Helper.WriteToLog("Dll was given a password due to password reset", "OUTPUT");

                    // Toast 
                    ToastContentBuilder toast = new ToastContentBuilder()
                    .AddText("Lsass Logged on a Process")
                    .AddText("The source probably needs to be added to the known-good list");
                    toast.Show();

                    Helper.WriteToLog("---------------------------------------");

                }
                catch (System.ArgumentOutOfRangeException)
                {
                    Helper.WriteToLog("Tried to print a vaule outside of pre-prescribed XPath Array during Service Install alert", "ERROR");
                }
            }
        }

        // DLLs that Windows calls into whenenever a user changes his/her password. Malicious ones are Rare but deadly
        internal static void process4614_NotifcationPackageLoaded(EventRecordWrittenEventArgs eventRecord)
        {
            String[] xPathArray = new[]
                {
                    "Event/EventData/Data[@Name='SubjectUserName']", // Don't know what the structure of the XML is so TODO: fill in later
                };

            using (var loginEventPropertySelector = new EventLogPropertySelector(xPathArray))
            {
                try
                {
                    IList<object> logEventProps = ((EventLogRecord)eventRecord.EventRecord).GetPropertyValues(loginEventPropertySelector);

                    Helper.WriteToLog("Description: \n" + eventRecord.EventRecord.FormatDescription());
                    Helper.WriteToLog("Description (XML): \n" + eventRecord.EventRecord.ToXml());



                    // Output to File, Console and Pop-up
                    Helper.WriteToLog("Dll was given a password due to password reset", "OUTPUT");

                    // Toast 
                    ToastContentBuilder toast = new ToastContentBuilder()
                    .AddText("Dll was given a password due to password reset")
                    .AddText("The Dll probably needs to be added to the known-good list"); ;
                    toast.Show();

                    Helper.WriteToLog("---------------------------------------");

                }
                catch (System.ArgumentOutOfRangeException)
                {
                    Helper.WriteToLog("Tried to print a vaule outside of pre-prescribed XPath Array during Service Install alert", "ERROR");
                }
            }
        }

        // "An Auth Providers or Support Package was loadead. Malicious ones are Rare but deadly. Possible to make a list of known valid ones"
        internal static void process4622_LsassLoadedPackage(EventRecordWrittenEventArgs eventRecord)
        {
            String[] xPathArray = new[]
                {
                    "Event/EventData/Data[@Name='SubjectUserName']", // Don't know what the structure of the XML is so TODO: fill in later
                };

            using (var loginEventPropertySelector = new EventLogPropertySelector(xPathArray))
            {
                try
                {
                    IList<object> logEventProps = ((EventLogRecord)eventRecord.EventRecord).GetPropertyValues(loginEventPropertySelector);

                    Helper.WriteToLog("Description: \n" + eventRecord.EventRecord.FormatDescription());
                    Helper.WriteToLog("Description (XML): \n" + eventRecord.EventRecord.ToXml());



                    // Output to File, Console and Pop-up
                    Helper.WriteToLog("Lsass Loaded a Package!", "OUTPUT");

                    // Toast 
                    ToastContentBuilder toast = new ToastContentBuilder()
                    .AddText("Lsass Loaded a Package!")
                    .AddText("This probably needs to be added to the known-good list"); ;
                    toast.Show();

                    Helper.WriteToLog("---------------------------------------");

                }
                catch (System.ArgumentOutOfRangeException)
                {
                    Helper.WriteToLog("Tried to print a vaule outside of pre-prescribed XPath Array during Service Install alert", "ERROR");
                }
            }
        }



        // Test with: runas /user:user cmd
        public static void process4624_LogonSuccess(EventRecordWrittenEventArgs eventRecord)
        {
            String[] xPathArray = new[]
                {
                    // (The XPath expression evaluates to null if no Data element exists with the specified name.)
                    "Event/EventData/Data[@Name='TargetUserSid']",
                    "Event/EventData/Data[@Name='TargetLogonId']",
                    "Event/EventData/Data[@Name='LogonType']",
                    "Event/EventData/Data[@Name='ElevatedToken']",
                    "Event/EventData/Data[@Name='WorkstationName']",
                    "Event/EventData/Data[@Name='ProcessName']",
                    "Event/EventData/Data[@Name='IpAddress']",
                    "Event/EventData/Data[@Name='IpPort']",
                    "Event/EventData/Data[@Name='TargetDomainName']",   // The attempted domain
                    "Event/EventData/Data[@Name='TargetUserName']",   // The attempted username
                    "Event/EventData/Data[@Name='SubjectUserName']",   // I guess the user that is attempted the auth?
                    "Event/EventData/Data[@Name='SubjectDomainName']",  // WORKGROUP by default
                    "Event/EventData/Data[@Name='AuthenticationPackageName']",  // auth
                    "Event/EventData/Data[@Name='LmPackageName']",  // auth package names
                };

            using (var loginEventPropertySelector = new EventLogPropertySelector(xPathArray))
            {
                try
                {
                    IList<object> logEventProps = ((EventLogRecord)eventRecord.EventRecord).GetPropertyValues(loginEventPropertySelector);
                    Helper.WriteToLog("SID: " + logEventProps[0]);
                    Helper.WriteToLog("Logon Id: " + logEventProps[1]);
                    Helper.WriteToLog("Logon Type: " + logEventProps[2]);
                    Helper.WriteToLog("Elevated Token: " + logEventProps[3]);
                    Helper.WriteToLog("Workstation Name: " + logEventProps[4]); // Workstation Name: XPSTAU
                    Helper.WriteToLog("Process Name: " + logEventProps[5]);
                    Helper.WriteToLog("IP Address: " + logEventProps[6]);
                    Helper.WriteToLog("IP Port: " + logEventProps[7]);
                    Helper.WriteToLog("Description: \n" + eventRecord.EventRecord.FormatDescription());

                    // Rule logic. TODO: Create a blacklist style JSON config file
                    // See https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventID=4624
                    int logonType = 0;
                    if (int.TryParse(logEventProps[2].ToString(), out logonType))
                    {
                        if (logonType != 5 && logonType != 11 && logonType != 7 && logonType != 2)
                        // Further testing needed but I'll probably want to exclude
                        // 4	Batch (i.e. scheduled task)
                        // 2	Interactive (logon at keyboard and screen of system)
                        {
                            // Output to File, Console and Pop-up
                            Helper.WriteToLog("Logon Success: ", "OUTPUT");
                            Helper.WriteToLog("Logon Type: " + logEventProps[2], "OUTPUT");
                            Helper.WriteToLog("Username: " + logEventProps[8] + "\\" + logEventProps[9], "OUTPUT");
                            Helper.WriteToLog("Auth: " + logEventProps[12], "OUTPUT");
                            Helper.WriteToLog("Auth Package: " + logEventProps[13], "OUTPUT");

                            string ip = logEventProps[6].ToString();
                            string port = logEventProps[7].ToString();
                            if (Helper.isRemoteIP(ip))
                            {
                                Helper.WriteToLog("IP Address: " + ip, "OUTPUT");
                                Helper.WriteToLog("IP Port: " + port, "OUTPUT");
                            }

                            // Toast 
                            string message = "";
                            // From https://docs.microsoft.com/en-us/windows/apps/design/shell/tiles-and-notifications/adaptive-interactive-toasts?tabs=builder-syntax
                            ToastContentBuilder toast = new ToastContentBuilder()
                            //.AddText("Logon Success")
                            .AddText("Logon Success Type: " + logEventProps[2]);
                            message += "User: " + logEventProps[8] + "\\" + logEventProps[9];
                            if (Helper.isRemoteIP(ip))
                            {
                                message += "\nAttacker Hostname: " + logEventProps[4];
                                message += "\nIP: " + ip;
                            }

                            // This is too many lines that toast will display (Max: 4)
                            if (logEventProps[12].ToString() != "" && logEventProps[12].ToString() != "-")
                            {
                                message += " Auth: " + logEventProps[12];
                            }
                            if (logEventProps[13].ToString() == "" && logEventProps[13].ToString() == "-")
                            {
                                message += " Auth Package: " + logEventProps[13];
                            }
                            toast.AddText(message);
                            toast.Show();
                        }
                    }
                    else
                    {
                        Helper.WriteToLog("Could not parse the Logon Type number: " + logEventProps[2], "ERROR");
                    }

                    Helper.WriteToLog("---------------------------------------");

                }
                catch (System.ArgumentOutOfRangeException)
                {
                    Helper.WriteToLog("Tried to print a vaule outside of pre-prescribed XPath Array", "ERROR");
                }
            }
        }

    } // end class
} // end namespace

