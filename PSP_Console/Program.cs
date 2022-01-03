using Microsoft.Toolkit.Uwp.Notifications;
using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.Security.Principal;



/*
 * Sean Pierce
 * Dec 2021
 * Personal Security Product
 * */
namespace PSP_Console
{
    class Program
    {
        static void Main(string[] args)
        {
            //Log("Info", "Starting First");
            //readPast();

            
            // Second way (code below):
            Helper.WriteToLog("Starting second");
            subscribe();
            Helper.WriteToLog("Done");
        }

        private static void readPast()
        {
            // From https://stackoverflow.com/questions/31488175/how-to-find-out-eventproperty-name
            var query = new EventLogQuery(
                "Security",
                PathType.LogName,
                "*[System[EventID=4624 or EventID=4634]]");

            using (var loginEventPropertySelector = new EventLogPropertySelector(new[]
            {
                // (The XPath expression evaluates to null if no Data element exists with the specified name.)
                "Event/EventData/Data[@Name='TargetUserSid']",
                "Event/EventData/Data[@Name='TargetLogonId']",
                "Event/EventData/Data[@Name='LogonType']",
                "Event/EventData/Data[@Name='ElevatedToken']",
                "Event/EventData/Data[@Name='WorkstationName']",
                "Event/EventData/Data[@Name='ProcessName']",
                "Event/EventData/Data[@Name='IpAddress']",
                "Event/EventData/Data[@Name='IpPort']"
            }))
            using (var logoffEventPropertySelector = new EventLogPropertySelector(new[]
            {
                "Event/EventData/Data[@Name='TargetUserSid']",
                "Event/EventData/Data[@Name='TargetLogonId']"
            }))
            using (var reader = new EventLogReader(query))
            {
                // In C# 8: while (reader.ReadEvent() is { } ev)
                while (reader.ReadEvent() is var ev && ev != null)
                {
                    using (ev)
                    {
                        switch (ev.Id)
                        {
                            case 4624:
                                var loginPropertyValues = ((EventLogRecord)ev).GetPropertyValues(loginEventPropertySelector);
                                var targetUserSid = (SecurityIdentifier)loginPropertyValues[0];
                                // ...

                                // printing
                                Helper.WriteToLog(targetUserSid.ToString() + " " + loginPropertyValues);
                                break;

                            case 4634:
                                var logoffPropertyValues = ((EventLogRecord)ev).GetPropertyValues(logoffEventPropertySelector);
                                var targetUserSid2 = (SecurityIdentifier)logoffPropertyValues[0];
                                // ...

                                // printing
                                Helper.WriteToLog(targetUserSid2.ToString() + " " + logoffPropertyValues);
                                break;
                        }
                    }


                }
            }
        }

        public static void subscribe()
        {
            EventLogWatcher watcher = null;
            try
            {

                // If the query is too board and is slowing the system down too much then I could probably improve performance 
                // by scoping down the query: https://docs.microsoft.com/en-us/previous-versions/bb671202(v=vs.90)?redirectedfrom=MSDN
                EventLogQuery subscriptionQuery = new EventLogQuery(
                  //  "Security", PathType.LogName, "*[System/EventID=4624]"); 
                    "Security", PathType.LogName, "*[System[EventID=4624 or EventID=4625]]");
                // "*[System[EventID=4624 or EventID=4634]]");

                watcher = new EventLogWatcher(subscriptionQuery);

                // Make the watcher listen to the EventRecordWritten
                // events.  When this event happens, the callback method
                // (EventLogEventRead) is called.
                watcher.EventRecordWritten +=
                    new EventHandler<EventRecordWrittenEventArgs>(
                        EventLogEventRead);

                // Activate the subscription
                watcher.Enabled = true;

                while(true)
                {
                    //Helper.WriteToLog("Waiting for someone to log in...");
                    // Wait for events to occur. 
                    System.Threading.Thread.Sleep(10000);
                }
                Helper.WriteToLog("Done Waiting");
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
                // Stop listening to events
                watcher.Enabled = false;

                if (watcher != null)
                {
                    watcher.Dispose();
                }
            }
            Console.ReadKey();
        }



        // Callback method that gets executed when an event is reported to the subscription.
        public static void EventLogEventRead(object obj, EventRecordWrittenEventArgs arg)
        {
            // Make sure there was no error reading the event.
            if (arg.EventRecord == null)
            {
                Helper.WriteToLog("The event instance was null.", "ERROR");
                return;
            }


            switch(arg.EventRecord.Id)
            {
                case 4624:
                    process4624_LogonSuccess(arg);
                    break;
                case 4625:
                    process4625_LogonFailed(arg);
                    break;
                default:
                    Helper.WriteToLog("Unsupported Log ID: " + arg.EventRecord.Id, "ERROR");
                    break;

            }
        } // end of function

        // Test with: runas /user:attacker cmd
        private static void process4625_LogonFailed(EventRecordWrittenEventArgs eventRecord)
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
                            Helper.WriteToLog("Logon Success: ", "OUTPUT");
                            Helper.WriteToLog("Logon Type: " + logEventProps[2], "OUTPUT");
                            Helper.WriteToLog("Username: " + logEventProps[8] + "\\" + logEventProps[9], "OUTPUT");
                            Helper.WriteToLog("Auth: " + logEventProps[12], "OUTPUT");
                            Helper.WriteToLog("Auth Package: " + logEventProps[13], "OUTPUT");

                            string ip = logEventProps[6].ToString();
                            string port = logEventProps[7].ToString();
                            if (isRemoteIP(ip) )
                            {
                                Helper.WriteToLog("IP Address: " + ip, "OUTPUT");
                                Helper.WriteToLog("IP Port: " + port, "OUTPUT");
                            }

                            // Toast 
                            string message = "";
                            // From https://docs.microsoft.com/en-us/windows/apps/design/shell/tiles-and-notifications/adaptive-interactive-toasts?tabs=builder-syntax
                            ToastContentBuilder toast = new ToastContentBuilder()
                            .AddText("Logon Failed")
                            .AddText("Logon Type: " + logEventProps[2]);

                            message += "Attempted Username: " + logEventProps[8] + "\\" + logEventProps[9];
                            if (isRemoteIP(ip))
                            {
                                message += "\nAttacker Hostname: " + logEventProps[11] + "\\" + logEventProps[4];
                                message += "\nIP: " + ip ;
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

        private static bool isRemoteIP(string ip)
        {
            ip = ip.Trim();
            if (ip == "" || ip == "-" || ip == "::1" || ip == "127.0.0.1") 
            { 
                return false; 
            }
            else
            {
                return true;
            }
        }


        // Test with: runas /user:user cmd
        private static void process4624_LogonSuccess(EventRecordWrittenEventArgs eventRecord)
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
                        if (logonType != 5 && logonType != 11 && logonType != 7 && logonType != 2 )
                        // Further testing needed but I'll probably want to exclude
                        // 4	Batch (i.e. scheduled task)
                        // 2	Interactive (logon at keyboard and screen of system)
                        {
                            // Output to File, Console and Pop-up
                            Helper.WriteToLog("Logon Success: ", "OUTPUT");
                            Helper.WriteToLog("Logon Type: " + logEventProps[2] , "OUTPUT");
                            Helper.WriteToLog("Username: " + logEventProps[8] + "\\" + logEventProps[9], "OUTPUT");
                            Helper.WriteToLog("Auth: " + logEventProps[12], "OUTPUT");
                            Helper.WriteToLog("Auth Package: " + logEventProps[13], "OUTPUT");

                            string ip = logEventProps[6].ToString();
                            string port = logEventProps[7].ToString();
                            if (isRemoteIP(ip) ) { 
                                Helper.WriteToLog("IP Address: " + ip, "OUTPUT");
                                Helper.WriteToLog("IP Port: " + port, "OUTPUT");
                            }

                            // Toast 
                            string message = "";
                            // From https://docs.microsoft.com/en-us/windows/apps/design/shell/tiles-and-notifications/adaptive-interactive-toasts?tabs=builder-syntax
                            ToastContentBuilder toast = new ToastContentBuilder()
                            .AddText("Logon Success")
                            .AddText("Logon Type: " + logEventProps[2]);
                            message += "User: " + logEventProps[8] + "\\" + logEventProps[9];
                            if (isRemoteIP(ip))
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

    }


}
