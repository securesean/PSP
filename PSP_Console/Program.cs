using Microsoft.Toolkit.Uwp.Notifications;
using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.Security.Principal;



/*
 * Sean Pierce
 * Dec 2021
 * Personal Security Product
 * I wrote this while I was home sick so I'm sorry for the typo's, bad structure, and dumb logic
 * */
namespace PSP_Console
{
    class Program
    {
        static void Main(string[] args)
        {
            Helper.WriteToLog("Starting Security Event Subscription");
            subscribe();
            
            Helper.WriteToLog("Press Any key to exit");
            Console.ReadKey();
        }

        public static void subscribe()
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

                // Cleared Log
                "EventID=1102 or " +

                // Security System Extention
                "EventID=4697 or " +    // Server Installed
                "EventID=4610 or EventID=4611 or EventID=4614 or EventID=4622" +    // Lsass Stuff
                
                "]]");
                //EventLogQuery SecurityAuditingQuery = new EventLogQuery("Microsoft-Windows-Security-Auditing", PathType.LogName, "*[System[EventID=4697 or EventID=4634]]");

                SecurityWatcher = new EventLogWatcher(securityQuery);
                //SecurityAuditingWatcher = new EventLogWatcher(SecurityAuditingQuery);

                // Make the watcher listen to the EventRecordWritten
                // events.  When this event happens, the callback method
                // (EventLogEventRead) is called.
                SecurityWatcher.EventRecordWritten += new EventHandler<EventRecordWrittenEventArgs>(EventLogEventRead);
                //SecurityAuditingWatcher.EventRecordWritten += new EventHandler<EventRecordWrittenEventArgs>(EventLogEventRead);

                // Activate the subscription
                SecurityWatcher.Enabled = true;
                //SecurityAuditingWatcher.Enabled = true;

                // Infine loop because when this function exits, the subscription stops
                Helper.WriteToLog("Subscribed");
                while (true)
                {
                    Helper.WriteToLog("Waiting for Events...");
                    // Wait for events to occur. 
                    System.Threading.Thread.Sleep(10000);
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
                // Stop listening to events
                SecurityWatcher.Enabled = false;
                //SecurityAuditingWatcher.Enabled = false;

                if (SecurityWatcher != null)
                {
                    SecurityWatcher.Dispose();
                }
                if (SecurityAuditingWatcher != null)
                {
                    SecurityAuditingWatcher.Dispose();
                }
            }

            
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


            switch (arg.EventRecord.Id)
            {
                // Natively Supported Events
                case 4624:
                    EventProcessor.process4624_LogonSuccess(arg);
                    break;
                case 4625:
                    EventProcessor.process4625_LogonFailed(arg);
                    break;
                case 1102:
                    EventProcessor.process1102_SecuritytLogCleared(arg);
                    break;

                // Events supported by "Security System Extension"
                case 4697:
                    EventProcessor.process4697_ServiceInstalled(arg);
                    break;
                case 4622:
                    // Untested: "An Auth Providers or Support Package was loadead. Malicious ones are Rare but deadly. Possible to make a list of known valid ones"
                    EventProcessor.process4622_LsassLoadedPackage(arg); 
                    break;
                case 4614:
                    // Untested: DLLs that Windows calls into whenenever a user changes his/her password. Malicious ones are Rare but deadly
                    EventProcessor.process4614_NotifcationPackageLoaded(arg); 
                    break;
                case 4611:
                    // Untested: 4611 is logged at startup and occasionally afterwards for each logon process on the system. Possible to make a list of known valid ones
                    EventProcessor.process4611_LsassLogon(arg); 
                    break;
                case 4610:
                    // Untested: "An Auth Provider was loadead. Malicious ones are Rare but deadly. Possible to make a list of known valid ones"
                    EventProcessor.process4610_LsassLoadedAuthPackage(arg); 
                    break;

                default:
                    Helper.WriteToLog("Unsupported Log ID: " + arg.EventRecord.Id, "ERROR");
                    break;

            }
        } // end of function









    }
}
