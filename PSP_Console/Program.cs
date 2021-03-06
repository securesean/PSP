using Microsoft.Toolkit.Uwp.Notifications;
using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.Security.Principal;
using Windows.Foundation.Collections;



/*
 * Sean Pierce
 * Started: Dec 2021
 * Personal Security Product
 * I wrote this while I was home sick so I'm sorry for the typo's, bad structure, and dumb logic
 * TODO: Add persistence so auto-start on logon
 * */
namespace PSP_Console
{
    class Program
    {
        static EventProcessor eventProcessor;
        private static bool testMode = false;
        private static List<int> supportedEventIDList = new List<int>();

        static void Main(string[] args)
        {

            // Some argument processing
            foreach (string arg in args)
            {
                if(arg.ToLower() == "-h" || arg.ToLower() == "--help")
                {
                    printBanner();
                    return;
                }
                if(arg.ToLower() == "-t" || arg.ToLower() == "--test")
                {
                    // launch a thread that will wait for the subscriptions, then execute the tests
                    testMode = true;
                }
            }

            eventProcessor = new EventProcessor();
            eventProcessor.TestMode = testMode;

            // Listen to notification activation
            ToastNotificationManagerCompat.OnActivated += toastArgs =>
            {
                // Obtain the arguments from the notification
                ToastArguments argsFromToast = ToastArguments.Parse(toastArgs.Argument);

                // Obtain any user input (text boxes, menu selections) from the notification
                ValueSet userInput = toastArgs.UserInput;

                // Need to dispatch to UI thread if performing UI operations
                //Application.Current.Dispatcher.Invoke(delegate
                //{
                //    // TODO: Show the corresponding content
                //    MessageBox.Show("Toast activated. Args: " + toastArgs.Argument);
                //});

                string eventRecordID = toastArgs.Argument.Substring(15);  // Remove "conversationId="
                System.Console.WriteLine("Openning Event Record " + eventRecordID);
                eventProcessor.WriteAndOpen(eventRecordID);
            };

            Helper.WriteToLog("Initiallizing EventProcessor. Starting Security Event Subscription");
            subscribe();
            
            Helper.WriteToLog("Press Any key to exit");
            Console.ReadKey();
        }

        private static void printBanner()
        {
            Console.WriteLine("Only support -t/--test parameter right now");
            Helper.WriteToLog("Only support -t/--test parameter right now");
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
                // User Logged on with creds
                "EventID=4648 or " +

                // Cleared Log
                "EventID=1102 or " +

                // User Group Enumerated - will probably remove this
                "EventID=4798 or " +

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

                supportedEventIDList.Add(4624);
                supportedEventIDList.Add(4625);
                supportedEventIDList.Add(4648);
                supportedEventIDList.Add(1102);
                supportedEventIDList.Add(4798);
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


                // Another example:
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
                    //Helper.WriteToLog("Waiting for Events...");
                    // Wait for events to occur. 
                    
                    if (testMode)
                    {
                        // Natively Supported Events
                        eventProcessor.trigger_process4624_LogonSuccess();
                        eventProcessor.trigger_process4625_LogonFailed();
                        eventProcessor.trigger_process1102_SecuritytLogCleared();
                        eventProcessor.trigger_process4798_LocalGroupEnum();
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
                        System.Threading.Thread.Sleep(10000);

                        foreach (int eventID in supportedEventIDList)
                        {
                            if (eventProcessor.TestTriggeredEventIDs.Contains(eventID))
                            {
                                Helper.WriteToLog("Event Supported " + eventID.ToString(), "OUTPUT");
                            } else
                            {
                                Helper.WriteToLog("Event NOT Supported " + eventID.ToString(), "ERROR");
                            }
                        }

                        Helper.WriteToLog("Press Any key to exit");
                        Console.ReadKey();
                        return;
                    }

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
        public static void EventLogEventRead(object obj, EventRecordWrittenEventArgs eventRecord)
        {
            // Make sure there was no error reading the event.
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
                    // Untested: "An Auth Providers or Support Package was loadead. Malicious ones are Rare but deadly. Possible to make a list of known valid ones"
                    eventProcessor.process4622_LsassLoadedPackage(eventRecord); 
                    break;
                case 4614:
                    // Untested: DLLs that Windows calls into whenenever a user changes his/her password. Malicious ones are Rare but deadly
                    eventProcessor.process4614_NotifcationPackageLoaded(eventRecord); 
                    break;
                case 4611:
                    // Untested: 4611 is logged at startup and occasionally afterwards for each logon process on the system. Possible to make a list of known valid ones
                    eventProcessor.process4611_LsassLogon(eventRecord); 
                    break;
                case 4610:
                    // Untested: "An Auth Provider was loadead. Malicious ones are Rare but deadly. Possible to make a list of known valid ones"
                    eventProcessor.process4610_LsassLoadedAuthPackage(eventRecord); 
                    break;

                default:
                    Helper.WriteToLog("Unsupported Log ID: " + eventRecord.EventRecord.Id, "ERROR");
                    break;

            }
        } // end of function









    }
}
