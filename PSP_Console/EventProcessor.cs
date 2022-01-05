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



                    // Output to File, Console and Pop-up
                    Helper.WriteToLog("User who Cleared Security Log: " + logEventProps[0], "OUTPUT");

                    /*  ToDo: Test remote clearing of a log via RPC
                    string ip = logEventProps[6].ToString();
                    string port = logEventProps[7].ToString();
                    if (isRemoteIP(ip))
                    {
                        Helper.WriteToLog("IP Address: " + ip, "OUTPUT");
                        Helper.WriteToLog("IP Port: " + port, "OUTPUT");
                    }
                    */

                    // Toast 
                    string message = "";
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
    }
}
