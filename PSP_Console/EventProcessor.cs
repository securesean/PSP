using Microsoft.Toolkit.Uwp.Notifications;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.DirectoryServices;
using System.IO;
using System.Threading;

// I just made this to hold all the Event processing code so everything wouldn't be all in one big .cs file
namespace PSP_Console
{
    internal class EventProcessor
    {
        private List<string> localAdminGroupList = new List<string>();
        private Dictionary<long, EventRecordWrittenEventArgs> RecordedEvents = new Dictionary<long, EventRecordWrittenEventArgs>();
        private readonly object _recordedEventsLock = new object();
        private volatile bool _stopping = false;
        Thread RefreshAdminListThread;

        public bool TestMode { get; internal set; }
        public List<int> TestTriggeredEventIDs { get; internal set; }

        public EventProcessor()
        {
            // Periodically get list of SID's in the admin group
            RefreshAdminListThread = new Thread(RefreshAdminListDriver);
            RefreshAdminListThread.IsBackground = true;
            RefreshAdminListThread.Start();
            TestMode = false;
            TestTriggeredEventIDs = new List<int>();
        }

        public void Stop()
        {
            _stopping = true;
        }

        private void RefreshAdminListDriver()
        {
            List<string> tempList = new List<string>();
            while (!_stopping)
            {
                tempList = Helper.GetLocalAdminSIDs();
                if (tempList.Count != 0)
                {
                    localAdminGroupList = tempList;
                }
                for (int i = 0; i < 60 && !_stopping; i++)
                {
                    Thread.Sleep(1000);
                }
            }
        }

        private string SaveEventRecord(EventRecordWrittenEventArgs eventRecord)
        {
            long record_id = eventRecord.EventRecord.RecordId ?? LongRandom();
            string eventRecordString = record_id.ToString("0." + new string('#', 339));
            lock (_recordedEventsLock)
            {
                RecordedEvents[record_id] = eventRecord;
            }
            try
            {
                if (!Directory.Exists(Helper.path))
                {
                    Directory.CreateDirectory(Helper.path);
                }
                string xmlPath = Path.Combine(Helper.path, eventRecordString + ".xml");
                File.WriteAllText(xmlPath, eventRecord.EventRecord.ToXml());
            }
            catch (Exception ex)
            {
                Helper.WriteToLog("Failed to save event XML: " + ex.Message, "ERROR");
            }
            return eventRecordString;
        }


        long LongRandom(long min = 900000000000000000, long max = 990000000000000000)
        {
            Random rand = new Random(); ;
            byte[] buf = new byte[8];
            rand.NextBytes(buf);
            long longRand = BitConverter.ToInt64(buf, 0);

            return (Math.Abs(longRand % (max - min)) + min);
        }

        /*
         * Test with :
         * PS: Clear-EventLog Security
            cmd: wevtutil.exe cl Security
         * */
        internal void process1102_SecuritytLogCleared(EventRecordWrittenEventArgs eventRecord)
        {
            if (TestMode)
                TestTriggeredEventIDs.Add(1102);

            String[] xPathArray = new[]
                {
                    "Event/UserData/LogFileCleared/SubjectUserName", // For when it's like <SubjectUserName>Admin</SubjectUserName>
                };

            using (var loginEventPropertySelector = new EventLogPropertySelector(xPathArray))
            {
                try
                {
                    IList<object> logEventProps = ((EventLogRecord)eventRecord.EventRecord).GetPropertyValues(loginEventPropertySelector);
                    for (int i = 0; i < logEventProps.Count; i++)
                    {
                        if (logEventProps[i] == null || logEventProps[i].ToString() == "-")
                        {
                            logEventProps[i] = "";
                        }
                    }
                    String SubjectUserName = logEventProps[0].ToString();

                    Helper.WriteToLog("User who Cleared Security Log: " + SubjectUserName);

                    Helper.WriteToLog("Description: \n" + eventRecord.EventRecord.FormatDescription());
                    Helper.WriteToLog("Description (XML): \n" + eventRecord.EventRecord.ToXml());



                    // Output to File, Console and Pop-up
                    Helper.WriteToLog("User who Cleared Security Log: " + SubjectUserName, "OUTPUT");

                    // Store in 'Database' and save XML for user-mode toast agent
                    string eventRecordString = SaveEventRecord(eventRecord);

                    // Toast via user-mode component
                    ToastHelper.ShowToast(eventRecordString, SubjectUserName + " Cleared Security Log!");

                    

                }
                catch (System.ArgumentOutOfRangeException)
                {
                    Helper.WriteToLog("Tried to print a vaule outside of pre-prescribed XPath Array", "ERROR");
                }
                catch (System.NullReferenceException)
                {
                    Helper.WriteToLog("Event Log had an unexpected Null", "ERROR");
                }
                finally
                {
                    Helper.WriteToLog("---------------------------------------");
                }
            }
        }

        internal void WriteAndOpen(string eventRecordString)
        {
            long eventRecord = 0;
            if (long.TryParse(eventRecordString, out eventRecord))
            {

                WriteAndOpen(eventRecord);
            }
            else
            {
                Helper.WriteToLog("Unable to parse Record ID: " + eventRecordString, "ERROR");
            }
        }

        internal Boolean WriteAndOpen(long eventRecord)
        {
            // eventRecord in RecordedEvents
            // write the xml out to a file then open it - maybe make a funciton in the helper
            if (RecordedEvents.ContainsKey(eventRecord))
            {
                // Create a file to write to.   
                string path = Helper.path + "\\" + eventRecord.ToString() + ".xml";
                using (StreamWriter sw = File.CreateText(path))
                {
                    EventRecordWrittenEventArgs eventRecordObj;
                    RecordedEvents.TryGetValue(eventRecord, out eventRecordObj);

                    sw.WriteLine(eventRecordObj.EventRecord.ToXml());

                    ProcessStartInfo startInfo;
                    startInfo = new ProcessStartInfo(path);

                    startInfo.Verb = "open";    // <<=== put here "Edit" 
                    //startInfo.Arguments = args;  // <<== probably don't need this one...  

                    Process newProcess = new Process();
                    newProcess.StartInfo = startInfo;

                    //try
                    //{
                    newProcess.Start();
                    //}

                    return true;
                }

            }
            else
            {
                return false;
            }
        }

        internal void trigger_process1102_SecuritytLogCleared()
        {
            Process p = new Process();
            p.StartInfo.UseShellExecute = false;
            p.StartInfo.RedirectStandardOutput = true;
            p.StartInfo.Arguments = "cl Security";
            p.StartInfo.FileName = "wevtutil.exe";
            p.Start();
            string output = p.StandardOutput.ReadToEnd();
            Helper.WriteToLog("Cleared Security Log: " + output.Trim(), "TEST");
            //p.WaitForExit();
        }

        internal void trigger_process4726_UserDeleted()
        {
            trigger_process4720_UserCreated();
        }

        internal void trigger_process4722_UserEnabled()
        {
            Process p = new Process();
            p.StartInfo.UseShellExecute = false;
            p.StartInfo.RedirectStandardOutput = true;
            p.StartInfo.Arguments = "user testUser /add";
            p.StartInfo.FileName = "net.exe";
            p.Start();
            string output = p.StandardOutput.ReadToEnd();
            Helper.WriteToLog("Created user: " + output.Trim(), "TEST");
            //p.WaitForExit();


            // Enable
            Process p2 = new Process();
            p2.StartInfo.UseShellExecute = false;
            p2.StartInfo.RedirectStandardOutput = true;
            p2.StartInfo.Arguments = "user testUser /active:yes";
            p2.StartInfo.FileName = "net.exe";
            p2.Start();
            string output2 = p2.StandardOutput.ReadToEnd();
            Helper.WriteToLog("Activate User: " + output2.Trim(), "TEST");
            //p2.WaitForExit();

            // Clean up
            Process p3 = new Process();
            p3.StartInfo.UseShellExecute = false;
            p3.StartInfo.RedirectStandardOutput = true;
            p3.StartInfo.Arguments = "user testUser /del";
            p3.StartInfo.FileName = "net.exe";
            p3.Start();
            string output3 = p3.StandardOutput.ReadToEnd();
            Helper.WriteToLog("Deleted User: " + output2.Trim(), "TEST");
            //p2.WaitForExit();
        }

        internal void trigger_process4648_UserLogonWithCreds()
        {
            
        }

        internal void trigger_process4724_PasswordReset()
        {
            Process p = new Process();
            p.StartInfo.UseShellExecute = false;
            p.StartInfo.RedirectStandardOutput = true;
            p.StartInfo.Arguments = "user testUser /add";
            p.StartInfo.FileName = "net.exe";
            p.Start();
            string output = p.StandardOutput.ReadToEnd();
            Helper.WriteToLog("Created user: " + output.Trim(), "TEST");
            //p.WaitForExit();


            // Enable
            Process p2 = new Process();
            p2.StartInfo.UseShellExecute = false;
            p2.StartInfo.RedirectStandardOutput = true;
            p2.StartInfo.Arguments = "user testUser Password123Password123";
            p2.StartInfo.FileName = "net.exe";
            p2.Start();
            string output2 = p2.StandardOutput.ReadToEnd();
            Helper.WriteToLog("User Password was set: " + output2.Trim(), "TEST");
            //p2.WaitForExit();

            // Clean up
            Process p3 = new Process();
            p3.StartInfo.UseShellExecute = false;
            p3.StartInfo.RedirectStandardOutput = true;
            p3.StartInfo.Arguments = "user testUser /del";
            p3.StartInfo.FileName = "net.exe";
            p3.Start();
            string output3 = p3.StandardOutput.ReadToEnd();
            Helper.WriteToLog("Deleted User: " + output2.Trim(), "TEST");
            //p2.WaitForExit();
        }

        internal void trigger_process4697_ServiceInstalled()
        {
            // Test with: sc.exe create aService3 start= delayed-auto binpath= C:\a.exe
            Process p = new Process();
            p.StartInfo.UseShellExecute = false;
            p.StartInfo.RedirectStandardOutput = true;
            p.StartInfo.Arguments = "create aService start= delayed-auto binpath= C:\\a.exe";
            p.StartInfo.FileName = "sc.exe";
            p.Start();
            string output = p.StandardOutput.ReadToEnd();
            Helper.WriteToLog("Installing Service: " + output.Trim(), "TEST");
            //p.WaitForExit();


            // Clean up
            Process p2 = new Process();
            p2.StartInfo.UseShellExecute = false;
            p2.StartInfo.RedirectStandardOutput = true;
            p2.StartInfo.Arguments = "delete aService";
            p2.StartInfo.FileName = "sc.exe";
            p2.Start();
            string output2 = p2.StandardOutput.ReadToEnd();
            Helper.WriteToLog("Installing Service: " + output2.Trim(), "TEST");
            //p2.WaitForExit();
        }

        internal void trigger_process4614_NotifcationPackageLoaded()
        {
            
        }

        internal void trigger_process4610_LsassLoadedAuthPackage()
        {
            
        }

        internal void trigger_process4611_LsassLogon()
        {
            
        }

        internal void trigger_process4622_LsassLoadedPackage()
        {
            
        }

        // ToDo: Clean all this up - make a CreateUser()
        internal void trigger_process4732_UserAddedToGroup()
        {
            // create user
            Process p = new Process();
            p.StartInfo.UseShellExecute = false;
            p.StartInfo.RedirectStandardOutput = true;
            p.StartInfo.Arguments = "user testUser /add";
            p.StartInfo.FileName = "net.exe";
            p.Start();
            string output = p.StandardOutput.ReadToEnd();
            Helper.WriteToLog("Created user: " + output.Trim(), "TEST");
            //p.WaitForExit();

            // create group
            p = new Process();
            p.StartInfo.UseShellExecute = false;
            p.StartInfo.RedirectStandardOutput = true;
            p.StartInfo.Arguments = "localgroup tempgroup5 /add";
            p.StartInfo.FileName = "net.exe";
            p.Start();
            output = p.StandardOutput.ReadToEnd();
            Helper.WriteToLog("Created user: " + output.Trim(), "TEST");
            //p.WaitForExit();

            // add user to group
            p = new Process();
            p.StartInfo.UseShellExecute = false;
            p.StartInfo.RedirectStandardOutput = true;
            p.StartInfo.Arguments = "localgroup tempgroup5 testUser /add";
            p.StartInfo.FileName = "net.exe";
            p.Start();
            output = p.StandardOutput.ReadToEnd();
            Helper.WriteToLog("Created user: " + output.Trim(), "TEST");
            //p.WaitForExit();


            // delete group
            p = new Process();
            p.StartInfo.UseShellExecute = false;
            p.StartInfo.RedirectStandardOutput = true;
            p.StartInfo.Arguments = "localgroup tempgroup5 /del";
            p.StartInfo.FileName = "net.exe";
            p.Start();
            output = p.StandardOutput.ReadToEnd();
            Helper.WriteToLog("Created user: " + output.Trim(), "TEST");
            //p.WaitForExit();


            // Clean up
            Process p2 = new Process();
            p2.StartInfo.UseShellExecute = false;
            p2.StartInfo.RedirectStandardOutput = true;
            p2.StartInfo.Arguments = "user testUser /del";
            p2.StartInfo.FileName = "net.exe";
            p2.Start();
            string output2 = p2.StandardOutput.ReadToEnd();
            Helper.WriteToLog("Deleted User: " + output2.Trim(), "TEST");
        }

        internal void trigger_process4720_UserCreated()
        {
            // create user
            Process p = new Process();
            p.StartInfo.UseShellExecute = false;
            p.StartInfo.RedirectStandardOutput = true;
            p.StartInfo.Arguments = "user testUser /add";
            p.StartInfo.FileName = "net.exe";
            p.Start();
            string output = p.StandardOutput.ReadToEnd();
            Helper.WriteToLog("Created user: " + output.Trim(), "TEST");
            //p.WaitForExit();


            // Clean up
            Process p2 = new Process();
            p2.StartInfo.UseShellExecute = false;
            p2.StartInfo.RedirectStandardOutput = true;
            p2.StartInfo.Arguments = "user testUser /del";
            p2.StartInfo.FileName = "net.exe";
            p2.Start();
            string output2 = p2.StandardOutput.ReadToEnd();
            Helper.WriteToLog("Deleted User: " + output2.Trim(), "TEST");
            //p2.WaitForExit();
        }

        internal void trigger_process4798_LocalGroupEnum()
        {
            // Test with: sc.exe create aService3 start= delayed-auto binpath= C:\a.exe
            Process p = new Process();
            p.StartInfo.UseShellExecute = false;
            p.StartInfo.RedirectStandardOutput = true;
            p.StartInfo.Arguments = "localgroup Administrators";
            p.StartInfo.FileName = "net.exe";
            p.Start();
            string output = p.StandardOutput.ReadToEnd();
            Helper.WriteToLog("Enumerating localgroup: " + output.Trim(), "TEST");
            //p.WaitForExit();
        }

        internal void trigger_process4625_LogonFailed()
        {
            
        }

        internal void trigger_process4624_LogonSuccess()
        {
            
        }

        
        // ToDo: change to'Installed Service: <name>'
        // And list the executeable that did the installation 
        internal void process4697_ServiceInstalled(EventRecordWrittenEventArgs eventRecord)
        {
            if (TestMode)
                TestTriggeredEventIDs.Add(4697);

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
                    for (int i = 0; i < logEventProps.Count; i++)
                    {
                        if (logEventProps[i] == null || logEventProps[i].ToString() == "-")
                        {
                            logEventProps[i] = "";
                        }
                    }
                    String SubjectUserName = logEventProps[0].ToString();
                    String ServiceName = logEventProps[1].ToString();
                    String ServiceFileName = logEventProps[2].ToString();

                    Helper.WriteToLog("User who installed Service: " + SubjectUserName);
                    Helper.WriteToLog("ServiceName: " + ServiceName);
                    Helper.WriteToLog("ServiceFileName: " + ServiceFileName);

                    Helper.WriteToLog("Description: \n" + eventRecord.EventRecord.FormatDescription());
                    Helper.WriteToLog("Description (XML): \n" + eventRecord.EventRecord.ToXml());

                    // Store in 'Database' and save XML for user-mode toast agent
                    string eventRecordString = SaveEventRecord(eventRecord);

                    // Output to File, Console and Pop-up
                    Helper.WriteToLog("User who installed Service: " + SubjectUserName, "OUTPUT");
                    Helper.WriteToLog("ServiceName: " + ServiceName, "OUTPUT");
                    Helper.WriteToLog("ServiceFileName: " + ServiceFileName, "OUTPUT");

                    // Toast via user-mode component
                    ToastHelper.ShowToast(
                        eventRecordString,
                        "Service Installed by " + SubjectUserName,
                        "ServiceName: " + ServiceName,
                        "ServiceFileName: " + ServiceFileName);



                    

                }
                catch (System.ArgumentOutOfRangeException)
                {
                    Helper.WriteToLog("Tried to print a vaule outside of pre-prescribed XPath Array", "ERROR");
                }
                catch (System.NullReferenceException)
                {
                    Helper.WriteToLog("Event Log had an unexpected Null", "ERROR");
                }
                finally
                {
                    Helper.WriteToLog("---------------------------------------");
                }
            }
        } // end process4697_ServiceInstalled

        
        internal void process4722_UserEnabled(EventRecordWrittenEventArgs eventRecord)
        {
            if (TestMode)
                TestTriggeredEventIDs.Add(4722);

            String[] xPathArray = new[]
                {
                    "Event/EventData/Data[@Name='SubjectUserName']",
                    "Event/EventData/Data[@Name='TargetUserName']",
                    "Event/EventData/Data[@Name='TargetSid']",
                };

            using (var loginEventPropertySelector = new EventLogPropertySelector(xPathArray))
            {
                try
                {
                    IList<object> logEventProps = ((EventLogRecord)eventRecord.EventRecord).GetPropertyValues(loginEventPropertySelector);
                    for (int i = 0; i < logEventProps.Count; i++)
                    {
                        if (logEventProps[i] == null || logEventProps[i].ToString() == "-")
                        {
                            logEventProps[i] = "";
                        }
                    }
                    String SubjectUserName = logEventProps[0].ToString();
                    String TargetUserName = logEventProps[1].ToString();
                    String TargetSid = logEventProps[2].ToString();

                    Helper.WriteToLog("Description: \n" + eventRecord.EventRecord.FormatDescription());
                    Helper.WriteToLog("Description (XML): \n" + eventRecord.EventRecord.ToXml());

                    // Store in 'Database' and save XML for user-mode toast agent
                    string eventRecordString = SaveEventRecord(eventRecord);

                    // Output to File, Console and Pop-up
                    Helper.WriteToLog(SubjectUserName + " enabled the local user " + TargetUserName, "OUTPUT");

                    // Toast via user-mode component
                    List<string> toastLines = new List<string>
                    {
                        SubjectUserName + " enabled the local user " + TargetUserName
                    };
                    if (TargetSid.ToString().EndsWith("-500"))
                    {
                        toastLines.Add(TargetUserName + " is the local RID 500 Admin account! ");
                    }
                    ToastHelper.ShowToast(eventRecordString, toastLines.ToArray());

                    

                }
                catch (System.ArgumentOutOfRangeException)
                {
                    Helper.WriteToLog("Tried to print a vaule outside of pre-prescribed XPath Array", "ERROR");
                }
                catch (System.NullReferenceException)
                {
                    Helper.WriteToLog("Event Log had an unexpected Null", "ERROR");
                }
                finally
                {
                    Helper.WriteToLog("---------------------------------------");
                }
            }
        }

        // Test with> net user temp /add ; net user temp Password12345; net user temp /delete
        internal void process4724_PasswordReset(EventRecordWrittenEventArgs eventRecord)
        {
            if (TestMode)
                TestTriggeredEventIDs.Add(4724);

            String[] xPathArray = new[]
                {
                    "Event/EventData/Data[@Name='SubjectUserName']", // the user who done it
                    "Event/EventData/Data[@Name='TargetUserName']", // the user who they logged in as
                };

            using (var loginEventPropertySelector = new EventLogPropertySelector(xPathArray))
            {
                try
                {
                    IList<object> logEventProps = ((EventLogRecord)eventRecord.EventRecord).GetPropertyValues(loginEventPropertySelector);
                    for (int i = 0; i < logEventProps.Count; i++)
                    {
                        if (logEventProps[i] == null || logEventProps[i].ToString() == "-")
                        {
                            logEventProps[i] = "";
                        }
                    }
                    String SubjectUserName = logEventProps[0].ToString();
                    String TargetUserName = logEventProps[1].ToString();

                    Helper.WriteToLog("A password reset attempt was made");

                    Helper.WriteToLog("Description: \n" + eventRecord.EventRecord.FormatDescription());
                    Helper.WriteToLog("Description (XML): \n" + eventRecord.EventRecord.ToXml());

                    // Store in 'Database' and save XML for user-mode toast agent
                    string eventRecordString = SaveEventRecord(eventRecord);

                    // Output to File, Console
                    Helper.WriteToLog(SubjectUserName + " performed a performed a password reset for '" + TargetUserName + "'", "OUTPUT");

                    // Toast via user-mode component
                    ToastHelper.ShowToast(
                        eventRecordString,
                        SubjectUserName + " performed a performed a password reset for '" + TargetUserName + "'");



                    

                }
                catch (System.ArgumentOutOfRangeException)
                {
                    Helper.WriteToLog("Tried to print a vaule outside of pre-prescribed XPath Array", "ERROR");
                }
                catch (System.NullReferenceException)
                {
                    Helper.WriteToLog("Event Log had an unexpected Null", "ERROR");
                }
                finally
                {
                    Helper.WriteToLog("---------------------------------------");
                }
            }
        }

        //  runas /user:temp cmd
        internal void process4648_UserLogonWithCreds(EventRecordWrittenEventArgs eventRecord)
        {
            if (TestMode)
                TestTriggeredEventIDs.Add(4648);

            String[] xPathArray = new[]
                {
                    "Event/EventData/Data[@Name='SubjectUserName']", // the user who done it
                    "Event/EventData/Data[@Name='TargetUserName']", // the user who they logged in as
                    "Event/EventData/Data[@Name='IpAddress']", // where the user logged in initially
                    "Event/EventData/Data[@Name='ProcessId']", // PID that did it
                    "Event/EventData/Data[@Name='ProcessName']", // Exe that did it - probably C:\Windows\System32\svchost.exe
                    "Event/EventData/Data[@Name='SubjectUserSid']",
                    "Event/EventData/Data[@Name='TargetDomainName']",
                };

            using (var loginEventPropertySelector = new EventLogPropertySelector(xPathArray))
            {
                try
                {
                    IList<object> logEventProps = ((EventLogRecord)eventRecord.EventRecord).GetPropertyValues(loginEventPropertySelector);
                    for (int i = 0; i < logEventProps.Count; i++)
                    {
                        if (logEventProps[i] == null || logEventProps[i].ToString() == "-")
                        {
                            logEventProps[i] = "";
                        }
                    }
                    String SubjectUserName = logEventProps[0].ToString();
                    String TargetUserName = logEventProps[1].ToString();
                    String IpAddress = logEventProps[2].ToString();
                    String ProcessId = logEventProps[3].ToString();
                    String ProcessName = logEventProps[4].ToString();
                    String SubjectUserSid = logEventProps[5].ToString();
                    String TargetDomainName = logEventProps[6].ToString();

                    Helper.WriteToLog("A logon was attempted using explicit credentials. (Usually runas.exe or RDP)");

                    Helper.WriteToLog("Description: \n" + eventRecord.EventRecord.FormatDescription());
                    Helper.WriteToLog("Description (XML): \n" + eventRecord.EventRecord.ToXml());

                    if (RuleEngine.ShouldAlertExplicitCredsLogon(SubjectUserSid, SubjectUserName))
                    {
                        string eventRecordString = SaveEventRecord(eventRecord);
                        Helper.WriteToLog(SubjectUserName + " performed a logon using explicit creds (Usually runas.exe or RDP) as '" + TargetDomainName + "\\" + TargetUserName + "'", "OUTPUT");

                        List<string> toastLines = new List<string>
                        {
                            SubjectUserName + " performed a logon using explicit creds as '" + TargetDomainName + "\\" + TargetUserName + "'"
                        };
                        if (Helper.isRemoteIP(IpAddress))
                        {
                            toastLines.Add("From " + IpAddress);
                        }
                        toastLines.Add("From " + ProcessName + " (PID: " + ProcessId + ")");
                        string processHint = RuleEngine.GetExplicitCredsProcessHint(ProcessName);
                        if (!string.IsNullOrEmpty(processHint))
                        {
                            toastLines.Add(processHint);
                        }
                        ToastHelper.ShowToast(eventRecordString, toastLines.ToArray());
                    }

                    

                }
                catch (System.ArgumentOutOfRangeException)
                {
                    Helper.WriteToLog("Tried to print a vaule outside of pre-prescribed XPath Array", "ERROR");
                }
                catch (System.NullReferenceException)
                {
                    Helper.WriteToLog("Event Log had an unexpected Null", "ERROR");
                }
                finally
                {
                    Helper.WriteToLog("---------------------------------------");
                }
            }
        }

        // Test with net user temp /add ; net localgroup Administrators /add temp
        // cmd> net localgroup tempgroup /add temp
        // cmd> net localgroup "Remote Management Users" /add temp
        // cmd> net localgroup "Hyper-V Administrators" /delete temp;   net localgroup "Hyper-V Administrators" /add temp
        internal void process4732_UserAddedToGroup(EventRecordWrittenEventArgs eventRecord)
        {
            if (TestMode)
                TestTriggeredEventIDs.Add(4732);

            String[] xPathArray = new[]
                {
                    "Event/EventData/Data[@Name='SubjectUserName']",
                    "Event/EventData/Data[@Name='TargetUserName']", // the group name
                    "Event/EventData/Data[@Name='TargetSid']",  // the SID of the group  
                    "Event/EventData/Data[@Name='MemberSid']",  // the SID of the user we're adding to the group 
                };

            using (var loginEventPropertySelector = new EventLogPropertySelector(xPathArray))
            {
                try
                {
                    IList<object> logEventProps = ((EventLogRecord)eventRecord.EventRecord).GetPropertyValues(loginEventPropertySelector);
                    for (int i = 0; i < logEventProps.Count; i++)
                    {
                        if (logEventProps[i] == null || logEventProps[i].ToString() == "-")
                        {
                            logEventProps[i] = "";
                        }
                    }
                    String SubjectUserName = logEventProps[0].ToString();
                    String TargetUserName = logEventProps[1].ToString();
                    String TargetSid = logEventProps[2].ToString();
                    String MemberSid = logEventProps[3].ToString();

                    Helper.WriteToLog("Description: \n" + eventRecord.EventRecord.FormatDescription());
                    Helper.WriteToLog("Description (XML): \n" + eventRecord.EventRecord.ToXml());

                    // Store in 'Database' and save XML for user-mode toast agent
                    string eventRecordString = SaveEventRecord(eventRecord);

                    string translatedUserName = "";
                    try
                    {
                        translatedUserName = new System.Security.Principal.SecurityIdentifier(MemberSid).Translate(typeof(System.Security.Principal.NTAccount)).ToString();
                    }
                    catch (System.Security.Principal.IdentityNotMappedException)
                    {
                        Helper.WriteToLog("Failed to lookup user identity: " + MemberSid, "ERROR");
                        translatedUserName = MemberSid;
                    }
                    
                    Helper.WriteToLog(SubjectUserName + " added a user (" + translatedUserName + ") to the local group: '" + TargetUserName + "'", "OUTPUT");

                    List<string> toastLines = new List<string>
                    {
                        SubjectUserName + " added a user (" + translatedUserName + ") to the group: " + TargetUserName
                    };
                    toastLines.AddRange(RuleEngine.GetGroupSidWarningLines(TargetSid));

                    if (!RuleEngine.ShouldAlertUserAddedToGroup(TargetSid, MemberSid, localAdminGroupList))
                    {
                        Helper.WriteToLog("Supressed alert notifying user added to the admin group because they were already a member");
                    }
                    else
                    {
                        ToastHelper.ShowToast(eventRecordString, toastLines.ToArray());
                    }



                }
                catch (System.ArgumentOutOfRangeException)
                {
                    Helper.WriteToLog("Tried to print a vaule outside of pre-prescribed XPath Array", "ERROR");
                }
                catch (System.NullReferenceException)
                {
                    Helper.WriteToLog("Event Log had an unexpected Null", "ERROR");
                }
                finally
                {
                    Helper.WriteToLog("---------------------------------------");
                }
            }
        }

        /*
         * 
         * Good info: 
         * https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4720
         * https://ebookreading.net/view/book/EB9781119390640_12.html
         * */
        internal void process4720_UserCreated(EventRecordWrittenEventArgs eventRecord)
        {
            if (TestMode)
                TestTriggeredEventIDs.Add(4720);

            String[] xPathArray = new[]
                {
                    "Event/EventData/Data[@Name='SubjectUserName']",
                    "Event/EventData/Data[@Name='TargetUserName']",  // newly created account name
                    "Event/EventData/Data[@Name='PrivilegeList']",
                    "Event/EventData/Data[@Name='SamAccountName']",
                    "Event/EventData/Data[@Name='DisplayName']", //  %%1793 is 'not set' for many vaules including this one
                    "Event/EventData/Data[@Name='UserPrincipalName']",  // '-' is 'not set' 
                    "Event/EventData/Data[@Name='AllowedToDelegateTo']",  // '-' is 'not set' 
                    "Event/EventData/Data[@Name='OldUacValue']",  // 
                    "Event/EventData/Data[@Name='NewUacValue']",  // 
                    "Event/EventData/Data[@Name='UserAccountControl']",  //  %%2080 %%2082 %%2084
                    "Event/EventData/Data[@Name='SidHistory']",  // '-' is 'not set' 
                };

            using (var loginEventPropertySelector = new EventLogPropertySelector(xPathArray))
            {
                try
                {
                    IList<object> logEventProps = ((EventLogRecord)eventRecord.EventRecord).GetPropertyValues(loginEventPropertySelector);
                    for (int i = 0; i < logEventProps.Count; i++)
                    {
                        if (logEventProps[i] == null || logEventProps[i].ToString() == "-")
                        {
                            logEventProps[i] = "";
                        }
                    }
                    Helper.WriteToLog("Description: \n" + eventRecord.EventRecord.FormatDescription());
                    Helper.WriteToLog("Description (XML): \n" + eventRecord.EventRecord.ToXml());

                    // Store in 'Database' and save XML for user-mode toast agent
                    string eventRecordString = SaveEventRecord(eventRecord);

                    String SubjectUsername = logEventProps[0].ToString();
                    String TargetUserName = logEventProps[1].ToString();
                    String PrivilegeList = logEventProps[2].ToString();
                    String SamAccountName = logEventProps[3].ToString();
                    String DisplayName = logEventProps[4].ToString();
                    String UserPrincipalName = logEventProps[5].ToString();
                    String AllowedToDelegateTo = logEventProps[6].ToString();
                    String OldUacValue = logEventProps[7].ToString();
                    String NewUacValue = logEventProps[8].ToString();
                    String UserAccountControl = logEventProps[9].ToString();
                    String SidHistory = logEventProps[10].ToString();

                    // Output to File, Console and Pop-up
                    Helper.WriteToLog(SubjectUsername + " Created a User Account: " + TargetUserName, "OUTPUT");
                    Helper.WriteToLog("TargetUserName: " + TargetUserName, "OUTPUT");
                    Helper.WriteToLog("SamAccountName: " + SamAccountName, "OUTPUT");
                    Helper.WriteToLog("DisplayName: " + DisplayName, "OUTPUT");
                    Helper.WriteToLog("UserPrincipalName: " + UserPrincipalName, "OUTPUT");

                    List<string> toastLines = new List<string>
                    {
                        "User " + SubjectUsername + " created account: " + TargetUserName
                    };

                    string message = RuleEngine.BuildUserCreatedSummary(
                        TargetUserName,
                        SamAccountName,
                        DisplayName,
                        UserPrincipalName,
                        SidHistory,
                        AllowedToDelegateTo);

                    if (!string.IsNullOrEmpty(message))
                    {
                        toastLines.Add(message);
                    }
                    ToastHelper.ShowToast(eventRecordString, toastLines.ToArray());

                    

                }
                catch (System.ArgumentOutOfRangeException)
                {
                    Helper.WriteToLog("Tried to print a vaule outside of pre-prescribed XPath Array", "ERROR");
                }
                catch (System.NullReferenceException)
                {
                    Helper.WriteToLog("Event Log had an unexpected Null", "ERROR");
                }
                finally
                {
                    Helper.WriteToLog("---------------------------------------");
                }
            }
        }

        internal void process4625_LogonFailed(EventRecordWrittenEventArgs eventRecord)
        {
            if (TestMode)
                TestTriggeredEventIDs.Add(4625);

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
                    "Event/EventData/Data[@Name='LogonGuid']",  // It seems to be "{00000000-0000-0000-0000-000000000000}" for many types of connections connections
                };

            using (var loginEventPropertySelector = new EventLogPropertySelector(xPathArray))
            {
                try
                {
                    IList<object> logEventProps = ((EventLogRecord)eventRecord.EventRecord).GetPropertyValues(loginEventPropertySelector);
                    for (int i = 0; i < logEventProps.Count; i++)
                    {
                        if (logEventProps[i] == null || logEventProps[i].ToString() == "-")
                        {
                            logEventProps[i] = "";
                        }
                    }
                    String SID = logEventProps[0].ToString();
                    String LogonId = logEventProps[1].ToString();
                    String LogonType = logEventProps[2].ToString();
                    String ElevatedToken = logEventProps[3].ToString();
                    String WorkstationName = logEventProps[4].ToString();
                    String ProcessName = logEventProps[5].ToString();
                    String IP = logEventProps[6].ToString();
                    String Port = logEventProps[7].ToString();
                    String TargetDomainName = logEventProps[8].ToString();
                    String TargetUserName = logEventProps[9].ToString();
                    String SubjectUserName = logEventProps[10].ToString();
                    String SubjectDomainName = logEventProps[11].ToString();
                    String AuthenticationPackageName = logEventProps[12].ToString();
                    String LmPackageName = logEventProps[13].ToString();
                    String LogonGuid = logEventProps[14].ToString();

                    String Description = eventRecord.EventRecord.FormatDescription();
                    String DescriptionXML = eventRecord.EventRecord.ToXml();

                    Helper.WriteToLog("SID: " + SID);
                    Helper.WriteToLog("Logon Id: " + LogonId);
                    Helper.WriteToLog("Logon Type: " + LogonType);
                    Helper.WriteToLog("Elevated Token: " + ElevatedToken);
                    Helper.WriteToLog("Workstation Name: " + WorkstationName);
                    Helper.WriteToLog("Process Name: " + ProcessName);
                    Helper.WriteToLog("IP Address: " + IP);
                    Helper.WriteToLog("IP Port: " + Port);
                    Helper.WriteToLog("Description: \n" + eventRecord.EventRecord.FormatDescription());
                    Helper.WriteToLog("Description (XML): \n" + eventRecord.EventRecord.ToXml());

                    int logonType = 0;
                    if (int.TryParse(LogonType, out logonType))
                    {
                        if (RuleEngine.ShouldEvaluateLogonType(logonType))
                        {
                            Helper.WriteToLog("Logon Failed: ", "OUTPUT");
                            Helper.WriteToLog("Logon Type: " + LogonType, "OUTPUT");
                            Helper.WriteToLog("Username: " + TargetDomainName + "\\" + TargetUserName, "OUTPUT");
                            Helper.WriteToLog("Auth: " + AuthenticationPackageName, "OUTPUT");
                            Helper.WriteToLog("Auth Package: " + LmPackageName, "OUTPUT");

                            string eventRecordString = SaveEventRecord(eventRecord);

                            if (Helper.isRemoteIP(IP))
                            {
                                Helper.WriteToLog("IP Address: " + IP, "OUTPUT");
                                Helper.WriteToLog("IP Port: " + Port, "OUTPUT");
                            }

                            List<string> toastLines = RuleEngine.BuildLogonFailedToastLines(
                                logonType,
                                TargetDomainName,
                                TargetUserName,
                                IP,
                                SubjectDomainName,
                                WorkstationName,
                                AuthenticationPackageName,
                                LmPackageName);
                            ToastHelper.ShowToast(eventRecordString, toastLines.ToArray());
                        }
                    }
                    else
                    {
                        Helper.WriteToLog("Could not parse the Logon Type number: " + LogonType, "ERROR");
                    }

                    

                }
                catch (System.ArgumentOutOfRangeException)
                {
                    Helper.WriteToLog("Tried to print a vaule outside of pre-prescribed XPath Array", "ERROR");
                }
                catch (System.NullReferenceException)
                {
                    Helper.WriteToLog("Event Log had an unexpected Null", "ERROR");
                }
                finally
                {
                    Helper.WriteToLog("---------------------------------------");
                }
            }
        } // end process4625_LogonFailed




        // I found this happend when I deleted a user. 
        // Test with: net user temp /add ; net user temp /delete
        internal void process4798_LocalGroupEnum(EventRecordWrittenEventArgs eventRecord)
        {
            if (TestMode)
                TestTriggeredEventIDs.Add(4798);

            String[] xPathArray = new[]
                {
                    "Event/EventData/Data[@Name='SubjectUserName']",
                    "Event/EventData/Data[@Name='TargetUserName']",
                    "Event/EventData/Data[@Name='CallerProcessName']",
                    "Event/EventData/Data[@Name='CallerProcessId']",
                };

            using (var loginEventPropertySelector = new EventLogPropertySelector(xPathArray))
            {
                try
                {
                    IList<object> logEventProps = ((EventLogRecord)eventRecord.EventRecord).GetPropertyValues(loginEventPropertySelector);
                    for (int i = 0; i < logEventProps.Count; i++)
                    {
                        if (logEventProps[i] == null || logEventProps[i].ToString() == "-")
                        {
                            logEventProps[i] = "";
                        }
                    }
                    Helper.WriteToLog("Description: \n" + eventRecord.EventRecord.FormatDescription());
                    Helper.WriteToLog("Description (XML): \n" + eventRecord.EventRecord.ToXml());

                    string SubjectUserName = logEventProps[0].ToString();
                    string TargetUserName = logEventProps[1].ToString();
                    string CallerProcessName = logEventProps[2].ToString();
                    string CallerProcessId = logEventProps[3].ToString();

                    if (RuleEngine.ShouldAlertLocalGroupEnum(SubjectUserName, CallerProcessName, CallerProcessId))
                    {
                        string eventRecordString = SaveEventRecord(eventRecord);
                        Helper.WriteToLog("Local Group was Enumerated by " + CallerProcessName, "OUTPUT");

                        ToastHelper.ShowToast(
                            eventRecordString,
                            "User " + SubjectUserName + " Enumerated the groups of local user " + TargetUserName,
                            "Process: " + CallerProcessName);
                    }
                    

                }
                catch (System.ArgumentOutOfRangeException)
                {
                    Helper.WriteToLog("Tried to print a vaule outside of pre-prescribed XPath Array", "ERROR");
                }
                catch (System.NullReferenceException)
                {
                    Helper.WriteToLog("Event Log had an unexpected Null", "ERROR");
                }
                finally
                {
                    Helper.WriteToLog("---------------------------------------");
                }
            }
        } // process4798_LocalGroupEnum

        
        // TODO: Figure out if I can do this via RPC and do it remotely
        internal void process4726_UserDeleted(EventRecordWrittenEventArgs eventRecord)
        {
            if (TestMode)
                TestTriggeredEventIDs.Add(4726);

            String[] xPathArray = new[]
                {
                    "Event/EventData/Data[@Name='SubjectUserName']", // Don't know what the structure of the XML is so TODO: fill in later
                    "Event/EventData/Data[@Name='TargetUserName']",
                };

            using (var loginEventPropertySelector = new EventLogPropertySelector(xPathArray))
            {
                try
                {
                    IList<object> logEventProps = ((EventLogRecord)eventRecord.EventRecord).GetPropertyValues(loginEventPropertySelector);
                    for (int i = 0; i < logEventProps.Count; i++)
                    {
                        if (logEventProps[i] == null || logEventProps[i].ToString() == "-")
                        {
                            logEventProps[i] = "";
                        }
                    }
                    string SubjectUserName = logEventProps[0].ToString();
                    string TargetUserName = logEventProps[1].ToString();

                    Helper.WriteToLog("Description: \n" + eventRecord.EventRecord.FormatDescription());
                    Helper.WriteToLog("Description (XML): \n" + eventRecord.EventRecord.ToXml());

                    // Store in 'Database' and save XML for user-mode toast agent
                    string eventRecordString = SaveEventRecord(eventRecord);

                    // Output to File, Console and Pop-up
                    Helper.WriteToLog("User " + SubjectUserName + " deleted local user " + TargetUserName, "OUTPUT");

                    // Toast via user-mode component
                    ToastHelper.ShowToast(
                        eventRecordString,
                        "User " + SubjectUserName + " deleted local user " + TargetUserName);

                    

                }
                catch (System.ArgumentOutOfRangeException)
                {
                    Helper.WriteToLog("Tried to print a vaule outside of pre-prescribed XPath Array", "ERROR");
                }
                catch (System.NullReferenceException)
                {
                    Helper.WriteToLog("Event Log had an unexpected Null", "ERROR");
                }
                finally
                {
                    Helper.WriteToLog("---------------------------------------");
                }
            }
        } // process4798_LocalGroupEnum

        // "An Auth Provider was loadead. Malicious ones are Rare but deadly. Possible to make a list of known valid ones"
        internal void process4610_LsassLoadedAuthPackage(EventRecordWrittenEventArgs eventRecord)
        {
            if (TestMode)
                TestTriggeredEventIDs.Add(4610);

            String[] xPathArray = new[]
                {
                    "Event/EventData/Data[@Name='SubjectUserName']", // Don't know what the structure of the XML is so TODO: fill in later
                };

            using (var loginEventPropertySelector = new EventLogPropertySelector(xPathArray))
            {
                try
                {
                    IList<object> logEventProps = ((EventLogRecord)eventRecord.EventRecord).GetPropertyValues(loginEventPropertySelector);
                    for (int i = 0; i < logEventProps.Count; i++)
                    {
                        if (logEventProps[i] == null || logEventProps[i].ToString() == "-")
                        {
                            logEventProps[i] = "";
                        }
                    }
                    Helper.WriteToLog("Description: \n" + eventRecord.EventRecord.FormatDescription());
                    Helper.WriteToLog("Description (XML): \n" + eventRecord.EventRecord.ToXml());

                    // Store in 'Database' and save XML for user-mode toast agent
                    string eventRecordString = SaveEventRecord(eventRecord);

                    // Output to File, Console and Pop-up
                    Helper.WriteToLog("An Auth Provider was loadead", "OUTPUT");

                    // Toast via user-mode component
                    ToastHelper.ShowToast(
                        eventRecordString,
                        "An Auth Provider was loadead",
                        "The source probably needs to be added to the known-good list");

                    

                }
                catch (System.ArgumentOutOfRangeException)
                {
                    Helper.WriteToLog("Tried to print a vaule outside of pre-prescribed XPath Array", "ERROR");
                }
                catch (System.NullReferenceException)
                {
                    Helper.WriteToLog("Event Log had an unexpected Null", "ERROR");
                }
                finally
                {
                    Helper.WriteToLog("---------------------------------------");
                }
            }
        }

        // 4611 is logged at startup and occasionally afterwards for each logon process on the system. Possible to make a list of known valid ones
        internal void process4611_LsassLogon(EventRecordWrittenEventArgs eventRecord)
        {
            if (TestMode)
                TestTriggeredEventIDs.Add(4611);

            String[] xPathArray = new[]
                {
                    "Event/EventData/Data[@Name='SubjectUserName']", // Don't know what the structure of the XML is so TODO: fill in later
                    "Event/EventData/Data[@Name='LogonProcessName']", // Don't know what the structure of the XML is so TODO: fill in later
                };

            using (var loginEventPropertySelector = new EventLogPropertySelector(xPathArray))
            {
                try
                {
                    IList<object> logEventProps = ((EventLogRecord)eventRecord.EventRecord).GetPropertyValues(loginEventPropertySelector);
                    for (int i = 0; i < logEventProps.Count; i++)
                    {
                        if (logEventProps[i] == null || logEventProps[i].ToString() == "-")
                        {
                            logEventProps[i] = "";
                        }
                    }
                    String SubjectUserName = logEventProps[0].ToString();
                    String LogonProcessName = logEventProps[1].ToString();
                    Helper.WriteToLog("Description: \n" + eventRecord.EventRecord.FormatDescription());
                    Helper.WriteToLog("Description (XML): \n" + eventRecord.EventRecord.ToXml());

                    if (RuleEngine.ShouldAlertLsassLogon(LogonProcessName))
                    {
                        string eventRecordString = SaveEventRecord(eventRecord);
                        Helper.WriteToLog("Lsass Logged on a Process: " + LogonProcessName, "OUTPUT");

                        ToastHelper.ShowToast(
                            eventRecordString,
                            "Lsass Logged on a Process: " + LogonProcessName,
                            "Done by: " + SubjectUserName,
                            RuleEngine.GetLsassLogonProcessHint(LogonProcessName));
                    }


                    

                }
                catch (System.ArgumentOutOfRangeException)
                {
                    Helper.WriteToLog("Tried to print a vaule outside of pre-prescribed XPath Array", "ERROR");
                }
                catch (System.NullReferenceException)
                {
                    Helper.WriteToLog("Event Log had an unexpected Null", "ERROR");
                }
                finally
                {
                    Helper.WriteToLog("---------------------------------------");
                }
            }
        }

        // DLLs that Windows calls into whenenever a user changes his/her password. Malicious ones are Rare but deadly
        internal void process4614_NotifcationPackageLoaded(EventRecordWrittenEventArgs eventRecord)
        {
            if (TestMode)
                TestTriggeredEventIDs.Add(4614);

            String[] xPathArray = new[]
                {
                    "Event/EventData/Data[@Name='SubjectUserName']", // Don't know what the structure of the XML is so TODO: fill in later
                };

            using (var loginEventPropertySelector = new EventLogPropertySelector(xPathArray))
            {
                try
                {
                    IList<object> logEventProps = ((EventLogRecord)eventRecord.EventRecord).GetPropertyValues(loginEventPropertySelector);
                    for (int i = 0; i < logEventProps.Count; i++)
                    {
                        if (logEventProps[i] == null || logEventProps[i].ToString() == "-")
                        {
                            logEventProps[i] = "";
                        }
                    }
                    Helper.WriteToLog("Description: \n" + eventRecord.EventRecord.FormatDescription());
                    Helper.WriteToLog("Description (XML): \n" + eventRecord.EventRecord.ToXml());

                    // Store in 'Database' and save XML for user-mode toast agent
                    string eventRecordString = SaveEventRecord(eventRecord);

                    // Output to File, Console and Pop-up
                    Helper.WriteToLog("Dll was given a password due to password reset", "OUTPUT");

                    // Toast via user-mode component
                    ToastHelper.ShowToast(
                        eventRecordString,
                        "Dll was given a password due to password reset",
                        "The Dll probably needs to be added to the known-good list");

                    

                }
                catch (System.ArgumentOutOfRangeException)
                {
                    Helper.WriteToLog("Tried to print a vaule outside of pre-prescribed XPath Array", "ERROR");
                }
                catch (System.NullReferenceException)
                {
                    Helper.WriteToLog("Event Log had an unexpected Null", "ERROR");
                }
                finally
                {
                    Helper.WriteToLog("---------------------------------------");
                }
            }
        }

        // "An Auth Providers or Support Package was loadead. Malicious ones are Rare but deadly. Possible to make a list of known valid ones"
        internal void process4622_LsassLoadedPackage(EventRecordWrittenEventArgs eventRecord)
        {
            if (TestMode)
                TestTriggeredEventIDs.Add(4622);

            String[] xPathArray = new[]
                {
                    "Event/EventData/Data[@Name='SubjectUserName']", // Don't know what the structure of the XML is so TODO: fill in later
                };

            using (var loginEventPropertySelector = new EventLogPropertySelector(xPathArray))
            {
                try
                {
                    IList<object> logEventProps = ((EventLogRecord)eventRecord.EventRecord).GetPropertyValues(loginEventPropertySelector);
                    for (int i = 0; i < logEventProps.Count; i++)
                    {
                        if (logEventProps[i] == null || logEventProps[i].ToString() == "-")
                        {
                            logEventProps[i] = "";
                        }
                    }

                    Helper.WriteToLog("Description: \n" + eventRecord.EventRecord.FormatDescription());
                    Helper.WriteToLog("Description (XML): \n" + eventRecord.EventRecord.ToXml());

                    // Store in 'Database' and save XML for user-mode toast agent
                    string eventRecordString = SaveEventRecord(eventRecord);

                    // Output to File, Console and Pop-up
                    Helper.WriteToLog("Lsass Loaded a Package!", "OUTPUT");

                    // Toast via user-mode component
                    ToastHelper.ShowToast(
                        eventRecordString,
                        "Lsass Loaded a Package!",
                        "This probably needs to be added to the known-good list");

                    

                }
                catch (System.ArgumentOutOfRangeException)
                {
                    Helper.WriteToLog("Tried to print a vaule outside of pre-prescribed XPath Array", "ERROR");
                }
                catch (System.NullReferenceException)
                {
                    Helper.WriteToLog("Event Log had an unexpected Null", "ERROR");
                }
                finally
                {
                    Helper.WriteToLog("---------------------------------------");
                }
            }
        }


        // Test with: runas /user:user cmd
        internal void process4624_LogonSuccess(EventRecordWrittenEventArgs eventRecord)
        {
            if (TestMode)
                TestTriggeredEventIDs.Add(4624);

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
                    "Event/EventData/Data[@Name='LogonGuid']",  // Seems to be "{00000000-0000-0000-0000-000000000000}" for (Malicious) WinRM connections
                };

            using (var loginEventPropertySelector = new EventLogPropertySelector(xPathArray))
            {
                try
                {
                    IList<object> logEventProps = ((EventLogRecord)eventRecord.EventRecord).GetPropertyValues(loginEventPropertySelector);
                    for (int i = 0; i < logEventProps.Count; i++)
                    {
                        if (logEventProps[i] == null || logEventProps[i].ToString() == "-")
                        {
                            logEventProps[i] = "";
                        }
                    }
                    String SID = logEventProps[0].ToString();
                    String LogonId = logEventProps[1].ToString();
                    String LogonType = logEventProps[2].ToString();
                    String ElevatedToken = logEventProps[3].ToString();
                    String WorkstationName = logEventProps[4].ToString();
                    String ProcessName = logEventProps[5].ToString();
                    String IP = logEventProps[6].ToString();
                    String Port = logEventProps[7].ToString();
                    String TargetDomainName = logEventProps[8].ToString();
                    String TargetUserName = logEventProps[9].ToString();
                    String SubjectUserName = logEventProps[10].ToString();
                    String SubjectDomainName = logEventProps[11].ToString();
                    String AuthenticationPackageName = logEventProps[12].ToString();
                    String LmPackageName = logEventProps[13].ToString();
                    String LogonGuid = logEventProps[14].ToString();

                    Helper.WriteToLog("SID: " + SID);
                    Helper.WriteToLog("Logon Id: " + LogonId);
                    Helper.WriteToLog("Logon Type: " + LogonType);
                    Helper.WriteToLog("Elevated Token: " + ElevatedToken);
                    Helper.WriteToLog("Workstation Name: " + WorkstationName); 
                    Helper.WriteToLog("Process Name: " + ProcessName);
                    Helper.WriteToLog("IP Address: " + IP);
                    Helper.WriteToLog("IP Port: " + Port);
                    Helper.WriteToLog("Description: \n" + eventRecord.EventRecord.FormatDescription());
                    Helper.WriteToLog("Description (XML): \n" + eventRecord.EventRecord.ToXml());

                    int logonType = 0;
                    if (int.TryParse(LogonType, out logonType))
                    {
                        if (RuleEngine.ShouldEvaluateLogonType(logonType))
                        {
                            Helper.WriteToLog("Logon Success: ", "OUTPUT");
                            Helper.WriteToLog("Logon Type: " + LogonType, "OUTPUT");
                            Helper.WriteToLog("Username: " + TargetDomainName + "\\" + TargetUserName, "OUTPUT");
                            Helper.WriteToLog("Auth: " + AuthenticationPackageName, "OUTPUT");
                            Helper.WriteToLog("Auth Package: " + LmPackageName, "OUTPUT");

                            string eventRecordString = SaveEventRecord(eventRecord);

                            if (Helper.isRemoteIP(IP))
                            {
                                Helper.WriteToLog("IP Address: " + IP, "OUTPUT");
                                Helper.WriteToLog("IP Port: " + Port, "OUTPUT");
                            }

                            if (RuleEngine.IsKerberosMachineNoise(logonType, AuthenticationPackageName, TargetUserName))
                            {
                                Helper.WriteToLog("(Kerberos is being weird again)", "OUTPUT");
                            }
                            else
                            {
                                List<string> toastLines = RuleEngine.BuildLogonSuccessToastLines(
                                    logonType,
                                    TargetDomainName,
                                    TargetUserName,
                                    IP,
                                    WorkstationName,
                                    AuthenticationPackageName,
                                    LmPackageName);
                                ToastHelper.ShowToast(eventRecordString, toastLines.ToArray());
                            }
                        }
                    }
                    else
                    {
                        Helper.WriteToLog("Could not parse the Logon Type number: " + LogonType, "ERROR");
                    }

                    

                }
                catch (System.ArgumentOutOfRangeException)
                {
                    Helper.WriteToLog("Tried to print a vaule outside of pre-prescribed XPath Array", "ERROR");
                }
                catch (System.NullReferenceException)
                {
                    Helper.WriteToLog("Event Log had an unexpected Null", "ERROR");
                }
                finally
                {
                    Helper.WriteToLog("---------------------------------------");
                }
            }
        }

    } // end class
} // end namespace

