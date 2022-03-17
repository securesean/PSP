using Microsoft.Toolkit.Uwp.Notifications;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.DirectoryServices;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

// I just made this to hold all the Event processing code so everything wouldn't be all in one big .cs file
namespace PSP_Console
{
    internal class EventProcessor
    {
        private List<string> localAdminGroupList;
        private Dictionary<long, EventRecordWrittenEventArgs> RecordedEvents = new Dictionary<long, EventRecordWrittenEventArgs>();
        private string EventVaule_NotSet = "%%1793";
        Thread RefreshAdminListThread;
        public EventProcessor()
        {
            // Periodically get list of SID's in the admin group
            RefreshAdminListThread = new Thread(RefreshAdminListDriver);
            RefreshAdminListThread.Start();
            
        }

        private void RefreshAdminListDriver()
        {
            while (true)
            {
                // The WMI is taking 4 to 8 minutes!
                localAdminGroupList = Helper.GetLocalAdminSIDs();
                Thread.Sleep(1000 * 60);
            }
            
        }


        /*
         * Test with :
         * PS: Clear-EventLog Security
            cmd: wevtutil.exe cl Security
         * */
        internal void process1102_SecuritytLogCleared(EventRecordWrittenEventArgs eventRecord)
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

                    // Store in 'Database'
                    long record_id = (long)eventRecord.EventRecord.RecordId;
                    if (eventRecord.EventRecord.RecordId != null)
                    {
                        RecordedEvents.Add(record_id, eventRecord);
                    }
                    

                    // Toast 
                    ToastContentBuilder toast = new ToastContentBuilder()
                    .AddText(SubjectUserName + " Cleared Security Log!");
                    toast.AddArgument("conversationId", record_id);
                    toast.Show();

                    Helper.WriteToLog("---------------------------------------");

                }
                catch (System.ArgumentOutOfRangeException)
                {
                    Helper.WriteToLog("Tried to print a vaule outside of pre-prescribed XPath Array", "ERROR");
                }
                catch (System.NullReferenceException)
                {
                    Helper.WriteToLog("Event Log had an unexpected Null", "ERROR");
                }
            }
        }

        internal void WriteAndOpen(string eventRecordString)
        {
            long eventRecord = 0;
            if (long.TryParse(eventRecordString, out eventRecord))
            {
                
                WriteAndOpen(eventRecord);
            }else
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

            } else
            {
                return false;
            }
        }

        // Test with: sc.exe create aService3 start= delayed-auto binpath= C:\a.exe
        // ToDo: change to'Installed Service: <name>'
        // And list the executeable that did the installation 
        internal void process4697_ServiceInstalled(EventRecordWrittenEventArgs eventRecord)
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

                    // Store in 'Database'
                    long record_id = (long)eventRecord.EventRecord.RecordId;
                    if (eventRecord.EventRecord.RecordId != null)
                    {
                        RecordedEvents.Add(record_id, eventRecord);
                    }

                    // Output to File, Console and Pop-up
                    Helper.WriteToLog("User who installed Service: " + SubjectUserName, "OUTPUT");
                    Helper.WriteToLog("ServiceName: " + ServiceName, "OUTPUT");
                    Helper.WriteToLog("ServiceFileName: " + ServiceFileName, "OUTPUT");

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
                    .AddArgument("conversationId", record_id)
                    .AddText("Service Installed by " + SubjectUserName)
                    .AddText("ServiceName: " + ServiceName)
                    .AddText("ServiceFileName: " + ServiceFileName);
                    toast.Show();



                    Helper.WriteToLog("---------------------------------------");

                }
                catch (System.ArgumentOutOfRangeException)
                {
                    Helper.WriteToLog("Tried to print a vaule outside of pre-prescribed XPath Array", "ERROR");
                }
                catch (System.NullReferenceException)
                {
                    Helper.WriteToLog("Event Log had an unexpected Null", "ERROR");
                }
            }
        } // end process4697_ServiceInstalled

        // net user Administrator /active:yes; net user Administrator /active:no
        internal void process4726_UserEnabled(EventRecordWrittenEventArgs eventRecord)
        {
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

                    // Store in 'Database'
                    long record_id = (long)eventRecord.EventRecord.RecordId;
                    if (eventRecord.EventRecord.RecordId != null)
                    {
                        RecordedEvents.Add(record_id, eventRecord);
                    }

                    // Output to File, Console and Pop-up
                    Helper.WriteToLog(SubjectUserName + " enabled the local user " + TargetUserName, "OUTPUT");

                    // Toast 
                    ToastContentBuilder toast = new ToastContentBuilder()
                    .AddArgument("conversationId", record_id)
                    .AddText(SubjectUserName + " enabled the local user " + TargetUserName);
                    if (TargetSid.ToString().EndsWith("-500"))
                    {
                        toast.AddText(TargetUserName + " is the local RID 500 Admin account! ");
                    }
                        
                    toast.Show();

                    Helper.WriteToLog("---------------------------------------");

                }
                catch (System.ArgumentOutOfRangeException)
                {
                    Helper.WriteToLog("Tried to print a vaule outside of pre-prescribed XPath Array", "ERROR");
                }
                catch (System.NullReferenceException)
                {
                    Helper.WriteToLog("Event Log had an unexpected Null", "ERROR");
                }
            }
        }

        // Test with> net user temp /add ; net user temp Password12345; net user temp /delete
        internal void process4724_PasswordReset(EventRecordWrittenEventArgs eventRecord)
        {
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

                    // Store in 'Database'
                    long record_id = (long)eventRecord.EventRecord.RecordId;
                    if (eventRecord.EventRecord.RecordId != null)
                    {
                        RecordedEvents.Add(record_id, eventRecord);
                    }

                    // Output to File, Console
                    Helper.WriteToLog(SubjectUserName + " performed a performed a password reset for '" + TargetUserName + "'", "OUTPUT");

                    // Toast 
                    ToastContentBuilder toast = new ToastContentBuilder()
                    .AddArgument("conversationId", record_id)
                    .AddText(SubjectUserName + " performed a performed a password reset for '" + TargetUserName + "'");
                    
                    toast.Show();



                    Helper.WriteToLog("---------------------------------------");

                }
                catch (System.ArgumentOutOfRangeException)
                {
                    Helper.WriteToLog("Tried to print a vaule outside of pre-prescribed XPath Array", "ERROR");
                }
                catch (System.NullReferenceException)
                {
                    Helper.WriteToLog("Event Log had an unexpected Null", "ERROR");
                }
            }
        }

        //  runas /user:temp cmd
        internal void process4648_UserLogonWithCreds(EventRecordWrittenEventArgs eventRecord)
        {
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

                    // I don't know why, but sometimes the LOCAL SYSTEM (S-1-5-18) will logon with creds as the machine account
                    // added "Event/EventData/Data[@Name='SubjectUserSid']", 
                    if (SubjectUserSid != "S-1-5-18" && !SubjectUserName.ToUpper().Contains(Environment.MachineName.ToUpper() + "$"))
                    {

                        // Store in 'Database'
                        long record_id = (long)eventRecord.EventRecord.RecordId;
                        if (eventRecord.EventRecord.RecordId != null)
                        {
                            RecordedEvents.Add(record_id, eventRecord);
                        }

                        // Output to File, Console
                        Helper.WriteToLog(SubjectUserName + " performed a logon using explicit creds (Usually runas.exe or RDP) as '" + TargetDomainName + "\\" + TargetUserName + "'", "OUTPUT");


                        // Toast 
                        ToastContentBuilder toast = new ToastContentBuilder()
                        .AddArgument("conversationId", record_id)
                        .AddText(SubjectUserName + " performed a logon using explicit creds as '" + TargetDomainName + "\\" + TargetUserName + "'");
                        if (Helper.isRemoteIP(IpAddress))
                        {
                            toast.AddText("From " + IpAddress);
                        }
                        toast.AddText("From " + ProcessName + " (PID: " + ProcessId + ")");
                        if (ProcessName.Contains("svchost.exe"))
                        {
                            toast.AddText("(svchost.exe usually means you usually just ran runas.exe)");
                        } else if (ProcessName.Contains("lsass.exe"))
                        {
                            toast.AddText("(lsass.exe usually means you just RDP'd)");
                        }
                        toast.Show();

                    }

                    Helper.WriteToLog("---------------------------------------");

                }
                catch (System.ArgumentOutOfRangeException)
                {
                    Helper.WriteToLog("Tried to print a vaule outside of pre-prescribed XPath Array", "ERROR");
                }
                catch (System.NullReferenceException)
                {
                    Helper.WriteToLog("Event Log had an unexpected Null", "ERROR");
                }
            }
        }

        // Test with net user temp /add ; net localgroup Administrators /add temp
        // cmd> net localgroup tempgroup /add temp
        // cmd> net localgroup "Remote Management Users" /add temp
        // cmd> net localgroup "Hyper-V Administrators" /delete temp;   net localgroup "Hyper-V Administrators" /add temp
        internal void process4732_UserAddedToGroup(EventRecordWrittenEventArgs eventRecord)
        {
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

                    // Store in 'Database'
                    long record_id = (long)eventRecord.EventRecord.RecordId;
                    if (eventRecord.EventRecord.RecordId != null)
                    {
                        RecordedEvents.Add(record_id, eventRecord);
                    }

                    string sid = MemberSid;
                    string localGroup = TargetUserName;
                    string translatedUserName = new System.Security.Principal.SecurityIdentifier(MemberSid).Translate(typeof(System.Security.Principal.NTAccount)).ToString();

                    // Output to File, Console and Pop-up
                    Helper.WriteToLog(SubjectUserName + " added a user (" + translatedUserName + ") to the local group: '" + TargetUserName + "'", "OUTPUT");

                    // Toast 
                    ToastContentBuilder toast = new ToastContentBuilder()
                    .AddArgument("conversationId", record_id)
                    .AddText(SubjectUserName + " added a user (" + translatedUserName + ") to the group: " + TargetUserName);


                    // Is the machine account doing it?
                    if ( !SubjectUserName.ToUpper().Contains(Environment.MachineName.ToUpper() + "$"))
                    {
                        Helper.WriteToLog("Machine Account was the one to query", "OUTPUT");
                    }

                    if (sid.EndsWith("-544") && localAdminGroupList.Contains(translatedUserName) )
                    {
                        Helper.WriteToLog("User was already in Admin Group!", "OUTPUT");
                    }



                    if (TargetSid.EndsWith("-544"))
                    {
                        toast.AddText("WARNING: User added to local Admin Group! ");
                    }
                    else if (TargetSid.EndsWith("--546")) {
                        toast.AddText("WARNING: User added to local Guest Group! ");
                    }
                    else if (TargetSid.EndsWith("-547"))
                    {
                        toast.AddText("WARNING: User added to local Power Users Group! ");
                    }
                    else if (TargetSid.EndsWith("-548"))
                    {
                        toast.AddText("WARNING: User added to local Account Operators Group! ");
                    }
                    else if (TargetSid.EndsWith("-549"))
                    {
                        toast.AddText("WARNING: User added to local Server Operators Group! ");
                    }
                    else if (TargetSid.EndsWith("-551"))
                    {
                        toast.AddText("WARNING: User added to local Backup Operators Group! ");
                    }
                    else if (TargetSid.EndsWith("-552"))
                    {
                        toast.AddText("WARNING: User added to local Replicators Group! ");
                    }
                    else if (TargetSid.EndsWith("-554"))
                    {
                        toast.AddText("WARNING: User added to backward compatibility group that allows read access on all users and groups in the domain! ");
                    }
                    else if (TargetSid.EndsWith("-555"))
                    {
                        toast.AddText("WARNING: User added to local RDP Group! ");
                    }
                    else if (TargetSid.EndsWith("-556"))
                    {
                        toast.AddText("WARNING: User added to Network Configuration Operators Group! ");
                    }
                    else if (TargetSid.EndsWith("-557"))
                    {
                        toast.AddText("WARNING: User added to Incoming Forest Trust Builders Group! ");
                    }
                    else if (TargetSid.EndsWith("-558"))
                    {
                        toast.AddText("WARNING: User added to Performance Monitor Users Group! ");
                    }
                    else if (TargetSid.EndsWith("-559"))
                    {
                        toast.AddText("WARNING: User added to Performance Log Users Group! ");
                    }
                    else if (TargetSid.EndsWith("-560"))
                    {
                        toast.AddText("WARNING: User added to Windows Authorization Access Group Group! ");
                    }
                    else if (TargetSid.EndsWith("-544"))
                    {
                        toast.AddText("WARNING: User added to Terminal Server License Servers Group! ");
                    }
                    else if (TargetSid.EndsWith("-561"))
                    {
                        toast.AddText("WARNING: User added to Terminal Server License Servers Group! ");
                    }
                    else if (TargetSid.EndsWith("-562"))
                    {
                        toast.AddText("WARNING: User added to Distributed COM Users Group! ");
                    }
                    else if (TargetSid.EndsWith("-569"))
                    {
                        toast.AddText("WARNING: User added to Cryptographic Operators Group! ");
                    }
                    else if (TargetSid.EndsWith("-573"))
                    {
                        toast.AddText("WARNING: User added to Event Log Readers Group! ");
                    }
                    else if (TargetSid.EndsWith("-574"))
                    {
                        toast.AddText("WARNING: User added to Certificate Service DCOM Access Group! ");
                    }
                    else if (TargetSid.EndsWith("-575"))
                    {
                        toast.AddText("WARNING: User added to RDS Remote Access Servers Group! ");
                    }
                    else if (TargetSid.EndsWith("-576"))
                    {
                        toast.AddText("WARNING: User added to RDS Endpoint Servers Group! ");
                    }
                    else if (TargetSid.EndsWith("-577"))
                    {
                        toast.AddText("WARNING: User added to RDS Management Servers Group! ");
                    }
                    else if (TargetSid.EndsWith("-578"))
                    {
                        toast.AddText("WARNING: Members of this group have complete and unrestricted access to all features of Hyper-V.");
                    }
                    else if (TargetSid.EndsWith("-579"))
                    {
                        toast.AddText("WARNING: Members of this group can remotely query authorization attributes and permissions for resources on this computer.");
                    }
                    else if (TargetSid.EndsWith("-580"))
                    {
                        toast.AddText("WARNING: Members of this group can access WMI resources over management protocols (such as WS-Management via the Windows Remote Management service). This applies only to WMI namespaces that grant access to the user.");
                    }
                    else if (TargetSid.EndsWith("-10"))
                    {
                        toast.AddText("WARNING: User added to NTLM Authentication Group! ");
                        toast.AddText("A SID that is used when the NTLM authentication package authenticated the client");
                    }
                    else if (TargetSid.EndsWith("-64-14"))
                    {
                        toast.AddText("WARNING: A SID that is used when the SChannel authentication package authenticated the client.");
                    }
                    else if (TargetSid.EndsWith("-64-21"))
                    {
                        toast.AddText("WARNING: A SID that is used when the Digest authentication package authenticated the client.");
                    }
                    else if (TargetSid.EndsWith("-5-80"))
                    {
                        toast.AddText("WARNING: A SID that is used as an NT Service account prefix.");
                    }
                    else if (TargetSid.EndsWith("-80-0"))
                    {
                        toast.AddText("WARNING: A group that includes all service processes that are configured on the system. Membership is controlled by the operating system. SID S-1-5-80-0 equals NT SERVICES\\ALL SERVICES. ");
                    }
                    else if (TargetSid.EndsWith("-83-0"))
                    {
                        toast.AddText("WARNING: User added to NT VIRTUAL MACHINE\\Virtual Machines Group! ");
                        toast.AddText("The group is created when the Hyper-V role is installed. Membership in the group is maintained by the Hyper-V Management Service (VMMS). This group requires the Create Symbolic Links right (SeCreateSymbolicLinkPrivilege), and also the Log on as a Service right (SeServiceLogonRight).");
                    }
                    else if (TargetSid.EndsWith("-501"))
                    {
                        toast.AddText("WARNING: User added to DOMAIN_USER_RID_GUEST Group! ");
                        toast.AddText("The guest-user account in a domain. Users who do not have an account can automatically sign in to this account.");
                    }
                    else if (TargetSid.EndsWith("-513"))
                    {
                        toast.AddText("WARNING: User added to DOMAIN_GROUP_RID_USERS Group! ");
                        toast.AddText("A group that contains all user accounts in a domain. All users are automatically added to this group.");
                    }
                    else if (TargetSid.EndsWith("-514"))
                    {
                        toast.AddText("WARNING: User added to DOMAIN_GROUP_RID_GUESTS Group! ");
                        toast.AddText("The group Guest account in a domain.");
                    }
                    else if (TargetSid.EndsWith("-515"))
                    {
                        toast.AddText("WARNING: User added to DOMAIN_GROUP_RID_COMPUTERS Group! ");
                        toast.AddText("The Domain Computer group. All computers in the domain are members of this group.");
                    }
                    else if (TargetSid.EndsWith("-516"))
                    {
                        toast.AddText("WARNING: User added to DOMAIN_GROUP_RID_CONTROLLERS Group! ");
                        toast.AddText("The Domain Controller group. All domain controllers in the domain are members of this group.");
                    }
                    else if (TargetSid.EndsWith("-517"))
                    {
                        toast.AddText("WARNING: User added to DOMAIN_GROUP_RID_CERT_ADMINS Group! ");
                        toast.AddText("The certificate publishers' group. Computers running Active Directory Certificate Services are members of this group.");
                    }
                    else if (TargetSid.EndsWith("-518"))
                    {
                        toast.AddText("WARNING: User added to DOMAIN_GROUP_RID_SCHEMA_ADMINS Group! ");
                        toast.AddText("The schema administrators' group. Members of this group can modify the Active Directory schema.");
                    }
                    else if (TargetSid.EndsWith("-519"))
                    {
                        toast.AddText("WARNING: User added to DOMAIN_GROUP_RID_ENTERPRISE_ADMINS Group! ");
                        toast.AddText("	The enterprise administrators' group. Members of this group have full access to all domains in the Active Directory forest. Enterprise administrators are responsible for forest-level operations such as adding or removing new domains.");
                    }
                    else if (TargetSid.EndsWith("-520"))
                    {
                        toast.AddText("WARNING: User added to DOMAIN_GROUP_RID_POLICY_ADMINS Group! ");
                        toast.AddText("The policy administrators' group.");
                    }
                    else 
                    {
                        toast.AddText("With a cumstom (Unknown) Group");
                    }

                    // I AM SO SORRY THIS IS SO SLOPPY. I suspect that everytime Group Policy is enforced, the API's add the
                    // correct users to the correct groups without checking to see if they are already in there. This means
                    // that every few hours this will redundantly tell me that the users that are already in the admin group
                    // are being added to the admin group. So this is a quick fix
                    // TODO: Create my own list of users & group memeberships
                    if(TargetSid.EndsWith("-544") && localAdminGroupList.Contains(MemberSid))
                    {
                        Helper.WriteToLog("Supressed alert notifying user added to the admin group because they were already a member");
                    }
                    else
                    {
                        toast.Show();
                    }
                        

                    Helper.WriteToLog("---------------------------------------");

                }
                catch (System.ArgumentOutOfRangeException)
                {
                    Helper.WriteToLog("Tried to print a vaule outside of pre-prescribed XPath Array", "ERROR");
                }
                catch (System.NullReferenceException)
                {
                    Helper.WriteToLog("Event Log had an unexpected Null", "ERROR");
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

                    // Store in 'Database'
                    long record_id = (long)eventRecord.EventRecord.RecordId;
                    if (eventRecord.EventRecord.RecordId != null)
                    {
                        RecordedEvents.Add(record_id, eventRecord);
                    }

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
                    Helper.WriteToLog(SubjectUsername + " Created a User Account: " + TargetUserName , "OUTPUT");
                    Helper.WriteToLog("TargetUserName: " + TargetUserName, "OUTPUT");
                    Helper.WriteToLog("SamAccountName: " + SamAccountName, "OUTPUT");
                    Helper.WriteToLog("DisplayName: " + DisplayName, "OUTPUT");
                    Helper.WriteToLog("UserPrincipalName: " + UserPrincipalName, "OUTPUT");

                    // Toast 
                    ToastContentBuilder toast = new ToastContentBuilder()
                    .AddArgument("conversationId", record_id)
                    .AddText("User " + SubjectUsername + " created account: " + TargetUserName);

                    string message = "";
                    // Looking at SAM account name
                    if(TargetUserName.Trim() != SamAccountName.Trim() && SamAccountName != "-" && SamAccountName.Trim() != "")
                    {
                        message += "Sam Account Name: " + SamAccountName + ".  ";
                    }

                    // Looking at DisplayName
                    if (TargetUserName.Trim() != DisplayName.Trim() && DisplayName != "-" && DisplayName.Trim() != "" && DisplayName.Trim() != EventVaule_NotSet)
                    {
                        message += "Display Name: " + DisplayName + ".  ";
                    }

                    // Looking at UserPrincipalName
                    if (TargetUserName.Trim() != UserPrincipalName.Trim() && UserPrincipalName != "-" && UserPrincipalName.Trim() != "" && UserPrincipalName.Trim() != EventVaule_NotSet)
                    {
                        message += "Display Name: " + DisplayName + ".  ";
                    }

                    // Looking at SidHistory
                    if (SidHistory != "-" && SidHistory.Trim() != "" && SidHistory.Trim() != EventVaule_NotSet)
                    {
                        message += "Interesting SID History: " + SidHistory + ".  ";
                        Helper.WriteToLog("Interesting SID History: " + SidHistory, "OUTPUT");
                    }

                    // Looking at Deligation
                    if (AllowedToDelegateTo != "-" && AllowedToDelegateTo.Trim() != "" && AllowedToDelegateTo.Trim() != EventVaule_NotSet)
                    {
                        message += "Interesting Deligation Powers: " + AllowedToDelegateTo + ".  ";
                        Helper.WriteToLog("Interesting Deligation Powers: " + AllowedToDelegateTo, "OUTPUT");
                    }

                    if (message != "")
                    {
                        toast.AddText(message);
                    }
                    toast.Show();

                    Helper.WriteToLog("---------------------------------------");

                }
                catch (System.ArgumentOutOfRangeException)
                {
                    Helper.WriteToLog("Tried to print a vaule outside of pre-prescribed XPath Array", "ERROR");
                }
                catch (System.NullReferenceException)
                {
                    Helper.WriteToLog("Event Log had an unexpected Null", "ERROR");
                }
            }
        }

        internal void process4625_LogonFailed(EventRecordWrittenEventArgs eventRecord)
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
                    "Event/EventData/Data[@Name='LogonGuid']",  // It seems to be "{00000000-0000-0000-0000-000000000000}" for (malicious) WinRM connections
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

                    // Rule logic. TODO: Create a blacklist style JSON config file
                    // See https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventID=4624
                    int logonType = 0;
                    if (int.TryParse(LogonType, out logonType))
                    {
                        if (logonType != 5 && logonType != 11 && logonType != 7 && logonType != 2)
                        // Further testing needed but I'll probably want to exclude
                        // 4	Batch (i.e. scheduled task)
                        // 2	Interactive (logon at keyboard and screen of system)
                        {
                            // Output to File, Console and Pop-up
                            Helper.WriteToLog("Logon Failed: ", "OUTPUT");
                            Helper.WriteToLog("Logon Type: " + LogonType, "OUTPUT");
                            Helper.WriteToLog("Username: " + TargetDomainName + "\\" + TargetUserName, "OUTPUT");
                            Helper.WriteToLog("Auth: " + AuthenticationPackageName, "OUTPUT");
                            Helper.WriteToLog("Auth Package: " + LmPackageName, "OUTPUT");

                            // Store in 'Database'
                            long record_id = (long)eventRecord.EventRecord.RecordId;
                            if (eventRecord.EventRecord.RecordId != null)
                            {
                                RecordedEvents.Add(record_id, eventRecord);
                            }

                            if (Helper.isRemoteIP(IP))
                            {
                                Helper.WriteToLog("IP Address: " + IP, "OUTPUT");
                                Helper.WriteToLog("IP Port: " + Port, "OUTPUT");
                            }

                            // Toast 
                            string message = "";
                            // From https://docs.microsoft.com/en-us/windows/apps/design/shell/tiles-and-notifications/adaptive-interactive-toasts?tabs=builder-syntax
                            ToastContentBuilder toast = new ToastContentBuilder()
                            .AddArgument("conversationId", record_id)
                            //.AddText("Logon Failed")
                            .AddText("Logon Failed Type: " + LogonType);

                            message += "Attempted Username: " + TargetDomainName + "\\" + TargetUserName;
                            if (Helper.isRemoteIP(IP))
                            {
                                message += "\nIP: " + IP;
                            }
                            if (SubjectDomainName != "" && WorkstationName != "")
                            {
                                message += "\nAttacker Hostname: " + SubjectDomainName + "\\" + WorkstationName;
                            }

                            // This is too many lines that toast will display (Max: 4)
                            if (AuthenticationPackageName != "" && AuthenticationPackageName != "-")
                            {
                                message += " Auth: " + AuthenticationPackageName;
                            }
                            if (LmPackageName == "" && LmPackageName == "-")
                            {
                                message += " Auth Package: " + LmPackageName;
                            }
                            toast.AddText(message);
                            toast.Show();
                        }
                    }
                    else
                    {
                        Helper.WriteToLog("Could not parse the Logon Type number: " + LogonType, "ERROR");
                    }

                    Helper.WriteToLog("---------------------------------------");

                }
                catch (System.ArgumentOutOfRangeException)
                {
                    Helper.WriteToLog("Tried to print a vaule outside of pre-prescribed XPath Array", "ERROR");
                }
                catch (System.NullReferenceException)
                {
                    Helper.WriteToLog("Event Log had an unexpected Null", "ERROR");
                }
            }
        } // end process4625_LogonFailed




        // I found this happend when I deleted a user. 
        // TODO: Figure out what exactly triggers 4798 LocalGroupEnum
        // Test with: net user temp /add ; net user temp /delete
        internal void process4798_LocalGroupEnum(EventRecordWrittenEventArgs eventRecord)
        {
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

                    if ((CallerProcessName != "-" && CallerProcessId != "0"))
                    {
                        // When alerting for local group enumeration, the machine account should just be ignored
                        if (!SubjectUserName.ToUpper().Contains(Environment.MachineName.ToUpper() + "$"))  // This might fail if the hostname is longer than 15 chars
                        {
                            // There seems to be a lot of WMI based group enumeration, I think I would only care if cmd.exe or something did it
                            if(CallerProcessName != @"C:\Windows\System32\wbem\WmiPrvSE.exe")
                            {
                                // Store in 'Database'
                                long record_id = (long)eventRecord.EventRecord.RecordId;
                                if (eventRecord.EventRecord.RecordId != null)
                                {
                                    RecordedEvents.Add(record_id, eventRecord);
                                }

                                // Output to File, Console and Pop-up
                                Helper.WriteToLog("Local Group was Enumerated by " + CallerProcessName, "OUTPUT");

                                // Toast 
                                ToastContentBuilder toast = new ToastContentBuilder()
                                .AddArgument("conversationId", record_id)
                                .AddText("User " + SubjectUserName + " Enumerated the groups of local user " + TargetUserName)
                                .AddText("Process: " + CallerProcessName);


                                toast.Show();
                            }
                        }
                    }
                    Helper.WriteToLog("---------------------------------------");

                }
                catch (System.ArgumentOutOfRangeException)
                {
                    Helper.WriteToLog("Tried to print a vaule outside of pre-prescribed XPath Array", "ERROR");
                }
                catch (System.NullReferenceException)
                {
                    Helper.WriteToLog("Event Log had an unexpected Null", "ERROR");
                }
            }
        } // process4798_LocalGroupEnum

        // Test with: net user temp /add ; net user temp /delete
        // TODO: Figure out if I can do this via RPC and do it remotely
        internal void process4726_UserDeleted(EventRecordWrittenEventArgs eventRecord)
        {
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

                    // Store in 'Database'
                    long record_id = (long)eventRecord.EventRecord.RecordId;
                    if (eventRecord.EventRecord.RecordId != null)
                    {
                        RecordedEvents.Add(record_id, eventRecord);
                    }

                    // Output to File, Console and Pop-up
                    Helper.WriteToLog("User " + SubjectUserName + " deleted local user " + TargetUserName, "OUTPUT");

                    // Toast 
                    ToastContentBuilder toast = new ToastContentBuilder()
                    .AddArgument("conversationId", record_id)
                    .AddText("User " + SubjectUserName + " deleted local user " + TargetUserName);
                    //.AddText("The source probably needs to be added to the known-good list");
                    toast.Show();

                    Helper.WriteToLog("---------------------------------------");

                }
                catch (System.ArgumentOutOfRangeException)
                {
                    Helper.WriteToLog("Tried to print a vaule outside of pre-prescribed XPath Array", "ERROR");
                }
                catch (System.NullReferenceException)
                {
                    Helper.WriteToLog("Event Log had an unexpected Null", "ERROR");
                }
            }
        } // process4798_LocalGroupEnum

        // "An Auth Provider was loadead. Malicious ones are Rare but deadly. Possible to make a list of known valid ones"
        internal void process4610_LsassLoadedAuthPackage(EventRecordWrittenEventArgs eventRecord)
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
                    for (int i = 0; i < logEventProps.Count; i++)
                    {
                        if (logEventProps[i] == null || logEventProps[i].ToString() == "-")
                        {
                            logEventProps[i] = "";
                        }
                    }
                    Helper.WriteToLog("Description: \n" + eventRecord.EventRecord.FormatDescription());
                    Helper.WriteToLog("Description (XML): \n" + eventRecord.EventRecord.ToXml());

                    // Store in 'Database'
                    long record_id = (long)eventRecord.EventRecord.RecordId;
                    if (eventRecord.EventRecord.RecordId != null)
                    {
                        RecordedEvents.Add(record_id, eventRecord);
                    }

                    // Output to File, Console and Pop-up
                    Helper.WriteToLog("An Auth Provider was loadead", "OUTPUT");

                    // Toast 
                    ToastContentBuilder toast = new ToastContentBuilder()
                    .AddArgument("conversationId", record_id)
                    .AddText("An Auth Provider was loadead")
                    .AddText("The source probably needs to be added to the known-good list");
                    toast.Show();

                    Helper.WriteToLog("---------------------------------------");

                }
                catch (System.ArgumentOutOfRangeException)
                {
                    Helper.WriteToLog("Tried to print a vaule outside of pre-prescribed XPath Array", "ERROR");
                }
                catch (System.NullReferenceException)
                {
                    Helper.WriteToLog("Event Log had an unexpected Null", "ERROR");
                }
            }
        }

        // 4611 is logged at startup and occasionally afterwards for each logon process on the system. Possible to make a list of known valid ones
        internal void process4611_LsassLogon(EventRecordWrittenEventArgs eventRecord)
        {
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

                    if (
                            LogonProcessName != "ConsentUI" && // UAC I believe
                            LogonProcessName != "Secondary Logon Service" && // runas.exe - STIG suggests that this be disabled: https://www.stigviewer.com/stig/windows_10/2017-12-01/finding/V-74719
                            LogonProcessName != "UserManager"  // Lock screen I believe

                        )
                    {
                        // Store in 'Database'
                        long record_id = (long)eventRecord.EventRecord.RecordId;
                        if (eventRecord.EventRecord.RecordId != null)
                        {
                            RecordedEvents.Add(record_id, eventRecord);
                        }


                        // Output to File, Console and Pop-up
                        Helper.WriteToLog("Lsass Logged on a Process: " + LogonProcessName, "OUTPUT");

                        // Toast 
                        ToastContentBuilder toast = new ToastContentBuilder()
                        .AddArgument("conversationId", record_id)
                        .AddText("Lsass Logged on a Process: " + LogonProcessName)
                        .AddText("Done by: " + SubjectUserName);

                        // TODO: Translate SID's to human readble
                        if(LogonProcessName.ToUpper() == "WINLOGON")
                        {
                            toast.AddText("This might be RDP Traffic");
                            toast.AddText("");
                        } else if (LogonProcessName.ToUpper() == "HTTP.SYS")
                        {
                            toast.AddText("This might be WinRM being enabled");
                        }
                        else
                        {
                            toast.AddText("The source probably needs to be added to the known-good list");
                        }
                        
                        toast.Show();
                    }
                    

                    Helper.WriteToLog("---------------------------------------");

                }
                catch (System.ArgumentOutOfRangeException)
                {
                    Helper.WriteToLog("Tried to print a vaule outside of pre-prescribed XPath Array", "ERROR");
                }
                catch (System.NullReferenceException)
                {
                    Helper.WriteToLog("Event Log had an unexpected Null", "ERROR");
                }
            }
        }

        // DLLs that Windows calls into whenenever a user changes his/her password. Malicious ones are Rare but deadly
        internal void process4614_NotifcationPackageLoaded(EventRecordWrittenEventArgs eventRecord)
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
                    for (int i = 0; i < logEventProps.Count; i++)
                    {
                        if (logEventProps[i] == null || logEventProps[i].ToString() == "-")
                        {
                            logEventProps[i] = "";
                        }
                    }
                    Helper.WriteToLog("Description: \n" + eventRecord.EventRecord.FormatDescription());
                    Helper.WriteToLog("Description (XML): \n" + eventRecord.EventRecord.ToXml());

                    // Store in 'Database'
                    long record_id = (long)eventRecord.EventRecord.RecordId;
                    if (eventRecord.EventRecord.RecordId != null)
                    {
                        RecordedEvents.Add(record_id, eventRecord);
                    }

                    // Output to File, Console and Pop-up
                    Helper.WriteToLog("Dll was given a password due to password reset", "OUTPUT");

                    // Toast 
                    ToastContentBuilder toast = new ToastContentBuilder()
                    .AddArgument("conversationId", record_id)
                    .AddText("Dll was given a password due to password reset")
                    .AddText("The Dll probably needs to be added to the known-good list"); ;
                    toast.Show();

                    Helper.WriteToLog("---------------------------------------");

                }
                catch (System.ArgumentOutOfRangeException)
                {
                    Helper.WriteToLog("Tried to print a vaule outside of pre-prescribed XPath Array", "ERROR");
                }
                catch (System.NullReferenceException)
                {
                    Helper.WriteToLog("Event Log had an unexpected Null", "ERROR");
                }
            }
        }

        // "An Auth Providers or Support Package was loadead. Malicious ones are Rare but deadly. Possible to make a list of known valid ones"
        internal void process4622_LsassLoadedPackage(EventRecordWrittenEventArgs eventRecord)
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
                    for (int i = 0; i < logEventProps.Count; i++)
                    {
                        if (logEventProps[i] == null || logEventProps[i].ToString() == "-")
                        {
                            logEventProps[i] = "";
                        }
                    }

                    Helper.WriteToLog("Description: \n" + eventRecord.EventRecord.FormatDescription());
                    Helper.WriteToLog("Description (XML): \n" + eventRecord.EventRecord.ToXml());

                    // Store in 'Database'
                    long record_id = (long)eventRecord.EventRecord.RecordId;
                    if (eventRecord.EventRecord.RecordId != null)
                    {
                        RecordedEvents.Add(record_id, eventRecord);
                    }

                    // Output to File, Console and Pop-up
                    Helper.WriteToLog("Lsass Loaded a Package!", "OUTPUT");

                    // Toast 
                    ToastContentBuilder toast = new ToastContentBuilder()
                    .AddArgument("conversationId", record_id)
                    .AddText("Lsass Loaded a Package!")
                    .AddText("This probably needs to be added to the known-good list"); ;
                    toast.Show();

                    Helper.WriteToLog("---------------------------------------");

                }
                catch (System.ArgumentOutOfRangeException)
                {
                    Helper.WriteToLog("Tried to print a vaule outside of pre-prescribed XPath Array", "ERROR");
                }
                catch (System.NullReferenceException)
                {
                    Helper.WriteToLog("Event Log had an unexpected Null", "ERROR");
                }
            }
        }



        // Test with: runas /user:user cmd
        internal void process4624_LogonSuccess(EventRecordWrittenEventArgs eventRecord)
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
                    "Event/EventData/Data[@Name='LogonGuid']",  // Seems to be "{00000000-0000-0000-0000-000000000000}" for (Malicious) WinRM connections
                };

            using (var loginEventPropertySelector = new EventLogPropertySelector(xPathArray))
            {
                try
                {
                    IList<object> logEventProps = ((EventLogRecord)eventRecord.EventRecord).GetPropertyValues(loginEventPropertySelector);
                    for(int i = 0; i < logEventProps.Count; i++)
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
                    Helper.WriteToLog("Workstation Name: " + WorkstationName); // Workstation Name: XPSTAU
                    Helper.WriteToLog("Process Name: " + ProcessName);
                    Helper.WriteToLog("IP Address: " + IP);
                    Helper.WriteToLog("IP Port: " + Port);
                    Helper.WriteToLog("Description: \n" + eventRecord.EventRecord.FormatDescription());
                    Helper.WriteToLog("Description (XML): \n" + eventRecord.EventRecord.ToXml());

                    // Rule logic. TODO: Create a blacklist style JSON config file
                    // See https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventID=4624
                    int logonType = 0;
                    if (int.TryParse(LogonType, out logonType))
                    {
                        if (logonType != 5 && logonType != 11 && logonType != 7 && logonType != 2)
                        // Further testing needed but I'll probably want to exclude
                        // 4	Batch (i.e. scheduled task)
                        // 2	Interactive (logon at keyboard and screen of system)
                        // 10   
                        {
                            // Output to File, Console and Pop-up
                            Helper.WriteToLog("Logon Success: ", "OUTPUT");
                            Helper.WriteToLog("Logon Type: " + LogonType, "OUTPUT");
                            Helper.WriteToLog("Username: " + TargetDomainName + "\\" + TargetUserName, "OUTPUT");
                            Helper.WriteToLog("Auth: " + AuthenticationPackageName, "OUTPUT");
                            Helper.WriteToLog("Auth Package: " + LmPackageName, "OUTPUT");

                            // Store in 'Database'
                            long record_id = (long)eventRecord.EventRecord.RecordId;
                            if (eventRecord.EventRecord.RecordId != null)
                            {
                                RecordedEvents.Add(record_id, eventRecord);
                            }

                            if (Helper.isRemoteIP(IP))
                            {
                                Helper.WriteToLog("IP Address: " + IP, "OUTPUT");
                                Helper.WriteToLog("IP Port: " + Port, "OUTPUT");
                            }

                            // For some unknown reason, when this is running on a domain joined machine I will get a
                            // local network logon from "kerberos" and with no subject information
                            // and to the machine account. This person appears to be saying the same thing:
                            // https://docs.microsoft.com/en-us/answers/questions/46899/computer-account-logon.html
                            if ((logonType == 3) && (AuthenticationPackageName == "Kerberos") && (TargetUserName.ToUpper().Contains(Environment.MachineName.ToUpper() + "$")))  // This might fail if the hostname is longer than 15 chars
                            {
                                Helper.WriteToLog("(Kerberos is being weird again)", "OUTPUT");
                            } else 
                            {
                                // Toast 
                                string message = "";
                                // From https://docs.microsoft.com/en-us/windows/apps/design/shell/tiles-and-notifications/adaptive-interactive-toasts?tabs=builder-syntax
                                ToastContentBuilder toast = new ToastContentBuilder()
                                .AddArgument("conversationId", record_id);

                                // Title Message
                                if(logonType == 10)
                                {
                                    toast.AddText("RDP Logon Success (Logon Type 10) ");
                                } else if((logonType == 3) && (LogonGuid.Contains("00000000-0000-0000-0000-000000000000")))
                                {
                                    toast.AddText("WinRM Logon Success (Type 3, Null GUID)");
                                }
                                    else
                                {
                                    toast.AddText("Logon Success Type: " + LogonType);
                                }

                                

                                message += "User: " + TargetDomainName + "\\" + TargetUserName;
                                if (Helper.isRemoteIP(IP))
                                {
                                    if (WorkstationName.Trim() == "")
                                    {
                                        message += "\nAttacker Hostname: " + WorkstationName;
                                    }
                                    message += "\nIP: " + IP;
                                }

                                // This is too many lines that toast will display (Max: 4)
                                if (AuthenticationPackageName != "" && AuthenticationPackageName != "-")
                                {
                                    message += " Auth: " + AuthenticationPackageName;
                                }
                                if (LmPackageName == "" && LmPackageName == "-")
                                {
                                    message += " Auth Package: " + LmPackageName;
                                }
                                toast.AddText(message);
                                toast.Show();
                            }
                            
                        }
                    }
                    else
                    {
                        Helper.WriteToLog("Could not parse the Logon Type number: " + LogonType, "ERROR");
                    }

                    Helper.WriteToLog("---------------------------------------");

                }
                catch (System.ArgumentOutOfRangeException)
                {
                    Helper.WriteToLog("Tried to print a vaule outside of pre-prescribed XPath Array", "ERROR");
                }
                catch (System.NullReferenceException)
                {
                    Helper.WriteToLog("Event Log had an unexpected Null", "ERROR");
                }
            }
        }

    } // end class
} // end namespace

