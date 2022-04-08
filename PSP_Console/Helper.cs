using Microsoft.Toolkit.Uwp.Notifications;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.DirectoryServices.AccountManagement;
using System.IO;
using System.Management;

namespace PSP_Console
{
    class Helper
    {
        /*
         * level = "INFO", "ERROR", "OUTPUT"
         * */

        public static string path = System.Environment.GetEnvironmentVariable("PROGRAMDATA") + "\\PSP_Logs";
        public static string filepath = path + "\\PSP_Log_" + DateTime.Now.Date.ToShortDateString().Replace('/', '_') + ".txt";
        private static readonly object _syncObject = new object();

        public static void WriteToLog(string Message, string level = "INFO")
        {
            level = level.ToUpper();

            // Craft message //
            string prefix = "[ ] ";
            if (level == "ERROR")
            {
                prefix = "[!] ";
            }
            // Doesn't seem very useful
            //Process currentProcess = Process.GetCurrentProcess();
            // " PID-" + currentProcess.Id.ToString() +
            String sumString = prefix + DateTime.Now.ToLongTimeString() +  ": " + Message;


            // Log to Console //
            Console.ForegroundColor = ConsoleColor.Blue;
            if (level == "ERROR")
            {
                Console.ForegroundColor = ConsoleColor.Red;
            } else if (level == "OUTPUT")
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
            }
            System.Console.WriteLine(sumString);
            Console.ForegroundColor = ConsoleColor.White;   // Resetting back to normal

            

            // Log to file //
            if (!Directory.Exists(path))
            {
                Directory.CreateDirectory(path);
            }
            if (!File.Exists(filepath))
            {
                // Create a file to write to.   
                using (StreamWriter sw = File.CreateText(filepath))
                {
                    sw.WriteLine(sumString);
                }
            }
            else
            {
                using (StreamWriter sw = File.AppendText(filepath))
                {
                    lock (_syncObject)
                    {
                        sw.WriteLine(sumString);
                    }
                }
            }


        }
        private static ManagementObjectCollection CheckWmiQuery(string wminamespace, string query)
        {
            ManagementObjectCollection instances;
            string wmipathstr = @"\\" + Environment.MachineName + wminamespace;
            //WriteToLog("Namespace: " + wmipathstr);
            //WriteToLog("Query: " + query);
            ManagementObjectSearcher searcher = new System.Management.ManagementObjectSearcher(wmipathstr, query);
            instances = searcher.Get();
            return instances;
        }

        internal static List<string> GetLocalRDPSIDs()
        {
            List<string> SidsFromLocalRDPGroup = new List<string>();
            try
            {
                PrincipalContext ctx = new PrincipalContext(ContextType.Machine);
                GroupPrincipal rdpGroup = GroupPrincipal.FindByIdentity(ctx, IdentityType.Sid, "S-1-5-32-555");

                var adminMembers = rdpGroup.GetMembers(true);

                foreach (Principal principal in adminMembers)
                {
                    SidsFromLocalRDPGroup.Add(principal.Sid.ToString());
                }

                adminMembers.Dispose();
                ctx.Dispose();
            }
            catch (Exception ex)
            {
                WriteToLog("\tFailed to get admin group: " + ex.Message);
            }
            return SidsFromLocalRDPGroup;
        }

        internal static List<string> GetLocalAdminSIDs()
        {
            List<string> SidsFromLocalAdminGroup = new List<string>();
            try
            {
                PrincipalContext ctx = new PrincipalContext(ContextType.Machine);
                GroupPrincipal adminGroup = GroupPrincipal.FindByIdentity(ctx, IdentityType.Sid, "S-1-5-32-544");

                var adminMembers = adminGroup.GetMembers(true);

                foreach (Principal principal in adminMembers)
                {
                    SidsFromLocalAdminGroup.Add(principal.Sid.ToString());
                }

                adminMembers.Dispose();
                ctx.Dispose();
            }
            catch (Exception ex)
            {
                WriteToLog("\tFailed to get admin group: " + ex.Message);
            }
            return SidsFromLocalAdminGroup;
        }
        internal static List<string> GetLocalAdminSIDs_slow_in_enterprises()
        {
            List<string> SidsFromLocalAdminGroup = new List<string>();
            ManagementObjectCollection instances = CheckWmiQuery(@"\root\cimv2", "SELECT * FROM Win32_Group WHERE SID = 'S-1-5-32-544'");

            try
            {
                // This is occationally throwing the ManagementException exception
                //if (instances.Count == 0)
                //{
                //    WriteToLog("Could not find Admin group via WMI", "ERROR");
                //} else
                //{
                //if (instances.Count != 1)
                //{
                //    WriteToLog("There was more than one Admin group returned by WMI", "ERROR");
                //}
                    foreach (ManagementObject instance in instances)
                    {
                        Group aGroup = new Group((string)instance.GetPropertyValue("Domain"), (string)instance.GetPropertyValue("Name"));
                        aGroup.LocalAccount = (bool)instance.GetPropertyValue("LocalAccount");
                        aGroup.SID = (string)instance.GetPropertyValue("SID");

                        byte byteSIDType = (byte)instance.GetPropertyValue("SIDType");
                        int intSIDType = (int)byteSIDType;
                        aGroup.SIDType = (SIDType)intSIDType;

                        aGroup.Status = (string)instance.GetPropertyValue("Status");
                        string ErrorLevel = "INFO";
                        if (aGroup.Status != "OK")
                        {
                            ErrorLevel = "ERROR";
                        }

                    // System.Console.WriteLine(instance.GetText());

                        WriteToLog("-------------------------------------------------------------------------------");
                        WriteToLog(instance.ToString());
                        WriteToLog("\tDomain: " + instance.GetPropertyValue("Domain"), ErrorLevel);
                        WriteToLog("\tLocalAccount: " + instance.GetPropertyValue("LocalAccount"), ErrorLevel);
                        WriteToLog("\tName: " + instance.GetPropertyValue("Name"), ErrorLevel);
                        WriteToLog("\tSID: " + instance.GetPropertyValue("SID"), ErrorLevel);
                        WriteToLog("\tSIDType: " + instance.GetPropertyValue("SIDType"), ErrorLevel);

                        WriteToLog("\tStatus: " + instance.GetPropertyValue("Status"), ErrorLevel);
                        WriteToLog("-------------------------------------------------------------------------------");

                        //WriteToLog("\tGetting Users Related to the Admin group");
                        foreach (ManagementObject user in instance.GetRelated())
                        {
                            WriteToLog("-------------------------------------------------------------------------------");
                            WriteToLog("\t\tFound user. Getting SID");
                            /*  $group = gwmi win32_group -filter 'Name = "Administrators"'
                            // $group.GetRelated('Win32_UserAccount')           (Management.ManagementBaseObject)

                                ManagementObject#root\cimv2\Win32_Group

                                Name                MemberType    Definition
                                ----                ----------    ----------
                                PSComputerName      AliasProperty PSComputerName = __SERVER
                                Rename              Method        System.Management.ManagementBaseObject Rename(System.String Name)
                                Caption             Property      string Caption {get;set;}
                                Description         Property      string Description {get;set;}
                                Domain              Property      string Domain {get;set;}
                                InstallDate         Property      string InstallDate {get;set;}
                                LocalAccount        Property      bool LocalAccount {get;set;}
                                Name                Property      string Name {get;set;}
                                SID                 Property      string SID {get;set;}
                                SIDType             Property      byte SIDType {get;set;}
                                Status              Property      string Status {get;set;}
                                PSStatus            PropertySet   PSStatus {Status, Name}
                                ConvertFromDateTime ScriptMethod  System.Object ConvertFromDateTime();
                                ConvertToDateTime   ScriptMethod  System.Object ConvertToDateTime();

                                TODO: Create legit User Object
                            */

                            //User aUser = new User();
                            //aGroup.AddMember()


                            try
                            {
                                string sid = (string)user.GetPropertyValue("SID");
                                WriteToLog("\t\tSID: " + sid);
                                SidsFromLocalAdminGroup.Add(sid);
                                WriteToLog("\t\tDone Adding SID: " + sid);
                                
                            }
                            catch (System.Management.ManagementException ex)
                            {
                                // This occationally happens for reasons I cannot fathom
                                WriteToLog("WMI Failed to return information about a user in the admin's group: " + ex.Message, "ERROR");
                            }
                            WriteToLog("-------------------------------------------------------------------------------");


                    }
                        // This line is taking a FREAKISHLY long time... like sometimes MINUTES. maybe becuase commissioning the ManagementObject takes a while?
                        //WriteToLog("\tDone Getting Users Related to the Admin group");
                    }// End foreach
                    //WriteToLog("\tDone with Admin group");
                //} // End if statement

            }
            catch (System.Management.ManagementException e)
            {
                WriteToLog("WMI Failed to return information about the admin's group: " + e.Message, "ERROR");
            }
            
            //WriteToLog("\tReturning... ");
            return SidsFromLocalAdminGroup;
        }

        public static bool isRemoteIP(string ip)
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



    } // end class
}
