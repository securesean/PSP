using System;
using System.IO;

namespace PSP_Console
{
    public static class LicenseManager
    {
        public const string LicenseText =
@"===================================================================================
Personal Security Product (PSP) - Basic License & End-User License Agreement (EULA)
===================================================================================
Copyright (c) 2021-2026 Sean Pierce (MIT License)

Permission is hereby granted, free of charge, to any person obtaining a copy of this
software and associated documentation files (the ""Software""), to deal in the Software
without restriction, subject to the conditions of the MIT License.

END-USER LICENSE AGREEMENT (EULA) & DISCLAIMER:
1. AUTHORIZED USE ONLY: You may only install or run PSP on systems you own or have
   explicit administrative authorization to monitor.
2. SYSTEM CONFIGURATION: PSP may configure Windows Audit Policies, listen on ports
   for port-scan detection, or execute user-selected response actions.
3. NO WARRANTY: THE SOFTWARE IS PROVIDED ""AS IS"", WITHOUT WARRANTY OF ANY KIND,
   EXPRESS OR IMPLIED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY CLAIM, DAMAGES,
   OR OTHER LIABILITY ARISING FROM THE USE OF THIS SOFTWARE.
===================================================================================";

        public static void DisplayLicense()
        {
            Console.WriteLine(LicenseText);
            Helper.WriteToLog("Displayed Basic License & EULA:\n" + LicenseText, "OUTPUT");
        }

        public static void EnsureFirstRunLicenseShown()
        {
            try
            {
                string markerFile = Path.Combine(Helper.path, "eula_shown.txt");
                if (!File.Exists(markerFile))
                {
                    DisplayLicense();
                    if (!Directory.Exists(Helper.path))
                    {
                        Directory.CreateDirectory(Helper.path);
                    }
                    File.WriteAllText(markerFile, "EULA displayed on " + DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss") + Environment.NewLine + LicenseText);
                }
                else
                {
                    Helper.WriteToLog("Personal Security Product (PSP) - Copyright (c) Sean Pierce. Run with --license to view full License & EULA.");
                }
            }
            catch
            {
            }
        }
    }
}
