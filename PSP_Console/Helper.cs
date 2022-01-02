﻿using Microsoft.Toolkit.Uwp.Notifications;
using System;
using System.Diagnostics;
using System.IO;

namespace PSP_Console
{
    class Helper
    {
        /*
         * level = "INFO", "ERROR", "OUTPUT"
         * */
        public static void WriteToLog(string Message, string level = "INFO")
        {
            level = level.ToUpper();

            // Craft message //
            string prefix = "[ ] ";
            if (level == "ERROR")
            {
                prefix = "[!] ";
            }
            Process currentProcess = Process.GetCurrentProcess();
            String sumString = prefix + DateTime.Now.ToShortDateString() + " PID-" + currentProcess.Id.ToString() + ": " + Message;


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
            string path = System.Environment.GetEnvironmentVariable("PROGRAMDATA") + "\\PSP_Logs";
            string filepath = path + "\\PSP_Log_" + DateTime.Now.Date.ToShortDateString().Replace('/', '_') + ".txt";
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
                    sw.WriteLine(sumString);
                }
            }


        }

    }
}