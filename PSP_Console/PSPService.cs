using System;
using System.ServiceProcess;
using System.Threading;

namespace PSP_Console
{
    public class PSPService : ServiceBase
    {
        public const string ServiceNameConst = "PSPService";
        public const string DisplayNameConst = "Personal Security Product";
        private Thread _workerThread;
        private ManualResetEvent _stopEvent;

        public PSPService()
        {
            this.ServiceName = ServiceNameConst;
            this.CanStop = true;
            this.CanPauseAndContinue = false;
            this.AutoLog = true;
        }

        protected override void OnStart(string[] args)
        {
            Helper.WriteToLog("PSPService starting...");
            ToastHelper.EnsureAlertDirectories();
            ServiceManager.EnsureUserModeNotifierRunning();

            _stopEvent = new ManualResetEvent(false);
            _workerThread = new Thread(() =>
            {
                try
                {
                    Program.RunServiceSubscription(_stopEvent);
                }
                catch (Exception ex)
                {
                    Helper.LogCrash("PSPService Worker Thread Crash", ex);
                }
            });
            _workerThread.IsBackground = true;
            _workerThread.Start();
            Helper.WriteToLog("PSPService started successfully.", "OUTPUT");
        }

        protected override void OnStop()
        {
            Helper.WriteToLog("PSPService stopping...");
            try
            {
                if (_stopEvent != null)
                {
                    _stopEvent.Set();
                }
                if (_workerThread != null && _workerThread.IsAlive)
                {
                    _workerThread.Join(5000);
                }
            }
            catch (Exception ex)
            {
                Helper.WriteToLog("Error while stopping PSPService: " + ex.Message, "ERROR");
            }
            Helper.WriteToLog("PSPService stopped.", "OUTPUT");
        }
    }
}
