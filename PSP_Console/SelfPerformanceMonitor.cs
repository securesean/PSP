using System;
using System.Diagnostics;
using System.Threading;

namespace PSP_Console
{
    internal class SelfPerformanceMonitor
    {
        private Thread _monitorThread;
        private volatile bool _running = false;
        private readonly EventProcessor _eventProcessor;
        private long _baselineWorkingSetBytes;
        private const long MemoryWarningThresholdBytes = 150L * 1024L * 1024L; // 150 MB

        public SelfPerformanceMonitor(EventProcessor eventProcessor)
        {
            _eventProcessor = eventProcessor;
        }

        public void Start()
        {
            if (_running) return;
            _running = true;

            using (Process current = Process.GetCurrentProcess())
            {
                _baselineWorkingSetBytes = current.WorkingSet64;
                Helper.WriteToLog(
                    string.Format("SelfPerformanceMonitor started - Baseline WorkingSet: {0:F2} MB, PrivateMemory: {1:F2} MB, Handles: {2}, Threads: {3}",
                        current.WorkingSet64 / (1024.0 * 1024.0),
                        current.PrivateMemorySize64 / (1024.0 * 1024.0),
                        current.HandleCount,
                        current.Threads.Count));
            }

            _monitorThread = new Thread(MonitorLoop)
            {
                IsBackground = true,
                Name = "SelfPerformanceMonitorThread"
            };
            _monitorThread.Start();
        }

        public void Stop()
        {
            _running = false;
        }

        private void MonitorLoop()
        {
            while (_running)
            {
                for (int i = 0; i < 30 && _running; i++)
                {
                    Thread.Sleep(1000);
                }
                if (!_running) break;

                try
                {
                    CheckMemoryAndPerformance();
                }
                catch (Exception ex)
                {
                    Helper.LogCrash("SelfPerformanceMonitor.CheckMemoryAndPerformance", ex);
                }
            }
        }

        public void CheckMemoryAndPerformance()
        {
            using (Process current = Process.GetCurrentProcess())
            {
                long workingSet = current.WorkingSet64;
                long privateBytes = current.PrivateMemorySize64;
                long managedBytes = GC.GetTotalMemory(false);

                // Always keep EventProcessor's in-memory dictionary bounded to prevent memory leaks
                if (_eventProcessor != null)
                {
                    _eventProcessor.TrimRecordedEventsCache(200);
                }

                if (workingSet > MemoryWarningThresholdBytes || privateBytes > MemoryWarningThresholdBytes)
                {
                    Helper.WriteToLog(
                        string.Format("WARNING: High memory usage detected (WorkingSet={0:F2} MB, Private={1:F2} MB, Managed={2:F2} MB, Baseline={3:F2} MB). Running cache trim & GC...",
                            workingSet / (1024.0 * 1024.0),
                            privateBytes / (1024.0 * 1024.0),
                            managedBytes / (1024.0 * 1024.0),
                            _baselineWorkingSetBytes / (1024.0 * 1024.0)),
                        "ERROR");

                    if (_eventProcessor != null)
                    {
                        _eventProcessor.TrimRecordedEventsCache(50);
                    }
                    GC.Collect();
                    GC.WaitForPendingFinalizers();
                    GC.Collect();

                    current.Refresh();
                    Helper.WriteToLog(
                        string.Format("Post-GC Memory: WorkingSet={0:F2} MB, Private={1:F2} MB, Managed={2:F2} MB",
                            current.WorkingSet64 / (1024.0 * 1024.0),
                            current.PrivateMemorySize64 / (1024.0 * 1024.0),
                            GC.GetTotalMemory(false) / (1024.0 * 1024.0)),
                        "OUTPUT");
                }
            }
        }
    }
}
