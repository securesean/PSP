using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Security;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace PSP_Console
{
    public class PortScanDetector
    {
        private readonly int[] _listenPorts;
        private readonly List<TcpListener> _listeners = new List<TcpListener>();
        private volatile bool _running = false;
        private readonly Dictionary<string, DateTime> _recentAlerts = new Dictionary<string, DateTime>();
        private readonly object _alertLock = new object();
        private static readonly int[] ReconPorts = new[] { 21, 22, 23, 80, 135, 139, 443, 445, 3389, 5985, 8080 };

        public bool TestPortConnectTriggered { get; private set; }
        public List<int> ActiveListeningPorts { get; } = new List<int>();

        public PortScanDetector(int[] portsToListen = null)
        {
            _listenPorts = portsToListen ?? new[] { 80, 443, 22 };
        }

        public void Start()
        {
            if (_running) return;
            _running = true;

            foreach (int port in _listenPorts)
            {
                int localPort = port;
                try
                {
                    TcpListener listener = new TcpListener(IPAddress.Any, localPort);
                    listener.Start();
                    _listeners.Add(listener);
                    ActiveListeningPorts.Add(localPort);

                    Thread acceptThread = new Thread(() => AcceptLoop(listener, localPort))
                    {
                        IsBackground = true,
                        Name = "PortScanListener_" + localPort
                    };
                    acceptThread.Start();
                    Helper.WriteToLog("PortScanDetector listening for connection attempts on TCP port " + localPort, "OUTPUT");
                }
                catch (SocketException ex)
                {
                    Helper.WriteToLog("PortScanDetector could not bind TCP port " + localPort + " (already in use or restricted): " + ex.Message);
                }
                catch (Exception ex)
                {
                    Helper.LogCrash("PortScanDetector Start Port " + localPort, ex);
                }
            }
        }

        public void Stop()
        {
            _running = false;
            foreach (TcpListener listener in _listeners)
            {
                try
                {
                    listener.Stop();
                }
                catch
                {
                }
            }
            _listeners.Clear();
            ActiveListeningPorts.Clear();
        }

        private void AcceptLoop(TcpListener listener, int localPort)
        {
            while (_running)
            {
                try
                {
                    TcpClient client = listener.AcceptTcpClient();
                    ThreadPool.QueueUserWorkItem(_ => HandleConnection(client, localPort));
                }
                catch (SocketException)
                {
                    if (!_running) break;
                }
                catch (ObjectDisposedException)
                {
                    break;
                }
                catch (Exception ex)
                {
                    if (_running)
                    {
                        Helper.LogCrash("PortScanDetector AcceptLoop Port " + localPort, ex);
                    }
                }
            }
        }

        private void HandleConnection(TcpClient client, int localPort)
        {
            string remoteIp = "Unknown";
            int remotePort = 0;
            string probePreview = "";

            try
            {
                using (client)
                {
                    IPEndPoint remoteEndPoint = client.Client.RemoteEndPoint as IPEndPoint;
                    if (remoteEndPoint != null)
                    {
                        remoteIp = remoteEndPoint.Address.ToString();
                        remotePort = remoteEndPoint.Port;
                    }

                    TestPortConnectTriggered = true;

                    // Try reading any initial probe bytes sent by scanner
                    try
                    {
                        client.ReceiveTimeout = 300;
                        NetworkStream stream = client.GetStream();
                        if (stream.DataAvailable)
                        {
                            byte[] buffer = new byte[256];
                            int read = stream.Read(buffer, 0, buffer.Length);
                            if (read > 0)
                            {
                                probePreview = Encoding.ASCII.GetString(buffer, 0, read)
                                    .Replace("\r", "\\r")
                                    .Replace("\n", "\\n");
                            }
                        }
                    }
                    catch
                    {
                    }
                }

                // Rate-limit repeated alerts from the same IP + port within 10 seconds
                string dedupKey = remoteIp + ":" + localPort;
                lock (_alertLock)
                {
                    DateTime lastTime;
                    if (_recentAlerts.TryGetValue(dedupKey, out lastTime) && (DateTime.UtcNow - lastTime).TotalSeconds < 10)
                    {
                        return;
                    }
                    _recentAlerts[dedupKey] = DateTime.UtcNow;
                }

                Helper.WriteToLog("ALERT: Connection attempt detected on honeypot port " + localPort + " from " + remoteIp + ":" + remotePort, "OUTPUT");

                // 1. Reverse DNS name resolution of the connecting host
                string resolvedHostname = ResolveHostName(remoteIp);
                Helper.WriteToLog("PortScan Recon - Hostname resolution for " + remoteIp + ": " + resolvedHostname, "OUTPUT");

                // 2. Basic TCP port scan of the connecting host
                List<int> openPortsOnAttacker = ScanAttackerPorts(remoteIp);
                string openPortsSummary = openPortsOnAttacker.Count > 0
                    ? string.Join(", ", openPortsOnAttacker)
                    : "None detected (or filtered)";
                Helper.WriteToLog("PortScan Recon - Open ports on " + remoteIp + ": " + openPortsSummary, "OUTPUT");

                // 3. Save detailed XML report so clicking the Toast opens it
                string recordId = DateTime.UtcNow.Ticks.ToString();
                SavePortScanXmlReport(recordId, remoteIp, remotePort, localPort, resolvedHostname, openPortsSummary, probePreview);

                // 4. Send Toast Notification
                ToastHelper.ShowToast(
                    recordId,
                    "Port Scan / Connection Attempt on Port " + localPort + "!",
                    "Source IP: " + remoteIp + " (" + resolvedHostname + ")",
                    "Scanner Open Ports: " + openPortsSummary);
            }
            catch (Exception ex)
            {
                Helper.LogCrash("PortScanDetector HandleConnection", ex);
            }
        }

        public static string ResolveHostName(string ipAddress)
        {
            try
            {
                IPHostEntry entry = Dns.GetHostEntry(ipAddress);
                if (entry != null && !string.IsNullOrEmpty(entry.HostName))
                {
                    return entry.HostName;
                }
            }
            catch
            {
            }
            return "Unresolved";
        }

        public static List<int> ScanAttackerPorts(string ipAddress, int timeoutMs = 400)
        {
            List<int> openPorts = new List<int>();
            object listLock = new object();

            Parallel.ForEach(ReconPorts, port =>
            {
                try
                {
                    using (TcpClient tcp = new TcpClient())
                    {
                        IAsyncResult ar = tcp.BeginConnect(ipAddress, port, null, null);
                        bool connected = ar.AsyncWaitHandle.WaitOne(timeoutMs);
                        if (connected && tcp.Connected)
                        {
                            try { tcp.EndConnect(ar); } catch { }
                            lock (listLock)
                            {
                                openPorts.Add(port);
                            }
                        }
                    }
                }
                catch
                {
                }
            });

            openPorts.Sort();
            return openPorts;
        }

        private static void SavePortScanXmlReport(
            string recordId,
            string remoteIp,
            int remotePort,
            int targetLocalPort,
            string resolvedHostname,
            string openPortsSummary,
            string probePreview)
        {
            try
            {
                if (!Directory.Exists(Helper.path))
                {
                    Directory.CreateDirectory(Helper.path);
                }

                string xml =
                    "<PortScanAlert>\n" +
                    "  <Timestamp>" + SecurityElement.Escape(DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss")) + "</Timestamp>\n" +
                    "  <TargetLocalPort>" + targetLocalPort + "</TargetLocalPort>\n" +
                    "  <AttackerIP>" + SecurityElement.Escape(remoteIp) + "</AttackerIP>\n" +
                    "  <AttackerSourcePort>" + remotePort + "</AttackerSourcePort>\n" +
                    "  <ResolvedHostName>" + SecurityElement.Escape(resolvedHostname) + "</ResolvedHostName>\n" +
                    "  <DiscoveredOpenPortsOnAttacker>" + SecurityElement.Escape(openPortsSummary) + "</DiscoveredOpenPortsOnAttacker>\n" +
                    "  <InitialProbeData>" + SecurityElement.Escape(probePreview ?? "") + "</InitialProbeData>\n" +
                    "</PortScanAlert>";

                File.WriteAllText(Path.Combine(Helper.path, recordId + ".xml"), xml);
            }
            catch
            {
            }
        }

        public void TriggerSelfTestConnection()
        {
            if (ActiveListeningPorts.Count == 0)
            {
                return;
            }
            int testPort = ActiveListeningPorts[0];
            try
            {
                using (TcpClient client = new TcpClient())
                {
                    client.Connect("127.0.0.1", testPort);
                }
                Helper.WriteToLog("Triggered real TCP connection to honeypot port " + testPort, "TEST");
            }
            catch (Exception ex)
            {
                Helper.WriteToLog("PortScan self-test connection failed: " + ex.Message, "ERROR");
            }
        }
    }
}
