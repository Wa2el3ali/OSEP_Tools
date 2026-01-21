using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

class Program
{
    static async Task Main(string[] args)
    {
        var options = Args.Parse(args);

        var ports = ParsePorts(options.PortSpec);
        var targets = ParseTargets(options.Target);

        List<int>? previousOpenPorts = null;

        while (true)
        {
            Console.WriteLine("\n[*] Running scan...");

            List<int> openPorts;

            if (ToolExists("nmap"))
                openPorts = ScanWithNmap(options.Protocol, ports, options.Target);
            else if (ToolExists("ncat"))
                openPorts = await ScanWithNcat(options.Protocol, ports, targets);
            else
                openPorts = await ScanWithSockets(options.Protocol, ports, targets, options.Threads, options.Timeout);

            Console.WriteLine($"[+] Open ports: [{string.Join(", ", openPorts)}]");

            if (previousOpenPorts != null)
            {
                var prev = previousOpenPorts.ToHashSet();
                var curr = openPorts.ToHashSet();

                var newPorts = curr.Except(prev).ToList();
                var closedPorts = prev.Except(curr).ToList();

                if (newPorts.Any())
                    Console.WriteLine($"[+] New open ports detected: [{string.Join(", ", newPorts)}]");

                if (closedPorts.Any())
                    Console.WriteLine($"[-] Ports closed: [{string.Join(", ", closedPorts)}]");

                if (!newPorts.Any() && !closedPorts.Any())
                    Console.WriteLine("[*] No change in open ports");
            }

            previousOpenPorts = openPorts;

            if (options.Interval == null)
                break;

            Console.WriteLine($"[*] Waiting {options.Interval}s before next scan...");
            await Task.Delay(options.Interval.Value * 1000);
        }
    }

    // ---------------- TOOLS ----------------
    static bool ToolExists(string tool)
        => Environment.GetEnvironmentVariable("PATH")!
            .Split(';')
            .Any(p => File.Exists(Path.Combine(p, tool + ".exe")));

    static bool IsAdmin()
    {
        try
        {
            return new System.Security.Principal.WindowsPrincipal(
                System.Security.Principal.WindowsIdentity.GetCurrent()
            ).IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
        }
        catch { return false; }
    }

    // ---------------- NMAP ----------------
    static List<int> ScanWithNmap(string protocol, List<int> ports, string target)
    {
        Console.WriteLine("[*] Using nmap");

        string portArg = string.Join(",", ports);
        string tempFile = Path.GetTempFileName();

        string scanType =
            protocol == "tcp"
                ? (IsAdmin() ? "-sS" : "-sT")
                : "-sU";

        var psi = new ProcessStartInfo
        {
            FileName = "nmap",
            Arguments = $"{scanType} -p {portArg} -oJ \"{tempFile}\" {target}",
            CreateNoWindow = true,
            UseShellExecute = false
        };

        Process.Start(psi)!.WaitForExit();

        var json = File.ReadAllText(tempFile);
        File.Delete(tempFile);

        var doc = JsonDocument.Parse(json);
        var openPorts = new List<int>();

        foreach (var host in doc.RootElement.GetProperty("host").EnumerateArray())
        {
            foreach (var port in host.GetProperty("ports").EnumerateArray())
            {
                if (port.GetProperty("state").GetProperty("state").GetString() == "open")
                    openPorts.Add(port.GetProperty("portid").GetInt32());
            }
        }

        return openPorts.Distinct().OrderBy(p => p).ToList();
    }

    // ---------------- NCAT ----------------
    static async Task<List<int>> ScanWithNcat(string protocol, List<int> ports, List<string> targets)
    {
        Console.WriteLine("[*] Using ncat");
        var openPorts = new HashSet<int>();

        foreach (var target in targets)
        {
            int count = 0;
            foreach (var port in ports)
            {
                count++;
                Console.Write($"\rScanning {target} [{count}/{ports.Count}]");

                string args = protocol == "tcp"
                    ? $"-z -w 1 {target} {port}"
                    : $"-u -z -w 1 {target} {port}";

                var p = Process.Start(new ProcessStartInfo
                {
                    FileName = "ncat",
                    Arguments = args,
                    CreateNoWindow = true,
                    UseShellExecute = false
                });

                await p!.WaitForExitAsync();

                if (p.ExitCode == 0)
                    openPorts.Add(port);
            }
            Console.WriteLine();
        }

        return openPorts.OrderBy(p => p).ToList();
    }

    // ---------------- SOCKET FALLBACK ----------------
    static async Task<List<int>> ScanWithSockets(
        string protocol,
        List<int> ports,
        List<string> targets,
        int threads,
        int timeout)
    {
        Console.WriteLine("[*] Using C# sockets (fallback)");

        var openPorts = new HashSet<int>();
        using var sem = new SemaphoreSlim(threads);

        var tasks = new List<Task>();

        foreach (var target in targets)
        {
            foreach (var port in ports)
            {
                await sem.WaitAsync();
                tasks.Add(Task.Run(async () =>
                {
                    try
                    {
                        bool open = protocol == "tcp"
                            ? TcpCheck(target, port, timeout)
                            : UdpCheck(target, port, timeout);

                        if (open)
                            openPorts.Add(port);
                    }
                    finally { sem.Release(); }
                }));
            }
        }

        await Task.WhenAll(tasks);
        return openPorts.OrderBy(p => p).ToList();
    }

    static bool TcpCheck(string host, int port, int timeout)
    {
        try
        {
            using var client = new TcpClient();
            var task = client.ConnectAsync(host, port);
            return task.Wait(timeout);
        }
        catch { return false; }
    }

    static bool UdpCheck(string host, int port, int timeout)
    {
        try
        {
            using var client = new UdpClient();
            client.Client.ReceiveTimeout = timeout * 1000;
            client.Send(new byte[1], 1, host, port);
            client.Receive(ref new IPEndPoint(IPAddress.Any, 0));
            return true;
        }
        catch { return false; }
    }

    // ---------------- PARSING ----------------
    static List<int> ParsePorts(string spec)
    {
        if (spec.Contains('-'))
        {
            var parts = spec.Split('-');
            return Enumerable.Range(
                int.Parse(parts[0]),
                int.Parse(parts[1]) - int.Parse(parts[0]) + 1
            ).ToList();
        }
        return new List<int> { int.Parse(spec) };
    }

    static List<string> ParseTargets(string target)
    {
        if (target.Contains('/'))
        {
            var net = IPNetwork.Parse(target);
            return net.ListIPAddress().Select(ip => ip.ToString()).ToList();
        }
        return new List<string> { target };
    }
}

// ---------------- ARG PARSER ----------------
class Args
{
    public string Protocol = "";
    public string PortSpec = "";
    public string Target = "";
    public int Threads = 100;
    public int Timeout = 2;
    public int? Interval;

    public static Args Parse(string[] args)
    {
        var o = new Args();
        for (int i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "-P": o.Protocol = args[++i]; break;
                case "-p": o.PortSpec = args[++i]; break;
                case "-t": o.Target = args[++i]; break;
                case "--threads": o.Threads = int.Parse(args[++i]); break;
                case "--timeout": o.Timeout = int.Parse(args[++i]); break;
                case "--interval": o.Interval = int.Parse(args[++i]); break;
            }
        }
        return o;
    }
}
