using System;
using System.Linq;
using System.Net.Sockets;
using System.Collections.Generic;
using System.Threading.Tasks;

class Program
{
    static void Main(string[] args)
    {
        if (args.Contains("-h") || args.Contains("--help"))
        {
            PrintHelp();
            return;
        }

        string proto = args[Array.IndexOf(args, "-P") + 1];
        string portSpec = args[Array.IndexOf(args, "-p") + 1];
        string target = args[Array.IndexOf(args, "-t") + 1];

        var ports = ParsePorts(portSpec);
        var previous = new HashSet<int>();

        Console.WriteLine("[*] Running scan...");
        var open = ScanTcp(target, ports);

        Console.WriteLine($"[+] Open ports: {string.Join(",", open)}");
    }

    static HashSet<int> ScanTcp(string host, List<int> ports)
    {
        var open = new HashSet<int>();
        Parallel.ForEach(ports, p =>
        {
            try
            {
                using var c = new TcpClient();
                c.Connect(host, p);
                open.Add(p);
            }
            catch { }
        });
        return open;
    }

    static List<int> ParsePorts(string s)
    {
        if (s.Contains("-"))
        {
            var p = s.Split('-');
            return Enumerable.Range(int.Parse(p[0]), int.Parse(p[1]) - int.Parse(p[0]) + 1).ToList();
        }
        return new List<int> { int.Parse(s) };
    }

    static void PrintHelp()
    {
        Console.WriteLine(@"
Usage:
  scanner.exe -P tcp -p PORTS -t TARGET

Options:
  -P            Protocol
  -p            Port or range
  -t            Target host/IP
  -h, --help    Show this help
");
    }
}
