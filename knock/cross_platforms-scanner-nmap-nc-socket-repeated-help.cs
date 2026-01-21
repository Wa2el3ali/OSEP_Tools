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

        Console.WriteLine("[*] Running scan...");
        var open = ScanTcp(target, ports);

        Console.WriteLine($"[+] Open ports: {string.Join(", ", open)}");
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

    static List<int> ParsePorts(string spec)
    {
        var ports = new HashSet<int>();
        foreach (var part in spec.Split(','))
        {
            if (part.Contains("-"))
            {
                var p = part.Split('-');
                int a = int.Parse(p[0]), b = int.Parse(p[1]);
                for (int i = a; i <= b; i++) ports.Add(i);
            }
            else ports.Add(int.Parse(part));
        }
        return ports.OrderBy(p => p).ToList();
    }

    static void PrintHelp()
    {
        Console.WriteLine(@"
Usage:
  scanner.exe -P tcp -p PORTS -t TARGET

Ports:
  22
  1-1024
  22,80,445
  22,80,1000-1010

Options:
  -h, --help    Show this help
");
    }
}
