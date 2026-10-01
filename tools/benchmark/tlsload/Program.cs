using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Security;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

if ((args.Length < 8) || ((args[0] != "dot") && (args[0] != "doh")))
{
    Console.Error.WriteLine("usage: tlsload dot|doh server port qps seconds connections popular_count pct_random");
    return 1;
}

string mode = args[0];
string host = args[1];
int port = int.Parse(args[2]);
int qps = int.Parse(args[3]);
int seconds = int.Parse(args[4]);
int connections = int.Parse(args[5]);
int popular = int.Parse(args[6]);
int pctRandom = int.Parse(args[7]);

long sent = 0, received = 0, errors = 0;
long[] hist = new long[200000];
long latCount = 0;
double latSum = 0;
object latLock = new object();
Random seedRng = new Random(42);
long stopAt = Stopwatch.GetTimestamp() + (long)(seconds * (double)Stopwatch.Frequency);

byte[] BuildQuery(ushort id, Random rng)
{
    string name = rng.Next(100) < pctRandom ? "r" + rng.NextInt64(0, 0xffffffffffffL).ToString("x12") + ".deadtld" : "w" + rng.Next(popular) + ".deadtld";
    List<byte> q = new List<byte>(64);
    q.Add((byte)(id >> 8)); q.Add((byte)id);
    q.Add(1); q.Add(0); q.Add(0); q.Add(1); q.Add(0); q.Add(0); q.Add(0); q.Add(0); q.Add(0); q.Add(0);
    foreach (string label in name.Split('.'))
    {
        q.Add((byte)label.Length);
        q.AddRange(Encoding.ASCII.GetBytes(label));
    }
    q.Add(0); q.Add(0); q.Add(1); q.Add(0); q.Add(1);
    return q.ToArray();
}

void Record(long startTs)
{
    double us = (Stopwatch.GetTimestamp() - startTs) * 1e6 / Stopwatch.Frequency;
    int b = (int)(us / 10);
    lock (latLock)
    {
        if (b < hist.Length) hist[b]++;
        latCount++;
        latSum += us;
    }
    Interlocked.Increment(ref received);
}

double Percentile(double p)
{
    long want = (long)(latCount * p), acc = 0;
    for (int i = 0; i < hist.Length; i++) { acc += hist[i]; if (acc > want) return i * 10 + 5; }
    return hist.Length * 10;
}

int perConnQps = Math.Max(1, qps / connections);

async Task DotConnection(int index)
{
    Random rng = new Random(seedRng.Next());
    using TcpClient tcp = new TcpClient();
    tcp.NoDelay = true;
    await tcp.ConnectAsync(host, port);
    using SslStream ssl = new SslStream(tcp.GetStream(), false);
    await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions { TargetHost = "bench.test", RemoteCertificateValidationCallback = delegate { return true; } });
    Dictionary<ushort, long> pending = new Dictionary<ushort, long>();
    object pendingLock = new object();
    SemaphoreSlim writeLock = new SemaphoreSlim(1);
    Task reader = Task.Run(async delegate
    {
        byte[] lenBuf = new byte[2];
        byte[] buf = new byte[65535];
        try
        {
            while (true)
            {
                await ssl.ReadExactlyAsync(lenBuf);
                int len = BinaryPrimitives.ReadUInt16BigEndian(lenBuf);
                await ssl.ReadExactlyAsync(buf.AsMemory(0, len));
                ushort id = BinaryPrimitives.ReadUInt16BigEndian(buf);
                long ts;
                lock (pendingLock) { if (!pending.Remove(id, out ts)) continue; }
                Record(ts);
            }
        }
        catch { }
    });
    ushort nextId = 0;
    long interval = Stopwatch.Frequency / perConnQps;
    long next = Stopwatch.GetTimestamp();
    while (Stopwatch.GetTimestamp() < stopAt)
    {
        long now = Stopwatch.GetTimestamp();
        if (now < next) { int ms = (int)((next - now) * 1000 / Stopwatch.Frequency); if (ms > 0) await Task.Delay(ms); else await Task.Yield(); continue; }
        next += interval;
        ushort id = nextId++;
        byte[] q = BuildQuery(id, rng);
        byte[] frame = new byte[q.Length + 2];
        BinaryPrimitives.WriteUInt16BigEndian(frame, (ushort)q.Length);
        q.CopyTo(frame, 2);
        lock (pendingLock) pending[id] = Stopwatch.GetTimestamp();
        try { await ssl.WriteAsync(frame); Interlocked.Increment(ref sent); }
        catch { Interlocked.Increment(ref errors); break; }
    }
    await Task.Delay(2000);
    tcp.Close();
    try { await reader; } catch { }
}

async Task DohConnection(int index)
{
    Random rng = new Random(seedRng.Next());
    SocketsHttpHandler handler = new SocketsHttpHandler { SslOptions = new SslClientAuthenticationOptions { RemoteCertificateValidationCallback = delegate { return true; } }, EnableMultipleHttp2Connections = false, MaxConnectionsPerServer = 1 };
    using HttpClient client = new HttpClient(handler) { DefaultRequestVersion = HttpVersion.Version20, DefaultVersionPolicy = HttpVersionPolicy.RequestVersionExact };
    Uri uri = new Uri("https://" + host + ":" + port + "/dns-query");
    long interval = Stopwatch.Frequency / perConnQps;
    long next = Stopwatch.GetTimestamp();
    List<Task> inflight = new List<Task>();
    while (Stopwatch.GetTimestamp() < stopAt)
    {
        long now = Stopwatch.GetTimestamp();
        if (now < next) { int ms = (int)((next - now) * 1000 / Stopwatch.Frequency); if (ms > 0) await Task.Delay(ms); else await Task.Yield(); continue; }
        next += interval;
        byte[] q = BuildQuery(0, rng);
        long ts = Stopwatch.GetTimestamp();
        Interlocked.Increment(ref sent);
        inflight.Add(Task.Run(async delegate
        {
            try
            {
                using ByteArrayContent content = new ByteArrayContent(q);
                content.Headers.ContentType = new MediaTypeHeaderValue("application/dns-message");
                using HttpResponseMessage resp = await client.PostAsync(uri, content);
                await resp.Content.ReadAsByteArrayAsync();
                if (resp.IsSuccessStatusCode) Record(ts); else Interlocked.Increment(ref errors);
            }
            catch { Interlocked.Increment(ref errors); }
        }));
        if (inflight.Count > 4096) { await Task.WhenAll(inflight); inflight.Clear(); }
    }
    await Task.WhenAll(inflight);
}

List<Task> tasks = new List<Task>();
for (int i = 0; i < connections; i++)
{
    int idx = i;
    tasks.Add(Task.Run(mode == "dot" ? () => DotConnection(idx) : () => DohConnection(idx)));
}
await Task.WhenAll(tasks);
Console.WriteLine($"sent={sent} recv={received} errors={errors}");
Console.WriteLine($"latency_us mean={(latCount > 0 ? latSum / latCount : 0):F0} p50={Percentile(0.5):F0} p90={Percentile(0.9):F0} p99={Percentile(0.99):F0} p999={Percentile(0.999):F0} samples={latCount}");
return 0;
