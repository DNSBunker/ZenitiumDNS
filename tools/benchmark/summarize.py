import re
import statistics
import sys
from pathlib import Path


def read(path):
    values = {}
    for line in Path(path).read_text().splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key] = value
        if key.endswith("_latency"):
            for name, number in re.findall(r"(\w+)=([0-9.]+)", value):
                values[key[:-8] + "_lat_" + name] = number
        if key.endswith("_answers"):
            for name, number in re.findall(r"(\w+)=([0-9]+)", value):
                values[key[:-8] + "_" + name] = number
    try:
        entries = float(values["fill_1m_entries"])
        used = float(values["fill_1m_rss_after_20s_mb"]) - float(values["idle_rss_mb"])
        if entries > 0:
            values["fill_1m_bytes_per_entry"] = str(used * 1048576 / entries)
    except (KeyError, ValueError):
        pass
    return values


def median(runs, key):
    numbers = []
    for run in runs:
        if key in run:
            try:
                numbers.append(float(run[key]))
            except ValueError:
                pass
    if not numbers:
        return None
    return statistics.median(numbers)


ROWS = [
    ("Resident memory after start (MB)", "idle_rss_mb", 0),
    ("Cache hits, 40,000 queries/s: CPU time per query (µs)", "cache_hits_40k_cpu_us_per_query", 1),
    ("Cache hits, 40,000 queries/s: median latency (µs)", "cache_hits_40k_lat_p50", 0),
    ("Cache hits, 40,000 queries/s: 99th percentile (µs)", "cache_hits_40k_lat_p99", 0),
    ("Cache hits, 40,000 queries/s: 99.9th percentile (µs)", "cache_hits_40k_lat_p999", 0),
    ("Cache hits: maximum answers per second", "cache_hits_max_answers_per_second", 0),
    ("DNS-over-TLS cache hits, 8,000 queries/s: CPU time per query (µs)", "dot_8k_cpu_us_per_query", 1),
    ("DNS-over-TLS cache hits, 8,000 queries/s: median latency (µs)", "dot_8k_lat_p50", 0),
    ("DNS-over-TLS cache hits, 8,000 queries/s: 99th percentile (µs)", "dot_8k_lat_p99", 0),
    ("Recursive resolution, 2,000 new names/s: CPU time per query (µs)", "resolve_2k_cpu_us_per_query", 0),
    ("Recursive resolution, 2,000 new names/s: median latency (µs)", "resolve_2k_lat_p50", 0),
    ("Recursive resolution, 2,000 new names/s: 99th percentile (µs)", "resolve_2k_lat_p99", 0),
    ("Recursive resolution, 2,000 new names/s: 99.9th percentile (µs)", "resolve_2k_lat_p999", 0),
    ("20,000 new names/s for 50 s: answered queries", "fill_1m_recv", 0),
    ("20,000 new names/s for 50 s: mean latency (ms)", "fill_1m_lat_mean", -3),
    ("20,000 new names/s for 50 s: cache entries", "fill_1m_entries", 0),
    ("20,000 new names/s for 50 s: resident memory (MB)", "fill_1m_rss_after_20s_mb", 0),
    ("20,000 new names/s for 50 s: memory per cached name (bytes)", "fill_1m_bytes_per_entry", 0),
    ("Block lists (domains)", "blocklist_domains", 0),
    ("Block lists: resident memory (MB)", "blocklist_rss_mb", 0),
    ("50 % blocked names, 40,000 queries/s: CPU time per query (µs)", "blocked_40k_cpu_us_per_query", 1),
    ("50 % blocked names, 40,000 queries/s: median latency (µs)", "blocked_40k_lat_p50", 0),
    ("50 % blocked names, 40,000 queries/s: 99th percentile (µs)", "blocked_40k_lat_p99", 0),
]


def fmt(value, digits):
    if value is None:
        return "–"
    if digits == -3:
        return f"{value / 1000:,.1f}"
    if digits == 0:
        return f"{value:,.0f}"
    return f"{value:,.{digits}f}"


def main():
    if len(sys.argv) < 5 or "--" not in sys.argv:
        print("usage: summarize.py <label A> <results A...> -- <label B> <results B...>")
        return 1
    split = sys.argv.index("--")
    label_a, files_a = sys.argv[1], sys.argv[2:split]
    label_b, files_b = sys.argv[split + 1], sys.argv[split + 2:]
    runs_a = [read(f) for f in files_a]
    runs_b = [read(f) for f in files_b]
    print(f"| Measurement (median of {len(runs_a)}/{len(runs_b)} runs) | {label_a} | {label_b} | Change |")
    print("| --- | ---: | ---: | ---: |")
    for title, key, digits in ROWS:
        a = median(runs_a, key)
        b = median(runs_b, key)
        change = "–"
        if a and b is not None and a != 0:
            change = f"{(b - a) / a * 100:+.0f} %"
        print(f"| {title} | {fmt(a, digits)} | {fmt(b, digits)} | {change} |")
    return 0


if __name__ == "__main__":
    sys.exit(main())
