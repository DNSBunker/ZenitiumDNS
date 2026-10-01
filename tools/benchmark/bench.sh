#!/bin/bash
set -u

KIT="$(cd "$(dirname "$0")" && pwd)"
LABEL="${1:?label}"
KIND="${2:?zenitiumdns|technitium}"
APP="$(cd "${3:?application folder}" && pwd)"
LISTS="${4:-}"
OUT="${OUT:-$KIT/results}"
SERVER_CPUS="${SERVER_CPUS:-0-3}"
LOAD_CPUS="${LOAD_CPUS:-8-15}"
DOTNET="${DOTNET:-dotnet}"
SERVER_ENV="${SERVER_ENV:-}"
QUICK="${QUICK:-0}"
API=http://127.0.0.1:5380
RUN="$OUT/$LABEL"

rm -rf "$RUN"
mkdir -p "$RUN"

[ -x "$KIT/dnsload" ] || gcc -O2 -pthread -o "$KIT/dnsload" "$KIT/dnsload.c" || exit 1

TLSLOAD=""
if [ -f "$KIT/tlsload/bin/tlsload.dll" ] || "$DOTNET" build "$KIT/tlsload/tlsload.csproj" -c Release -o "$KIT/tlsload/bin" -v quiet > "$RUN/tlsload-build.log" 2>&1; then
    TLSLOAD="$KIT/tlsload/bin/tlsload.dll"
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout "$RUN/tls.key" -out "$RUN/tls.crt" -days 2 -subj "/CN=bench.deadtld" > /dev/null 2>&1
    openssl pkcs12 -export -out "$RUN/tls.pfx" -inkey "$RUN/tls.key" -in "$RUN/tls.crt" -passout pass:bench > /dev/null 2>&1 || TLSLOAD=""
fi

ip link set lo up
ip link add d0 type dummy
ip link set d0 up
for i in 1 2 5 10; do ip addr add 10.53.0.$i/24 dev d0; done
ip route add local 10.60.0.0/16 dev lo
mount --bind "$KIT/named.root" "$APP/named.root"

python3 "$KIT/fakeauth.py" root 10.53.0.1 > "$RUN/root.log" 2>&1 &
ROOTPID=$!
python3 "$KIT/fakeauth.py" tld 10.53.0.2 > "$RUN/tld.log" 2>&1 &
TLDPID=$!
HTTPPID=0
if [ -n "$LISTS" ]; then
    python3 -m http.server 8080 --bind 10.53.0.5 --directory "$LISTS" > "$RUN/http.log" 2>&1 &
    HTTPPID=$!
fi

PID=0
TOKEN=""

start_server() {
    local cfg="$RUN/config-$1"
    rm -rf "$cfg"
    mkdir -p "$cfg"

    if [ "$KIND" = "technitium" ]; then
        env $SERVER_ENV taskset -c "$SERVER_CPUS" "$DOTNET" "$APP/DnsServerApp.dll" --portable-app "$cfg" > "$RUN/server-$1.log" 2>&1 &
    else
        env $SERVER_ENV taskset -c "$SERVER_CPUS" "$APP/ZenitiumDns" --portable-app "$cfg" > "$RUN/server-$1.log" 2>&1 &
    fi

    PID=$!

    for i in $(seq 1 120); do
        curl -s -o /dev/null "$API/" && break
        sleep 1
    done

    TOKEN=$(curl -s "$API/api/user/login?user=admin&pass=admin" | python3 -c 'import sys,json; print(json.load(sys.stdin)["token"])')
    local tls=""
    [ -n "$TLSLOAD" ] && tls="&enableDnsOverTls=true&dnsTlsCertificatePath=$RUN/tls.pfx&dnsTlsCertificatePassword=bench"
    curl -s "$API/api/settings/set?token=$TOKEN&dnsServerLocalEndPoints=10.53.0.10:53&dnssecValidation=false&cacheMaximumEntries=$2&qpmLimitBypassList=10.53.0.0/24,10.60.0.0/16&rateLimitBypassList=10.53.0.0/24,10.60.0.0/16&blockListUrls=&enableBlocking=true$tls" > "$RUN/settings-$1.json"
    sleep 4
    curl -s "$API/api/cache/flush?token=$TOKEN" > /dev/null
}

stop_server() {
    kill "$PID" 2>/dev/null
    for i in $(seq 1 30); do
        kill -0 "$PID" 2>/dev/null || break
        sleep 1
    done
    kill -9 "$PID" 2>/dev/null
    wait "$PID" 2>/dev/null
}

cpu_ticks() {
    awk '{print $14 + $15}' "/proc/$PID/stat"
}

rss_mb() {
    awk '/VmRSS/ {printf "%d", $2 / 1024}' "/proc/$PID/status"
}

load() {
    taskset -c "$LOAD_CPUS" "$KIT/dnsload" 10.53.0.10 "$@"
}

result() {
    echo "$1=$2" | tee -a "$RUN/results.txt"
}

fixed_run() {
    local name=$1 qps=$2 seconds=$3
    shift 3
    local c0 c1
    c0=$(cpu_ticks)
    load "$qps" "$seconds" 10.60.0.1 1000 "$@" > "$RUN/$name.txt" 2> "$RUN/$name.err"
    c1=$(cpu_ticks)
    result "${name}_answers" "$(sed -n 1p "$RUN/$name.txt")"
    result "${name}_latency" "$(sed -n 2p "$RUN/$name.txt")"
    result "${name}_cpu_us_per_query" "$(python3 -c "print(round(($c1 - $c0) * 10000.0 / ($qps * $seconds), 1))")"
    result "${name}_rss_mb" "$(rss_mb)"
}

tls_run() {
    local name=$1 qps=$2 seconds=$3
    local c0 c1 n
    c0=$(cpu_ticks)
    taskset -c "$LOAD_CPUS" "$DOTNET" "$TLSLOAD" dot 10.53.0.10 853 "$qps" "$seconds" 32 1000 0 > "$RUN/$name.txt" 2> "$RUN/$name.err"
    c1=$(cpu_ticks)
    n=$(sed -n 1p "$RUN/$name.txt" | sed 's/.*recv=\([0-9]*\).*/\1/')
    result "${name}_answers" "$(sed -n 1p "$RUN/$name.txt")"
    result "${name}_latency" "$(sed -n 2p "$RUN/$name.txt")"
    result "${name}_cpu_us_per_query" "$(python3 -c "print(round(($c1 - $c0) * 10000.0 / max(1, ${n:-0}), 1))")"
}

max_run() {
    local name=$1
    shift
    load 1000000 15 10.60.0.1 1000 "$@" > "$RUN/$name.txt" 2> "$RUN/$name.err"
    result "${name}_offered_per_second" "$(grep -o 'sent [0-9]* ([0-9]*/s)' "$RUN/$name.err" | sed 's/.*(\([0-9]*\)\/s)/\1/' | sort -n | awk '{a[NR]=$1} END {print a[int((NR+1)/2)]}')"
    result "${name}_answers_per_second" "$(grep -o 'recv [0-9]* ([0-9]*/s)' "$RUN/$name.err" | sed 's/.*(\([0-9]*\)\/s)/\1/' | sort -n | awk '{a[NR]=$1} END {print a[int((NR+1)/2)]}')"
}

result "kind" "$KIND"
result "cpus" "$SERVER_CPUS"

if [ "$QUICK" = "2" ]; then
    start_server a 100000
    load 2000 10 10.60.0.1 1000 100 0 0 /dev/null 5000 9 > /dev/null 2>&1
    fixed_run resolve_2k 2000 30 100 0 0 /dev/null 5000 4
    stop_server
    kill "$ROOTPID" "$TLDPID" 2>/dev/null
    [ "$HTTPPID" != "0" ] && kill "$HTTPPID" 2>/dev/null
    umount "$APP/named.root"
    exit 0
fi

start_server a 100000
result "idle_rss_mb" "$(rss_mb)"
load 20000 15 10.60.0.1 1000 0 0 0 /dev/null 5000 1 > /dev/null 2>&1
fixed_run cache_hits_40k 40000 30 0 0 0 /dev/null 5000 2
if [ "$QUICK" = "1" ]; then
    stop_server
    kill "$ROOTPID" "$TLDPID" 2>/dev/null
    [ "$HTTPPID" != "0" ] && kill "$HTTPPID" 2>/dev/null
    umount "$APP/named.root"
    exit 0
fi
max_run cache_hits_max 0 0 0 /dev/null 5000 3
[ -n "$TLSLOAD" ] && tls_run dot_8k 8000 30
fixed_run resolve_2k 2000 30 100 0 0 /dev/null 5000 4
stop_server

start_server b 0
fixed_run fill_1m 20000 50 100 0 0 /dev/null 5000 5
sleep 20
result "fill_1m_entries" "$(curl -s "$API/api/dashboard/stats/get?token=$TOKEN&type=LastHour" | python3 -c 'import sys,json; print(json.load(sys.stdin)["response"]["stats"].get("cachedEntries"))')"
result "fill_1m_rss_after_20s_mb" "$(rss_mb)"
stop_server

if [ -n "$LISTS" ]; then
    start_server c 100000
    URLS=""
    for f in "$LISTS"/*.txt; do
        URLS="$URLS${URLS:+,}http://10.53.0.5:8080/$(basename "$f")"
    done
    curl -s "$API/api/settings/set?token=$TOKEN&blockListUrls=$URLS&blockListUpdateIntervalHours=0" > /dev/null
    curl -s "$API/api/settings/forceUpdateBlockLists?token=$TOKEN" > /dev/null
    LAST=-1
    for i in $(seq 1 180); do
        N=$(curl -s "$API/api/dashboard/stats/get?token=$TOKEN&type=LastHour" | python3 -c 'import sys,json; print(json.load(sys.stdin)["response"]["stats"].get("blockListZones", 0))' 2>/dev/null)
        if [ "${N:-0}" != "0" ] && [ "$N" = "$LAST" ]; then
            break
        fi
        LAST=${N:-0}
        sleep 5
    done
    sleep 30
    result "blocklist_domains" "$LAST"
    result "blocklist_rss_mb" "$(rss_mb)"
    cat "$LISTS"/*.txt | grep -v -E '^[#!]|^$' | sed 's/^||//; s/\^$//; s/^\*\.//' | shuf -n 20000 --random-source=<(yes) > "$RUN/blocked-names.txt"
    fixed_run blocked_40k 40000 30 0 0 50 "$RUN/blocked-names.txt" 5000 6
    stop_server
fi

kill "$ROOTPID" "$TLDPID" 2>/dev/null
[ "$HTTPPID" != "0" ] && kill "$HTTPPID" 2>/dev/null
umount "$APP/named.root"
echo "results in $RUN/results.txt"
