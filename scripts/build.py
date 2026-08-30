#!/usr/bin/env python3
"""SSOT compiler: blueprint.yaml -> shadowrocket.conf + clash-rules.yaml (CN GFWList, blacklist).

Runs in GitHub Actions (outside the GFW): fetches MetaCubeX .list files, converts them to
Surge / mihomo syntax, and INLINES everything so the shipped configs fetch nothing at runtime.
mihomo rules are emitted as flat `rules:` lines (portable across Stash / old cores, no `type: inline`).

Fail-closed: any unrecognized source line shape aborts the build (no silent widen/drop).
"""
import os, sys, json, urllib.request, datetime
import yaml

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BP = yaml.safe_load(open(os.path.join(ROOT, "blueprint.yaml"), encoding="utf-8"))
UP = BP["upstream"].rstrip("/")

def die(msg):
    print("BUILD FAILED:", msg, file=sys.stderr); sys.exit(1)

def fetch(url):
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    return urllib.request.urlopen(req, timeout=120).read().decode("utf-8", "ignore").splitlines()

def read_local(fn):
    p = os.path.join(ROOT, fn)
    return open(p, encoding="utf-8").read().splitlines() if os.path.exists(p) else []

def is_bare_domain(s):
    # accept domain tokens incl. single-label TLD suffixes (+.cn, +.alibaba); reject *, keyword:, regexp:, spaces
    return bool(s) and all(c.isalnum() or c in ".-_" for c in s)

# ---------- parse a MetaCubeX domain .list, fail-closed ----------
def parse_domain(lines, where):
    """-> list of (TYPE, domain). +.x=DOMAIN-SUFFIX, bare x=DOMAIN. Aborts on anything else."""
    out = []
    for l in lines:
        l = l.strip()
        if not l or l[0] in "#!":
            continue
        if l.startswith("+."):
            base = l[2:]
            if not is_bare_domain(base):
                die(f"{where}: bad suffix line {l!r}")
            out.append(("DOMAIN-SUFFIX", base))
        elif is_bare_domain(l):
            out.append(("DOMAIN", l))
        else:
            die(f"{where}: unrecognized domain line {l!r} (no *, keyword:, regexp: allowed)")
    return out

def parse_ipcidr(lines, where):
    out = []
    for l in lines:
        l = l.strip()
        if not l or l[0] in "#!":
            continue
        if "/" not in l:
            die(f"{where}: not a CIDR {l!r}")
        out.append(("IP-CIDR6" if ":" in l else "IP-CIDR", l))
    return out

def parse_local(lines):
    """mine-*.list is already Surge syntax: TYPE,domain[,...]."""
    out = []
    for l in lines:
        l = l.strip()
        if not l or l[0] in "#!":
            continue
        parts = [p.strip() for p in l.split(",")]
        if len(parts) < 2:
            die(f"overlay: bad line {l!r}")
        out.append((parts[0], parts[1]))
    return out

# ---------- CN coverage set (for subtracting mis-tagged CN domains from AI) ----------
cn_suf, cn_exa = set(), set()
for t, d in parse_domain(fetch(f"{UP}/geosite/cn.list"), "cn"):
    (cn_suf if t == "DOMAIN-SUFFIX" else cn_exa).add(d)

def cn_covers(domain):
    if domain in cn_exa or domain in cn_suf:
        return True
    parts = domain.split(".")
    return any(".".join(parts[i:]) in cn_suf for i in range(1, len(parts)))

# ---------- build groups ----------
counts = {}
groups = []  # each: (name, policy, [(TYPE,val), ...], is_ip)
for g in BP["groups"]:
    src = g["source"]; pol = g["policy"]; name = g["name"]
    if src["kind"] == "local":
        rules = parse_local(read_local(src["file"])); is_ip = False
    elif src["kind"] == "domain":
        rules = parse_domain(fetch(f"{UP}/{src['path']}.list"), name); is_ip = False
        if g.get("subtract_cn"):
            before = len(rules)
            rules = [(t, d) for (t, d) in rules if not cn_covers(d)]
            print(f"  {name}: subtracted {before-len(rules)} CN-domestic domains")
    elif src["kind"] == "ipcidr":
        rules = parse_ipcidr(fetch(f"{UP}/{src['path']}.list"), name); is_ip = True
    else:
        die(f"{name}: unknown source kind {src['kind']!r}")
    counts[name] = len(rules)
    groups.append((name, pol, rules, is_ip))

# private guardrail, inlined (no geo-DB dependency)
priv_dom = parse_domain(fetch(f"{UP}/geosite/private.list"), "private")
priv_ip  = parse_ipcidr(fetch(f"{UP}/geoip/private.list"), "private-ip")
counts["private-domain"] = len(priv_dom); counts["private-ip"] = len(priv_ip)

# ---------- guards ----------
for cat, floor in BP.get("floors", {}).items():
    if counts.get(cat, 0) < floor:
        die(f"floor: {cat}={counts.get(cat,0)} < {floor} (upstream truncated/empty?)")
# AI must contain zero CN-domestic domains after subtraction
ai_rules = next(r for (n, p, r, ip) in groups if n == "ai")
leaked = [d for (t, d) in ai_rules if cn_covers(d)]
if leaked:
    die(f"ai still contains CN-domestic domains: {leaked[:10]}")

# ---------- provenance ----------
try:
    sha = json.load(urllib.request.urlopen(
        "https://api.github.com/repos/MetaCubeX/meta-rules-dat/commits/meta", timeout=60))["sha"][:12]
except Exception:
    sha = "unknown"
stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")
hdr = [f"upstream MetaCubeX/meta-rules-dat@meta {sha} | built {stamp} | " +
       " ".join(f"{k}={v}" for k, v in sorted(counts.items()))]

# ---------- emit Shadowrocket ----------
def sr_line(t, v, pol, is_ip):
    return f"{t},{v},{pol}" + (",no-resolve" if is_ip else "")

sr = []
sr.append("# Shadowrocket GFWList (CN, blacklist) - AUTO-GENERATED by scripts/build.py, do not edit.")
sr.append("# " + hdr[0])
sr.append("# No node baked in (OPSEC): rules target PROXY = your selected node; add your subscription in-app.")
sr.append("")
sr.append("[General]")
sr.append("bypass-system = true")
sr.append("skip-proxy = 127.0.0.1, 192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12, localhost, *.local, captive.apple.com")
sr.append("tun-excluded-routes = 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16")
sr.append("dns-server = 223.5.5.5, 119.29.29.29")
sr.append("ipv6 = false")
sr.append("")
sr.append("[Rule]")
sr.append("# ---- private (LAN) -> DIRECT ----")
for t, v in priv_ip:  sr.append(sr_line(t, v, "DIRECT", True))
for t, v in priv_dom: sr.append(sr_line(t, v, "DIRECT", False))
for name, pol, rules, is_ip in groups:
    sr.append(f"# ---- {name} -> {pol} ----")
    for t, v in rules:
        sr.append(sr_line(t, v, pol, is_ip))
sr.append("# ---- blacklist default ----")
sr.append("FINAL,DIRECT")
sr.append("")
open(os.path.join(ROOT, "shadowrocket.conf"), "w", encoding="utf-8").write("\n".join(sr))

# ---------- emit mihomo (flat rules, portable; geox-url mirror; no runtime rule fetch) ----------
MIRROR = BP["geox_mirror"].rstrip("/")
mihomo_head = f"""# mihomo GFWList (CN, blacklist) - AUTO-GENERATED by scripts/build.py, do not edit.
# {hdr[0]}
# Client-facing override (cn-router keeps its own OpenClash). No node baked in; include-all adopts your subscription.
# Requires a mihomo-based core; rules are flat (portable to Stash / older cores). geo DB via CN mirror below.
mode: rule
ipv6: false
unified-delay: true
tcp-concurrent: true
global-client-fingerprint: chrome
profile:
  store-selected: true
  store-fake-ip: true
geox-url:
  geoip: "{MIRROR}/geoip.dat"
  geosite: "{MIRROR}/geosite.dat"
  mmdb: "{MIRROR}/country.mmdb"
dns:
  enable: true
  ipv6: false
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  respect-rules: false
  nameserver: ["system"]
  proxy-server-nameserver: ["system"]
  fake-ip-filter:
    - "*.lan"
    - "+.local"
    - "+.home.arpa"
    - "+.msftconnecttest.com"
    - "+.msftncsi.com"
    - "captive.apple.com"
    - "time.*.com"
    - "+.pool.ntp.org"
    - "geosite:cn"
    - "geosite:private"
    - "geosite:connectivity-check"
sniffer:
  enable: true
  force-dns-mapping: true
  parse-pure-ip: true
  override-destination: false
  sniff:
    TLS: {{ ports: [443, 8443] }}
    HTTP: {{ ports: [80, 8080-8880] }}
    QUIC: {{ ports: [443] }}
  skip-domain:
    - "+.push.apple.com"
    - "+.oray.com"
    - "+.sunlogin.net"
proxy-groups:
  - name: "PROXY"
    type: select
    include-all: true
    proxies: ["AUTO", "URLTEST"]
  - name: "AUTO"
    type: fallback
    include-all: true
    url: "https://www.gstatic.com/generate_204"
    interval: 60
    lazy: true
  - name: "URLTEST"
    type: url-test
    include-all: true
    url: "https://www.gstatic.com/generate_204"
    interval: 300
    tolerance: 50
rules:
"""
def mi_line(t, v, pol, is_ip):
    return f"  - {t},{v},{pol}" + (",no-resolve" if is_ip else "")

mi = [mihomo_head.rstrip("\n")]
mi.append("  # ---- private (LAN) -> DIRECT ----")
for t, v in priv_ip:  mi.append(mi_line(t, v, "DIRECT", True))
for t, v in priv_dom: mi.append(mi_line(t, v, "DIRECT", False))
for name, pol, rules, is_ip in groups:
    mi.append(f"  # ---- {name} -> {pol} ----")
    for t, v in rules:
        mi.append(mi_line(t, v, pol, is_ip))
mi.append("  # ---- blacklist default ----")
mi.append("  - MATCH,DIRECT")
mi.append("")
open(os.path.join(ROOT, "clash-rules.yaml"), "w", encoding="utf-8").write("\n".join(mi))

print("OK:", " ".join(f"{k}={v}" for k, v in sorted(counts.items())))
print("upstream", sha, "->", "shadowrocket.conf", f"({len(sr)} lines)", "clash-rules.yaml", f"({len(mi)} lines)")
