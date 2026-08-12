#!/usr/bin/env python3
"""Generate a self-contained Shadowrocket .conf (GFWList blacklist + adblock).

Sources:
  - gfw      : Loyalsoldier/surge-rules @release gfw.txt   -> PROXY
  - adblock  : anti-AD anti-ad-domains.txt                 -> REJECT
  - overlay  : this repo's mine-direct.list / mine-proxy.list

Rule order (Shadowrocket = first match wins, so this is the precedence):
  mine-direct DIRECT  ->  mine-proxy PROXY  ->  adblock REJECT  ->  gfw PROXY  ->  FINAL DIRECT
Blacklist mode: default DIRECT; only gfw + mine-proxy go to PROXY.

No node / no subscription URL is baked in (OPSEC). Rules target the built-in
policy PROXY (= whichever node you select). Add your PRIVATE subscription
separately inside Shadowrocket.
"""
import os, sys, urllib.request

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GFW_URL     = "https://raw.githubusercontent.com/Loyalsoldier/surge-rules/release/gfw.txt"
ADBLOCK_URL = "https://raw.githubusercontent.com/privacy-protection-tools/anti-AD/master/anti-ad-domains.txt"

def fetch(url):
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    return urllib.request.urlopen(req, timeout=90).read().decode("utf-8", "ignore").splitlines()

def read_local(name):
    p = os.path.join(REPO, name)
    return open(p, encoding="utf-8").read().splitlines() if os.path.exists(p) else []

def to_rules(lines, policy):
    """Normalise a source list into 'TYPE,domain,POLICY' rule strings."""
    out = []
    for l in lines:
        l = l.strip()
        if not l or l[0] in "#!":
            continue
        if "," in l:                       # already rule-shaped (overlay: DOMAIN-SUFFIX,x)
            t, d = l.split(",")[0].strip(), l.split(",")[1].strip()
            out.append(f"{t},{d},{policy}")
        else:                              # bare / leading-dot domain (gfw, adblock)
            out.append(f"DOMAIN-SUFFIX,{l.lstrip('.')},{policy}")
    return out

# precedence order = output order (top wins in Shadowrocket)
seen = set()
def dedupe(rules):
    o = []
    for r in rules:
        key = r.rsplit(",", 1)[0]          # TYPE,domain  (ignore policy for dedupe)
        if key in seen:
            continue
        seen.add(key); o.append(r)
    return o

mine_direct = dedupe(to_rules(read_local("mine-direct.list"), "DIRECT"))
mine_proxy  = dedupe(to_rules(read_local("mine-proxy.list"),  "PROXY"))
adblock     = dedupe(to_rules(fetch(ADBLOCK_URL),             "REJECT"))
gfw         = dedupe(to_rules(fetch(GFW_URL),                 "PROXY"))

GENERAL = """[General]
bypass-system = true
skip-proxy = 127.0.0.1, 192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12, localhost, *.local, captive.apple.com
tun-excluded-routes = 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16
dns-server = 223.5.5.5, 119.29.29.29
ipv6 = true
"""

out = []
out.append("# Shadowrocket GFWList (blacklist) + adblock - AUTO-GENERATED, do not edit by hand.")
out.append("# Blacklist: default DIRECT; only GFW-blocked + your mine-proxy list go to PROXY.")
out.append("# No node baked in: rules target PROXY (your selected node). Add your PRIVATE subscription in the app.")
out.append("")
out.append(GENERAL)
out.append("[Rule]")
out.append("# ---- overlay: force DIRECT ----");        out += mine_direct
out.append("# ---- overlay: force PROXY ----");         out += mine_proxy
out.append("# ---- adblock (REJECT) ----");             out += adblock
out.append("# ---- GFW blocked -> PROXY ----");         out += gfw
out.append("# ---- blacklist default ----")
out.append("FINAL,DIRECT")
out.append("")

open(os.path.join(REPO, "shadowrocket.conf"), "w", encoding="utf-8").write("\n".join(out))
print(f"mine_direct={len(mine_direct)} mine_proxy={len(mine_proxy)} adblock={len(adblock)} gfw={len(gfw)} total_rules={len(mine_direct)+len(mine_proxy)+len(adblock)+len(gfw)}")
