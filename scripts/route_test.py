#!/usr/bin/env python3
"""Semantic route-diff: a first-match-wins matcher over the GENERATED artifacts.

Neither engine has a route-query CLI, so we interpret the emitted rule lists directly
(both grammars are ordered first-match lists) and assert a canary corpus routes as
expected for BOTH shadowrocket.conf and clash-rules.yaml. Exit non-zero on any miss.
"""
import os, sys, ipaddress

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# (target, kind, expected_policy). kind: "domain" or "ip".
CORPUS = [
    ("linkedin.com",        "domain", "PROXY"),   # mine-proxy / gfw (LinkedIn-China)
    ("www.linkedin.com",    "domain", "PROXY"),   # suffix match
    ("openai.com",          "domain", "PROXY"),   # ai
    ("kimi.ai",             "domain", "DIRECT"),  # regression guard: subtracted from ai -> default DIRECT
    ("bloomberg.cn",        "domain", "PROXY"),   # gfw keeps intentionally-blocked .cn
    ("baidu.com",           "domain", "DIRECT"),
    ("taobao.com",          "domain", "DIRECT"),
    ("t.me",                "domain", "PROXY"),   # telegram domain
    ("ai.google.dev",       "domain", "PROXY"),   # AI entry routes proxy
    ("openaiassets.blob.core.windows.net", "domain", "PROXY"),   # bare EXACT on a shared cloud host
    ("attacker.blob.core.windows.net",     "domain", "DIRECT"),  # exact must NOT widen -> rest of Azure stays direct
    ("91.108.4.1",          "ip",     "PROXY"),   # telegram MTProto v4
    ("192.168.1.7",         "ip",     "DIRECT"),  # private
    ("140.82.112.3",        "ip",     "DIRECT"),  # foreign bare IP, no IP rule -> default DIRECT
]

def parse_rules(path):
    """Return ordered [(TYPE, value, policy, no_resolve)] from either artifact."""
    rules, in_block = [], False
    for raw in open(path, encoding="utf-8"):
        line = raw.rstrip("\n")
        s = line.strip()
        if path.endswith(".conf"):
            if s == "[Rule]": in_block = True; continue
            if s.startswith("[") and s != "[Rule]": in_block = False; continue
            if not in_block or not s or s.startswith("#"): continue
            body = s
        else:  # clash-rules.yaml
            if s == "rules:": in_block = True; continue
            if in_block and not line.startswith("  "): in_block = False
            if not in_block or not s.startswith("- "): continue
            body = s[2:].strip()
        if not body or body.startswith("#"): continue
        parts = [p.strip() for p in body.split(",")]
        typ = parts[0].upper()
        if typ in ("FINAL", "MATCH"):
            rules.append((typ, None, parts[1].upper(), False)); continue
        val, pol = parts[1], parts[2].upper()
        rules.append((typ, val, pol, "no-resolve" in [p.lower() for p in parts[3:]]))
    return rules

def match(rules, target, kind):
    if kind == "ip":
        ip = ipaddress.ip_address(target)
    for typ, val, pol, nores in rules:
        if typ in ("FINAL", "MATCH"):
            return pol
        if kind == "domain":
            if typ.startswith("IP-CIDR"):
                continue  # no-resolve: IP rules don't apply to a domain connection
            if typ == "DOMAIN" and target == val: return pol
            if typ == "DOMAIN-SUFFIX" and (target == val or target.endswith("." + val)): return pol
            if typ == "DOMAIN-KEYWORD" and val in target: return pol
        else:  # ip target
            if not typ.startswith("IP-CIDR"):
                continue
            try:
                if ip in ipaddress.ip_network(val, strict=False): return pol
            except ValueError:
                continue
    return "DIRECT"  # nothing matched (shouldn't happen; FINAL/MATCH always present)

def main():
    fails = 0
    for art in ("shadowrocket.conf", "clash-rules.yaml"):
        rules = parse_rules(os.path.join(ROOT, art))
        print(f"== {art} ({len(rules)} rules) ==")
        for target, kind, want in CORPUS:
            got = match(rules, target, kind)
            ok = got == want
            fails += not ok
            print(f"  {'ok ' if ok else 'FAIL'} {target:22} {kind:6} -> {got:6} (want {want})")
    if fails:
        print(f"\n{fails} canary FAILURES", file=sys.stderr); sys.exit(1)
    print("\nAll canaries pass on both artifacts.")

if __name__ == "__main__":
    main()
