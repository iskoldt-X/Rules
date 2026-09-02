# Rules

Selective-routing rules, compiled from one source into one artifact per kind of consumer.
The default is a direct connection; only the listed destinations are sent through a proxy.

Useful on any network where part of the internet is slow or unreachable over the direct route, and
you want the rest of your traffic to stay direct instead of tunnelling everything.

**No proxy nodes are baked into anything here.** The rules target a policy named `PROXY`; you supply
the nodes yourself (a subscription in your client, a provider on your router). Nothing in this repo
is a secret.

## How it works

```
blueprint.yaml          the only place you edit: which upstream categories, what policy, what order
mine-proxy.list         your own additions -> PROXY
mine-direct.list        your own additions -> DIRECT
        |
   scripts/build.py     runs in GitHub Actions, daily and on every push
        |
        +--> shadowrocket.conf   full config    for Shadowrocket / Surge (iOS)
        +--> clash-rules.yaml    full override  for mihomo-based client apps
        +--> proxy-routes.list   bare list      for a router that already has its own config
```

All three come out of the same compile, so the destination set is identical across them. Upstream is
[MetaCubeX/meta-rules-dat](https://github.com/MetaCubeX/meta-rules-dat) (`meta` branch), tracked
rather than pinned; the build guards against a truncated or empty upstream with per-category
minimum counts, a set of routing canaries, and `mihomo -t`.

## Pick your artifact

Replace `main` with a tag if you ever want to pin. The jsDelivr mirror is reachable from more
networks than `raw.githubusercontent.com`, so prefer it unless you have a reason not to.

### Shadowrocket / Surge (iOS)

```
https://testingcf.jsdelivr.net/gh/iskoldt-X/Rules@main/shadowrocket.conf
```

Add your nodes in the app first, then import this as a config. Rules that match send traffic to
whichever node you have selected; everything else goes direct.

### mihomo client apps (Clash Verge Rev, mihomo-party, FlClash, Stash, ...)

```
https://testingcf.jsdelivr.net/gh/iskoldt-X/Rules@main/clash-rules.yaml
```

Add your node subscription as the profile, then apply this file as the override / global extended
config. The proxy groups use `include-all`, so they adopt whatever nodes your subscription provides.
Rules are emitted as flat `rules:` lines rather than `type: inline`, which keeps them loadable on
Stash and older cores.

### A router that already has its own config (OpenClash / mihomo on OpenWrt)

```
https://testingcf.jsdelivr.net/gh/iskoldt-X/Rules@main/proxy-routes.list
https://testingcf.jsdelivr.net/gh/iskoldt-X/Rules@main/mine-proxy.list
https://testingcf.jsdelivr.net/gh/iskoldt-X/Rules@main/mine-direct.list
```

Do **not** feed a router the full `clash-rules.yaml`. A router already owns its DNS, tun,
transparent-proxy ports and its own lifeline rules (LAN and management networks first), and a second
full config fights with those. It only needs the list.

`proxy-routes.list` is a mihomo rule-provider with `behavior: classical`, `format: text`: one rule
per line, no settings block, and **no policy column** -- you assign the policy where you reference
it.

```yaml
rule-providers:
  routes:
    type: http
    behavior: classical
    format: text
    url: "https://testingcf.jsdelivr.net/gh/iskoldt-X/Rules@main/proxy-routes.list"
    path: ./rule_provider/proxy-routes.list
    interval: 86400
  mine-proxy:  { type: http, behavior: classical, format: text, url: ".../mine-proxy.list",  path: ./rule_provider/mine-proxy.list,  interval: 86400 }
  mine-direct: { type: http, behavior: classical, format: text, url: ".../mine-direct.list", path: ./rule_provider/mine-direct.list, interval: 86400 }

rules:
  # your own lifeline rules go first: LAN, management/overlay networks, DNS policy, ...
  - RULE-SET,mine-direct,DIRECT
  - RULE-SET,mine-proxy,PROXY
  - RULE-SET,routes,PROXY
  - MATCH,DIRECT
```

`proxy-routes.list` covers the upstream categories only (currently Telegram domains, Telegram IP
ranges, non-domestic AI services, and the main bulk list). Your own overlays ship as separate files
because they carry different policies, and because keeping them separate means one copy, not two.

## Adding your own destinations

Edit `mine-proxy.list` or `mine-direct.list` -- one rule per line, Surge syntax, no policy:

```
DOMAIN-SUFFIX,example.com
DOMAIN,host.example.com
DOMAIN-KEYWORD,example
IP-CIDR,203.0.113.0/24
```

Push, and CI regenerates all three artifacts within a couple of minutes. Clients pick the change up
on their next refresh.

## Notes on the compile

- **Domestic services are subtracted from the AI group.** Upstream files a few of them into that
  category anyway, and routing a local service abroad only makes it slower or unusable, so anything
  covered by the domestic list is removed from that group. The bulk group keeps its entries under
  domestic TLDs, which are listed there on purpose.
- **The converter is fail-closed.** MetaCubeX writes `+.example.com` for a suffix match and a bare
  `example.com` for an exact match, and roughly a fifth of the AI entries are exact matches on shared
  cloud hosts. Widening one of those would route an entire cloud provider through the proxy, so any
  line shape the parser does not recognize aborts the build instead of guessing.
- **The mihomo artifact carries a `geox-url` mirror.** A fresh mihomo install on a restricted network
  otherwise fails at startup trying to download its geo database.
- **IP rules carry `no-resolve`** so a domain lookup is never forced through them.

Run it yourself:

```sh
pip install pyyaml
python3 scripts/build.py
python3 scripts/route_test.py
```
