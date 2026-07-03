# Threat Map — BunkerWeb plugin

A live world **threat map** for the [BunkerWeb](https://www.bunkerweb.io) web UI. It turns the blocked‑request reports your BunkerWeb instances already collect into an animated, real‑time map of attacks against your infrastructure — with attack arcs, a live event feed, per‑country / per‑reason statistics, a time‑windowed activity timeline, country drill‑downs with one‑click bans, and a fullscreen SOC mode.

The map is **fully self‑contained** — the dotted world map and country coordinates are pre‑generated from [Natural Earth](https://www.naturalearthdata.com/) data and embedded in the page. No CDN, no external requests, CSP‑friendly.

> _Screenshots go in `docs/` — drop a `map.png` there and it will render below._
> <!-- ![Threat map](docs/map.png) -->

## Features

- **Animated attack map** — glowing arcs fly from each attacker's country to your server marker, with impact ripples and heat‑glows under the most aggressive countries. Arc colour encodes the block reason (ModSecurity, blacklist, DNSBL, rate‑limit, …) with a legend.
- **Live feed & stat cards** — attacks and unique IPs over the last 24 h, top origin, and a scrolling feed of blocked requests with country flags.
- **Time windows** — 1 h / 24 h / 7 d / all, applied to the map, charts, timeline and drill‑downs.
- **Activity timeline** — an attacks‑per‑interval sparkline under the map.
- **Country drill‑down + bans** — click a country to see its top attacker IPs and ban any of them via the UI's ban API, choosing duration (1 h / 24 h / 7 d / permanent) and scope (global / this service). Already‑banned IPs are remembered for the session.
- **Replay & Demo** — replay the recorded attacks of the current window, or run a synthetic demo when nothing has been blocked yet.
- **SOC fullscreen mode** — a wall‑monitor view with overlay stat chips, an embedded feed and auto‑cycling country highlights.
- **Efficient & resilient** — report fetches are cached briefly and shared across polls, window switches and drill‑downs; animations honour the OS "reduce motion" setting.

## How it works

The plugin reads the blocked‑request reports produced by the **metrics** plugin (enabled by default via `USE_METRICS`). When the **Redis** plugin is enabled it reads through the same Redis‑backed query the official Reports page uses, so history survives instance reloads and the 7‑day window is meaningful; otherwise it falls back to the in‑memory per‑instance reports. No extra agent or job is required.

## Installation

This repository is laid out so the `threatmap/` folder **is** the plugin (its folder name must stay `threatmap`, matching the plugin `id`). Install it like any other BunkerWeb external plugin — see the [plugins documentation](https://docs.bunkerweb.io/latest/plugins/).

### Docker / Autoconf

Copy the `threatmap/` folder into the volume mounted on `/data/plugins` of the **scheduler**:

```bash
git clone https://github.com/ssnrshnn/threatMapPlugin.git
cp -r threatMapPlugin/threatmap /path/to/bw-data/plugins/
```

…or point `EXTERNAL_PLUGIN_URLS` at a `.tar.gz` archive of the `threatmap/` folder.

### Linux

```bash
cp -r threatmap /etc/bunkerweb/plugins/
systemctl restart bunkerweb-scheduler
```

Then open the web UI → **Plugins → Threat Map**.

> After adding or updating the plugin, restart **both** the scheduler and the web UI container — the UI extracts external plugins on startup.

## Settings

| Setting                 | Default     | Context | Description                                                    |
| ----------------------- | ----------- | ------- | -------------------------------------------------------------- |
| `USE_THREAT_MAP`        | `yes`       | global  | Enable the threat map page in the web UI.                      |
| `THREAT_MAP_MAX_EVENTS` | `200`       | global  | Max recent blocked requests sent to the browser.              |
| `THREAT_MAP_HOME_LAT`   | `48.86`     | global  | Latitude of your infrastructure (target of the attack arcs).  |
| `THREAT_MAP_HOME_LON`   | `2.35`      | global  | Longitude of your infrastructure (target of the attack arcs). |
| `THREAT_MAP_HOME_LABEL` | `BunkerWeb` | global  | Label shown next to the home marker on the map.               |

Set `THREAT_MAP_HOME_LAT` / `THREAT_MAP_HOME_LON` to your server's location so the arcs converge on the right spot.

## Try it locally

A complete test stack (BunkerWeb + scheduler + UI + MariaDB + Redis + syslog collector + a demo backend) lives in [`examples/`](examples/):

```bash
cd examples
docker compose up -d
```

Then browse to **http://localhost:7000** (default dev credentials `admin` / `P@ssw0rd`) → **Plugins → Threat Map**.

Generate some harmless, WAF‑tripping traffic from spoofed source countries (HTTPS, self‑signed cert):

```bash
curl -sk -H "Host: app1.example.com" -H "X-Forwarded-For: 45.9.148.2" \
  "https://localhost:8443/?q=<script>alert(1)</script>"
```

> The example stack binds its ports to `127.0.0.1` only and trusts any `X-Forwarded-For` (`REAL_IP_FROM: 0.0.0.0/0`) **purely so attacks from arbitrary countries can be simulated**. Never use that setting in production.

## Repository layout

```
threatmap/            The plugin — drop this folder into /data/plugins
  plugin.json         Metadata & settings schema
  README.md           Plugin documentation
  ui/
    actions.py        Server-side data aggregation (pre_render + poll action)
    template.html     The map page (self-contained canvas renderer)
examples/             Local test stack (docker compose) — not shipped with the plugin
```

## License

Licensed under the **GNU AGPL‑3.0** (matching BunkerWeb) — see [`LICENSE`](LICENSE). If you prefer a different license for your fork, replace that file.

## Acknowledgements

- Built for [BunkerWeb](https://github.com/bunkerity/bunkerweb) by Bunkerity.
- World map geometry derived from [Natural Earth](https://www.naturalearthdata.com/) (public domain).
