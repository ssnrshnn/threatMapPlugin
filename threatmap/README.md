# Threat Map plugin for BunkerWeb

Live world threat map for the BunkerWeb web UI: see where blocked attacks against your infrastructure come from, in real time, on an animated dotted world map with attack arcs, impact ripples, a live event feed and per-country / per-reason statistics.

The map is fully self-contained (no CDN, no external requests): the land dot-grid and country centroids are pre-generated from Natural Earth data and embedded in the page.

## Features

- Dotted world map in the BunkerWeb color palette with animated attack arcs from the attacker's country to your infrastructure
- Heat glow under the most aggressive countries
- Live feed of blocked requests (IP, country flag, targeted service, block reason)
- Stat cards: attacks and unique IPs over the last 24 hours, top origin country, tracked events
- Top attacking countries and block reasons charts
- Live polling every 10 seconds through the plugin action endpoint
- Country drill-down: click a country on the map (or in the top-countries chart) to see its top attacker IPs and ban any of them via the UI's ban API, choosing duration (1h / 24h / 7d / permanent) and scope (global / this service). The open panel auto-refreshes on the poll cycle and remembers IPs already banned this session.
- Time window selector (1h / 24h / 7d / all) applied to the map heat, charts and drill-downs
- Attacks-per-interval timeline sparkline under the map
- Replay mode: re-animate the recorded attacks of the selected window
- SOC fullscreen mode: wall-monitor view with overlay stat chips, embedded attack feed and auto-cycling country highlights
- Demo mode button to preview the animation when no attack has been recorded yet

Data comes from the reports (blocked requests) already collected by BunkerWeb instances via the metrics plugin, so no extra agent or job is needed. The `USE_METRICS` setting must stay enabled (it is by default).

Reports live in each instance's shared memory and are therefore cleared on a configuration reload. Enabling the **Redis** plugin (`USE_REDIS=yes` + `REDIS_HOST`) makes them persistent: the plugin reads through the same Redis-backed query the official Reports page uses, so history survives reloads and the 7-day window becomes meaningful. Without Redis it falls back transparently to the in-memory per-instance reports.

The plugin caches the report fetch for a few seconds (shared across polls, window switches and drill-downs) so opening several browser tabs or many instances does not multiply the load on the instance/Redis query. Animations honor the operating system's "reduce motion" setting.

## Installation

Like any other external plugin (see the [plugins documentation](https://docs.bunkerweb.io/latest/plugins/)):

### Docker / Autoconf

Copy the `threatmap` folder into the volume mounted on `/data/plugins` of the scheduler container:

```bash
cp -r threatmap /path/to/bw-data/plugins/
```

or use the `EXTERNAL_PLUGIN_URLS` setting with an URL pointing to a tar.gz archive of the plugin.

### Linux

```bash
cp -r threatmap /etc/bunkerweb/plugins/
systemctl restart bunkerweb-scheduler
```

Once the scheduler has loaded the plugin, open the web UI → **Plugins** → **Threat Map**.

## Settings

| Setting                 | Default     | Context | Description                                                        |
| ----------------------- | ----------- | ------- | ------------------------------------------------------------------ |
| `USE_THREAT_MAP`        | `yes`       | global  | Enable the threat map page in the web UI.                          |
| `THREAT_MAP_MAX_EVENTS` | `200`       | global  | Maximum number of recent blocked requests sent to the browser.     |
| `THREAT_MAP_HOME_LAT`   | `48.86`     | global  | Latitude of your infrastructure (target of the attack arcs).       |
| `THREAT_MAP_HOME_LON`   | `2.35`      | global  | Longitude of your infrastructure (target of the attack arcs).      |
| `THREAT_MAP_HOME_LABEL` | `BunkerWeb` | global  | Label displayed next to the home marker on the map.                |
