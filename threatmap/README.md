# Threat Map plugin for BunkerWeb

Live world map of the requests BunkerWeb blocks, in the web UI: animated attack arcs on a Natural Earth dot map, countries coloured by their share of the attacks, a live feed, per-country / per-reason / per-service statistics, an activity timeline, country drill-downs with one-click bans and a SOC wall mode.

The page is self-contained: the map data (Natural Earth, public domain) is embedded, with no CDN and no external request.

## Where the data comes from

- **Reports**: the blocked-request reports of the metrics plugin, through the same Redis-backed query as the Reports page (`get_reports_query`), with a fallback to the per-instance in-memory buffers. Duplicates and future timestamps are dropped.
- **Countries**: the country BunkerWeb resolved at request time with its GeoIP database (`LOCAL` = private address, `UNKNOWN` = failed lookup).
- **Blocked vs detected**: the `security_mode` stored with each report. Requests of services in `SECURITY_MODE=detect` are counted apart and drawn with dashed arcs.
- **Bans**: the ban state is read from the instances and bans go through the UI's own ban helper. The result names the instances where a ban failed.

Statistics cover every stored report. The footer of the map shows the source (Redis or in-memory), how far back it goes, and whether the Redis buffer is full. Without Redis, reports live in each worker's memory (`METRICS_MAX_BLOCKED_REQUESTS`, 1,000 by default) and are cleared on reload. Enable the Redis plugin to keep history (`METRICS_MAX_BLOCKED_REQUESTS_REDIS`, 10,000 by default) and make the 7-day window meaningful.

## Requirements

- BunkerWeb 1.6.12 or later (tested on 1.6.17) with the web UI, and `USE_METRICS=yes` (the default).
- Live updates, drill-downs and bans are POST actions, which BunkerWeb allows for admin accounts only. Other accounts see a snapshot taken at page load.

## Installation

Like any other external plugin (see the [plugins documentation](https://docs.bunkerweb.io/latest/plugins/)):

- `EXTERNAL_PLUGIN_URLS=https://github.com/ssnrshnn/threatMapPlugin/releases/latest/download/threatmap.tar.gz`, or
- copy this `threatmap` folder into the volume mounted on `/data/plugins` of the scheduler (Docker) or into `/etc/bunkerweb/plugins` (Linux).

Restart the scheduler and the web UI, then open **Plugins → Threat Map**.

## Settings

| Setting                 | Default     | Context | Description                                                                                                                              |
| ----------------------- | ----------- | ------- | ---------------------------------------------------------------------------------------------------------------------------------------- |
| `USE_THREAT_MAP`        | `yes`       | global  | Enable the threat map page in the web UI.                                                                                                |
| `THREAT_MAP_MAX_EVENTS` | `200`       | global  | Recent blocked requests sent to the browser for the animation, the feed and replays (clamped to 1 to 2,000). Statistics are not limited. |
| `THREAT_MAP_HOME_LAT`   | `48.86`     | global  | Latitude (-90 to 90) of your infrastructure, where the arcs land.                                                                        |
| `THREAT_MAP_HOME_LON`   | `2.35`      | global  | Longitude (-180 to 180) of your infrastructure, where the arcs land.                                                                     |
| `THREAT_MAP_HOME_LABEL` | `BunkerWeb` | global  | Label shown next to the home marker (up to 32 characters).                                                                               |
