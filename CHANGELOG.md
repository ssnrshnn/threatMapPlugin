# Changelog

## 1.1

### Map

- New map: Natural Earth I projection with a hexagonal grid of 15,800 land dots (was a coarse 220×100 equirectangular grid), generated reproducibly from pinned Natural Earth v5.1.2 data by `tools/build_geo.py`.
- Every dot carries its ISO country code: countries are coloured by their share of the attacks and can be hovered (tooltip) and clicked anywhere, not only near their centroid.
- Every one of the 250 geographic country codes BunkerWeb can report has a position on the map (246 with their own dots). The previous data only knew 174 countries, so attacks from Singapore, Hong Kong, Malta, Bahrain, Luxembourg, the French overseas regions and others were silently not drawn.
- Arcs start at Natural Earth's label points (the visual centre of the main landmass) instead of geometric centroids.
- Smoother animation: eased comet trails with contrails, glow sprites instead of `shadowBlur`, country flashes and impact ripples. New reports are spread over the polling interval with their real relative timing. Measured at a steady 60 fps with the map full of arcs.

### Accuracy

- Reports are de-duplicated by request id, and reports dated in the future are dropped.
- Requests in `SECURITY_MODE=detect` (logged, not denied) are counted apart from blocked ones and drawn with dashed arcs.
- The page shows its data source, how far back the buffer goes, and warns when the Redis buffer is full and older reports were dropped.
- "vs previous 24 h" trend, only shown when the buffer covers the previous day.
- Timeline: blocked and detected stacked, buckets aligned on whole minutes and hours so they don't slide between polls, hover for exact counts.
- Reason names come from the plugin names in BunkerWeb's database.
- The live poll re-reads the last 2 minutes, so reports synced late by another instance are no longer missed.

### Bans

- Bans go through the UI's ban helper inside the plugin action and report the instances where they failed. Previously the Bans page always answered with a redirect, so a failed ban was shown as successful.
- The drill-down shows the real ban state from the instances (scope and time left) instead of remembering the bans made in the current tab.
- 30-day ban duration, a guard against banning your own address, and server-side validation of IP, duration and service.

### Design

- Redesigned page: the UI's sans-serif font throughout (monospace only for addresses), large stat figures with hourly sparklines of the last 24 h, the top origin's share and the blocked / detected split.
- Countries are coloured on a single-hue scale with a legend; reason colours were checked for colour-blind readers and always come with their name.
- The legend and the data source moved under the map; the activity timeline has a value scale, time ticks and stacked blocked / detected bars.
- The feed folds repeated requests from the same address into one row with a counter, and adapts its layout to its width.
- New "Top attacking IPs" and "Targeted services" cards; reasons and services show their composition as a 100% bar.
- Restyled tooltip, drill-down panel, SOC mode overlays and toasts; the map card fills its height next to the feed; better small-screen layout.

### Other

- SOC mode works on BunkerWeb 1.6.17, whose UI sends `Permissions-Policy: fullscreen=()`: it is now a window-filling overlay, made truly fullscreen when the browser allows it.
- Fixed: the report cache never worked, because BunkerWeb re-executes `actions.py` on every request; the cache now survives that.
- Read-only (non-admin) accounts get a clear `SNAPSHOT` state instead of silently failing polls; polling backs off while the instances are unreachable and pauses in hidden tabs.
- Demo events use RFC 5737 documentation addresses and are labelled as demo.
- Stricter setting validation (latitude -90 to 90, longitude -180 to 180).
- The page is split into `template.html`, `threatmap.js`, `threatmap.css` and `threatmap-geo.json`.
- Example stack on BunkerWeb 1.6.17 with a detect-mode service, configurable ports (`UI_PORT` for macOS) and `traffic.sh`.
- pytest suite (actions, template rendering, map data), CI (lint, tests on Python 3.11 and 3.13, reproducible map data) and tagged releases with a ready-to-use `threatmap.tar.gz`.

## 1.0

- Initial release.
