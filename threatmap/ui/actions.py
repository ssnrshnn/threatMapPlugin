"""Server side of the Threat Map page.

Every number shown on the page is derived from BunkerWeb's own blocked-request
reports, the same records the official Reports page lists:

* reports come from ``bw_instances_utils.get_reports_query`` (the Redis-backed,
  de-duplicated query of the Reports page) and fall back to the per-instance
  in-memory buffers (``get_reports``) on cores that lack it or when it fails;
* the country of each request is the one BunkerWeb resolved at request time with
  its bundled GeoIP database (``LOCAL`` for private addresses, ``UNKNOWN`` when the
  lookup failed), nothing is looked up again here;
* a request is *detected* when BunkerWeb recorded it with ``security_mode=detect``
  (logged, not denied) and *blocked* otherwise;
* ban state comes from the instances themselves (``get_bans``) and bans go through
  the same ``bw_instances_utils.ban`` helper the Bans page uses.

The page calls :func:`pre_render` once, then polls :func:`threatmap` (a POST to the
plugin page, admin-only in BunkerWeb) for live updates, drill-downs and bans.
"""

import sys
from contextlib import suppress
from ipaddress import ip_address
from logging import getLogger
from math import ceil, floor, isfinite
from threading import Lock
from time import time
from traceback import format_exc
from types import ModuleType

VERSION = "1.1"
BAN_REASON = "threat map"

REPORTS_TTL = 5.0  # shared by polls, window switches and drill-downs of every open tab
CONFIG_TTL = 15.0
LABELS_TTL = 600.0
BANS_TTL = 10.0
FUTURE_TOLERANCE = 300.0  # clock skew allowed between instances
MAX_EVENTS_CAP = 2000
DRILL_TOP_IPS = 15
HISTOGRAM_TARGET_BARS = 60
SPARK_HOURS = 24
TOP_IPS = 10
BUCKET_STEPS = (60, 120, 300, 600, 900, 1800, 3600, 7200, 10800, 21600, 43200, 86400, 172800, 604800)
BAN_MAX_DURATION = 365 * 86400
DEFAULTS = {"max_events": 200, "lat": 48.86, "lon": 2.35, "label": "BunkerWeb"}

# Reason ids that are not plugin ids, or whose plugin name is not explicit enough.
REASON_LABELS = {"modsecurity-body": "ModSecurity (body)", "unknown": "Unknown"}

LOGGER = getLogger("UI")

# BunkerWeb re-executes this file (SourceFileLoader("actions").load_module()) on every
# request, which would reset any module-level cache. The cache therefore lives in a
# private module registered once in sys.modules and reused by every re-execution.
_STATE_MODULE = "_bw_threatmap_state"
if _STATE_MODULE not in sys.modules:
    _state = ModuleType(_STATE_MODULE)
    _state.cache = {}
    _state.lock = Lock()
    sys.modules[_STATE_MODULE] = _state
_CACHE = sys.modules[_STATE_MODULE].cache
_LOCK = sys.modules[_STATE_MODULE].lock


# --------------------------------------------------------------------------- #
#  Small helpers                                                              #
# --------------------------------------------------------------------------- #
def _cached(key, ttl, compute):
    """Return compute() memoised for ttl seconds (process wide, thread safe)."""
    now = time()
    with _LOCK:
        hit = _CACHE.get(key)
        if hit is not None and now - hit[0] < ttl:
            return hit[1]
    value = compute()
    with _LOCK:
        _CACHE[key] = (time(), value)
    return value


def _invalidate(key):
    with _LOCK:
        _CACHE.pop(key, None)


def _to_float(value, default):
    try:
        number = float(value)
    except (TypeError, ValueError):
        return default
    return number if isfinite(number) else default


def _parse_count(value, default=0):
    """BunkerWeb count settings accept k/m shorthand ("10k", "1m")."""
    text = str(value if value is not None else "").strip().lower()
    multiplier = 1
    if text.endswith("k"):
        multiplier, text = 1000, text[:-1]
    elif text.endswith("m"):
        multiplier, text = 1000000, text[:-1]
    return int(text) * multiplier if text.isdigit() else default


def _country(value):
    code = str(value or "").strip().upper()
    if len(code) == 2 and code.isalpha():
        return code
    return "LOCAL" if code == "LOCAL" else "UNKNOWN"


def _settings(config):
    max_events = int(_to_float(config.get("THREAT_MAP_MAX_EVENTS"), DEFAULTS["max_events"]))
    return {
        "max_events": min(MAX_EVENTS_CAP, max(1, max_events)),
        "home": {
            "lat": min(90.0, max(-90.0, _to_float(config.get("THREAT_MAP_HOME_LAT"), DEFAULTS["lat"]))),
            "lon": min(180.0, max(-180.0, _to_float(config.get("THREAT_MAP_HOME_LON"), DEFAULTS["lon"]))),
            "label": (str(config.get("THREAT_MAP_HOME_LABEL") or "").strip() or DEFAULTS["label"])[:32],
        },
    }


def _get_config(db):
    return _cached("config", CONFIG_TTL, lambda: db.get_config() or {})


# --------------------------------------------------------------------------- #
#  Reports                                                                    #
# --------------------------------------------------------------------------- #
def _fetch_reports(bw_instances_utils):
    """Prefer the Redis-backed query of the Reports page (de-duplicated, survives
    reloads); fall back to the per-instance buffers on older cores or errors."""
    query = getattr(bw_instances_utils, "get_reports_query", None)
    if callable(query):
        try:
            result = query(start=0, length=-1, order_column="date", order_dir="desc", include_pane_counts=False)
            data = (result or {}).get("data")
            if isinstance(data, list):
                return data
        except Exception:
            LOGGER.debug(format_exc())
    return bw_instances_utils.get_reports() or []


def _source(config):
    """Where the reports live: "redis" (persistent) or "instances" (memory, cleared on reload)."""
    if str(config.get("USE_REDIS", "no")).lower() != "yes":
        return "instances"
    if _parse_count(config.get("METRICS_MAX_BLOCKED_REQUESTS_REDIS", "10k"), 10000) <= 0:
        return "instances"
    try:
        from app.routes.utils import get_redis_client  # BunkerWeb UI runtime only
    except Exception:
        return "redis"
    with suppress(Exception):
        if get_redis_client():
            return "redis"
    return "instances"


def _normalize(report, now):
    """One report -> compact event dict, or None when it cannot be placed in time."""
    date = _to_float(report.get("date"), 0.0)
    if date <= 0 or date > now + FUTURE_TOLERANCE:
        return None
    try:
        status = int(report.get("status") or 0)
    except (TypeError, ValueError):
        status = 0
    return {
        "id": str(report.get("id") or ""),
        "ip": str(report.get("ip") or "") or "unknown",
        "country": _country(report.get("country")),
        "date": date,
        "reason": str(report.get("reason") or "") or "unknown",
        "service": str(report.get("server_name") or "") or "unknown",
        "method": str(report.get("method") or "")[:16],
        "url": str(report.get("url") or "")[:160],
        "status": status,
        "mode": "detect" if str(report.get("security_mode") or "").lower() == "detect" else "block",
    }


def _load_events(bw_instances_utils):
    """All valid reports, normalised, de-duplicated by request id, newest first."""
    now = time()
    events = []
    seen = set()
    for report in _fetch_reports(bw_instances_utils):
        if not isinstance(report, dict):
            continue
        event = _normalize(report, now)
        if event is None:
            continue
        if event["id"]:
            if event["id"] in seen:
                continue
            seen.add(event["id"])
        events.append(event)
    events.sort(key=lambda e: e["date"], reverse=True)
    return events


def _get_events(bw_instances_utils):
    return _cached("events", REPORTS_TTL, lambda: _load_events(bw_instances_utils))


def _labels_for(db, reasons):
    """Display names of the reasons present: the plugin names from the database, also
    for ban reasons spelled with spaces ("bad behavior" is the badbehavior plugin)."""

    def compute():
        names = {}
        with suppress(Exception):
            for plugin in db.get_plugins() or []:
                if isinstance(plugin, dict) and plugin.get("id") and plugin.get("name"):
                    names[str(plugin["id"])] = str(plugin["name"])
        names.update(REASON_LABELS)
        return names

    names = _cached("labels", LABELS_TTL, compute)
    labels = {}
    for reason in reasons:
        label = names.get(reason) or names.get(reason.replace(" ", ""))
        if label:
            labels[reason] = label
    return labels


# --------------------------------------------------------------------------- #
#  Aggregation                                                                #
# --------------------------------------------------------------------------- #
def _bucket_size(span):
    for step in BUCKET_STEPS:
        if span / step <= HISTOGRAM_TARGET_BARS:
            return step
    return ceil(span / HISTOGRAM_TARGET_BARS / 86400) * 86400


def _histogram(events, window, now):
    """Blocked / detected counts per bucket. Buckets are aligned on multiples of their
    size (e.g. whole minutes / half hours) so the bars do not slide between polls."""
    if window > 0:
        span = window
    else:
        oldest = events[-1]["date"] if events else now
        span = max(3600.0, now - oldest)
    bucket = _bucket_size(span)
    start = floor((now - span) / bucket) * bucket
    count = max(1, int(ceil((now - start) / bucket)))
    blocked = [0] * count
    detected = [0] * count
    for event in events:
        if event["date"] < start:
            break  # newest first
        idx = min(count - 1, int((event["date"] - start) // bucket))
        (detected if event["mode"] == "detect" else blocked)[idx] += 1
    return {"start": start, "bucket": bucket, "blocked": blocked, "detected": detected}


def _coverage(events, config, source, now):
    """How far back the buffer goes, and whether older reports were already dropped."""
    oldest = events[-1]["date"] if events else None
    capacity = _parse_count(config.get("METRICS_MAX_BLOCKED_REQUESTS_REDIS", "10k"), 10000) if source == "redis" else None
    return {
        "source": source,
        "records": len(events),
        "oldest": oldest,
        "capacity": capacity,
        # Redis trims the list to its cap: a full list means older reports are gone.
        "full": bool(capacity and len(events) >= capacity),
    }


def _collect(db, bw_instances_utils, since=0.0, window=0.0):
    config = _get_config(db)
    settings = _settings(config)
    source = _source(config)
    events = _get_events(bw_instances_utils)

    now = time()
    window_start = now - window if window > 0 else 0.0
    day_ago = now - 86400
    two_days_ago = now - 2 * 86400

    countries = {}
    reasons = {}
    services = {}
    window_ips = {}
    totals = {"total": 0, "blocked": 0, "detected": 0}
    day = {"total": 0, "blocked": 0, "detected": 0}
    day_ips = set()
    day_countries = set()
    previous_day = 0
    fresh = []
    # Sparklines of the stat cards: the last 24 whole hours, the current one included.
    spark_start = floor(now / 3600) * 3600 - (SPARK_HOURS - 1) * 3600
    spark_blocked = [0] * SPARK_HOURS
    spark_ips = [set() for _ in range(SPARK_HOURS)]

    for event in events:
        date = event["date"]
        detected = event["mode"] == "detect"

        if date >= day_ago:
            day["total"] += 1
            day["detected" if detected else "blocked"] += 1
            day_ips.add(event["ip"])
            day_countries.add(event["country"])
        if date >= spark_start:
            hour = min(SPARK_HOURS - 1, int((date - spark_start) // 3600))
            if not detected:
                spark_blocked[hour] += 1
            spark_ips[hour].add(event["ip"])
        elif date >= two_days_ago:
            previous_day += 1

        if date < window_start:
            continue
        totals["total"] += 1
        totals["detected" if detected else "blocked"] += 1
        # newest first: the first report seen for an address carries its latest country
        attacker = window_ips.get(event["ip"])
        if attacker is None:
            window_ips[event["ip"]] = attacker = {"ip": event["ip"], "count": 0, "country": event["country"], "last": date}
        attacker["count"] += 1
        entry = countries.setdefault(event["country"], {"total": 0, "detected": 0})
        entry["total"] += 1
        if detected:
            entry["detected"] += 1
        reasons[event["reason"]] = reasons.get(event["reason"], 0) + 1
        services[event["service"]] = services.get(event["service"], 0) + 1

        if date > since and len(fresh) < settings["max_events"]:
            fresh.append(event)

    coverage = _coverage(events, config, source, now)
    # The previous 24 h are only comparable when the buffer reaches back that far.
    previous_complete = bool(coverage["oldest"] is not None and coverage["oldest"] <= two_days_ago and not coverage["full"])

    return {
        "version": VERSION,
        "now": now,
        "window": window,
        "home": settings["home"],
        "max_events": settings["max_events"],
        "events": fresh,
        "stats": dict(
            totals,
            unique_ips=len(window_ips),
            countries=countries,
            reasons=reasons,
            services=services,
            top_ips=sorted(window_ips.values(), key=lambda a: (-a["count"], -a["last"]))[:TOP_IPS],
        ),
        "stats24": dict(
            day,
            unique_ips=len(day_ips),
            countries=len(day_countries),
            previous=previous_day if previous_complete else None,
            hourly={"start": spark_start, "blocked": spark_blocked, "ips": [len(ips) for ips in spark_ips]},
        ),
        "histogram": _histogram(events, window, now),
        "coverage": coverage,
        "reason_labels": _labels_for(db, reasons),
    }


# --------------------------------------------------------------------------- #
#  Drill-down and bans                                                        #
# --------------------------------------------------------------------------- #
def _banned_ips(bw_instances_utils):
    def compute():
        banned = {}
        with suppress(Exception):
            for ban in bw_instances_utils.get_bans() or []:
                if not isinstance(ban, dict) or not ban.get("ip"):
                    continue
                scope = ban.get("ban_scope") or ("global" if ban.get("service", "_") in ("", "_") else "service")
                banned.setdefault(str(ban["ip"]), []).append(
                    {
                        "scope": scope,
                        "service": ban.get("service") or "",
                        "exp": ban.get("exp"),  # seconds left, 0 when permanent
                        "permanent": bool(ban.get("permanent")),
                        "reason": ban.get("reason") or "",
                    }
                )
        return banned

    return _cached("bans", BANS_TTL, compute)


def _country_details(db, bw_instances_utils, country, window=0.0):
    country = _country(country)
    now = time()
    window_start = now - window if window > 0 else 0.0

    ips = {}
    reasons = {}
    services = {}
    total = detected = 0
    first = last = None

    for event in _get_events(bw_instances_utils):
        if event["country"] != country:
            continue
        if event["date"] < window_start:
            break  # newest first
        total += 1
        is_detect = event["mode"] == "detect"
        detected += is_detect
        last = event["date"] if last is None else last
        first = event["date"]
        reasons[event["reason"]] = reasons.get(event["reason"], 0) + 1
        services[event["service"]] = services.get(event["service"], 0) + 1
        entry = ips.get(event["ip"])
        if entry is None:
            # first sighting walking newest -> oldest is the most recent one
            entry = ips[event["ip"]] = {
                "ip": event["ip"],
                "count": 0,
                "detected": 0,
                "last": event["date"],
                "reason": event["reason"],
                "service": event["service"],
            }
        entry["count"] += 1
        entry["detected"] += is_detect

    top = sorted(ips.values(), key=lambda e: (-e["count"], -e["last"]))[:DRILL_TOP_IPS]
    banned = _banned_ips(bw_instances_utils) if top else {}
    for entry in top:
        entry["bans"] = banned.get(entry["ip"], [])

    return {
        "country": country,
        "total": total,
        "detected": detected,
        "unique_ips": len(ips),
        "first": first,
        "last": last,
        "ips": top,
        "reasons": reasons,
        "services": services,
        "reason_labels": _labels_for(db, reasons),
        "now": now,
        "window": window,
    }


def _requester_ips():
    with suppress(Exception):
        from flask import request  # BunkerWeb UI runtime only

        return {str(addr) for addr in [request.remote_addr, *request.access_route] if addr}
    return set()


def _ban(db, bw_instances_utils, data):
    try:
        ip = str(ip_address(str(data.get("ip") or "").strip()))
    except ValueError:
        return {"error": "Invalid IP address"}
    if getattr(db, "readonly", False):
        return {"error": "The database is in read-only mode"}
    if ip in _requester_ips():
        return {"error": f"Refusing to ban {ip}: it is the address you are connected from"}

    try:
        exp = int(data.get("exp", 86400))
    except (TypeError, ValueError):
        return {"error": "Invalid ban duration"}
    if not 0 <= exp <= BAN_MAX_DURATION:
        return {"error": "Invalid ban duration"}

    scope = "service" if data.get("scope") == "service" else "global"
    service = ""
    if scope == "service":
        service = str(data.get("service") or "")
        if service not in str(_get_config(db).get("SERVER_NAME", "")).split():
            return {"error": f"Unknown service {service!r}, cannot ban for it"}

    failed = bw_instances_utils.ban(ip, exp, BAN_REASON, service, scope)
    _invalidate("bans")
    if failed:
        names = ", ".join(map(str, failed)) if isinstance(failed, (list, tuple)) else str(failed)
        return {"error": f"Ban of {ip} failed on: {names}"}
    LOGGER.info(f"Threat map: banned {ip} ({scope}{' ' + service if service else ''}) for {exp or 'ever'}{' s' if exp else ''}")
    return {"ok": True, "ip": ip, "exp": exp, "scope": scope, "service": service}


# --------------------------------------------------------------------------- #
#  Entry points called by the BunkerWeb UI                                    #
# --------------------------------------------------------------------------- #
def pre_render(**kwargs):
    try:
        return _collect(kwargs["db"], kwargs["bw_instances_utils"])
    except BaseException as e:
        LOGGER.debug(format_exc())
        LOGGER.error(f"Failed to collect threat map data: {e}")
        return {"error": str(e)}


def threatmap(**kwargs):
    """POST action of the page: live poll, country drill-down or ban."""
    try:
        data = kwargs.get("data") or {}
        if not isinstance(data, dict):
            data = {}
        window = max(0.0, _to_float(data.get("window"), 0.0))
        action = data.get("action")
        if action == "country":
            return _country_details(kwargs["db"], kwargs["bw_instances_utils"], data.get("country"), window=window)
        if action == "ban":
            return _ban(kwargs["db"], kwargs["bw_instances_utils"], data)
        since = max(0.0, _to_float(data.get("since"), 0.0))
        return _collect(kwargs["db"], kwargs["bw_instances_utils"], since=since, window=window)
    except BaseException as e:
        LOGGER.debug(format_exc())
        LOGGER.error(f"Failed to refresh threat map data: {e}")
        return {"error": str(e)}
