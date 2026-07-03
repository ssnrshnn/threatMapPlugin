from logging import getLogger
from threading import Lock
from time import time
from traceback import format_exc

HISTOGRAM_BUCKETS = 48

# Reports are pulled from every instance's API (or Redis) on each poll, window
# switch and drill-down. A short shared TTL cache coalesces those redundant
# fetches across concurrent requests / open browser tabs.
REPORTS_TTL = 5.0
_REPORTS_CACHE = {"ts": 0.0, "data": None}
_REPORTS_LOCK = Lock()


def _to_float(value, default):
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _fetch_reports(bw_instances_utils):
    """Prefer the Redis-backed query so history survives instance reloads;
    fall back to the in-memory per-instance reports on any error / older cores."""
    try:
        query = getattr(bw_instances_utils, "get_reports_query", None)
        if query is not None:
            result = query(start=0, length=-1, order_column="date", order_dir="desc", include_pane_counts=False)
            data = (result or {}).get("data")
            if isinstance(data, list):
                return data
    except BaseException:
        getLogger("UI").debug(format_exc())
    return bw_instances_utils.get_reports()


def _get_reports(bw_instances_utils):
    now = time()
    with _REPORTS_LOCK:
        cached = _REPORTS_CACHE["data"]
        if cached is not None and (now - _REPORTS_CACHE["ts"]) < REPORTS_TTL:
            return cached
    reports = _fetch_reports(bw_instances_utils)
    with _REPORTS_LOCK:
        _REPORTS_CACHE["data"] = reports
        _REPORTS_CACHE["ts"] = time()
    return reports


def _report_fields(report):
    try:
        date = float(report.get("date", 0) or 0)
    except (TypeError, ValueError):
        date = 0.0
    return {
        "id": str(report.get("id", "")),
        "ip": str(report.get("ip", "") or "unknown"),
        "country": (str(report.get("country", "") or "").strip().upper() or "??")[:7],
        "date": date,
        "reason": str(report.get("reason", "") or "unknown"),
        "service": str(report.get("server_name", "") or "unknown"),
        "method": str(report.get("method", "") or ""),
    }


def _histogram(dates, window, now):
    """Attacks-per-bucket histogram over the window (or over the whole buffer when window <= 0)."""
    if window <= 0:
        oldest = min((d for d in dates if d > 0), default=now)
        # pad the derived span so the oldest event lands inside the first bucket
        window = max(3600.0, (now - oldest) * 1.05)
    bucket = max(60.0, window / HISTOGRAM_BUCKETS)
    buckets = max(1, int(round(window / bucket)))
    start = now - buckets * bucket
    counts = [0] * buckets
    for d in dates:
        if d <= start:
            continue
        idx = int((d - start) / bucket)
        if 0 <= idx < buckets:
            counts[idx] += 1
    return {"start": start, "bucket": bucket, "counts": counts}


def _collect(db, bw_instances_utils, since=0.0, window=0.0):
    """Aggregate blocked requests from all instances into map events and statistics."""
    config = db.get_config()

    max_events = int(_to_float(config.get("THREAT_MAP_MAX_EVENTS", "200"), 200)) or 200
    home = {
        "lat": _to_float(config.get("THREAT_MAP_HOME_LAT", "48.86"), 48.86),
        "lon": _to_float(config.get("THREAT_MAP_HOME_LON", "2.35"), 2.35),
        "label": str(config.get("THREAT_MAP_HOME_LABEL", "BunkerWeb") or "BunkerWeb"),
    }

    reports = _get_reports(bw_instances_utils)  # already sorted newest first

    now = time()
    day_ago = now - 86400
    window_start = now - window if window > 0 else 0.0

    country_counts = {}
    reason_counts = {}
    service_counts = {}
    unique_ips_24h = set()
    last_24h = 0
    windowed_total = 0
    events = []
    dates = []

    for report in reports:
        r = _report_fields(report)
        dates.append(r["date"])

        # 24h stats are always computed over the whole buffer
        if r["date"] >= day_ago:
            last_24h += 1
            unique_ips_24h.add(r["ip"])

        # Everything else respects the selected time window
        if r["date"] < window_start:
            continue
        windowed_total += 1
        country_counts[r["country"]] = country_counts.get(r["country"], 0) + 1
        reason_counts[r["reason"]] = reason_counts.get(r["reason"], 0) + 1
        service_counts[r["service"]] = service_counts.get(r["service"], 0) + 1

        if r["date"] > since and len(events) < max_events:
            events.append(r)

    return {
        "events": events,
        "stats": {
            "total": windowed_total,
            "countries": country_counts,
            "reasons": reason_counts,
            "services": service_counts,
        },
        "stats24": {
            "last_24h": last_24h,
            "unique_ips_24h": len(unique_ips_24h),
        },
        "histogram": _histogram(dates, window, now),
        "home": home,
        "now": now,
        "max_events": max_events,
        "window": window,
    }


def _country_details(bw_instances_utils, country, window=0.0):
    """Drill-down data for one country: top IPs (with last reason/service) and breakdowns."""
    country = (str(country or "").strip().upper() or "??")[:7]
    now = time()
    window_start = now - window if window > 0 else 0.0

    ips = {}
    reason_counts = {}
    service_counts = {}
    total = 0

    for report in _get_reports(bw_instances_utils):
        r = _report_fields(report)
        if r["country"] != country or r["date"] < window_start:
            continue
        total += 1
        reason_counts[r["reason"]] = reason_counts.get(r["reason"], 0) + 1
        service_counts[r["service"]] = service_counts.get(r["service"], 0) + 1
        entry = ips.setdefault(r["ip"], {"ip": r["ip"], "count": 0, "reason": r["reason"], "service": r["service"], "last": 0.0})
        entry["count"] += 1
        if r["date"] >= entry["last"]:
            entry["last"] = r["date"]
            entry["reason"] = r["reason"]
            entry["service"] = r["service"]

    top_ips = sorted(ips.values(), key=lambda e: e["count"], reverse=True)[:10]

    return {
        "country": country,
        "total": total,
        "ips": top_ips,
        "reasons": reason_counts,
        "services": service_counts,
        "now": now,
        "window": window,
    }


def pre_render(**kwargs):
    logger = getLogger("UI")
    try:
        return _collect(kwargs["db"], kwargs["bw_instances_utils"])
    except BaseException as e:
        logger.debug(format_exc())
        logger.error(f"Failed to collect threat map data: {e}")
        return {"error": str(e)}


def threatmap(**kwargs):
    """POST action polled by the page for live updates and drill-downs."""
    logger = getLogger("UI")
    try:
        data = kwargs.get("data") or {}
        window = max(0.0, _to_float(data.get("window"), 0.0))
        if data.get("action") == "country":
            return _country_details(kwargs["bw_instances_utils"], data.get("country"), window=window)
        since = _to_float(data.get("since"), 0.0)
        return _collect(kwargs["db"], kwargs["bw_instances_utils"], since=since, window=window)
    except BaseException as e:
        logger.debug(format_exc())
        logger.error(f"Failed to refresh threat map data: {e}")
        return {"error": str(e)}
