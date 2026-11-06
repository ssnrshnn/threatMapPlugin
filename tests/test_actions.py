from time import time

import pytest

from conftest import FakeDB, FakeUtils, LegacyUtils, load_actions, report


def collect(actions, db, utils, **data):
    return actions.threatmap(db=db, bw_instances_utils=utils, data=data)


# --------------------------------------------------------------------------- #
#  Sources                                                                    #
# --------------------------------------------------------------------------- #
def test_uses_the_redis_backed_reports_query(actions, db):
    utils = FakeUtils([report()])
    actions.pre_render(db=db, bw_instances_utils=utils)
    assert utils.query_calls == 1 and utils.get_reports_calls == 0
    assert utils.last_query == {"start": 0, "length": -1, "order_column": "date", "order_dir": "desc", "include_pane_counts": False}


def test_falls_back_to_instance_buffers_without_query(actions, db):
    utils = LegacyUtils([report()])
    data = actions.pre_render(db=db, bw_instances_utils=utils)
    assert utils.get_reports_calls == 1
    assert data["stats"]["total"] == 1


def test_falls_back_to_instance_buffers_when_query_fails(actions, db):
    class Broken(FakeUtils):
        def get_reports_query(self, **kwargs):
            raise RuntimeError("redis down")

    utils = Broken([report()])
    data = actions.pre_render(db=db, bw_instances_utils=utils)
    assert utils.get_reports_calls == 1
    assert data["stats"]["total"] == 1


def test_cache_survives_bunkerweb_reexecuting_the_module(db):
    """The UI re-executes actions.py on every request: the TTL cache must persist."""
    import sys

    sys.modules.pop("_bw_threatmap_state", None)
    utils = FakeUtils([report()])
    load_actions().pre_render(db=db, bw_instances_utils=utils)
    load_actions().threatmap(db=db, bw_instances_utils=utils, data={})
    load_actions().threatmap(db=db, bw_instances_utils=utils, data={"action": "country", "country": "US"})
    assert utils.query_calls == 1
    assert db.config_calls == 1
    sys.modules.pop("_bw_threatmap_state", None)


# --------------------------------------------------------------------------- #
#  Accuracy of the numbers                                                    #
# --------------------------------------------------------------------------- #
def test_reports_are_deduplicated_by_request_id(actions, db):
    dup = report(id="same")
    data = actions.pre_render(db=db, bw_instances_utils=FakeUtils([dup, dict(dup), report()]))
    assert data["stats"]["total"] == 2


def test_detect_mode_is_not_counted_as_blocked(actions, db):
    reports = [report(), report(), report(security_mode="detect", status=200, country="DE")]
    data = actions.pre_render(db=db, bw_instances_utils=FakeUtils(reports))
    assert data["stats"]["blocked"] == 2
    assert data["stats"]["detected"] == 1
    assert data["stats24"]["blocked"] == 2 and data["stats24"]["detected"] == 1
    assert data["stats"]["countries"]["DE"] == {"total": 1, "detected": 1}
    assert sorted(e["mode"] for e in data["events"]) == ["block", "block", "detect"]


def test_future_and_invalid_dates_are_dropped(actions, db):
    now = time()
    reports = [report(date=now + 3600), report(date="nan"), report(date=None), report(date=0), report(date=now - 10), report(date=now + 60)]
    data = actions.pre_render(db=db, bw_instances_utils=FakeUtils(reports))
    # a few seconds of clock skew between instances is tolerated, an hour is not
    assert data["stats"]["total"] == 2


@pytest.mark.parametrize(
    "raw, expected",
    [("fr", "FR"), (" us ", "US"), ("local", "LOCAL"), ("unknown", "UNKNOWN"), ("", "UNKNOWN"), (None, "UNKNOWN"), ("xyz", "UNKNOWN")],
)
def test_country_codes_are_normalised(actions, db, raw, expected):
    data = actions.pre_render(db=db, bw_instances_utils=FakeUtils([report(country=raw)]))
    assert list(data["stats"]["countries"]) == [expected]


def test_window_and_24h_statistics(actions, db):
    now = time()
    reports = [
        report(date=now - 30, ip="198.51.100.1", country="CN"),
        report(date=now - 1800, ip="198.51.100.1", country="CN"),
        report(date=now - 7200, ip="198.51.100.2", country="RU", reason="badbehavior"),
        report(date=now - 3 * 86400, ip="198.51.100.3", country="BR"),
    ]
    utils = FakeUtils(reports)
    hour = collect(actions, db, utils, window=3600)
    assert hour["stats"]["total"] == 2
    assert hour["stats"]["unique_ips"] == 1
    assert hour["stats"]["countries"] == {"CN": {"total": 2, "detected": 0}}
    everything = collect(actions, db, utils, window=0)
    assert everything["stats"]["total"] == 4
    assert everything["stats"]["reasons"] == {"modsecurity": 3, "badbehavior": 1}
    # 24 h cards do not depend on the selected window
    assert hour["stats24"] == everything["stats24"]
    assert hour["stats24"]["blocked"] == 3
    assert hour["stats24"]["unique_ips"] == 2
    assert hour["stats24"]["countries"] == 2


def test_top_attacking_ips_of_the_window(actions, db):
    now = time()
    reports = [report(date=now - 10 - i, ip="198.51.100.1", country="CN") for i in range(3)]
    reports += [report(date=now - 20 - i, ip="198.51.100.2", country="RU") for i in range(2)]
    reports += [report(date=now - 30, ip="198.51.100.3", country="BR"), report(date=now - 7200, ip="198.51.100.4", country="US")]
    top = collect(actions, db, FakeUtils(reports), window=3600)["stats"]["top_ips"]
    assert [(a["ip"], a["count"], a["country"]) for a in top] == [("198.51.100.1", 3, "CN"), ("198.51.100.2", 2, "RU"), ("198.51.100.3", 1, "BR")]
    assert top[0]["last"] == pytest.approx(now - 10)


def test_top_ips_are_capped(actions, db):
    reports = [report(ip="198.51.100.%d" % i) for i in range(1, 30)]
    data = actions.pre_render(db=db, bw_instances_utils=FakeUtils(reports))
    assert len(data["stats"]["top_ips"]) == 10
    assert data["stats"]["unique_ips"] == 29


def test_hourly_sparklines_of_the_last_24_hours(actions, db):
    now = time()
    current_hour = now // 3600 * 3600
    reports = [
        # current hour (at most a few seconds ahead of the clock, which is tolerated)
        report(date=current_hour + 1, ip="198.51.100.1"),
        report(date=current_hour + 2, ip="198.51.100.1"),
        report(date=current_hour + 3, ip="198.51.100.2", security_mode="detect"),
        report(date=current_hour - 60, ip="198.51.100.3"),  # previous hour
        report(date=current_hour - 30 * 3600, ip="198.51.100.4"),  # older than the sparkline
    ]
    hourly = actions.pre_render(db=db, bw_instances_utils=FakeUtils(reports))["stats24"]["hourly"]
    assert hourly["start"] == current_hour - 23 * 3600
    assert len(hourly["blocked"]) == len(hourly["ips"]) == 24
    # detected requests are not blocked, but their IPs did reach the instances
    assert hourly["blocked"][-1] == 2 and hourly["ips"][-1] == 2
    assert hourly["blocked"][-2] == 1 and hourly["ips"][-2] == 1
    assert sum(hourly["blocked"]) == 3


def test_previous_day_only_reported_when_the_buffer_reaches_back(actions, db):
    now = time()
    recent = [report(date=now - 100), report(date=now - 90000)]
    data = actions.pre_render(db=db, bw_instances_utils=FakeUtils(recent))
    assert data["stats24"]["previous"] is None  # oldest report is < 48 h old: unknown, not zero

    actions._invalidate("events")
    older = recent + [report(date=now - 3 * 86400)]
    data = actions.pre_render(db=db, bw_instances_utils=FakeUtils(older))
    assert data["stats24"]["previous"] == 1


def test_reason_labels_come_from_plugin_names(actions, db):
    reports = [report(reason="badbehavior"), report(reason="bad behavior"), report(reason="modsecurity-body"), report(reason="someexternal")]
    data = actions.pre_render(db=db, bw_instances_utils=FakeUtils(reports))
    assert data["reason_labels"] == {
        "badbehavior": "Bad behavior",
        "bad behavior": "Bad behavior",  # ban reasons are spelled with a space
        "modsecurity-body": "ModSecurity (body)",
    }


# --------------------------------------------------------------------------- #
#  Histogram                                                                  #
# --------------------------------------------------------------------------- #
def test_histogram_is_aligned_and_sums_to_the_window(actions, db):
    now = time()
    reports = [report(date=now - k * 97) for k in range(30)] + [report(date=now - 50, security_mode="detect")]
    data = collect(actions, db, FakeUtils(reports), window=3600)
    hist = data["histogram"]
    assert hist["bucket"] == 60
    assert hist["start"] % hist["bucket"] == 0  # aligned on whole minutes: bars do not slide
    assert hist["start"] <= now - 3600
    assert sum(hist["blocked"]) == data["stats"]["blocked"]
    assert sum(hist["detected"]) == data["stats"]["detected"] == 1
    assert len(hist["blocked"]) <= 62


@pytest.mark.parametrize("window, bucket", [(3600, 60), (86400, 1800), (604800, 10800)])
def test_histogram_bucket_sizes(actions, db, window, bucket):
    data = collect(actions, db, FakeUtils([report()]), window=window)
    assert data["histogram"]["bucket"] == bucket


def test_histogram_of_the_whole_buffer_covers_the_oldest_report(actions, db):
    now = time()
    reports = [report(date=now - 10), report(date=now - 5 * 86400)]
    hist = collect(actions, db, FakeUtils(reports), window=0)["histogram"]
    assert hist["start"] <= now - 5 * 86400
    assert sum(hist["blocked"]) == 2


# --------------------------------------------------------------------------- #
#  Events                                                                     #
# --------------------------------------------------------------------------- #
def test_events_since_and_max_events(actions):
    now = time()
    db = FakeDB({"THREAT_MAP_MAX_EVENTS": "3"})
    reports = [report(date=now - k) for k in range(1, 11)]
    utils = FakeUtils(reports)
    data = collect(actions, db, utils)
    assert len(data["events"]) == 3
    assert [e["date"] for e in data["events"]] == sorted((e["date"] for e in data["events"]), reverse=True)
    newer = collect(actions, db, utils, since=now - 2.5)
    assert len(newer["events"]) == 2


def test_event_fields_are_compact_and_safe(actions, db):
    data = actions.pre_render(db=db, bw_instances_utils=FakeUtils([report(url="/" + "a" * 500, data={"secret": 1})]))
    event = data["events"][0]
    assert set(event) == {"id", "ip", "country", "date", "reason", "service", "method", "url", "status", "mode"}
    assert len(event["url"]) == 160


@pytest.mark.parametrize(
    "config, expected",
    [
        ({}, {"lat": 48.86, "lon": 2.35, "label": "BunkerWeb", "max": 200}),
        ({"THREAT_MAP_HOME_LAT": "123", "THREAT_MAP_HOME_LON": "-500"}, {"lat": 90.0, "lon": -180.0, "label": "BunkerWeb", "max": 200}),
        ({"THREAT_MAP_HOME_LAT": "oops", "THREAT_MAP_HOME_LABEL": "  "}, {"lat": 48.86, "lon": 2.35, "label": "BunkerWeb", "max": 200}),
        ({"THREAT_MAP_MAX_EVENTS": "999999"}, {"lat": 48.86, "lon": 2.35, "label": "BunkerWeb", "max": 2000}),
        ({"THREAT_MAP_MAX_EVENTS": "0"}, {"lat": 48.86, "lon": 2.35, "label": "BunkerWeb", "max": 1}),
    ],
)
def test_settings_are_clamped(actions, config, expected):
    data = actions.pre_render(db=FakeDB(config), bw_instances_utils=FakeUtils())
    assert data["home"] == {"lat": expected["lat"], "lon": expected["lon"], "label": expected["label"]}
    assert data["max_events"] == expected["max"]


# --------------------------------------------------------------------------- #
#  Coverage                                                                   #
# --------------------------------------------------------------------------- #
def test_coverage_reports_in_memory_source(actions, db):
    data = actions.pre_render(db=db, bw_instances_utils=FakeUtils([report()]))
    assert data["coverage"]["source"] == "instances"
    assert data["coverage"]["records"] == 1
    assert data["coverage"]["full"] is False


def test_coverage_flags_a_full_redis_buffer(actions):
    db = FakeDB({"USE_REDIS": "yes", "METRICS_MAX_BLOCKED_REQUESTS_REDIS": "3"})
    data = actions.pre_render(db=db, bw_instances_utils=FakeUtils([report() for _ in range(3)]))
    coverage = data["coverage"]
    assert coverage["source"] == "redis" and coverage["capacity"] == 3 and coverage["full"] is True
    assert data["stats24"]["previous"] is None


@pytest.mark.parametrize("value, expected", [("10k", 10000), ("1m", 1000000), ("250", 250), ("", 7), ("abc", 7), (None, 7)])
def test_parse_count(actions, value, expected):
    assert actions._parse_count(value, 7) == expected


# --------------------------------------------------------------------------- #
#  Drill-down                                                                 #
# --------------------------------------------------------------------------- #
def test_country_details(actions, db):
    now = time()
    reports = [
        report(date=now - 10, ip="198.51.100.7", country="CN", reason="badbehavior"),
        report(date=now - 20, ip="198.51.100.7", country="CN"),
        report(date=now - 30, ip="198.51.100.8", country="CN", security_mode="detect"),
        report(date=now - 5000, ip="198.51.100.9", country="CN"),
        report(date=now - 5, ip="198.51.100.1", country="US"),
    ]
    bans = [{"ip": "198.51.100.7", "exp": 3000, "reason": "manual", "service": "_", "ban_scope": "global", "permanent": False}]
    utils = FakeUtils(reports, bans=bans)
    data = collect(actions, db, utils, action="country", country="cn", window=3600)
    assert data["country"] == "CN"
    assert data["total"] == 3 and data["detected"] == 1 and data["unique_ips"] == 2
    assert data["last"] == pytest.approx(now - 10) and data["first"] == pytest.approx(now - 30)
    top = data["ips"][0]
    assert top["ip"] == "198.51.100.7" and top["count"] == 2
    assert top["reason"] == "badbehavior"  # the most recent request decides
    assert top["bans"] == [{"scope": "global", "service": "_", "exp": 3000, "permanent": False, "reason": "manual"}]
    assert data["ips"][1]["bans"] == []
    assert data["reason_labels"]["badbehavior"] == "Bad behavior"


# --------------------------------------------------------------------------- #
#  Bans                                                                       #
# --------------------------------------------------------------------------- #
def ban(actions, db, utils, **data):
    return collect(actions, db, utils, action="ban", **data)


def test_ban_goes_through_bunkerweb_helper(actions, db):
    utils = FakeUtils()
    res = ban(actions, db, utils, ip="198.51.100.7", exp=3600, scope="global")
    assert res == {"ok": True, "ip": "198.51.100.7", "exp": 3600, "scope": "global", "service": ""}
    assert utils.ban_calls == [("198.51.100.7", 3600, "threat map", "", "global")]


def test_ban_for_a_service(actions, db):
    utils = FakeUtils()
    res = ban(actions, db, utils, ip="2001:db8::1", exp=0, scope="service", service="app1.example.com")
    assert res["ok"] and utils.ban_calls == [("2001:db8::1", 0, "threat map", "app1.example.com", "service")]


@pytest.mark.parametrize(
    "data, message",
    [
        ({"ip": "not-an-ip"}, "Invalid IP"),
        ({"ip": "198.51.100.7", "exp": -5}, "Invalid ban duration"),
        ({"ip": "198.51.100.7", "exp": "soon"}, "Invalid ban duration"),
        ({"ip": "198.51.100.7", "exp": 10**9}, "Invalid ban duration"),
        ({"ip": "198.51.100.7", "scope": "service", "service": "evil.example.com"}, "Unknown service"),
    ],
)
def test_ban_rejects_bad_input(actions, db, data, message):
    utils = FakeUtils()
    res = ban(actions, db, utils, **data)
    assert message in res["error"]
    assert utils.ban_calls == []


def test_ban_refused_on_read_only_database(actions):
    utils = FakeUtils()
    res = ban(actions, FakeDB(readonly=True), utils, ip="198.51.100.7")
    assert "read-only" in res["error"] and utils.ban_calls == []


def test_ban_reports_failed_instances(actions, db):
    res = ban(actions, db, FakeUtils(ban_result=["bunkerweb-1", "bunkerweb-2"]), ip="198.51.100.7")
    assert res["error"] == "Ban of 198.51.100.7 failed on: bunkerweb-1, bunkerweb-2"


def test_ban_refreshes_the_ban_cache(actions, db):
    utils = FakeUtils([report(ip="198.51.100.7")])
    first = collect(actions, db, utils, action="country", country="US")
    assert first["ips"][0]["bans"] == []
    ban(actions, db, utils, ip="198.51.100.7")
    utils.bans = [{"ip": "198.51.100.7", "exp": 86400, "ban_scope": "global", "service": "_"}]
    second = collect(actions, db, utils, action="country", country="US")
    assert second["ips"][0]["bans"][0]["scope"] == "global"


# --------------------------------------------------------------------------- #
#  Robustness                                                                 #
# --------------------------------------------------------------------------- #
def test_errors_are_returned_not_raised(actions, db):
    class Exploding(FakeUtils):
        def get_reports_query(self, **kwargs):
            raise RuntimeError("boom")

        def get_reports(self):
            raise RuntimeError("instances down")

    assert actions.pre_render(db=db, bw_instances_utils=Exploding()) == {"error": "instances down"}
    assert collect(actions, db, Exploding()) == {"error": "instances down"}


def test_garbage_reports_are_ignored(actions, db):
    reports = [None, "x", 42, report(), {"date": "yesterday"}]
    data = actions.pre_render(db=db, bw_instances_utils=FakeUtils(reports))
    assert data["stats"]["total"] == 1


def test_non_dict_payload(actions, db):
    data = actions.threatmap(db=db, bw_instances_utils=FakeUtils([report()]), data=["nope"])
    assert data["stats"]["total"] == 1


# --------------------------------------------------------------------------- #
#  plugin.json                                                                #
# --------------------------------------------------------------------------- #
def _settings():
    import json
    import re

    from conftest import ROOT

    plugin = json.loads((ROOT / "threatmap" / "plugin.json").read_text(encoding="utf-8"))
    assert plugin["id"] == "threatmap"
    return {name: re.compile(s["regex"]) for name, s in plugin["settings"].items()}, plugin["settings"]


def test_setting_defaults_match_their_regex():
    regexes, settings = _settings()
    for name, setting in settings.items():
        assert regexes[name].match(setting["default"]), name


@pytest.mark.parametrize(
    "name, good, bad",
    [
        ("THREAT_MAP_HOME_LAT", ["0", "48.86", "-33.9", "90", "-90.0", "9.5"], ["91", "-90.5", "100", "abc", "1e3", ""]),
        ("THREAT_MAP_HOME_LON", ["0", "2.35", "-122.42", "180", "-180.0", "179.99"], ["181", "-180.5", "200", "abc", ""]),
        ("THREAT_MAP_MAX_EVENTS", ["1", "200", "2000"], ["-1", "abc", ""]),
    ],
)
def test_setting_regexes(name, good, bad):
    regexes, _ = _settings()
    assert all(regexes[name].match(v) for v in good)
    assert not any(regexes[name].match(v) for v in bad)
