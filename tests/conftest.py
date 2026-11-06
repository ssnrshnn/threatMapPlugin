"""Shared fixtures: load threatmap/ui/actions.py the way the BunkerWeb UI does and
provide small fakes for the ``db`` and ``bw_instances_utils`` objects it receives."""

import importlib.machinery
import importlib.util
import sys
from itertools import count
from pathlib import Path
from time import time

import pytest

# never leave a __pycache__ inside threatmap/ui: that folder is what gets installed
sys.dont_write_bytecode = True

ROOT = Path(__file__).resolve().parent.parent
UI_DIR = ROOT / "threatmap" / "ui"
STATE_MODULE = "_bw_threatmap_state"
_ids = count(1)


def load_actions():
    """BunkerWeb runs SourceFileLoader("actions", path).load_module() on every request,
    which re-executes the file in place; exec_module on a fresh module is equivalent."""
    loader = importlib.machinery.SourceFileLoader("threatmap_actions", str(UI_DIR / "actions.py"))
    spec = importlib.util.spec_from_loader("threatmap_actions", loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


@pytest.fixture
def actions():
    sys.modules.pop(STATE_MODULE, None)
    yield load_actions()
    sys.modules.pop(STATE_MODULE, None)


def report(**overrides):
    """A blocked-request report as stored by BunkerWeb's metrics plugin."""
    data = {
        "id": f"req-{next(_ids)}",
        "date": time() - 60,
        "ip": "203.0.113.10",
        "country": "US",
        "method": "GET",
        "url": "/?q=<script>",
        "status": 403,
        "user_agent": "curl/8",
        "reason": "modsecurity",
        "server_name": "app1.example.com",
        "data": {},
        "security_mode": "block",
    }
    data.update(overrides)
    return data


class FakeDB:
    def __init__(self, config=None, plugins=None, readonly=False):
        self.config = {
            "SERVER_NAME": "www.example.com app1.example.com",
            "USE_REDIS": "no",
            "THREAT_MAP_MAX_EVENTS": "200",
            "THREAT_MAP_HOME_LAT": "48.86",
            "THREAT_MAP_HOME_LON": "2.35",
            "THREAT_MAP_HOME_LABEL": "BunkerWeb",
        }
        self.config.update(config or {})
        self.plugins = plugins if plugins is not None else [{"id": "modsecurity", "name": "ModSecurity"}, {"id": "badbehavior", "name": "Bad behavior"}]
        self.readonly = readonly
        self.config_calls = 0

    def get_config(self):
        self.config_calls += 1
        return dict(self.config)

    def get_plugins(self):
        return list(self.plugins)


class FakeUtils:
    """bw_instances_utils with the Redis-backed query of BunkerWeb >= 1.6."""

    def __init__(self, reports=None, bans=None, ban_result=""):
        self.reports = list(reports or [])
        self.bans = list(bans or [])
        self.ban_result = ban_result
        self.ban_calls = []
        self.query_calls = 0
        self.get_reports_calls = 0
        self.last_query = None

    def get_reports_query(self, **kwargs):
        self.query_calls += 1
        self.last_query = kwargs
        return {"total": len(self.reports), "filtered": len(self.reports), "data": list(self.reports), "pane_counts": {}}

    def get_reports(self):
        self.get_reports_calls += 1
        return list(self.reports)

    def get_bans(self):
        return list(self.bans)

    def ban(self, ip, exp, reason, service, ban_scope="global"):
        self.ban_calls.append((ip, exp, reason, service, ban_scope))
        return self.ban_result


class LegacyUtils(FakeUtils):
    """A core without get_reports_query: only the per-instance buffers."""

    get_reports_query = None


@pytest.fixture
def db():
    return FakeDB()
