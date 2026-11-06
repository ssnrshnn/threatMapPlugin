"""Render template.html exactly like BunkerWeb's custom_plugin_page() does."""

import json
import re
from html.parser import HTMLParser

import pytest
from jinja2 import Environment, FileSystemLoader, select_autoescape

from conftest import UI_DIR, FakeUtils, report

INCLUDED = ("threatmap.js", "threatmap.css", "threatmap-geo.json")


def render(pre_render):
    env = Environment(loader=FileSystemLoader((UI_DIR.as_posix() + "/",)), autoescape=select_autoescape(["html"]))
    page = (UI_DIR / "template.html").read_text(encoding="utf-8")
    return env.from_string(page).render(pre_render=pre_render, csrf_token=lambda: "csrf-123", script_nonce="nonce-abc")


class Scripts(HTMLParser):
    def __init__(self):
        super().__init__()
        self.scripts = []
        self._current = None

    def handle_starttag(self, tag, attrs):
        if tag == "script":
            self._current = [dict(attrs), ""]

    def handle_data(self, data):
        if self._current is not None:
            self._current[1] += data

    def handle_endtag(self, tag):
        if tag == "script" and self._current is not None:
            self.scripts.append(tuple(self._current))
            self._current = None


@pytest.fixture
def page(actions, db):
    data = actions.pre_render(db=db, bw_instances_utils=FakeUtils([report(url="/</script><script>alert(1)</script>")]))
    return render({"status": "ok", "code": 200, "data": data})


def scripts_of(page):
    parser = Scripts()
    parser.feed(page)
    return {attrs.get("id") or attrs.get("nonce"): (attrs, body) for attrs, body in parser.scripts}


def test_page_renders_with_all_includes(page):
    scripts = scripts_of(page)
    assert set(scripts) == {"threatmap-bootstrap", "threatmap-geo", "nonce-abc"}
    geo = json.loads(scripts["threatmap-geo"][1])
    assert geo["projection"] == "naturalEarth1"
    assert "const POLL_MS" in scripts["nonce-abc"][1]
    assert ":is(#threatmap-root, #threatmap-soc) .tm-map-card" in page
    assert 'value="csrf-123"' in page


def test_bootstrap_json_is_escaped(page):
    """A hostile URL in a report must not be able to close the <script> tag."""
    raw = scripts_of(page)["threatmap-bootstrap"][1]
    assert "</script" not in raw
    data = json.loads(raw)
    assert data["events"][0]["url"].startswith("/</script>")


def test_error_banner_when_pre_render_fails():
    html = render({"status": "ok", "code": 200, "data": {"error": "instances down"}})
    assert "An error occurred while collecting threat map data: instances down" in html


def test_error_banner_is_escaped():
    html = render({"status": "ok", "code": 200, "data": {"error": "<img src=x onerror=alert(1)>"}})
    assert "<img src=x" not in html


@pytest.mark.parametrize("name", INCLUDED)
def test_included_files_contain_no_jinja_syntax(name):
    """Included files are parsed as Jinja templates: a stray delimiter would break the page."""
    text = (UI_DIR / name).read_text(encoding="utf-8")
    assert not re.search(r"\{[{%#]", text)


def test_script_has_no_unsafe_dom_sinks():
    js = (UI_DIR / "threatmap.js").read_text(encoding="utf-8")
    for sink in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function"):
        assert sink not in js, sink


def test_page_works_without_data():
    html = render({"status": "ko", "code": 500, "message": "boom"})
    assert "An error occurred while collecting threat map data" in html
    assert 'id="threatmap-root"' in html
