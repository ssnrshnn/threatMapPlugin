"""Integrity of the generated map data (threatmap/ui/threatmap-geo.json)."""

import base64
import importlib.util
import json
from collections import Counter
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
GEO_FILE = ROOT / "threatmap" / "ui" / "threatmap-geo.json"
FLAGS_FILE = Path(__file__).resolve().parent / "data" / "bunkerweb_flag_codes.txt"


def load_builder():
    spec = importlib.util.spec_from_file_location("build_geo", ROOT / "tools" / "build_geo.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def geo():
    return json.loads(GEO_FILE.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def cells(geo):
    raw = base64.b64decode(geo["cells"])
    pos = 0

    def varint():
        nonlocal pos
        value = shift = 0
        while True:
            byte = raw[pos]
            pos += 1
            value |= (byte & 0x7F) << shift
            shift += 7
            if not byte & 0x80:
                return value

    out = []
    while pos < len(raw):
        value, run = varint(), varint()
        out.extend([value] * run)
    return out


def test_grid_dimensions(geo, cells):
    assert len(cells) == geo["cols"] * geo["rows"]
    assert max(cells) <= len(geo["codes"])
    assert geo["codes"][0] == ""  # land without an ISO code
    assert geo["codes"][1:] == sorted(geo["codes"][1:])


def test_bounds_match_the_projection(geo):
    builder = load_builder()
    x0, y0, x1, y1 = geo["bounds"]
    assert x1 == pytest.approx(builder.natural_earth1(180, 0)[0], abs=1e-8)
    assert y1 == pytest.approx(builder.natural_earth1(0, geo["lat"][1])[1], abs=1e-8)
    pitch = (x1 - x0) / geo["cols"] * builder.HEX_PITCH
    assert (y1 - y0) == pytest.approx(geo["rows"] * pitch, abs=1e-8)
    assert y0 <= builder.natural_earth1(0, geo["lat"][0])[1]


def test_every_code_has_a_label_and_a_dot(geo, cells):
    counts = Counter(cells)
    codes = geo["codes"]
    without_label = [cc for cc in codes[1:] if cc not in geo["labels"]]
    assert without_label == []
    without_dot = [cc for i, cc in enumerate(codes) if i and not counts[i + 1]]
    assert without_dot == ["AQ"]  # Antarctica lies below the cropped latitudes


def test_every_bunkerweb_flag_is_placeable(geo):
    """BunkerWeb ships one flag per country code its GeoIP data can return: all of the
    real territories must be placeable on the map."""
    lines = FLAGS_FILE.read_text(encoding="utf-8").splitlines()
    flags = {code for line in lines if not line.startswith("#") for code in line.split()}
    assert len(flags) == 258
    not_geographic = {"EU", "UN", "XX", "ZZ", "CP", "DG", "IC", "PC"}  # groupings / reserved codes
    assert sorted(flags - set(geo["labels"]) - not_geographic) == []


@pytest.mark.parametrize(
    "city, lon, lat, code",
    [
        ("Paris", 2.35, 48.86, "FR"),
        ("Berlin", 13.40, 52.52, "DE"),
        ("Madrid", -3.70, 40.42, "ES"),
        ("Ankara", 32.85, 39.93, "TR"),
        ("Moscow", 37.62, 55.75, "RU"),
        ("Beijing", 116.40, 39.90, "CN"),
        ("Delhi", 77.21, 28.61, "IN"),
        ("Kansas City", -94.58, 39.10, "US"),
        ("Brasilia", -47.88, -15.79, "BR"),
        ("Nairobi", 36.82, -1.29, "KE"),
        ("Alice Springs", 133.88, -23.70, "AU"),
        ("Mexico City", -99.13, 19.43, "MX"),
        ("Cayenne", -52.80, 4.40, "GF"),  # overseas region, not France
    ],
)
def test_known_places_land_in_the_right_country(geo, cells, city, lon, lat, code):
    builder = load_builder()
    grid = builder.Grid(geo["cols"])
    cell = grid.nearest_cell(lon, lat)
    assert cell is not None
    row, col = divmod(cell, geo["cols"])
    neighbourhood = {
        geo["codes"][cells[r * geo["cols"] + c] - 1] for r in range(row - 1, row + 2) for c in range(col - 1, col + 2) if cells[r * geo["cols"] + c]
    }
    assert code in neighbourhood, f"{city}: {sorted(neighbourhood)}"


def test_labels_are_inside_the_map(geo):
    for cc, (lon, lat) in geo["labels"].items():
        assert -180 <= lon <= 180, cc
        assert -90 <= lat <= 90, cc


def test_no_jinja_syntax_in_generated_file():
    text = GEO_FILE.read_text(encoding="utf-8")
    assert "{{" not in text and "{%" not in text and "{#" not in text
