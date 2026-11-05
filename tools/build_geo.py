#!/usr/bin/env python3
"""Build threatmap/ui/threatmap-geo.json from pinned Natural Earth data.

The threat map draws the world as a hexagonal grid of dots in the Natural Earth I
projection. Every land dot carries the ISO 3166-1 alpha-2 code of the territory it
falls in, so the page can colour, hover and click whole countries, and every code
gets a label point (Natural Earth's own LABEL_X / LABEL_Y, i.e. the visual centre of
the main landmass rather than a skewed geometric centroid) for the attack arcs.

Sources (public domain, https://www.naturalearthdata.com/about/terms-of-use/):

* ne_50m_admin_0_map_units   -> land dots and their country codes. Map units keep
  overseas regions apart from their sovereign (French Guiana is GF, not FR), which
  is how GeoIP databases, and therefore BunkerWeb reports, code them.
* ne_10m_admin_0_countries   -> label points of every country, tiny ones included.
* ne_10m_admin_0_map_units   -> label points of overseas regions (GF, RE, BQ, ...).

The files are downloaded from a pinned commit of nvkelso/natural-earth-vector
(tag v5.1.2) and verified against their SHA-256 before use, so the output is
reproducible byte for byte:

    python3 tools/build_geo.py            # writes threatmap/ui/threatmap-geo.json
    python3 tools/build_geo.py --check    # fails if the committed file is stale
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import math
import sys
import tempfile
import urllib.request
from pathlib import Path

NE_COMMIT = "f1890d9f152c896d250a77557a5751a93d494776"  # natural-earth-vector v5.1.2
NE_BASE = f"https://raw.githubusercontent.com/nvkelso/natural-earth-vector/{NE_COMMIT}/geojson/"
NE_FILES = {
    "ne_50m_admin_0_map_units": "b8d421aca6e9e08e8cdf09cc26af111cc3e0deba4fe915611d58ade71e8a4db0",
    "ne_10m_admin_0_countries": "239eec57ac17f100a11e2536cffc56752c318b50ae765b0918ff7aab4ce8f255",
    "ne_10m_admin_0_map_units": "57da82be755f4afccd8f3b14251bb2752f5df1395f47d2d86f817470c4a48862",
}

ROOT = Path(__file__).resolve().parent.parent
OUTPUT = ROOT / "threatmap" / "ui" / "threatmap-geo.json"

# Grid: COLS dots across the full projected width, hexagonal rows (odd rows shifted
# by half a cell, row pitch = cell * sqrt(3) / 2). The map is cropped to the
# latitudes that hold inhabited land (Antarctica is not a source of web attacks).
COLS = 340
LAT_TOP = 84.0
LAT_BOTTOM = -60.0
HEX_PITCH = math.sqrt(3) / 2


def natural_earth1(lon_deg: float, lat_deg: float) -> tuple[float, float]:
    """Natural Earth I projection (Savric et al., 2011), same polynomial as d3-geo-projection."""
    lam = math.radians(lon_deg)
    phi = math.radians(lat_deg)
    phi2 = phi * phi
    phi4 = phi2 * phi2
    x = lam * (0.8707 - 0.131979 * phi2 + phi4 * (-0.013791 + phi4 * (0.003971 * phi2 - 0.001529 * phi4)))
    y = phi * (1.007226 + phi2 * (0.015085 + phi4 * (-0.044475 + 0.028874 * phi2 - 0.005916 * phi4)))
    return x, y


def iso_code(props: dict) -> str:
    """ISO 3166-1 alpha-2 code of a Natural Earth feature, '' when it has none.

    ISO_A2_EH is Natural Earth's "everything handled" variant: France and Norway are
    -99 in ISO_A2 (because of their overseas parts) but FR / NO here, Kosovo is XK.
    """
    for key in ("ISO_A2_EH", "ISO_A2"):
        value = str(props.get(key) or "")
        if len(value) == 2 and value.isalpha() and value.isupper():
            return value
    return ""


def fetch(name: str, cache: Path) -> dict:
    path = cache / f"{name}.geojson"
    if not path.is_file():
        url = NE_BASE + f"{name}.geojson"
        print(f"downloading {url}", file=sys.stderr)
        with urllib.request.urlopen(url, timeout=120) as resp:  # nosec B310 - pinned https URL
            path.write_bytes(resp.read())
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    if digest != NE_FILES[name]:
        raise SystemExit(f"{path}: sha256 {digest} does not match the pinned {NE_FILES[name]}")
    return json.loads(path.read_text(encoding="utf-8"))


def polygons(geometry: dict):
    if geometry["type"] == "Polygon":
        yield geometry["coordinates"]
    elif geometry["type"] == "MultiPolygon":
        yield from geometry["coordinates"]


class Grid:
    def __init__(self, cols: int):
        self.cols = cols
        self.x1 = natural_earth1(180.0, 0.0)[0]
        self.x0 = -self.x1
        self.cell = (self.x1 - self.x0) / cols
        self.pitch = self.cell * HEX_PITCH
        self.y1 = natural_earth1(0.0, LAT_TOP)[1]
        y_bottom = natural_earth1(0.0, LAT_BOTTOM)[1]
        self.rows = math.ceil((self.y1 - y_bottom) / self.pitch)
        # Snap the bottom edge to a whole number of rows so that the page can map a
        # dot index to a position with nothing but (col, row) arithmetic.
        self.y0 = self.y1 - self.rows * self.pitch
        self.cells = bytearray(cols * self.rows)  # 0 = sea, else index into codes + 1

    def to_grid(self, lon: float, lat: float) -> tuple[float, float]:
        x, y = natural_earth1(lon, lat)
        return (x - self.x0) / self.cell, (self.y1 - y) / self.pitch

    @staticmethod
    def row_offset(row: int) -> float:
        return 0.5 if row & 1 else 0.0

    def fill_polygon(self, rings: list, value: int) -> None:
        """Scanline fill (even-odd, so holes such as Lesotho stay out) of one polygon."""
        crossings: dict[int, list[float]] = {}
        for ring in rings:
            pts = [self.to_grid(lon, lat) for lon, lat, *_ in ring]
            for (gx0, gy0), (gx1, gy1) in zip(pts, pts[1:] + pts[:1]):
                if gy0 == gy1:
                    continue
                lo, hi = (gy0, gy1) if gy0 < gy1 else (gy1, gy0)
                # rows whose centre line (row + 0.5) lies in [lo, hi)
                first = max(0, math.ceil(lo - 0.5))
                last = min(self.rows - 1, math.ceil(hi - 0.5) - 1)
                for row in range(first, last + 1):
                    cy = row + 0.5
                    t = (cy - gy0) / (gy1 - gy0)
                    crossings.setdefault(row, []).append(gx0 + t * (gx1 - gx0))
        for row, xs in crossings.items():
            xs.sort()
            off = self.row_offset(row)
            base = row * self.cols
            for xa, xb in zip(xs[0::2], xs[1::2]):
                # columns whose centre (col + 0.5 + off) lies in [xa, xb)
                c0 = max(0, math.ceil(xa - 0.5 - off))
                c1 = min(self.cols - 1, math.ceil(xb - 0.5 - off) - 1)
                for col in range(c0, c1 + 1):
                    if not self.cells[base + col]:
                        self.cells[base + col] = value

    def nearest_cell(self, lon: float, lat: float) -> int | None:
        gx, gy = self.to_grid(lon, lat)
        row = int(gy)
        if not 0 <= row < self.rows:
            return None
        col = int(gx - self.row_offset(row))
        if not 0 <= col < self.cols:
            return None
        return row * self.cols + col


def encode_runs(cells: bytearray) -> str:
    """Run-length encode the grid as LEB128 varint pairs (value, run), base64."""
    out = bytearray()

    def varint(n: int) -> None:
        while True:
            byte = n & 0x7F
            n >>= 7
            if n:
                out.append(byte | 0x80)
            else:
                out.append(byte)
                return

    run_value, run_len = cells[0], 0
    for value in cells:
        if value == run_value:
            run_len += 1
            continue
        varint(run_value)
        varint(run_len)
        run_value, run_len = value, 1
    varint(run_value)
    varint(run_len)
    return base64.b64encode(bytes(out)).decode("ascii")


def build(cache: Path) -> dict:
    units = fetch("ne_50m_admin_0_map_units", cache)
    countries_10m = fetch("ne_10m_admin_0_countries", cache)
    units_10m = fetch("ne_10m_admin_0_map_units", cache)

    # Label points: countries first (one feature per country), map units only fill
    # the codes that countries lack (overseas regions merged into their sovereign).
    labels: dict[str, list[float]] = {}
    for dataset in (countries_10m, units_10m):
        for feature in dataset["features"]:
            props = feature["properties"]
            code = iso_code(props)
            if not code or code in labels:
                continue
            lon, lat = props.get("LABEL_X"), props.get("LABEL_Y")
            if lon is None or lat is None:
                continue
            labels[code] = [round(float(lon), 2), round(float(lat), 2)]

    grid = Grid(COLS)
    # index 0 is "land without an ISO code" (Somaliland, N. Cyprus, Siachen): drawn,
    # never coloured, because GeoIP databases never report a code for them.
    codes = [""] + sorted({iso_code(f["properties"]) for f in units["features"]} - {""})
    if len(codes) >= 255:
        raise SystemExit("too many codes for a one-byte cell value")
    index = {code: i + 1 for i, code in enumerate(codes)}

    # Admin-0 polygons do not overlap, so a dot centre falls in at most one of them
    # and the (deterministic) file order is enough.
    for feature in units["features"]:
        value = index[iso_code(feature["properties"])]
        for rings in polygons(feature["geometry"]):
            grid.fill_polygon(rings, value)

    # Territories too small for a whole dot (Singapore, Malta, Hong Kong, Luxembourg,
    # most of the Pacific) get the cell under their label point, so every attack
    # origin has a visible, hoverable spot. A cell is only taken from a neighbour that
    # keeps at least one other dot; failing that the nearest free cell is used.
    counts = [0] * (len(codes) + 1)
    for value in grid.cells:
        counts[value] += 1

    def claimable(cell: int) -> bool:
        owner = grid.cells[cell]
        return owner == 0 or owner == index[""] or counts[owner] > 1

    for code in codes[1:]:
        if counts[index[code]] or code not in labels:
            continue
        center = grid.nearest_cell(*labels[code])
        if center is None:
            continue  # outside the cropped latitudes (Antarctica)
        row, col = divmod(center, grid.cols)
        candidates = [center] + [
            r * grid.cols + c
            for r in range(row - 1, row + 2)
            for c in range(col - 1, col + 2)
            if 0 <= r < grid.rows and 0 <= c < grid.cols and (r, c) != (row, col)
        ]
        for cell in candidates:
            if claimable(cell):
                counts[grid.cells[cell]] -= 1
                grid.cells[cell] = index[code]
                counts[index[code]] += 1
                break

    # Every code with a dot must have a label point and vice versa where possible.
    missing = sorted(code for code in codes[1:] if code not in labels)
    if missing:
        raise SystemExit(f"codes without a label point: {missing}")

    return {
        "version": 1,
        "source": f"Natural Earth v5.1.2 (nvkelso/natural-earth-vector@{NE_COMMIT[:12]}), public domain",
        "projection": "naturalEarth1",
        "cols": grid.cols,
        "rows": grid.rows,
        "hex": True,
        "bounds": [round(grid.x0, 9), round(grid.y0, 9), round(grid.x1, 9), round(grid.y1, 9)],
        "lat": [LAT_BOTTOM, LAT_TOP],
        "codes": codes,
        "cells": encode_runs(grid.cells),
        "labels": dict(sorted(labels.items())),
    }


def render(data: dict) -> str:
    # Compact, but one key per line keeps diffs readable; no "{{" / "{%" / "{#"
    # sequences can appear, so the file is safe to {% include %} in the Jinja page.
    lines = ["{"]
    items = list(data.items())
    for i, (key, value) in enumerate(items):
        sep = "," if i < len(items) - 1 else ""
        lines.append(f"  {json.dumps(key)}: {json.dumps(value, separators=(',', ':'), ensure_ascii=True)}{sep}")
    lines.append("}")
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--cache", type=Path, help="directory holding (or receiving) the Natural Earth GeoJSON files")
    parser.add_argument("--check", action="store_true", help="exit 1 if the committed file differs from a fresh build")
    parser.add_argument("--output", type=Path, default=OUTPUT)
    args = parser.parse_args()

    with tempfile.TemporaryDirectory() as tmp:
        cache = args.cache or Path(tmp)
        cache.mkdir(parents=True, exist_ok=True)
        text = render(build(cache))

    if args.check:
        current = args.output.read_text(encoding="utf-8") if args.output.is_file() else ""
        if current != text:
            print(f"{args.output} is stale: run tools/build_geo.py", file=sys.stderr)
            return 1
        print(f"{args.output} is up to date")
        return 0

    args.output.write_text(text, encoding="utf-8")
    print(f"wrote {args.output} ({len(text):,} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
