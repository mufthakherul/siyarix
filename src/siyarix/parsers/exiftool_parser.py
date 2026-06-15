# SPDX-License-Identifier: AGPL-3.0-or-later

"""Exiftool JSON output parser — extracts key EXIF fields: Make, Model, GPS, Software, CreateDate."""

from __future__ import annotations

from . import _now_iso

import json
import re

_JSON_LINE_RE = re.compile(r"^\s*[{[]")

_EXIF_FIELDS = (
    "Make",
    "Model",
    "GPSPosition",
    "GPSLatitude",
    "GPSLongitude",
    "Software",
    "CreateDate",
    "DateTimeOriginal",
    "Artist",
    "Copyright",
    "ImageDescription",
    "Orientation",
    "XResolution",
    "YResolution",
    "ExifImageWidth",
    "ExifImageHeight",
)

_SUMMARY_RE = re.compile(
    r"(?:files?\s+(?:read|processed)|image\s+files)",
    re.IGNORECASE,
)


class ExiftoolParser:
    """Parse exiftool JSON output into normalized finding dicts."""

    def parse(self, output: str) -> list[dict]:
        findings: list[dict] = []
        seen: set[str] = set()
        trimmed = output.strip()

        if not trimmed:
            return findings

        # Try JSON array or object
        data = None
        if trimmed.startswith("{"):
            try:
                data = json.loads(trimmed)
            except json.JSONDecodeError:
                pass

        if trimmed.startswith("["):
            try:
                data = json.loads(trimmed)
            except json.JSONDecodeError:
                pass

        if data is None:
            return findings

        entries = data if isinstance(data, list) else [data]

        for entry in entries:
            source_file = entry.get("SourceFile", "")
            if not source_file:
                continue

            key = f"exif:{source_file}"
            if key in seen:
                continue
            seen.add(key)

            extracted = {}
            for field in _EXIF_FIELDS:
                if field in entry and entry[field]:
                    extracted[field] = entry[field]

            if not extracted:
                continue

            gps_parts = []
            lat = entry.get("GPSLatitude")
            lon = entry.get("GPSLongitude")
            if lat and lon:
                gps_parts.append(f"Lat: {lat}, Lon: {lon}")
            gps = entry.get("GPSPosition")
            if gps:
                gps_parts.append(str(gps))
            gps_str = "; ".join(gps_parts)

            description_parts = []
            make_model = []
            if "Make" in extracted:
                make_model.append(str(extracted["Make"]))
            if "Model" in extracted:
                make_model.append(str(extracted["Model"]))
            if make_model:
                description_parts.append("Device: " + " ".join(make_model))

            if "CreateDate" in extracted:
                description_parts.append(f"Date: {extracted['CreateDate']}")

            if "Software" in extracted:
                description_parts.append(f"Software: {extracted['Software']}")

            if gps_str:
                description_parts.append(f"GPS: {gps_str}")

            evidence = json.dumps(extracted, default=str)
            description = "; ".join(description_parts) if description_parts else f"EXIF data from {source_file}"

            findings.append({
                "title": f"Exiftool: {source_file}",
                "severity": "info",
                "description": description,
                "evidence": evidence,
                "tool": "exiftool",
                "target": source_file,
                "timestamp": _now_iso(),
            })

        return findings
