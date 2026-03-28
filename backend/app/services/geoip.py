from __future__ import annotations

from dataclasses import dataclass
from ipaddress import ip_address
from pathlib import Path
from threading import Lock
from typing import Any

import geoip2.database
from geoip2.errors import AddressNotFoundError

from app.core.config import get_settings


@dataclass
class GeoIpRecord:
    latitude: float
    longitude: float
    country: str
    city: str
    provider: str


_SETTINGS = get_settings()
_CITY_PATH = Path(_SETTINGS.geoip_city_db_path)
_ASN_PATH = Path(_SETTINGS.geoip_asn_db_path)

_LOCK = Lock()
_CITY_READER: geoip2.database.Reader | None = None
_ASN_READER: geoip2.database.Reader | None = None
_CITY_MTIME_NS: int | None = None
_ASN_MTIME_NS: int | None = None


def _resolve_file_state(path: Path) -> int | None:
    try:
        return path.stat().st_mtime_ns
    except OSError:
        return None


def _refresh_reader_if_needed(
    *,
    current_reader: geoip2.database.Reader | None,
    file_path: Path,
    current_mtime_ns: int | None,
) -> tuple[geoip2.database.Reader | None, int | None]:
    next_mtime_ns = _resolve_file_state(file_path)
    if next_mtime_ns is None:
        if current_reader is not None:
            current_reader.close()
        return None, None

    if current_reader is not None and current_mtime_ns == next_mtime_ns:
        return current_reader, current_mtime_ns

    if current_reader is not None:
        current_reader.close()

    return geoip2.database.Reader(str(file_path)), next_mtime_ns


def _ensure_readers() -> tuple[geoip2.database.Reader | None, geoip2.database.Reader | None]:
    global _CITY_READER, _ASN_READER, _CITY_MTIME_NS, _ASN_MTIME_NS
    with _LOCK:
        _CITY_READER, _CITY_MTIME_NS = _refresh_reader_if_needed(
            current_reader=_CITY_READER,
            file_path=_CITY_PATH,
            current_mtime_ns=_CITY_MTIME_NS,
        )
        _ASN_READER, _ASN_MTIME_NS = _refresh_reader_if_needed(
            current_reader=_ASN_READER,
            file_path=_ASN_PATH,
            current_mtime_ns=_ASN_MTIME_NS,
        )
        return _CITY_READER, _ASN_READER


def close_geoip_readers() -> None:
    global _CITY_READER, _ASN_READER, _CITY_MTIME_NS, _ASN_MTIME_NS
    with _LOCK:
        if _CITY_READER is not None:
            _CITY_READER.close()
        if _ASN_READER is not None:
            _ASN_READER.close()
        _CITY_READER = None
        _ASN_READER = None
        _CITY_MTIME_NS = None
        _ASN_MTIME_NS = None


def lookup_geoip(ip_value: str) -> GeoIpRecord | None:
    city_reader, asn_reader = _ensure_readers()
    if city_reader is None:
        return None

    try:
        parsed_ip = ip_address(ip_value)
    except ValueError:
        return None

    if not parsed_ip.is_global:
        return None

    try:
        city_response = city_reader.city(ip_value)
    except AddressNotFoundError:
        return None
    except Exception:
        return None

    latitude = city_response.location.latitude
    longitude = city_response.location.longitude
    if latitude is None or longitude is None:
        return None

    city = city_response.city.name or "Unknown City"
    country = city_response.country.name or city_response.country.iso_code or "Unknown Country"
    provider = "Unknown Provider"

    if asn_reader is not None:
        try:
            asn_response = asn_reader.asn(ip_value)
            if asn_response.autonomous_system_organization:
                provider = asn_response.autonomous_system_organization
        except AddressNotFoundError:
            pass
        except Exception:
            pass

    return GeoIpRecord(
        latitude=float(latitude),
        longitude=float(longitude),
        city=city,
        country=country,
        provider=provider,
    )


def map_payload_node(
    *,
    ip_value: str,
    severity: str,
    asset_count: int,
    geoip_record: GeoIpRecord,
) -> dict[str, Any]:
    return {
        "ip": ip_value,
        "lat": geoip_record.latitude,
        "lon": geoip_record.longitude,
        "severity": severity,
        "provider": geoip_record.provider,
        "asset_count": asset_count,
        "city": geoip_record.city,
        "country": geoip_record.country,
    }
