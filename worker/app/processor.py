from datetime import datetime, timezone
from pathlib import Path

from pydantic import ValidationError

from app.db import get_database
from app.fingerprint import build_fingerprint
from app.models import IngestedVulnerability, ProcessingSummary, normalize_finding_payload
from app.parser import iter_raw_findings

SEVERITY_RANK = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "info": 1,
    "unknown": 0,
}


def _severity_key(value: str | None) -> int:
    return SEVERITY_RANK.get((value or "unknown").lower(), 0)


def _sort_ports(values: set[str]) -> list[str]:
    return sorted(values, key=lambda value: (not value.isdigit(), int(value) if value.isdigit() else value))


def _normalize_document(finding: IngestedVulnerability, source_file: str) -> dict:
    document = finding.model_dump(by_alias=True, exclude_none=True, exclude={"info"})
    document.update(
        {
            "name": finding.name,
            "severity": finding.normalized_severity(),
            "source_file": source_file,
        }
    )

    if finding.info and finding.info.author:
        document["author"] = finding.info.author
    if finding.info and finding.info.tags:
        document["tags"] = finding.info.tags
    if finding.info and finding.info.description:
        document["description"] = finding.info.description
    if finding.info and finding.info.reference:
        document["reference"] = finding.info.reference

    return document


async def _upsert_asset(
    host: str,
    severity: str,
    ip_address: str | None,
    port: str | None,
    service: str | None,
    template_id: str,
    seen_at: datetime,
) -> None:
    db = get_database()
    existing_asset = await db.assets.find_one({"host": host})
    current_highest = existing_asset.get("highest_severity") if existing_asset else None
    next_highest = severity if _severity_key(severity) > _severity_key(current_highest) else current_highest

    current_ip_addresses = existing_asset.get("ip_addresses", []) if existing_asset else []
    current_ports = existing_asset.get("open_ports", []) if existing_asset else []
    current_services = existing_asset.get("services", []) if existing_asset else []
    current_template_ids = existing_asset.get("template_ids", []) if existing_asset else []

    next_ip_addresses = sorted({*current_ip_addresses, *([ip_address] if ip_address else [])})
    next_open_ports = _sort_ports({*current_ports, *([str(port)] if port else [])})
    next_services = sorted({*current_services, *([service] if service else [])})
    next_template_ids = sorted({*current_template_ids, template_id})

    update_document = {
        "$set": {
            "host": host,
            "last_seen": seen_at,
            "highest_severity": next_highest,
            "type": "subdomain",
            "ip_addresses": next_ip_addresses,
            "open_ports": next_open_ports,
            "services": next_services,
            "template_ids": next_template_ids,
        },
        "$setOnInsert": {
            "first_seen": seen_at,
        },
    }

    await db.assets.update_one({"host": host}, update_document, upsert=True)


async def _recalculate_asset(host: str) -> None:
    db = get_database()
    vulnerabilities = await db.vulnerabilities.find({"host": host, "status": "Open"}).to_list(length=None)
    if vulnerabilities:
        highest_severity = max(
            (
                document.get("override_severity") or document.get("severity") or "unknown"
                for document in vulnerabilities
            ),
            key=_severity_key,
        )
        ip_addresses = sorted({document.get("ip") for document in vulnerabilities if document.get("ip")})
        open_ports = _sort_ports({str(document.get("port")) for document in vulnerabilities if document.get("port")})
        services = sorted(
            {
                document.get("scheme") or document.get("type")
                for document in vulnerabilities
                if document.get("scheme") or document.get("type")
            }
        )
        template_ids = sorted(
            {document.get("template-id") for document in vulnerabilities if document.get("template-id")}
        )
        last_seen_values = [document.get("last_seen") for document in vulnerabilities if document.get("last_seen")]
        last_seen = max(last_seen_values) if last_seen_values else datetime.now(timezone.utc)
        await db.assets.update_one(
            {"host": host},
            {
                "$set": {
                    "host": host,
                    "highest_severity": highest_severity,
                    "ip_addresses": ip_addresses,
                    "open_ports": open_ports,
                    "services": services,
                    "template_ids": template_ids,
                    "last_seen": last_seen,
                    "vulnerability_count": len(vulnerabilities),
                    "type": "subdomain",
                },
                "$setOnInsert": {
                    "first_seen": last_seen,
                },
            },
            upsert=True,
        )
        return

    existing_asset = await db.assets.find_one({"host": host})
    if existing_asset:
        await db.assets.update_one(
            {"host": host},
            {
                "$set": {
                    "highest_severity": None,
                    "vulnerability_count": 0,
                    "open_ports": [],
                    "services": [],
                    "template_ids": [],
                }
            },
        )


async def process_file(file_path: Path) -> ProcessingSummary:
    db = get_database()
    summary = ProcessingSummary(file_name=file_path.name)
    touched_hosts: set[str] = set()

    for raw_finding in iter_raw_findings(file_path):
        try:
            finding = IngestedVulnerability.model_validate(normalize_finding_payload(raw_finding))
        except ValidationError:
            summary.skipped += 1
            continue

        now = datetime.now(timezone.utc)
        normalized_severity = finding.normalized_severity()
        fingerprint = build_fingerprint(finding.template_id, finding.matched_at)
        summary.severities_seen.add(normalized_severity)
        touched_hosts.add(finding.host)

        existing = await db.vulnerabilities.find_one({"fingerprint": fingerprint})
        if existing:
            await db.vulnerabilities.update_one(
                {"fingerprint": fingerprint},
                {"$set": {"last_seen": now}},
            )
            summary.updated += 1
        else:
            document = _normalize_document(finding, file_path.name)
            document.update(
                {
                    "fingerprint": fingerprint,
                    "first_seen": now,
                    "last_seen": now,
                    "status": "Open",
                }
            )
            await db.vulnerabilities.insert_one(document)
            summary.inserted += 1

        await _upsert_asset(
            finding.host,
            normalized_severity,
            finding.ip,
            finding.port,
            finding.scheme or finding.type,
            finding.template_id,
            now,
        )
        summary.assets_updated += 1
        summary.processed += 1

    for host in touched_hosts:
        await _recalculate_asset(host)

    return summary
