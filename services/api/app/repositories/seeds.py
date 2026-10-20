"""Idempotent seeding of the evidence registry into the database."""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.dependencies import get_evidence_registry
from app.core.logging import get_logger
from app.models.orm import EvidenceRow

logger = get_logger(__name__)


def seed_evidence(session: Session) -> int:
    registry = get_evidence_registry()
    seeded = 0
    for item in registry.all():
        existing = session.scalars(
            select(EvidenceRow).where(EvidenceRow.evidence_id == item.evidence_id)
        ).first()
        if existing is not None:
            continue
        session.add(
            EvidenceRow(
                evidence_id=item.evidence_id,
                control_id=item.control_id,
                source=item.source,
                source_location=item.source_location,
                collected_at=item.collected_at,
                resource_refs=list(item.resource_refs),
                content_hash=item.content_hash,
                evidence_type=item.evidence_type,
                age_days=item.age_days,
                freshness_status=item.freshness_status,
                provenance=item.provenance,
                verification_status=item.verification_status,
            )
        )
        seeded += 1
    session.commit()
    if seeded:
        logger.info("evidence_seed", extra={"seeded": seeded})
    return seeded
