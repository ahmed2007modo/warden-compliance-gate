"""Read-only registry endpoints for the shared control set and evidence."""

from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.api.dependencies import get_control_registry, get_session_db
from app.domain.api_schemas import ControlOut, EvidenceOut
from app.domain.registry import ControlRegistry
from app.models.orm import EvidenceRow

router = APIRouter(tags=["registry"])


@router.get("/controls", response_model=list[ControlOut])
def list_controls(controls: ControlRegistry = Depends(get_control_registry)) -> list[ControlOut]:
    out: list[ControlOut] = []
    for control in controls.all_controls():
        for framework_id, mapping in controls.mappings.items():
            for ref, payload in mapping.items():
                if payload["control_id"] != control.control_id:
                    continue
                out.append(
                    ControlOut(
                        control_id=control.control_id,
                        shared_id=control.control_id,
                        framework_id=framework_id,
                        title=control.title,
                        requirement_text=payload["requirement_text"],
                        domain=ref,
                        evidence_expected=list(control.evidence_expected),
                    )
                )
    return out


@router.get("/evidence", response_model=list[EvidenceOut])
def list_evidence(session: Session = Depends(get_session_db)) -> list[EvidenceOut]:
    rows = session.query(EvidenceRow).all()
    return [
        EvidenceOut(
            evidence_id=row.evidence_id,
            control_id=row.control_id,
            source=row.source,
            content_hash=row.content_hash,
            freshness_status=row.freshness_status,
            age_days=row.age_days,
            evidence_type=row.evidence_type,
            resource_refs=list(row.resource_refs) if row.resource_refs else [],
        )
        for row in rows
    ]
