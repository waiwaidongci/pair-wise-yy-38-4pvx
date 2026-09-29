from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from .domain import (ConflictError, ensure_role, normalize_severity,
                     require_number, require_text)
from .repository import Repository
from .rules import (AUDIT_ROLES, CREATE_ROLES, ENTITY, RECORD_ROLES,
                    SNAPSHOT_FIELD_LABELS, SNAPSHOT_ROLES, TITLE, VIEW_ROLES,
                    completion_blockers, escalation_required, priority_score,
                    response_deadline_hours, role_for_transition,
                    snapshot_blockers, validate_transition)


class Service:
    def __init__(self, repository: Repository):
        self.repository = repository

    def _view(self, role: str) -> None:
        ensure_role(role, VIEW_ROLES)

    def create_item(self, payload: Dict[str, Any], actor: str, role: str) -> Dict[str, Any]:
        ensure_role(role, CREATE_ROLES)
        actor = require_text(actor, "actor", 100)
        title = require_text(payload.get("title"), "title", 200)
        description = require_text(payload.get("description"), "description")
        severity = normalize_severity(payload.get("severity"))
        quantity = require_number(payload.get("quantity", 0), "quantity")
        threshold = require_number(payload.get("threshold", 1), "threshold", 0.000001)
        external_ref = payload.get("external_ref")
        if external_ref is not None:
            external_ref = require_text(external_ref, "external_ref", 100)
        item = self.repository.create_item(title, description, severity, quantity,
                                           threshold, external_ref, actor)
        self.repository.append_audit("create", ENTITY, item["id"], actor, {
            "title": title, "severity": severity, "quantity": quantity,
            "priority": priority_score(severity, quantity, threshold),
            "snapshot_version": item["snapshot_version"],
        })
        return self.enrich(item)

    def add_record(self, item_id: int, payload: Dict[str, Any], actor: str,
                   role: str) -> Dict[str, Any]:
        ensure_role(role, RECORD_ROLES)
        actor = require_text(actor, "actor", 100)
        kind = require_text(payload.get("kind"), "kind", 100)
        detail = require_text(payload.get("detail"), "detail")
        status = payload.get("status", "open")
        if status not in ("open", "closed"):
            raise ValueError("status必须是open或closed")
        external_ref = payload.get("external_ref")
        if external_ref is not None:
            external_ref = require_text(external_ref, "external_ref", 100)
        record = self.repository.add_record(item_id, kind, detail, status,
                                            external_ref, actor)
        self.repository.append_audit("record", ENTITY, item_id, actor, {
            "record_id": record["id"], "kind": kind, "status": status,
        })
        return record

    def transition(self, item_id: int, target: str, expected_version: int,
                   actor: str, role: str,
                   idempotency_key: Optional[str] = None) -> Dict[str, Any]:
        actor = require_text(actor, "actor", 100)
        if idempotency_key is None:
            return self._do_transition(item_id, target, expected_version, actor, role, None)
        idempotency_key = require_text(idempotency_key, "idempotency_key", 200)
        action = f"transition:{target}"
        claim, _status, body = self.repository.claim_idempotency_key(
            idempotency_key, actor, action, item_id)
        if claim == "replay":
            self.repository.append_audit("idempotent_replay", ENTITY, item_id, actor, {
                "idempotency_key": idempotency_key, "target": target,
            })
            return self.enrich(body) if isinstance(body, dict) else body
        try:
            return self._do_transition(item_id, target, expected_version, actor, role,
                                       idempotency_key)
        except Exception as exc:
            self.repository.fail_idempotency_key(idempotency_key, actor, str(exc))
            raise

    def _do_transition(self, item_id: int, target: str, expected_version: int,
                       actor: str, role: str,
                       idem_key: Optional[str]) -> Dict[str, Any]:
        if not isinstance(expected_version, int) or expected_version < 1:
            raise ValueError("expected_version必须是正整数")
        item = self.repository.get_item(item_id)
        ensure_role(role, role_for_transition(target))
        if item["version"] != expected_version:
            raise ConflictError("版本冲突，请刷新后重试")
        validate_transition(item["status"], target)
        current_snapshot = self.repository.current_snapshot_version()
        blockers = completion_blockers(target, self.repository.open_record_count(item_id))
        blockers += snapshot_blockers(target, item["snapshot_version"], current_snapshot)
        if blockers:
            self.repository.append_audit("blocked", ENTITY, item_id, actor, {
                "from": item["status"], "to": target, "blockers": blockers,
                "snapshot_version": item["snapshot_version"],
                "current_snapshot_version": current_snapshot,
            })
            raise ConflictError("；".join(blockers), blockers=blockers)
        updated = self.repository.transition_item(item_id, target, expected_version,
                                                  actor, idem_key=idem_key)
        detail: Dict[str, Any] = {
            "from": item["status"], "to": target,
            "escalation_required": escalation_required(
                item["severity"], item["quantity"], item["threshold"]),
            "snapshot_version": updated["snapshot_version"],
            "current_snapshot_version": current_snapshot,
        }
        if idem_key is not None:
            detail["idempotency_key"] = idem_key
        if target == "authorized":
            auth = self.repository.latest_authorization(item_id)
            if auth:
                detail["authorization_id"] = auth["id"]
        self.repository.append_audit("transition", ENTITY, item_id, actor, detail)
        return self.enrich(updated)

    # ---- 水情快照 ----

    def publish_snapshot(self, payload: Dict[str, Any], actor: str,
                         role: str) -> Dict[str, Any]:
        ensure_role(role, SNAPSHOT_ROLES)
        actor = require_text(actor, "actor", 100)
        water_level = require_number(payload.get("water_level"), "water_level")
        inflow = require_number(payload.get("inflow"), "inflow")
        downstream_alert = require_text(payload.get("downstream_alert"), "downstream_alert", 500)
        construction_limits = self._normalize_limits(payload.get("construction_limits"))
        note = payload.get("note")
        if note is not None:
            note = require_text(note, "note", 500)
        previous = self.repository.current_snapshot()
        changed = self._changed_fields(previous, water_level, inflow,
                                       downstream_alert, construction_limits)
        snapshot, invalidated = self.repository.publish_snapshot(
            water_level, inflow, downstream_alert, construction_limits,
            note, actor, changed)
        return {"snapshot": snapshot, "invalidated": invalidated}

    @staticmethod
    def _normalize_limits(value: Any) -> str:
        if isinstance(value, list):
            parts = [require_text(v, "construction_limits", 200) for v in value]
            if not parts:
                raise ValueError("construction_limits不能为空")
            return json.dumps(parts, ensure_ascii=False)
        text = require_text(value, "construction_limits")
        return json.dumps([text], ensure_ascii=False)

    @staticmethod
    def _changed_fields(previous: Optional[Dict[str, Any]], water_level: float,
                        inflow: float, downstream_alert: str,
                        construction_limits: str) -> List[str]:
        if previous is None:
            return list(SNAPSHOT_FIELD_LABELS.keys())
        changed = []
        if float(previous["water_level"]) != water_level:
            changed.append("water_level")
        if float(previous["inflow"]) != inflow:
            changed.append("inflow")
        if previous["downstream_alert"] != downstream_alert:
            changed.append("downstream_alert")
        if previous["construction_limits"] != construction_limits:
            changed.append("construction_limits")
        return changed

    def list_snapshots(self, role: str) -> list:
        self._view(role)
        return self.repository.list_snapshots()

    def current_snapshot(self, role: str) -> Optional[Dict[str, Any]]:
        self._view(role)
        return self.repository.current_snapshot()

    # ---- 查询 ----

    def get_item(self, item_id: int, role: str) -> Dict[str, Any]:
        self._view(role)
        result = self.enrich(self.repository.get_item(item_id))
        auth = self.repository.latest_authorization(item_id)
        if auth is not None:
            result["authorization"] = auth
        return result

    def list_items(self, role: str, status: Optional[str] = None) -> list:
        self._view(role)
        current = self.repository.current_snapshot_version()
        return [self.enrich(item, current) for item in self.repository.list_items(status)]

    def list_records(self, item_id: int, role: str) -> list:
        self._view(role)
        return self.repository.list_records(item_id)

    def audit(self, role: str, item_id: Optional[int] = None) -> list:
        ensure_role(role, AUDIT_ROLES)
        return self.repository.list_audit(item_id)

    def enrich(self, item: Dict[str, Any],
               current_snapshot_version: Optional[int] = None) -> Dict[str, Any]:
        result = dict(item)
        result["priority"] = priority_score(
            item["severity"], item["quantity"], item["threshold"])
        result["deadline_hours"] = response_deadline_hours(
            item["severity"], item["quantity"], item["threshold"])
        result["escalation_required"] = escalation_required(
            item["severity"], item["quantity"], item["threshold"])
        if current_snapshot_version is None:
            current_snapshot_version = self.repository.current_snapshot_version()
        result["current_snapshot_version"] = current_snapshot_version
        result["snapshot_stale"] = (
            item.get("snapshot_version", 0) != current_snapshot_version
            and item["status"] in ("checked", "authorized"))
        return result
