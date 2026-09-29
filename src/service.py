from __future__ import annotations

from typing import Any, Dict, Optional

from .domain import (ConflictError, ValidationError, ensure_role, normalize_severity,
                     require_number, require_text)
from .repository import Repository
from .rules import (AUDIT_ROLES, CREATE_ROLES, ENTITY, EXECUTE_ROLES, RECORD_ROLES,
                    SNAPSHOT_INVALIDATION_REASON, SNAPSHOT_KINDS,
                    SNAPSHOT_KIND_LABELS, SNAPSHOT_ROLES, STALE_AUTHORIZATION_TARGET,
                    VIEW_ROLES, WATER_PAYLOAD_FIELDS, RESTRICTION_PAYLOAD_FIELDS,
                    completion_blockers, escalation_required, priority_score,
                    response_deadline_hours, role_for_transition, validate_transition)


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
                   actor: str, role: str) -> Dict[str, Any]:
        actor = require_text(actor, "actor", 100)
        item = self.repository.get_item(item_id)
        validate_transition(item["status"], target)
        ensure_role(role, role_for_transition(target))
        if not isinstance(expected_version, int) or expected_version < 1:
            raise ValidationError("expected_version必须是正整数")
        blockers = completion_blockers(target, self.repository.open_record_count(item_id))
        if blockers:
            from .domain import ConflictError
            raise ConflictError("；".join(blockers))
        snapshot_version = None
        if target == "authorized":
            snapshot = self.repository.latest_snapshot()
            snapshot_version = snapshot["version"] if snapshot else None
        updated = self.repository.transition_item(
            item_id, target, expected_version, actor, snapshot_version)
        self.repository.append_audit("transition", ENTITY, item_id, actor, {
            "from": item["status"], "to": target,
            "snapshot_version": snapshot_version,
            "escalation_required": escalation_required(
                item["severity"], item["quantity"], item["threshold"]),
        })
        return self.enrich(updated)

    def create_snapshot(self, kind: str, payload: Dict[str, Any], note: str,
                        actor: str, role: str) -> Dict[str, Any]:
        ensure_role(role, SNAPSHOT_ROLES)
        actor = require_text(actor, "actor", 100)
        if kind not in SNAPSHOT_KINDS:
            raise ValidationError("快照类型必须是water或restriction")
        if not isinstance(payload, dict):
            raise ValidationError("payload必须是JSON对象")
        for field in WATER_PAYLOAD_FIELDS + RESTRICTION_PAYLOAD_FIELDS:
            if field in payload:
                require_number(payload[field], field)
        if note is None:
            note = ""
        note = require_text(note, "note", 500) if note else ""
        snapshot, stale, blockers = self.repository.create_snapshot(
            kind, payload, note, actor)
        self.repository.append_audit("snapshot", "snapshot", snapshot["id"], actor, {
            "kind": kind,
            "kind_label": SNAPSHOT_KIND_LABELS[kind],
            "version": snapshot["version"],
            "invalidated_count": len(stale),
            "blocker_count": len(blockers),
        })
        for item in stale:
            self.repository.append_audit("invalidate", ENTITY, item["id"], actor, {
                "reason": SNAPSHOT_INVALIDATION_REASON,
                "trigger_snapshot_kind": kind,
                "old_snapshot_version": item["snapshot_version"],
                "new_snapshot_version": snapshot["version"],
                "blocking_items": blockers,
                "action_taken": f"授权失效，退回{STALE_AUTHORIZATION_TARGET}（待复核）",
            })
        for blocker in blockers:
            self.repository.append_audit("invalidate", ENTITY, blocker["id"], actor, {
                "reason": "指令已执行或已关闭，不能倒退，仅作为阻塞项记录",
                "trigger_snapshot_kind": kind,
                "old_snapshot_version": blocker["snapshot_version"],
                "new_snapshot_version": snapshot["version"],
                "blocking_items": [blocker],
                "action_taken": "不可倒退，保持原状态",
            })
        return {"snapshot": snapshot, "invalidated": stale, "blockers": blockers}

    def execute_dispatch(self, item_id: int, expected_version: int,
                         idempotency_key: str, actor: str, role: str) -> Dict[str, Any]:
        """凭复核授权执行泄洪（放水），幂等键保证重试不重复执行。"""
        ensure_role(role, EXECUTE_ROLES)
        actor = require_text(actor, "actor", 100)
        idempotency_key = require_text(idempotency_key, "idempotency_key", 100)
        if not isinstance(expected_version, int) or expected_version < 1:
            raise ValidationError("expected_version必须是正整数")
        op = self.repository.begin_operation(
            idempotency_key, item_id, "execute", expected_version,
            {"target": "executed"})
        if op["status"] == "committed":
            # 同键重试：直接返回已提交结果，不重复放水，并记录去重审计
            item = self.repository.get_item(item_id)
            self.repository.append_audit("execute", ENTITY, item_id, actor, {
                "operation_id": op["id"], "idempotency_key": idempotency_key,
                "snapshot_version": item.get("snapshot_version"),
                "replayed": True,
                "reason": "幂等重试，指令已执行，不重复放水",
            })
            return {"item": self.enrich(item), "operation": op, "replayed": True}
        item = self.repository.get_item(item_id)
        validate_transition(item["status"], "executed")
        snapshot = self.repository.latest_snapshot()
        if (item["status"] == "authorized" and snapshot is not None
                and item.get("snapshot_version") != snapshot["version"]):
            raise ConflictError("授权依据的水情或施工快照已过期，请重新授权后再执行")
        try:
            updated = self.repository.commit_execution(
                op["id"], item_id, expected_version, actor)
        except Exception as exc:
            self.repository.fail_operation(op["id"], str(exc), actor)
            raise
        return {"item": self.enrich(updated),
                "operation": self.repository.get_operation(idempotency_key),
                "replayed": False}

    def recover(self) -> Dict[str, int]:
        """重启后恢复未完成的调度提交。"""
        return self.repository.recover_pending()

    def get_item(self, item_id: int, role: str) -> Dict[str, Any]:
        self._view(role)
        return self.enrich(self.repository.get_item(item_id))

    def list_items(self, role: str, status: Optional[str] = None) -> list:
        self._view(role)
        return [self.enrich(item) for item in self.repository.list_items(status)]

    def list_records(self, item_id: int, role: str) -> list:
        self._view(role)
        return self.repository.list_records(item_id)

    def audit(self, role: str, item_id: Optional[int] = None) -> list:
        ensure_role(role, AUDIT_ROLES)
        return self.repository.list_audit(item_id)

    def list_snapshots(self, role: str) -> list:
        self._view(role)
        return self.repository.list_snapshots()

    def current_snapshot(self, role: str) -> Optional[Dict[str, Any]]:
        self._view(role)
        return self.repository.latest_snapshot()

    def get_operation(self, idempotency_key: str, role: str) -> Dict[str, Any]:
        self._view(role)
        return self.repository.get_operation(idempotency_key)

    @staticmethod
    def enrich(item: Dict[str, Any]) -> Dict[str, Any]:
        result = dict(item)
        result["priority"] = priority_score(
            item["severity"], item["quantity"], item["threshold"])
        result["deadline_hours"] = response_deadline_hours(
            item["severity"], item["quantity"], item["threshold"])
        result["escalation_required"] = escalation_required(
            item["severity"], item["quantity"], item["threshold"])
        return result
