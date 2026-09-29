from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .audit import make_entry, utc_now
from .domain import ConflictError, NotFoundError
from .rules import (ENTITY, IDEM_ENTITY, INVALIDATABLE_STATES, SNAPSHOT_ENTITY,
                    STATES, invalidation_reason)


class Repository:
    def __init__(self, db_path: str):
        self.db_path = str(db_path)
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON")
        self.conn.execute("PRAGMA journal_mode = WAL")
        self._create_schema()
        self.recover_incomplete_commits()

    def _create_schema(self) -> None:
        statuses = ",".join("'" + s.replace("'", "''") + "'" for s in STATES)
        with self._lock, self.conn:
            self.conn.executescript(f"""
                CREATE TABLE IF NOT EXISTS items (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    title TEXT NOT NULL,
                    description TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    quantity REAL NOT NULL DEFAULT 0,
                    threshold REAL NOT NULL DEFAULT 1,
                    status TEXT NOT NULL CHECK(status IN ({statuses})),
                    version INTEGER NOT NULL DEFAULT 1,
                    external_ref TEXT,
                    snapshot_version INTEGER NOT NULL DEFAULT 0,
                    created_by TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE UNIQUE INDEX IF NOT EXISTS ux_items_external_ref
                    ON items(external_ref) WHERE external_ref IS NOT NULL;
                CREATE TABLE IF NOT EXISTS records (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    item_id INTEGER NOT NULL REFERENCES items(id) ON DELETE CASCADE,
                    kind TEXT NOT NULL,
                    detail TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'open'
                        CHECK(status IN ('open','closed')),
                    external_ref TEXT,
                    created_by TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    UNIQUE(item_id, external_ref)
                );
                CREATE TABLE IF NOT EXISTS snapshots (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    version INTEGER NOT NULL UNIQUE,
                    water_level REAL NOT NULL,
                    inflow REAL NOT NULL,
                    downstream_alert TEXT NOT NULL,
                    construction_limits TEXT NOT NULL,
                    note TEXT,
                    created_by TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS authorizations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    item_id INTEGER NOT NULL REFERENCES items(id) ON DELETE CASCADE,
                    snapshot_version INTEGER NOT NULL,
                    status TEXT NOT NULL DEFAULT 'active'
                        CHECK(status IN ('active','invalidated')),
                    invalidation_reason TEXT,
                    authorized_by TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    invalidated_at TEXT
                );
                CREATE TABLE IF NOT EXISTS idempotency_keys (
                    key TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    action TEXT NOT NULL,
                    item_id INTEGER,
                    status TEXT NOT NULL DEFAULT 'pending'
                        CHECK(status IN ('pending','completed','failed')),
                    response_status INTEGER,
                    response_body TEXT,
                    error TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY(key, actor)
                );
                CREATE TABLE IF NOT EXISTS audit_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    action TEXT NOT NULL,
                    entity_type TEXT NOT NULL,
                    entity_id INTEGER NOT NULL,
                    actor TEXT NOT NULL,
                    detail TEXT NOT NULL,
                    previous_hash TEXT NOT NULL,
                    entry_hash TEXT NOT NULL UNIQUE,
                    created_at TEXT NOT NULL
                );
            """)
            columns = [row[1] for row in self.conn.execute("PRAGMA table_info(items)")]
            if "snapshot_version" not in columns:
                self.conn.execute(
                    "ALTER TABLE items ADD COLUMN snapshot_version INTEGER NOT NULL DEFAULT 0")

    @staticmethod
    def _item(row: sqlite3.Row) -> Dict[str, Any]:
        return dict(row)

    def create_item(self, title: str, description: str, severity: str,
                    quantity: float, threshold: float, external_ref: Optional[str],
                    actor: str) -> Dict[str, Any]:
        now = utc_now()
        try:
            with self._lock, self.conn:
                snapshot_version = self._current_snapshot_version_locked()
                cur = self.conn.execute(
                    """INSERT INTO items(title, description, severity, quantity, threshold,
                       status, version, external_ref, snapshot_version, created_by,
                       created_at, updated_at)
                       VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (title, description, severity, quantity, threshold, STATES[0], 1,
                     external_ref, snapshot_version, actor, now, now),
                )
                item_id = int(cur.lastrowid)
        except sqlite3.IntegrityError as exc:
            raise ConflictError("external_ref已存在") from exc
        return self.get_item(item_id)

    def get_item(self, item_id: int) -> Dict[str, Any]:
        with self._lock:
            row = self.conn.execute("SELECT * FROM items WHERE id=?", (item_id,)).fetchone()
        if row is None:
            raise NotFoundError("项目不存在")
        return self._item(row)

    def list_items(self, status: Optional[str] = None) -> List[Dict[str, Any]]:
        sql = "SELECT * FROM items"
        params: tuple = ()
        if status:
            sql += " WHERE status=?"
            params = (status,)
        sql += " ORDER BY id DESC"
        with self._lock:
            rows = self.conn.execute(sql, params).fetchall()
        return [self._item(row) for row in rows]

    def _current_snapshot_version_locked(self) -> int:
        row = self.conn.execute("SELECT COALESCE(MAX(version),0) AS v FROM snapshots").fetchone()
        return int(row["v"])

    def current_snapshot_version(self) -> int:
        with self._lock:
            return self._current_snapshot_version_locked()

    def transition_item(self, item_id: int, target: str, expected_version: int,
                        actor: str, idem_key: Optional[str] = None) -> Dict[str, Any]:
        """状态转换。复核绑定当前快照、授权校验快照时效均在同一事务内原子完成；
        携带幂等键时，键置为completed与业务写入同事务提交。"""
        now = utc_now()
        with self._lock, self.conn:
            if target == "checked":
                cur = self.conn.execute(
                    """UPDATE items SET status=?, version=version+1, updated_at=?,
                       snapshot_version=(SELECT COALESCE(MAX(version),0) FROM snapshots)
                       WHERE id=? AND version=? AND status='draft'""",
                    (target, now, item_id, expected_version),
                )
            elif target == "authorized":
                cur = self.conn.execute(
                    """UPDATE items SET status=?, version=version+1, updated_at=?
                       WHERE id=? AND version=? AND status='checked'
                       AND snapshot_version=(SELECT COALESCE(MAX(version),0) FROM snapshots)""",
                    (target, now, item_id, expected_version),
                )
            else:
                cur = self.conn.execute(
                    """UPDATE items SET status=?, version=version+1, updated_at=?
                       WHERE id=? AND version=?""",
                    (target, now, item_id, expected_version),
                )
            if cur.rowcount == 0:
                self._raise_transition_conflict(item_id, target, expected_version)
            row = self.conn.execute("SELECT * FROM items WHERE id=?", (item_id,)).fetchone()
            updated = self._item(row)
            if target == "authorized":
                self.conn.execute(
                    """INSERT INTO authorizations(item_id, snapshot_version, status,
                       authorized_by, created_at) VALUES(?,?,?,?,?)""",
                    (item_id, updated["snapshot_version"], "active", actor, now),
                )
            if idem_key is not None:
                self._complete_idem_locked(idem_key, actor, 200, updated)
        return updated

    def _raise_transition_conflict(self, item_id: int, target: str,
                                   expected_version: int) -> None:
        row = self.conn.execute("SELECT * FROM items WHERE id=?", (item_id,)).fetchone()
        if row is None:
            raise NotFoundError("项目不存在")
        if int(row["version"]) != expected_version:
            raise ConflictError("版本冲突，请刷新后重试")
        if target == "authorized":
            current = self._current_snapshot_version_locked()
            if int(row["snapshot_version"]) != current:
                blocker = (f"快照已更新（指令基于v{row['snapshot_version']}，当前v{current}），"
                           "授权失效需重新复核")
                raise ConflictError(blocker, blockers=[blocker])
        raise ConflictError(f"不能从{row['status']}转换到{target}")

    def add_record(self, item_id: int, kind: str, detail: str, status: str,
                   external_ref: Optional[str], actor: str) -> Dict[str, Any]:
        now = utc_now()
        self.get_item(item_id)
        try:
            with self._lock, self.conn:
                cur = self.conn.execute(
                    """INSERT INTO records(item_id, kind, detail, status, external_ref,
                       created_by, created_at) VALUES(?,?,?,?,?,?,?)""",
                    (item_id, kind, detail, status, external_ref, actor, now),
                )
                record_id = int(cur.lastrowid)
        except sqlite3.IntegrityError as exc:
            raise ConflictError("记录唯一标识已存在") from exc
        with self._lock:
            row = self.conn.execute("SELECT * FROM records WHERE id=?", (record_id,)).fetchone()
        return dict(row)

    def list_records(self, item_id: int) -> List[Dict[str, Any]]:
        self.get_item(item_id)
        with self._lock:
            rows = self.conn.execute(
                "SELECT * FROM records WHERE item_id=? ORDER BY id", (item_id,)
            ).fetchall()
        return [dict(row) for row in rows]

    def open_record_count(self, item_id: int) -> int:
        with self._lock:
            row = self.conn.execute(
                "SELECT COUNT(*) AS n FROM records WHERE item_id=? AND status='open'",
                (item_id,),
            ).fetchone()
        return int(row["n"])

    # ---- 水情快照 ----

    def publish_snapshot(self, water_level: float, inflow: float,
                         downstream_alert: str, construction_limits: str,
                         note: Optional[str], actor: str,
                         changed_fields: List[str]) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
        """发布快照并原子失效旧授权：checked/authorized指令退回draft待复核，
        授权记录置invalidated；executed/closed指令不倒退。失效审计与业务写入同事务。"""
        now = utc_now()
        with self._lock, self.conn:
            version = self._current_snapshot_version_locked() + 1
            cur = self.conn.execute(
                """INSERT INTO snapshots(version, water_level, inflow, downstream_alert,
                   construction_limits, note, created_by, created_at)
                   VALUES(?,?,?,?,?,?,?,?)""",
                (version, water_level, inflow, downstream_alert, construction_limits,
                 note, actor, now),
            )
            snapshot_id = int(cur.lastrowid)
            reason = invalidation_reason(version, changed_fields)
            placeholders = ",".join("?" for _ in INVALIDATABLE_STATES)
            rows = self.conn.execute(
                f"SELECT * FROM items WHERE status IN ({placeholders})",
                tuple(INVALIDATABLE_STATES),
            ).fetchall()
            invalidated: List[Dict[str, Any]] = []
            for item in rows:
                self.conn.execute(
                    """UPDATE items SET status='draft', version=version+1, updated_at=?
                       WHERE id=? AND version=?""",
                    (now, item["id"], item["version"]),
                )
                auth = self.conn.execute(
                    """SELECT id FROM authorizations WHERE item_id=? AND status='active'
                       ORDER BY id DESC LIMIT 1""",
                    (item["id"],),
                ).fetchone()
                auth_id: Optional[int] = None
                if auth is not None:
                    auth_id = int(auth["id"])
                    self.conn.execute(
                        """UPDATE authorizations SET status='invalidated',
                           invalidation_reason=?, invalidated_at=? WHERE id=?""",
                        (reason, now, auth_id),
                    )
                invalidated.append({
                    "item_id": item["id"], "from_status": item["status"],
                    "snapshot_version": item["snapshot_version"],
                    "authorization_id": auth_id,
                })
                self._append_audit_locked("invalidate", ENTITY, item["id"], actor, {
                    "reason": reason, "from_status": item["status"], "to_status": "draft",
                    "snapshot_version": item["snapshot_version"],
                    "new_snapshot_version": version, "changed_fields": changed_fields,
                    "authorization_id": auth_id,
                })
            skipped = self.conn.execute(
                "SELECT id FROM items WHERE status IN ('executed','closed')"
            ).fetchall()
            snapshot = dict(self.conn.execute(
                "SELECT * FROM snapshots WHERE id=?", (snapshot_id,)).fetchone())
            self._append_audit_locked("snapshot", SNAPSHOT_ENTITY, snapshot_id, actor, {
                "version": version, "changed_fields": changed_fields,
                "invalidated_items": [entry["item_id"] for entry in invalidated],
                "skipped_terminal_items": [int(row["id"]) for row in skipped],
            })
        return snapshot, invalidated

    def list_snapshots(self) -> List[Dict[str, Any]]:
        with self._lock:
            rows = self.conn.execute("SELECT * FROM snapshots ORDER BY version DESC").fetchall()
        return [dict(row) for row in rows]

    def current_snapshot(self) -> Optional[Dict[str, Any]]:
        with self._lock:
            row = self.conn.execute(
                "SELECT * FROM snapshots ORDER BY version DESC LIMIT 1").fetchone()
        return dict(row) if row else None

    def latest_authorization(self, item_id: int) -> Optional[Dict[str, Any]]:
        with self._lock:
            row = self.conn.execute(
                """SELECT * FROM authorizations WHERE item_id=?
                   ORDER BY id DESC LIMIT 1""",
                (item_id,),
            ).fetchone()
        return dict(row) if row else None

    # ---- 幂等提交与崩溃恢复 ----

    def claim_idempotency_key(self, key: str, actor: str, action: str,
                              item_id: Optional[int]) -> Tuple[str, Optional[int], Optional[Dict[str, Any]]]:
        """返回('claimed',None,None)表示获得执行权；('replay',status,body)表示已完成可直接回放。"""
        now = utc_now()
        with self._lock, self.conn:
            row = self.conn.execute(
                "SELECT * FROM idempotency_keys WHERE key=? AND actor=?", (key, actor)
            ).fetchone()
            if row is None:
                self.conn.execute(
                    """INSERT INTO idempotency_keys(key, actor, action, item_id, status,
                       created_at, updated_at) VALUES(?,?,?,?,?,?,?)""",
                    (key, actor, action, item_id, "pending", now, now),
                )
                return ("claimed", None, None)
            if row["action"] != action or row["item_id"] != item_id:
                raise ConflictError("幂等键已用于其他操作")
            if row["status"] == "completed":
                body = json.loads(row["response_body"]) if row["response_body"] else None
                return ("replay", int(row["response_status"] or 200), body)
            if row["status"] == "pending":
                raise ConflictError("相同幂等键的请求正在处理中，请稍后重试")
            self.conn.execute(
                """UPDATE idempotency_keys SET status='pending', error=NULL, updated_at=?
                   WHERE key=? AND actor=? AND status='failed'""",
                (now, key, actor),
            )
            return ("claimed", None, None)

    def _complete_idem_locked(self, key: str, actor: str, response_status: int,
                              response_body: Dict[str, Any]) -> None:
        self.conn.execute(
            """UPDATE idempotency_keys SET status='completed', response_status=?,
               response_body=?, updated_at=? WHERE key=? AND actor=? AND status='pending'""",
            (response_status,
             json.dumps(response_body, ensure_ascii=False, sort_keys=True),
             utc_now(), key, actor),
        )

    def fail_idempotency_key(self, key: str, actor: str, error: str) -> None:
        with self._lock, self.conn:
            self.conn.execute(
                """UPDATE idempotency_keys SET status='failed', error=?, updated_at=?
                   WHERE key=? AND actor=? AND status='pending'""",
                (error[:500], utc_now(), key, actor),
            )

    def recover_incomplete_commits(self) -> List[Dict[str, Any]]:
        """重启恢复：pending键的业务写入与完成标记在同一事务，残留pending即未提交，
        回收为failed允许客户端凭同一幂等键重试，不会重复执行。"""
        recovered: List[Dict[str, Any]] = []
        with self._lock, self.conn:
            rows = self.conn.execute(
                "SELECT * FROM idempotency_keys WHERE status='pending'").fetchall()
            now = utc_now()
            for row in rows:
                self.conn.execute(
                    """UPDATE idempotency_keys SET status='failed',
                       error='服务重启时提交未完成，已回收，可凭同一幂等键重试', updated_at=?
                       WHERE key=? AND actor=? AND status='pending'""",
                    (now, row["key"], row["actor"]),
                )
                recovered.append({"key": row["key"], "actor": row["actor"],
                                  "action": row["action"], "item_id": row["item_id"]})
            if recovered:
                self._append_audit_locked("recovery", IDEM_ENTITY, 0, "system", {
                    "reason": "写入中断后重启，未完成提交已回收",
                    "recovered": recovered,
                })
        return recovered

    # ---- 审计 ----

    def _append_audit_locked(self, action: str, entity_type: str, entity_id: int,
                             actor: str, detail: dict) -> Dict[str, Any]:
        row = self.conn.execute(
            "SELECT entry_hash FROM audit_events ORDER BY id DESC LIMIT 1"
        ).fetchone()
        previous = row["entry_hash"] if row else "GENESIS"
        event = make_entry(action, entity_type, entity_id, actor, detail, previous)
        cur = self.conn.execute(
            """INSERT INTO audit_events(action, entity_type, entity_id, actor, detail,
               previous_hash, entry_hash, created_at) VALUES(?,?,?,?,?,?,?,?)""",
            (event["action"], event["entity_type"], event["entity_id"], event["actor"],
             json.dumps(event["detail"], ensure_ascii=False, sort_keys=True),
             event["previous_hash"], event["entry_hash"], event["created_at"]),
        )
        event["id"] = int(cur.lastrowid)
        return event

    def append_audit(self, action: str, entity_type: str, entity_id: int,
                     actor: str, detail: dict) -> Dict[str, Any]:
        with self._lock, self.conn:
            return self._append_audit_locked(action, entity_type, entity_id, actor, detail)

    def list_audit(self, entity_id: Optional[int] = None) -> List[Dict[str, Any]]:
        sql = "SELECT * FROM audit_events"
        params: tuple = ()
        if entity_id is not None:
            sql += " WHERE entity_id=?"
            params = (entity_id,)
        sql += " ORDER BY id"
        with self._lock:
            rows = self.conn.execute(sql, params).fetchall()
        result = []
        for row in rows:
            item = dict(row)
            item["detail"] = json.loads(item["detail"])
            result.append(item)
        return result

    def verify_audit_chain(self) -> bool:
        from .audit import calculate_hash
        with self._lock:
            rows = self.conn.execute("SELECT * FROM audit_events ORDER BY id").fetchall()
        previous = "GENESIS"
        for row in rows:
            if row["previous_hash"] != previous:
                return False
            payload = {
                "action": row["action"], "entity_type": row["entity_type"],
                "entity_id": row["entity_id"], "actor": row["actor"],
                "detail": json.loads(row["detail"]), "created_at": row["created_at"],
            }
            if calculate_hash(previous, payload) != row["entry_hash"]:
                return False
            previous = row["entry_hash"]
        return True

    def close(self) -> None:
        with self._lock:
            self.conn.close()
