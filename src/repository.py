from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional

from .audit import make_entry, utc_now
from .domain import ConflictError, NotFoundError
from .rules import ID_PREFIX, STATES


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

    def _create_schema(self) -> None:
        statuses = ",".join("'" + s.replace("'", "''") + "'" for s in STATES)
        with self.conn:
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
                    snapshot_version INTEGER,
                    external_ref TEXT,
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
                    kind TEXT NOT NULL CHECK(kind IN ('water','restriction')),
                    payload TEXT NOT NULL,
                    note TEXT NOT NULL DEFAULT '',
                    created_by TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS operations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    idempotency_key TEXT NOT NULL UNIQUE,
                    item_id INTEGER NOT NULL REFERENCES items(id),
                    kind TEXT NOT NULL,
                    expected_version INTEGER NOT NULL,
                    status TEXT NOT NULL DEFAULT 'pending'
                        CHECK(status IN ('pending','committed','failed')),
                    payload TEXT NOT NULL,
                    result TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
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
        self._migrate()

    def _migrate(self) -> None:
        """为旧库补充 items.snapshot_version 列。"""
        with self._lock, self.conn:
            cols = {row["name"] for row in self.conn.execute("PRAGMA table_info(items)")}
            if "snapshot_version" not in cols:
                self.conn.execute("ALTER TABLE items ADD COLUMN snapshot_version INTEGER")

    @staticmethod
    def _item(row: sqlite3.Row) -> Dict[str, Any]:
        return dict(row)

    def create_item(self, title: str, description: str, severity: str,
                    quantity: float, threshold: float, external_ref: Optional[str],
                    actor: str) -> Dict[str, Any]:
        now = utc_now()
        try:
            with self._lock, self.conn:
                cur = self.conn.execute(
                    """INSERT INTO items(title, description, severity, quantity, threshold,
                       status, version, external_ref, created_by, created_at, updated_at)
                       VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                    (title, description, severity, quantity, threshold, STATES[0], 1,
                     external_ref, actor, now, now),
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

    def transition_item(self, item_id: int, target: str, expected_version: int,
                        actor: str, snapshot_version: Optional[int] = None) -> Dict[str, Any]:
        now = utc_now()
        with self._lock, self.conn:
            if snapshot_version is None:
                cur = self.conn.execute(
                    """UPDATE items SET status=?, version=version+1, updated_at=?
                       WHERE id=? AND version=?""",
                    (target, now, item_id, expected_version),
                )
            else:
                cur = self.conn.execute(
                    """UPDATE items SET status=?, version=version+1, updated_at=?, snapshot_version=?
                       WHERE id=? AND version=?""",
                    (target, now, snapshot_version, item_id, expected_version),
                )
            if cur.rowcount == 0:
                exists = self.conn.execute("SELECT 1 FROM items WHERE id=?", (item_id,)).fetchone()
                if exists is None:
                    raise NotFoundError("项目不存在")
                raise ConflictError("版本冲突，请刷新后重试")
        return self.get_item(item_id)

    # ---- 水情/施工快照 ----

    @staticmethod
    def _snapshot_row(row: sqlite3.Row) -> Dict[str, Any]:
        data = dict(row)
        data["payload"] = json.loads(data["payload"])
        return data

    def create_snapshot(self, kind: str, payload: Dict[str, Any], note: str,
                        actor: str) -> tuple:
        """原子地写入新快照，并把依赖旧快照的已授权指令退回待复核。

        返回 (snapshot, stale_items, blockers)：
        - stale_items：本次被退回待复核(checked)的指令（含旧快照版本）；
        - blockers：已执行/已关闭、不能倒退的指令，仅作为阻塞项记录。
        """
        now = utc_now()
        with self._lock, self.conn:
            version = int(self.conn.execute(
                "SELECT COALESCE(MAX(version),0)+1 AS v FROM snapshots").fetchone()["v"])
            cur = self.conn.execute(
                """INSERT INTO snapshots(version, kind, payload, note, created_by, created_at)
                   VALUES(?,?,?,?,?,?)""",
                (version, kind, json.dumps(payload, ensure_ascii=False, sort_keys=True),
                 note, actor, now),
            )
            snapshot_id = int(cur.lastrowid)
            stale = [dict(r) for r in self.conn.execute(
                """SELECT id, snapshot_version FROM items
                   WHERE status='authorized'
                     AND (snapshot_version IS NULL OR snapshot_version < ?)
                   ORDER BY id""", (version,)).fetchall()]
            blockers = [dict(r) for r in self.conn.execute(
                """SELECT id, title, status, snapshot_version FROM items
                   WHERE status IN ('executed','closed')
                     AND (snapshot_version IS NULL OR snapshot_version < ?)
                   ORDER BY id""", (version,)).fetchall()]
            if stale:
                self.conn.executemany(
                    """UPDATE items SET status='checked', snapshot_version=NULL,
                       version=version+1, updated_at=? WHERE id=?""",
                    [(now, row["id"]) for row in stale],
                )
            row = self.conn.execute("SELECT * FROM snapshots WHERE id=?", (snapshot_id,)).fetchone()
        return self._snapshot_row(row), stale, blockers

    def latest_snapshot(self) -> Optional[Dict[str, Any]]:
        with self._lock:
            row = self.conn.execute(
                "SELECT * FROM snapshots ORDER BY version DESC LIMIT 1").fetchone()
        return self._snapshot_row(row) if row else None

    def list_snapshots(self) -> List[Dict[str, Any]]:
        with self._lock:
            rows = self.conn.execute("SELECT * FROM snapshots ORDER BY version DESC").fetchall()
        return [self._snapshot_row(row) for row in rows]

    # ---- 幂等操作（调度指令执行/放水） ----

    @staticmethod
    def _op_row(row: sqlite3.Row) -> Dict[str, Any]:
        data = dict(row)
        data["payload"] = json.loads(data["payload"])
        if data.get("result"):
            data["result"] = json.loads(data["result"])
        return data

    def begin_operation(self, idempotency_key: str, item_id: int, kind: str,
                        expected_version: int, payload: Dict[str, Any]) -> Dict[str, Any]:
        """登记一笔幂等操作。

        - 新键：插入 pending；
        - 已 committed：原样返回（调用方据此重放，不重复执行）；
        - 已 failed：允许凭同一幂等键重试，回到 pending；
        - 键被别的指令/种类占用：冲突。
        """
        now = utc_now()
        with self._lock, self.conn:
            row = self.conn.execute(
                "SELECT * FROM operations WHERE idempotency_key=?", (idempotency_key,)
            ).fetchone()
            if row is None:
                cur = self.conn.execute(
                    """INSERT INTO operations(idempotency_key, item_id, kind, expected_version,
                       status, payload, created_at, updated_at)
                       VALUES(?,?,?,?,'pending',?,?,?)""",
                    (idempotency_key, item_id, kind, expected_version,
                     json.dumps(payload, ensure_ascii=False, sort_keys=True), now, now),
                )
                row = self.conn.execute(
                    "SELECT * FROM operations WHERE id=?", (cur.lastrowid,)).fetchone()
            else:
                if row["item_id"] != item_id or row["kind"] != kind:
                    raise ConflictError("幂等键已被其他操作占用")
                if row["status"] == "failed":
                    self.conn.execute(
                        """UPDATE operations SET status='pending', expected_version=?,
                           updated_at=? WHERE id=?""",
                        (expected_version, now, row["id"]),
                    )
                    row = self.conn.execute(
                        "SELECT * FROM operations WHERE id=?", (row["id"],)).fetchone()
        return self._op_row(row)

    def get_operation(self, idempotency_key: str) -> Dict[str, Any]:
        with self._lock:
            row = self.conn.execute(
                "SELECT * FROM operations WHERE idempotency_key=?", (idempotency_key,)
            ).fetchone()
        if row is None:
            raise NotFoundError("操作不存在")
        return self._op_row(row)

    def commit_execution(self, op_id: int, item_id: int, expected_version: int,
                         actor: str) -> Dict[str, Any]:
        """在同一事务内完成：指令执行 + 操作置 committed + 审计。

        若指令已是 executed（写入中断在提交标记之前），只补提交标记，不重复执行。
        """
        now = utc_now()
        with self._lock, self.conn:
            op = self.conn.execute(
                "SELECT * FROM operations WHERE id=?", (op_id,)).fetchone()
            if op is None:
                raise NotFoundError("操作不存在")
            item = self.conn.execute(
                "SELECT * FROM items WHERE id=?", (item_id,)).fetchone()
            if item is None:
                raise NotFoundError("项目不存在")
            if item["status"] == "executed":
                # 指令已执行：仅当没有其他已提交的执行操作时，才视为"提交前崩溃"补标记；
                # 否则属于异键重复提交，拒绝且不重复放水。
                other = self.conn.execute(
                    """SELECT id FROM operations
                       WHERE item_id=? AND kind='execute' AND status='committed' AND id<>?""",
                    (item_id, op_id),
                ).fetchall()
                if other:
                    raise ConflictError("指令已执行，不能重复放水")
                updated = item
                replayed = True
            else:
                cur = self.conn.execute(
                    """UPDATE items SET status='executed', version=version+1, updated_at=?
                       WHERE id=? AND version=? AND status='authorized'""",
                    (now, item_id, expected_version),
                )
                if cur.rowcount == 0:
                    current = self.conn.execute(
                        "SELECT status FROM items WHERE id=?", (item_id,)).fetchone()
                    if current is not None and current["status"] != "authorized":
                        raise ConflictError(
                            f"指令当前状态为{current['status']}，授权已失效，需重新授权后再执行")
                    raise ConflictError("版本冲突，快照或指令已更新，请刷新后重试")
                updated = self.conn.execute(
                    "SELECT * FROM items WHERE id=?", (item_id,)).fetchone()
                replayed = False
            self.conn.execute(
                """UPDATE operations SET status='committed', result=?, updated_at=? WHERE id=?""",
                (json.dumps({"item_id": item_id, "status": updated["status"],
                            "replayed": replayed}, ensure_ascii=False), now, op_id),
            )
            self._audit_in_tx("execute", "调度指令", item_id, actor, {
                "operation_id": op_id,
                "idempotency_key": op["idempotency_key"],
                "snapshot_version": updated["snapshot_version"],
                "replayed": replayed,
                "reason": "幂等重试，指令已执行，不重复放水" if replayed else "调度指令执行（放水）",
            })
        return self._item(updated)

    def _fail_op_in_tx(self, op: Dict[str, Any], reason: str, actor: str,
                       recovered: bool = False) -> None:
        """标记操作失败并写审计（调用方须持有 self._lock 且处于事务中）。"""
        now = utc_now()
        self.conn.execute(
            "UPDATE operations SET status='failed', result=?, updated_at=? WHERE id=?",
            (json.dumps({"reason": reason}, ensure_ascii=False), now, op["id"]),
        )
        self._audit_in_tx("execute_failed", "调度指令", op["item_id"], actor, {
            "operation_id": op["id"],
            "idempotency_key": op["idempotency_key"],
            "reason": reason,
            "recovered": recovered,
        })

    def fail_operation(self, op_id: int, reason: str, actor: str) -> Dict[str, Any]:
        with self._lock, self.conn:
            row = self.conn.execute(
                "SELECT * FROM operations WHERE id=?", (op_id,)).fetchone()
            if row is None:
                raise NotFoundError("操作不存在")
            self._fail_op_in_tx(self._op_row(row), reason, actor)
            row = self.conn.execute("SELECT * FROM operations WHERE id=?", (op_id,)).fetchone()
        return self._op_row(row)

    def recover_pending(self) -> Dict[str, int]:
        """重启后恢复未完成提交。

        - 指令已执行：补 committed 标记（已执行指令不能倒退）；
        - 指令仍 authorized 且版本未变：继续完成执行；
        - 授权已失效或版本已变：置 failed，不执行。
        """
        now = utc_now()
        summary = {"resumed": 0, "committed": 0, "failed": 0}
        with self._lock, self.conn:
            ops = [self._op_row(r) for r in self.conn.execute(
                "SELECT * FROM operations WHERE status='pending' ORDER BY id").fetchall()]
        for op in ops:
            with self._lock, self.conn:
                item = self.conn.execute(
                    "SELECT * FROM items WHERE id=?", (op["item_id"],)).fetchone()
                if item is None:
                    self._fail_op_in_tx(op, "指令不存在", "system", recovered=True)
                    summary["failed"] += 1
                elif item["status"] == "executed":
                    self.conn.execute(
                        "UPDATE operations SET status='committed', result=?, updated_at=? WHERE id=?",
                        (json.dumps({"recovered": True}, ensure_ascii=False), now, op["id"]),
                    )
                    self._audit_in_tx("execute_recovered", "调度指令", op["item_id"], "system", {
                        "operation_id": op["id"], "idempotency_key": op["idempotency_key"],
                        "reason": "重启恢复：指令已执行，补全提交标记，不重复放水",
                    })
                    summary["committed"] += 1
                elif item["status"] == "authorized" and item["version"] == op["expected_version"]:
                    cur = self.conn.execute(
                        """UPDATE items SET status='executed', version=version+1, updated_at=?
                           WHERE id=? AND version=? AND status='authorized'""",
                        (now, op["item_id"], op["expected_version"]),
                    )
                    if cur.rowcount == 0:
                        self._fail_op_in_tx(op, "恢复时版本冲突", "system", recovered=True)
                        summary["failed"] += 1
                    else:
                        self.conn.execute(
                            "UPDATE operations SET status='committed', result=?, updated_at=? WHERE id=?",
                            (json.dumps({"recovered": True}, ensure_ascii=False), now, op["id"]),
                        )
                        self._audit_in_tx("execute_recovered", "调度指令", op["item_id"], "system", {
                            "operation_id": op["id"], "idempotency_key": op["idempotency_key"],
                            "reason": "重启恢复：未完成提交继续执行",
                        })
                        summary["resumed"] += 1
                else:
                    if item["status"] != "authorized":
                        reason = "授权已因快照更新失效，不能恢复执行"
                    else:
                        reason = "指令版本已变更，不能按旧版本恢复"
                    self._fail_op_in_tx(op, reason, "system", recovered=True)
                    summary["failed"] += 1
        return summary

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

    def _audit_in_tx(self, action: str, entity_type: str, entity_id: int,
                     actor: str, detail: Dict[str, Any]) -> Dict[str, Any]:
        """写一条审计事件（调用方须持有 self._lock 且处于事务中）。"""
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
                     actor: str, detail: Dict[str, Any]) -> Dict[str, Any]:
        with self._lock, self.conn:
            return self._audit_in_tx(action, entity_type, entity_id, actor, detail)

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
