import json
import tempfile
import threading
import unittest
from pathlib import Path

from src.domain import ConflictError, PermissionDenied, ValidationError
from src.repository import Repository
from src.service import Service


class SnapshotTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = Repository(str(Path(self.tmp.name) / "test.db"))
        self.service = Service(self.repo)

    def tearDown(self):
        self.repo.close()
        self.tmp.cleanup()

    def _make_item(self, ref="IT-1"):
        return self.service.create_item(
            {"title": "泄洪指令", "description": "按调度令泄洪", "severity": "urgent",
             "quantity": 5, "threshold": 10, "external_ref": ref},
            "creator", "duty_officer")

    def _authorize(self, item):
        item = self.service.transition(item["id"], "checked", item["version"],
                                      "reviewer", "duty_officer")
        item = self.service.transition(item["id"], "authorized", item["version"],
                                      "approver", "chief_engineer")
        return item

    def _snapshot(self, kind="water", version_payload=None):
        payload = version_payload or {"water_level": 120.5, "inflow": 800,
                                      "downstream_warning_level": 115.0}
        return self.service.create_snapshot(kind, payload, "采样", "watcher",
                                            "duty_officer")

    def test_snapshot_pins_version_and_invalidates_authorization(self):
        item = self._make_item()
        snap1 = self._snapshot()
        self.assertEqual(snap1["snapshot"]["version"], 1)
        self.assertEqual(snap1["snapshot"]["kind"], "water")

        item = self._authorize(item)
        self.assertEqual(item["snapshot_version"], 1)

        snap2 = self._snapshot(version_payload={"water_level": 121.0, "inflow": 950,
                                               "downstream_warning_level": 115.0})
        self.assertEqual(snap2["snapshot"]["version"], 2)
        self.assertEqual(len(snap2["invalidated"]), 1)
        self.assertEqual(snap2["invalidated"][0]["id"], item["id"])
        self.assertEqual(snap2["blockers"], [])

        current = self.service.get_item(item["id"], "viewer")
        self.assertEqual(current["status"], "checked")
        self.assertIsNone(current["snapshot_version"])

        events = self.service.audit("viewer", item["id"])
        invalidate = [e for e in events if e["action"] == "invalidate"]
        self.assertEqual(len(invalidate), 1)
        detail = invalidate[0]["detail"]
        self.assertIn("reason", detail)
        self.assertEqual(detail["old_snapshot_version"], 1)
        self.assertEqual(detail["new_snapshot_version"], 2)
        self.assertIn("blocking_items", detail)
        self.assertTrue(self.repo.verify_audit_chain())

    def test_restriction_snapshot_also_invalidates(self):
        item = self._make_item()
        self._snapshot("water")
        item = self._authorize(item)
        self.assertEqual(item["snapshot_version"], 1)

        out = self.service.create_snapshot(
            "restriction", {"max_discharge": 300}, "下游施工", "watcher", "chief_engineer")
        self.assertEqual(out["snapshot"]["version"], 2)
        self.assertEqual(len(out["invalidated"]), 1)
        current = self.service.get_item(item["id"], "viewer")
        self.assertEqual(current["status"], "checked")

    def test_executed_instruction_is_blocker_not_rolled_back(self):
        item = self._make_item("IT-2")
        self._snapshot()
        item = self._authorize(item)
        res = self.service.execute_dispatch(
            item["id"], item["version"], "KEY-EXEC-1", "disp", "dispatcher")
        self.assertEqual(res["item"]["status"], "executed")

        out = self.service.create_snapshot(
            "water", {"water_level": 122.0, "inflow": 1000}, "洪峰", "watcher",
            "duty_officer")
        self.assertEqual(out["invalidated"], [])
        self.assertEqual(len(out["blockers"]), 1)
        self.assertEqual(out["blockers"][0]["id"], item["id"])
        self.assertEqual(out["blockers"][0]["status"], "executed")

        current = self.service.get_item(item["id"], "viewer")
        self.assertEqual(current["status"], "executed")

        events = self.service.audit("viewer", item["id"])
        invalidate = [e for e in events if e["action"] == "invalidate"]
        self.assertTrue(invalidate)
        self.assertIn("不能倒退", invalidate[0]["detail"]["reason"])
        self.assertTrue(self.repo.verify_audit_chain())

    def test_concurrent_submit_only_current_version_wins(self):
        item = self._make_item("IT-3")
        self._snapshot()
        item = self._authorize(item)
        version = item["version"]
        results = []

        def submit(key):
            try:
                r = self.service.execute_dispatch(
                    item["id"], version, key, "disp", "dispatcher")
                results.append(("ok", r["item"]["status"]))
            except ConflictError as exc:
                results.append(("conflict", str(exc)))

        t1 = threading.Thread(target=submit, args=("KEY-A",))
        t2 = threading.Thread(target=submit, args=("KEY-B",))
        t1.start()
        t2.start()
        t1.join()
        t2.join()

        self.assertEqual(len([r for r in results if r[0] == "ok"]), 1)
        self.assertEqual(len([r for r in results if r[0] == "conflict"]), 1)
        current = self.service.get_item(item["id"], "viewer")
        self.assertEqual(current["status"], "executed")

    def test_idempotent_retry_no_double_release(self):
        item = self._make_item("IT-4")
        self._snapshot()
        item = self._authorize(item)

        r1 = self.service.execute_dispatch(
            item["id"], item["version"], "SAME-KEY", "disp", "dispatcher")
        self.assertFalse(r1["replayed"])
        self.assertEqual(r1["operation"]["status"], "committed")

        r2 = self.service.execute_dispatch(
            item["id"], item["version"], "SAME-KEY", "disp", "dispatcher")
        self.assertTrue(r2["replayed"])
        self.assertEqual(r2["item"]["status"], "executed")

        with self.assertRaises(ConflictError):
            self.service.execute_dispatch(
                item["id"], item["version"], "OTHER-KEY", "disp", "dispatcher")

        events = [e for e in self.service.audit("viewer", item["id"])
                  if e["action"] == "execute"]
        self.assertEqual(len(events), 2)
        executed = [e for e in events if not e["detail"].get("replayed")]
        replayed = [e for e in events if e["detail"].get("replayed")]
        self.assertEqual(len(executed), 1)
        self.assertEqual(len(replayed), 1)
        self.assertIn("不重复放水", replayed[0]["detail"]["reason"])
        self.assertTrue(self.repo.verify_audit_chain())

    def test_failed_then_retry_same_key(self):
        item = self._make_item("IT-5")
        self._snapshot()
        item = self._authorize(item)

        with self.assertRaises(ConflictError):
            self.service.execute_dispatch(
                item["id"], 999, "FAIL-KEY", "disp", "dispatcher")
        op = self.repo.get_operation("FAIL-KEY")
        self.assertEqual(op["status"], "failed")

        r = self.service.execute_dispatch(
            item["id"], item["version"], "FAIL-KEY", "disp", "dispatcher")
        self.assertEqual(r["item"]["status"], "executed")
        self.assertFalse(r["replayed"])
        op = self.repo.get_operation("FAIL-KEY")
        self.assertEqual(op["status"], "committed")

    def test_recover_pending_operation_resumes(self):
        item = self._make_item("IT-6")
        self._snapshot()
        item = self._authorize(item)
        self.repo.begin_operation("REC-KEY", item["id"], "execute",
                                  item["version"], {"target": "executed"})

        summary = self.service.recover()
        self.assertGreaterEqual(summary["resumed"], 1)
        current = self.service.get_item(item["id"], "viewer")
        self.assertEqual(current["status"], "executed")
        op = self.repo.get_operation("REC-KEY")
        self.assertEqual(op["status"], "committed")
        recovered = [e for e in self.service.audit("viewer", item["id"])
                     if e["action"] == "execute_recovered"]
        self.assertTrue(recovered)

    def test_recover_after_apply_before_commit_marker(self):
        item = self._make_item("IT-7")
        self._snapshot()
        item = self._authorize(item)
        self.repo.begin_operation("REC2-KEY", item["id"], "execute",
                                  item["version"], {"target": "executed"})
        # 模拟：状态已推进但提交标记未写（写入中断在事务提交后、标记前）
        with self.repo._lock, self.repo.conn:
            self.repo.conn.execute(
                "UPDATE items SET status='executed', version=version+1 WHERE id=?",
                (item["id"],))

        summary = self.service.recover()
        self.assertGreaterEqual(summary["committed"], 1)
        current = self.service.get_item(item["id"], "viewer")
        self.assertEqual(current["status"], "executed")
        op = self.repo.get_operation("REC2-KEY")
        self.assertEqual(op["status"], "committed")

    def test_recover_stale_authorization_does_not_execute(self):
        item = self._make_item("IT-8")
        self._snapshot()
        item = self._authorize(item)
        self.repo.begin_operation("REC3-KEY", item["id"], "execute",
                                  item["version"], {"target": "executed"})
        # 快照更新导致授权失效，重启后不能恢复执行
        self._snapshot(version_payload={"water_level": 123.0, "inflow": 1100,
                                        "downstream_warning_level": 115.0})

        summary = self.service.recover()
        self.assertGreaterEqual(summary["failed"], 1)
        current = self.service.get_item(item["id"], "viewer")
        self.assertEqual(current["status"], "checked")
        op = self.repo.get_operation("REC3-KEY")
        self.assertEqual(op["status"], "failed")
        self.assertIn("失效", op["result"]["reason"])

    def test_execute_rejects_stale_authorization(self):
        item = self._make_item("IT-9")
        self._snapshot()
        item = self._authorize(item)
        self._snapshot(version_payload={"water_level": 123.0, "inflow": 1100,
                                        "downstream_warning_level": 115.0})
        current = self.service.get_item(item["id"], "viewer")
        self.assertEqual(current["status"], "checked")
        with self.assertRaises(ConflictError):
            self.service.execute_dispatch(
                item["id"], current["version"], "STALE-KEY", "disp", "dispatcher")

    def test_snapshot_requires_role_and_valid_payload(self):
        with self.assertRaises(PermissionDenied):
            self.service.create_snapshot("water", {"water_level": 120}, "",
                                          "watcher", "viewer")
        with self.assertRaises(ValidationError):
            self.service.create_snapshot("bogus", {}, "", "watcher", "duty_officer")
        with self.assertRaises(ValidationError):
            self.service.create_snapshot("water", {"water_level": "abc"}, "",
                                         "watcher", "duty_officer")

    def test_reauthorize_after_invalidation_pins_new_snapshot(self):
        item = self._make_item("IT-10")
        self._snapshot()
        item = self._authorize(item)
        self.assertEqual(item["snapshot_version"], 1)
        self._snapshot(version_payload={"water_level": 123.0, "inflow": 1100,
                                        "downstream_warning_level": 115.0})
        current = self.service.get_item(item["id"], "viewer")
        self.assertEqual(current["status"], "checked")
        # 失效后退回待复核，重新授权直接 checked -> authorized，钉住新快照版本
        current = self.service.transition(current["id"], "authorized", current["version"],
                                          "approver", "chief_engineer")
        self.assertEqual(current["snapshot_version"], 2)


if __name__ == "__main__":
    unittest.main()
