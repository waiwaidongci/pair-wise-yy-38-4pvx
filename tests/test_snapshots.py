import tempfile, unittest
from pathlib import Path
from src.domain import ConflictError
from src.repository import Repository
from src.service import Service
from src.rules import STATES, TRANSITION_ROLES

SNAPSHOT={"water_level":102.5,"inflow":1800.0,"downstream_alert":"蓝色警戒",
          "construction_limits":["下游3号闸施工，限泄500"],"note":"例行采样"}

class SnapshotLinkTest(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.db=str(Path(self.tmp.name)/"test.db")
        self.repo=Repository(self.db); self.service=Service(self.repo)
        self.item=self.service.create_item(
            {"title":"泄洪指令","description":"开启溢洪道","severity":"urgent",
             "quantity":12,"threshold":6,"external_ref":"CMD-1"},"officer","duty_officer")
    def tearDown(self): self.repo.close(); self.tmp.cleanup()

    def _publish(self,**overrides):
        payload=dict(SNAPSHOT); payload.update(overrides)
        return self.service.publish_snapshot(payload,"sampler","duty_officer")

    def _walk(self,item,targets):
        current=item
        for target in targets:
            current=self.service.transition(current["id"],target,current["version"],
                                            "worker",TRANSITION_ROLES[target][0])
        return current

    def test_snapshot_update_invalidates_authorization(self):
        self._publish()
        checked=self._walk(self.item,["checked"])
        self.assertEqual(checked["snapshot_version"],1)
        authorized=self._walk(checked,["authorized"])
        auth=self.service.get_item(authorized["id"],"viewer")["authorization"]
        self.assertEqual(auth["status"],"active"); self.assertEqual(auth["snapshot_version"],1)
        result=self._publish(water_level=103.0,construction_limits=["下游3号闸施工，限泄300"])
        self.assertEqual(result["snapshot"]["version"],2)
        self.assertEqual([e["item_id"] for e in result["invalidated"]],[self.item["id"]])
        reverted=self.service.get_item(self.item["id"],"viewer")
        self.assertEqual(reverted["status"],"draft")
        self.assertEqual(reverted["authorization"]["status"],"invalidated")
        self.assertIn("快照v2",reverted["authorization"]["invalidation_reason"])
        events=self.service.audit("viewer",self.item["id"])
        invalidate=[e for e in events if e["action"]=="invalidate"]
        self.assertEqual(len(invalidate),1)
        detail=invalidate[0]["detail"]
        self.assertEqual(detail["from_status"],"authorized")
        self.assertEqual(detail["snapshot_version"],1)
        self.assertEqual(detail["new_snapshot_version"],2)
        self.assertIn("库位",detail["reason"]); self.assertIn("施工限制",detail["reason"])
        self.assertTrue(self.repo.verify_audit_chain())

    def test_executed_command_never_rolls_back(self):
        self._publish()
        executed=self._walk(self.item,["checked","authorized","executed"])
        version_before=executed["version"]
        self._publish(inflow=2400.0)
        after=self.service.get_item(self.item["id"],"viewer")
        self.assertEqual(after["status"],"executed")
        self.assertEqual(after["version"],version_before)
        events=self.service.audit("viewer",self.item["id"])
        self.assertEqual([e for e in events if e["action"]=="invalidate"],[])

    def test_concurrent_submit_only_current_version_wins(self):
        self._publish()
        checked=self._walk(self.item,["checked"])
        stale_version=checked["version"]
        first=self.service.transition(checked["id"],"authorized",stale_version,
                                      "chief-a","chief_engineer")
        self.assertEqual(first["status"],"authorized")
        with self.assertRaises(ConflictError) as ctx:
            self.service.transition(checked["id"],"authorized",stale_version,
                                    "chief-b","chief_engineer")
        self.assertIn("版本冲突",str(ctx.exception))

    def test_idempotent_execute_no_duplicate_release(self):
        self._publish()
        authorized=self._walk(self.item,["checked","authorized"])
        executed=self.service.transition(authorized["id"],"executed",
                                         authorized["version"],"disp","dispatcher",
                                         idempotency_key="release-1")
        replay=self.service.transition(authorized["id"],"executed",
                                       authorized["version"],"disp","dispatcher",
                                       idempotency_key="release-1")
        self.assertEqual(replay["id"],executed["id"])
        self.assertEqual(replay["version"],executed["version"])
        final=self.service.get_item(self.item["id"],"viewer")
        self.assertEqual(final["status"],"executed")
        self.assertEqual(final["version"],executed["version"])
        events=self.service.audit("viewer",self.item["id"])
        executes=[e for e in events if e["action"]=="transition" and e["detail"].get("to")=="executed"]
        self.assertEqual(len(executes),1)
        self.assertEqual(len([e for e in events if e["action"]=="idempotent_replay"]),1)

    def test_failed_attempt_retries_with_same_key(self):
        self.service.add_record(self.item["id"],
            {"kind":"site","detail":"现场未反馈","status":"open","external_ref":"FB-1"},
            "officer","duty_officer")
        self._publish()
        executed=self._walk(self.item,["checked","authorized","executed"])
        with self.assertRaises(ConflictError) as ctx:
            self.service.transition(executed["id"],"closed",executed["version"],
                                    "chief","chief_engineer",idempotency_key="close-1")
        self.assertEqual(ctx.exception.blockers,["仍有未关闭事项"])
        row=self.repo.conn.execute(
            "SELECT status FROM idempotency_keys WHERE key='close-1'").fetchone()
        self.assertEqual(row["status"],"failed")
        self.repo.conn.execute("UPDATE records SET status='closed' WHERE external_ref='FB-1'")
        self.repo.conn.commit()
        closed=self.service.transition(executed["id"],"closed",executed["version"],
                                       "chief","chief_engineer",idempotency_key="close-1")
        self.assertEqual(closed["status"],"closed")

    def test_restart_recovers_pending_commit(self):
        self._publish()
        authorized=self._walk(self.item,["checked","authorized"])
        claim,_,_=self.repo.claim_idempotency_key("release-9","disp","transition:executed",
                                                  authorized["id"])
        self.assertEqual(claim,"claimed")
        self.repo.close()
        self.repo=Repository(self.db); self.service=Service(self.repo)
        row=self.repo.conn.execute(
            "SELECT status,error FROM idempotency_keys WHERE key='release-9'").fetchone()
        self.assertEqual(row["status"],"failed")
        self.assertIn("回收",row["error"])
        events=[e for e in self.repo.list_audit() if e["action"]=="recovery"]
        self.assertEqual(len(events),1)
        self.assertEqual(events[0]["detail"]["recovered"][0]["key"],"release-9")
        current=self.service.get_item(self.item["id"],"viewer")
        self.assertEqual(current["status"],"authorized")
        executed=self.service.transition(current["id"],"executed",current["version"],
                                         "disp","dispatcher",idempotency_key="release-9")
        self.assertEqual(executed["status"],"executed")
        self.assertTrue(self.repo.verify_audit_chain())

    def test_blocked_audit_shows_blockers_and_snapshot_version(self):
        self._publish()
        checked=self._walk(self.item,["checked"])
        self.repo.conn.execute("UPDATE items SET snapshot_version=0 WHERE id=?",
                               (self.item["id"],)); self.repo.conn.commit()
        with self.assertRaises(ConflictError) as ctx:
            self.service.transition(checked["id"],"authorized",checked["version"],
                                    "chief","chief_engineer")
        self.assertTrue(any("快照已更新" in b for b in ctx.exception.blockers))
        events=self.service.audit("viewer",self.item["id"])
        blocked=[e for e in events if e["action"]=="blocked"]
        self.assertEqual(len(blocked),1)
        detail=blocked[0]["detail"]
        self.assertEqual(detail["snapshot_version"],0)
        self.assertEqual(detail["current_snapshot_version"],1)
        self.assertTrue(any("快照已更新" in b for b in detail["blockers"]))

if __name__=="__main__": unittest.main()
