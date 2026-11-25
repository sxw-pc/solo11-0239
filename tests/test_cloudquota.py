import pathlib
import tempfile
import threading
import unittest

import cloudquota
from cloudquota import budget, loan, reserve
from cloudquota.cli import run
from cloudquota.store import open_db, one, verify_replay


class CloudQuotaTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = open_db(str(pathlib.Path(self.tmp.name) / "test.sqlite"))

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    def test_imported_module_is_local(self):
        print("module_file", cloudquota.__file__)
        self.assertIn("solo11-0239", str(pathlib.Path(cloudquota.__file__).resolve()))

    def test_budget_revision_keeps_old_commitment(self):
        budget.revise(self.db, "b1", "t", 8, 8, 1, 0)
        reserve.node(self.db, "n", "a", 8, 8)
        reserve.request(self.db, "w", "t", "g", 6, 6)
        self.assertEqual(reserve.place(self.db, "p1", "r", "w", 20, 1), "reserved:n")
        self.assertEqual(budget.revise(self.db, "b2", "t", 4, 4, 2, 2), "overcommitted")
        reserve.request(self.db, "w2", "t", "g2", 1, 1)
        self.assertEqual(reserve.place(self.db, "p2", "r2", "w2", 20, 3), "entitlement_denied")
        self.assertEqual(one(self.db, "SELECT released FROM reservations WHERE id='r'")["released"], 0)

    def test_grant_window_and_freeze_sequence(self):
        budget.revise(self.db, "b1", "t", 1, 1, 1, 0)
        budget.grant(self.db, "g1", "grant", "t", 2, 2, 5)
        reserve.node(self.db, "n", "a", 5, 5)
        reserve.request(self.db, "w1", "t", "g1", 2, 2)
        self.assertEqual(reserve.place(self.db, "p1", "r1", "w1", 4, 2), "reserved:n")
        self.assertEqual(budget.status(self.db, "s2", "t", 2, True), "frozen")
        self.assertEqual(budget.status(self.db, "s1", "t", 1, False), "stale_status")
        reserve.request(self.db, "w2", "t", "g2", 1, 1)
        self.assertEqual(reserve.place(self.db, "p2", "r2", "w2", 4, 3), "entitlement_denied")

    def test_future_budget_keeps_current_revision_until_effective(self):
        budget.revise(self.db,"b1","t",8,8,1,0)
        budget.revise(self.db,"b2","t",4,4,2,10)
        reserve.node(self.db,"n","a",8,8)
        reserve.request(self.db,"w","t","g",6,6)
        self.assertEqual(reserve.place(self.db,"p","r","w",8,2),"reserved:n")
        reserve.request(self.db,"w2","t","g2",1,1)
        self.assertEqual(reserve.place(self.db,"p2","r2","w2",12,11),"entitlement_denied")

    def test_distinct_zone_and_expired_start(self):
        budget.revise(self.db, "b", "t", 8, 8, 1, 0)
        reserve.node(self.db, "n1", "a", 8, 8)
        reserve.node(self.db, "n2", "a", 8, 8)
        reserve.request(self.db, "w1", "t", "g", 2, 2)
        reserve.request(self.db, "w2", "t", "g", 2, 2)
        self.assertEqual(reserve.place(self.db, "p1", "r1", "w1", 5, 2), "reserved:n1")
        self.assertEqual(reserve.place(self.db, "p2", "r2", "w2", 5, 2), "no_distinct_capacity")
        self.assertEqual(reserve.expire(self.db, 6), ["r1"])
        self.assertEqual(reserve.expire(self.db, 6), [])
        self.assertEqual(reserve.start(self.db, "s1", "r1", 1, 6), "late_or_stale")

    def test_group_shrink_protects_quorum(self):
        budget.revise(self.db, "b", "t", 6, 6, 1, 0)
        for i, zone in enumerate("abc", 1):
            reserve.node(self.db, f"n{i}", zone, 2, 2)
            reserve.request(self.db, f"w{i}", "t", "g", 2, 2)
            self.assertTrue(reserve.place(self.db, f"p{i}", f"r{i}", f"w{i}", 10, 1).startswith("reserved"))
        reserve.policy(self.db, "g", 2)
        self.assertEqual(reserve.shrink(self.db, "c1", "r1"), "approved")
        self.assertEqual(reserve.shrink(self.db, "c2", "r2"), "quorum_violation")

    def test_loan_floor_partial_repay_and_funding(self):
        budget.revise(self.db, "bl", "lender", 10, 10, 1, 0)
        budget.revise(self.db, "bb", "borrower", 1, 1, 1, 0)
        loan.offer(self.db, "o", "lender", 4, 4, 4, 4, 30)
        self.assertEqual(loan.issue(self.db, "i1", "L1", "o", "borrower", 3, 3, 20, 1), "issued")
        self.assertEqual(loan.issue(self.db, "i2", "L2", "o", "borrower", 3, 3, 20, 1), "lender_floor")
        reserve.node(self.db, "n", "a", 3, 3)
        reserve.request(self.db, "w", "borrower", "g", 2, 2)
        self.assertEqual(reserve.place(self.db, "p", "r", "w", 15, 2), "reserved:n")
        self.assertEqual(loan.allocate(self.db, "r", 2), "loan:L1")
        self.assertEqual(loan.repay(self.db, "pay", "L1", 1, 1), "partial")
        self.assertEqual(loan.repay(self.db, "pay", "L1", 1, 1), "duplicate")
        self.assertEqual(loan.reclaim(self.db, "case", "L1", 2, 2), "complete")
        self.assertEqual(one(self.db, "SELECT released FROM reservations WHERE id='r'")["released"], 1)

    def test_all_six_fixtures(self):
        root = pathlib.Path(__file__).resolve().parents[1]
        for name in ["budget_normal", "budget_failure", "reserve_normal", "reserve_failure", "loan_normal", "loan_failure"]:
            db_file = str(pathlib.Path(self.tmp.name) / (name + ".sqlite"))
            result = run(db_file, root / "fixtures" / (name + ".json"))
            self.assertTrue(result["results"], name)
            self.assertTrue(result["state"]["audit_replay"]["consistent"], name)

    def test_three_vertical_fixtures_replay_from_row_events(self):
        root = pathlib.Path(__file__).resolve().parents[1]
        expected = {
            "path_budget_to_reserve": "entitlement_denied",
            "path_loan_to_reserve": "lender_floor",
            "path_reclaim_to_eligibility": "overdue_debt",
        }
        for name, verdict in expected.items():
            output = run(str(pathlib.Path(self.tmp.name) / (name + ".sqlite")), root / "fixtures" / (name + ".json"))
            self.assertEqual(output["results"][-1]["result"], verdict, name)
            self.assertTrue(output["state"]["audit_replay"]["consistent"], name)
            self.assertGreater(output["state"]["audit_replay"]["events"], 5)

    def test_expired_debt_blocks_new_loan_after_reclaim(self):
        budget.revise(self.db, "l", "lender", 10, 10, 1, 0)
        budget.revise(self.db, "b", "borrower", 1, 1, 1, 0)
        loan.offer(self.db, "o", "lender", 4, 4, 4, 4, 30)
        self.assertEqual(loan.issue(self.db, "i1", "L1", "o", "borrower", 2, 2, 5, 1), "issued")
        reserve.node(self.db, "n", "a", 3, 3)
        reserve.request(self.db, "w", "borrower", "g", 2, 2)
        self.assertEqual(reserve.place(self.db, "p", "r", "w", 4, 2), "reserved:n")
        self.assertEqual(loan.allocate(self.db, "r", 2), "loan:L1")
        self.assertEqual(loan.reclaim(self.db, "c", "L1", 2, 2), "complete")
        self.assertEqual(loan.reclaim(self.db, "c", "L1", 2, 2), "complete")
        self.assertEqual(loan.issue(self.db, "i2", "L2", "o", "borrower", 1, 1, 20, 6), "overdue_debt")

    def test_loan_maturity_cannot_fund_longer_lease(self):
        budget.revise(self.db, "l", "lender", 10, 10, 1, 0)
        budget.revise(self.db, "b", "borrower", 1, 1, 1, 0)
        loan.offer(self.db, "o", "lender", 4, 4, 4, 4, 30)
        loan.issue(self.db, "i", "L", "o", "borrower", 2, 2, 5, 1)
        reserve.node(self.db, "n", "a", 3, 3)
        reserve.request(self.db, "w", "borrower", "g", 2, 2)
        self.assertEqual(reserve.place(self.db, "p", "r", "w", 10, 2), "source_expires_before_lease")
        self.assertIsNone(one(self.db, "SELECT * FROM reservations WHERE id='r'"))

    def test_two_offers_cannot_both_borrow_same_lender_floor(self):
        budget.revise(self.db,"b","lender",10,10,1,0)
        loan.offer(self.db,"o1","lender",4,4,4,4,30)
        loan.offer(self.db,"o2","lender",4,4,4,4,30)
        self.assertEqual(loan.issue(self.db,"i1","L1","o1","a",4,4,20,1),"issued")
        self.assertEqual(loan.issue(self.db,"i2","L2","o2","b",4,4,20,1),"lender_floor")

    def test_concurrent_lending_serializes_on_lender_capacity(self):
        budget.revise(self.db,"b","lender",10,10,1,0)
        loan.offer(self.db,"o1","lender",4,4,4,4,30)
        loan.offer(self.db,"o2","lender",4,4,4,4,30)
        path=one(self.db,"PRAGMA database_list")["file"]
        barrier=threading.Barrier(2)
        results=[]
        def claim(index):
            connection=open_db(path)
            barrier.wait()
            result=loan.issue(connection,f"i{index}",f"L{index}",f"o{index}",f"borrower{index}",4,4,20,1)
            results.append(result)
            connection.close()
        workers=[threading.Thread(target=claim,args=(i,)) for i in (1,2)]
        for worker in workers:worker.start()
        for worker in workers:worker.join()
        self.assertCountEqual(results,["issued","lender_floor"])


if __name__ == "__main__":
    unittest.main()
