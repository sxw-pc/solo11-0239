"""Tests for coolant imbalance investigation, interception and reporting.

The headline scenario is the minute-20 incident from the task brief:

* loop A meter: intake 12 / return 8 / drain 1  -> conventional gap 3
* loop B meter: intake 10 / return 9 / drain 0 -> conventional gap 1
* shared sump rise 3, abnormal off-sump sample, A drain receipt "closed"
* minute-23 tank reading: 1 entered the recovery buffer during minute 20

Neither "gap sum == leakage (4)" nor "closed receipt == zero discharge" is a
physical conclusion.  The tests pin the conservation, uncertainty intervals,
custody destinations and immutable regulatory versions.
"""
import pathlib
import tempfile
import unittest

from cloudquota import water_meter, valve_log, site_hazard, budget, reserve
from cloudquota import water_incident as wi
from cloudquota.store import open_db, one


# Physical windows for "minute 20": half-open [20, 21).
W20 = dict(window_start=20, window_end=21)
CAL = dict(calibrated_at=10, calibration_period=20)  # expires at 30


class IncidentTestBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = pathlib.Path(self.tmp.name) / "incident.sqlite"
        self.db = open_db(str(self.path))

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    # -- canonical world builders ---------------------------------------

    def open_case(self, cid="INC-20", **kw):
        args = dict(coolant="same-coolant", minute=20, permit_id="PERMIT-1",
                    loops={"A": "tenant-A", "B": "tenant-B"})
        args.update(kw)
        return wi.open_incident(self.db, cid, **args)

    def add_meters(self):
        self.assertEqual(wi.meter_reading(
            self.db, "meter-A", "A", 20, 12, 8, 1, incident_id="INC-20",
            location="loop-A/main-meter", sensor_id="fm-A",
            signature_ok=True, **W20, **CAL), "captured")
        self.assertEqual(wi.meter_reading(
            self.db, "meter-B", "B", 20, 10, 9, 0, incident_id="INC-20",
            location="loop-B/main-meter", sensor_id="fm-B",
            signature_ok=True, **W20, **CAL), "captured")

    def add_sump(self):
        self.assertEqual(wi.sump_reading(
            self.db, "sump-20", "INC-20", 20, 3, received_at=20,
            location="shared-sump/level", sensor_id="lt-sump",
            **W20, **CAL), "captured")

    def add_late_tank(self):
        # Observed during minute 20, only arrives at minute 23.
        self.assertEqual(wi.recovery_tank_reading(
            self.db, "tank-20", "INC-20", 20, 1, received_at=23,
            location="buffer-tank/level", sensor_id="lt-buf",
            **W20, **CAL), "captured")

    def add_valve_and_sample(self):
        self.assertEqual(wi.register_valve_receipt(
            self.db, "vA", "A", "drain-A", "close", 20, "closed",
            location="loop-A/drain-A", sensor_id="act-A",
            signature_ok=True, **CAL), "captured")
        self.assertEqual(wi.hazard_reading(
            self.db, "haz-1", "floor-drain-out", "chem-sniffer", 20,
            "coolant-marker", 7, abnormal=True, threshold=5,
            location="outside/floor-drain", signature_ok=True, **CAL),
            "captured")

    def build_canonical(self, late_tank=True):
        self.open_case()
        self.add_meters()
        self.add_sump()
        self.add_valve_and_sample()
        if late_tank:
            self.add_late_tank()


class TestConservationScenario(IncidentTestBase):
    def test_conventional_minute_gaps_are_exactly_3_and_1(self):
        self.build_canonical()
        inv = wi.investigate(self.db, "INC-20")
        self.assertEqual(inv["circuit_gaps"], {"A": 3, "B": 1})
        self.assertEqual(inv["total_gap"], 4)
        # The naive inference is exposed but explicitly not discharge.
        self.assertEqual(inv["naive_leak_total"], 4)
        self.assertFalse(inv["leak_equals_environmental_discharge"])
        self.assertEqual(inv["confirmed_environmental_discharge"], 0)

    def test_shared_sump_attribution_is_an_interval_not_a_verdict(self):
        self.build_canonical()
        attr = wi.investigate(self.db, "INC-20")["attribution"]
        self.assertEqual(attr["sump_amount"], 3)
        self.assertEqual((attr["loops"]["A"]["min"], attr["loops"]["A"]["max"]), (2, 3))
        self.assertEqual((attr["loops"]["B"]["min"], attr["loops"]["B"]["max"]), (0, 1))
        self.assertIsNone(attr["loops"]["A"]["point"])
        self.assertEqual(attr["status"], "uncertain")
        # Never force the minimum onto a tenant either.
        self.assertEqual(attr["loops"]["A"]["conservative_min"], 0)

    def test_aggregate_reconciles_sump_3_and_buffer_1_to_zero_unexplained(self):
        self.build_canonical()
        rec = wi.reconcile(self.db, "INC-20")
        self.assertTrue(rec["balanced"])
        self.assertEqual(rec["recognized_gap"], 4)
        self.assertEqual(rec["unexplained"], 0)
        self.assertEqual(rec["unaccounted"], 0)
        self.assertEqual(rec["recovered"], 1)
        self.assertEqual(rec["intercepted"], 3)   # the shared sump rise
        self.assertEqual(rec["discharged"], 0)
        self.assertEqual(rec["offsite_disposed"], 0)
        buckets = rec["buckets"]
        self.assertEqual(
            {k: buckets[k] for k in ("unexplained", "recovered",
                                     "intercepted_on_site",
                                     "discharged_permitted",
                                     "offsite_disposed")},
            {"unexplained": 0, "recovered": 1, "intercepted_on_site": 3,
             "discharged_permitted": 0, "offsite_disposed": 0})

    def test_without_tank_reading_one_unit_stays_unexplained_not_discharged(self):
        self.build_canonical(late_tank=False)
        rec = wi.reconcile(self.db, "INC-20")
        self.assertEqual(rec["unexplained"], 1)
        self.assertEqual(rec["recovered"], 0)
        self.assertEqual(rec["discharged"], 0)

    def test_closed_valve_receipt_and_abnormal_sample_warnings_present(self):
        self.build_canonical()
        inv = wi.investigate(self.db, "INC-20")
        self.assertIn("vA", [v["receipt_id"] for v in inv["valves"]])
        self.assertTrue(any("closed_receipt_is_not_zero_flow:vA" in w
                            for w in inv["warnings"]))
        self.assertTrue(any(w.startswith("abnormal_environmental_sample")
                            for w in inv["warnings"]))
        # All signatures valid does not license the leak==discharge inference.
        self.assertTrue(inv["all_signatures_valid"])
        self.assertTrue(any("signatures" in w for w in inv["warnings"]))
        # The abnormal outside sample is evidence, not a quantified discharge.
        h = inv["hazard_samples"][0]
        self.assertTrue(h["abnormal"])
        self.assertEqual(inv["confirmed_environmental_discharge"], 0)

    def test_integrates_directly_with_original_meter_valve_hazard_modules(self):
        # Use the seeded original entry points exactly as test_water_control_seed.
        self.assertEqual(water_meter.sample(
            self.db, "wA", "A", 20, 12, 8, 1), "captured")
        self.assertEqual(water_meter.sample(
            self.db, "wB", "B", 20, 10, 9, 0), "captured")
        self.assertEqual(valve_log.receipt(
            self.db, "vA", "A", "drain", "close", 20, "closed"), "captured")
        self.assertEqual(site_hazard.sample(
            self.db, "h1", "floor-drain-1", "chem-1", 20, "coolant", 7),
            "captured")
        # Original invariant still holds.
        self.assertEqual(
            self.db.execute(
                "SELECT intake-returned-drained FROM water_samples "
                "WHERE id='wA'").fetchone()[0], 3)
        # Incident layer reads the original tables without wrappers.
        inv = wi.investigate(self.db, minute=20)
        self.assertEqual(inv["circuit_gaps"], {"A": 3, "B": 1})
        self.assertEqual(inv["total_gap"], 4)
        self.assertEqual(len(inv["valves"]), 1)
        self.assertEqual(len(inv["hazard_samples"]), 1)

    def test_provenance_retains_location_calibration_and_window(self):
        self.build_canonical()
        p = one(self.db,
                "SELECT * FROM wi_provenance WHERE source_kind='water_sample' "
                "AND source_id='meter-A'")
        self.assertEqual(p["location"], "loop-A/main-meter")
        self.assertEqual((p["window_start"], p["window_end"]), (20, 21))
        self.assertEqual(p["calibration_expires_at"], 30)
        self.assertEqual(p["signature_ok"], 1)

    def test_tank_level_retains_location_calibration_and_window(self):
        self.open_case()
        self.assertEqual(wi.recovery_tank_reading(
            self.db, "t-cal", "INC-20", 20, 1, received_at=23,
            location="buffer-tank-2/level", sensor_id="lt-2",
            window_start=20, window_end=21,
            calibrated_at=10, calibration_period=20), "captured")
        row = one(self.db, "SELECT * FROM wi_levels WHERE id='t-cal'")
        self.assertEqual(row["location"], "buffer-tank-2/level")
        self.assertEqual((row["window_start"], row["window_end"]), (20, 21))
        self.assertEqual(row["calibration_expires_at"], 30)
        view = wi.investigate(self.db, "INC-20")["levels"][0]
        self.assertEqual(view["calibration"], "current")
        self.assertTrue(view["late_arrival"])

    def test_expired_calibration_is_flagged(self):
        self.open_case()
        wi.meter_reading(self.db, "m", "A", 20, 5, 4, 0,
                         window_start=20, window_end=21,
                         calibration_expires_at=19)
        inv = wi.investigate(self.db, "INC-20")
        self.assertTrue(any(w.startswith("meter_calibration_expired:m")
                            for w in inv["warnings"]))
        self.assertEqual(inv["circuits"][0]["calibration"], "expired")


class TestArrivalOrderAndWindows(IncidentTestBase):
    def test_late_arriving_tank_reading_is_keyed_to_physical_window(self):
        # Tank row recorded first but describing minute 20.
        self.open_case()
        self.assertEqual(wi.recovery_tank_reading(
            self.db, "tank-20", "INC-20", 20, 1, received_at=23, **W20),
            "captured")
        self.add_meters()
        self.add_sump()
        rec = wi.reconcile(self.db, "INC-20")
        self.assertEqual(rec["recovered"], 1)
        self.assertEqual(rec["unexplained"], 0)
        levels = wi.investigate(self.db, "INC-20")["levels"]
        tank = [x for x in levels if x["kind"] == "recovery_tank"][0]
        self.assertTrue(tank["late_arrival"])
        self.assertEqual(tank["received_at"], 23)

    def test_sensor_arrival_order_does_not_determine_flow_order(self):
        # A minute-19 reading inserted first must not enter minute-20 balance.
        self.build_canonical()
        wi.meter_reading(self.db, "old-A", "A", 19, 99, 0, 0,
                         window_start=19, window_end=20)
        inv = wi.investigate(self.db, "INC-20")
        self.assertEqual(inv["circuit_gaps"]["A"], 3)
        rec = wi.reconcile(self.db, "INC-20")
        self.assertEqual(rec["recognized_gap"], 4)

    def test_shuffled_insertion_order_gives_identical_reconciliation(self):
        # Order 1: canonical order.
        self.build_canonical()
        r1 = wi.reconcile(self.db, "INC-20")["buckets"]

        other = open_db(str(pathlib.Path(self.tmp.name) / "shuffle.sqlite"))
        try:
            wi.open_incident(other, "INC-20", minute=20, loops=["A", "B"])
            wi.recovery_tank_reading(other, "tank-20", "INC-20", 20, 1,
                                     received_at=23, **W20)
            wi.sump_reading(other, "sump-20", "INC-20", 20, 3, **W20)
            wi.meter_reading(other, "meter-B", "B", 20, 10, 9, 0, **W20)
            wi.meter_reading(other, "meter-A", "A", 20, 12, 8, 1, **W20)
            r2 = wi.reconcile(other, "INC-20")["buckets"]
        finally:
            other.close()
        self.assertEqual(r1, r2)

    def test_window_alignment_helpers(self):
        rel = wi.windows_relation
        self.assertEqual(rel(20, 21, 20, 21), "exact")
        self.assertEqual(rel(20, 21, 22, 23), "disjoint")
        self.assertEqual(rel(20, 30, 20, 21), "contains")
        self.assertEqual(rel(20, 21, 20, 30), "within")
        self.assertTrue(wi.windows_aligned(20, 21, 20, 21))
        self.assertFalse(wi.windows_aligned(20, 21, 20, 30))

    def test_concentration_cannot_multiply_unaligned_flow(self):
        ok = wi.discharge_mass(2, 8, 20, 21, 20, 21, "out", "out")
        self.assertEqual(ok["status"], "aligned")
        self.assertEqual(ok["pollutant_mass"], 16)
        bad = wi.discharge_mass(2, 8, 20, 21, 20, 30, "out", "out")
        self.assertEqual(bad["status"], "unaligned_windows")
        self.assertIsNone(bad["pollutant_mass"])
        mismatch = wi.discharge_mass(2, 8, 20, 21, 20, 21, "out-a", "out-b")
        self.assertEqual(mismatch["status"], "location_mismatch")
        missing = wi.discharge_mass(2, 8)
        self.assertEqual(missing["status"], "missing_windows")


class TestTracerAndUncertainty(IncidentTestBase):
    def test_clean_tracer_identifies_split_and_narrows_intervals(self):
        self.build_canonical()
        self.assertEqual(wi.tracer_result(
            self.db, "tr-1", "INC-20", 22,
            fractions={"A": 2, "B": 1}, lab="cert-lab"), "source_identified")
        inv = wi.investigate(self.db, "INC-20")
        self.assertEqual(inv["source_status"], "identified")
        loops = inv["attribution"]["loops"]
        self.assertEqual(loops["A"]["point"], 2)
        self.assertEqual(loops["B"]["point"], 1)

    def test_single_source_tracer_assigns_whole_sump(self):
        self.build_canonical()
        wi.tracer_result(self.db, "tr", "INC-20", 22, source_circuit="A")
        loops = wi.investigate(self.db, "INC-20")["attribution"]["loops"]
        self.assertEqual(loops["A"]["point"], 3)
        self.assertEqual(loops["B"]["point"], 0)

    def test_contaminated_tracer_keeps_uncertain_intervals(self):
        self.build_canonical()
        self.assertEqual(wi.tracer_result(
            self.db, "tr-bad", "INC-20", 22, contaminated=True,
            note="tracer vial contaminated in field"), "tracer_contaminated")
        inv = wi.investigate(self.db, "INC-20")
        self.assertEqual(inv["source_status"], "contaminated")
        loops = inv["attribution"]["loops"]
        self.assertEqual((loops["A"]["min"], loops["A"]["max"]), (2, 3))
        self.assertEqual((loops["B"]["min"], loops["B"]["max"]), (0, 1))
        self.assertTrue(any("tracer_contaminated" in w for w in inv["warnings"]))

    def test_unidentified_external_source_is_an_explicit_interval(self):
        # Sump rise 5 exceeds both loop caps (3 + 1): at least 1 external.
        attr = wi.source_intervals(5, {"A": 3, "B": 1})
        self.assertFalse(attr["closed_world_feasible"])
        self.assertEqual(attr["unidentified_external"]["min"], 1)
        self.assertEqual(attr["unidentified_external"]["max"], 5)


class TestValveStuckAndIsolation(IncidentTestBase):
    def test_stuck_open_valve_contradicts_closed_receipt(self):
        self.build_canonical()
        verdict = wi.inspect_valve(
            self.db, "insp-1", "INC-20", "drain-A", 21,
            observed_position="open", circuit="A", receipt_id="vA",
            location="loop-A/drain-A/position-switch", sensor_id="zs-A",
            window_start=21, window_end=22,
            calibrated_at=10, calibration_period=30)
        self.assertEqual(verdict, "stuck_open")
        row = one(self.db, "SELECT * FROM wi_valve_inspections WHERE id='insp-1'")
        self.assertEqual(row["location"], "loop-A/drain-A/position-switch")
        self.assertEqual((row["window_start"], row["window_end"]), (21, 22))
        self.assertEqual(row["calibration_expires_at"], 40)
        inv = wi.investigate(self.db, "INC-20")
        self.assertIn("drain-A", inv["stuck_valves"])
        self.assertTrue(any(w == "valve_stuck:drain-A" for w in inv["warnings"]))

    def test_closed_receipt_alone_is_not_isolation(self):
        self.build_canonical()
        self.assertEqual(wi.isolate_valve(
            self.db, "iso-1", "INC-20", "drain-A", 21,
            method="close_command", verified=True), "receipt_not_isolation")

    def test_stuck_valve_needs_positive_physical_isolation(self):
        self.build_canonical()
        wi.inspect_valve(self.db, "insp", "INC-20", "drain-A", 21,
                         observed_position="open")
        self.assertEqual(wi.isolate_valve(
            self.db, "iso-c", "INC-20", "drain-A", 22,
            method="close_command", verified=True),
            "valve_stuck_requires_positive_isolation")
        self.assertEqual(wi.isolate_valve(
            self.db, "iso-bf", "INC-20", "drain-A", 22,
            method="blind_flange", verified=True,
            zero_flow_confirmed=True), "isolated")

    def test_verified_closed_inspection_allows_isolation(self):
        wi.open_incident(self.db, "I", minute=20)
        wi.inspect_valve(self.db, "insp", "I", "v-1", 21,
                         observed_position="closed")
        self.assertEqual(wi.isolate_valve(
            self.db, "iso", "I", "v-1", 22,
            method="close_command", verified=True), "isolated")


class TestContainmentAndDisposer(IncidentTestBase):
    def _sealed_world(self):
        self.build_canonical()
        self.assertEqual(wi.choose_control(
            self.db, "ctl", "INC-20", "seal_sump", 21), "control_selected")
        self.assertEqual(wi.seal_sump(self.db, "seal", "INC-20", 21), "sealed")
        self.assertEqual(wi.disable_outlet(
            self.db, "out", "INC-20", "floor-drain-out", 21), "disabled")

    def test_pump_requires_containment_and_seal(self):
        self.build_canonical()
        self.assertEqual(wi.pump_to_tank(
            self.db, "p", "INC-20", "T-7", 3, 22),
            "containment_control_required")
        wi.choose_control(self.db, "ctl", "INC-20", "containment", 21)
        self.assertEqual(wi.pump_to_tank(
            self.db, "p", "INC-20", "T-7", 3, 22), "sump_not_sealed")

    def test_full_containment_chain_to_licensed_disposer(self):
        self._sealed_world()
        self.assertEqual(wi.pump_to_tank(
            self.db, "pump", "INC-20", "T-7", 3, 22), "transferred")
        # Tanked but not yet handed over: still actually intercepted on site.
        mid = wi.reconcile(self.db, "INC-20")
        self.assertEqual(mid["intercepted"], 3)
        tanks = {d["container"]: d["amount"] for d in mid["destinations"]
                 if d["bucket"] == wi.INTERCEPTED}
        self.assertEqual(tanks.get("T-7"), 3)

        result = wi.create_handoff(
            self.db, "hand", "INC-20", "T-7", 25,
            disposer="Certified Disposals Ltd", license_no="LIC-88",
            receipt_no="RCPT-001", gross_weight=10, tare_weight=7,
            accepted=True)
        self.assertEqual(result, "handoff_accepted")
        final = wi.reconcile(self.db, "INC-20")
        self.assertEqual(final["offsite_disposed"], 3)
        self.assertEqual(final["offsite_disposed_receipted"], 3)
        self.assertEqual(final["intercepted"], 0)
        self.assertEqual(final["recovered"], 1)
        self.assertEqual(final["discharged"], 0)
        self.assertEqual(final["unexplained"], 0)
        self.assertTrue(final["balanced"])

    def test_accepted_handoff_requires_tank_number_weighing_and_receipt(self):
        self._sealed_world()
        wi.pump_to_tank(self.db, "p", "INC-20", "T-7", 3, 22)
        self.assertTrue(wi.create_handoff(
            self.db, "h1", "INC-20", "T-7", 25,
            disposer="D", accepted=True).startswith("incomplete_handoff"))
        self.assertEqual(wi.create_handoff(
            self.db, "h2", "INC-20", "T-7", 25, disposer="D",
            license_no="L", receipt_no="R", accepted=True),
            "weighing_required")
        self.assertEqual(wi.create_handoff(
            self.db, "h3", "INC-20", "T-7", 25, disposer="D",
            license_no="L", receipt_no="R", amount=3, net_weight=2.5,
            accepted=True), "weight_mismatch")
        # Failed validation did not move custody.
        self.assertEqual(wi.reconcile(self.db, "INC-20")["intercepted"], 3)

    def test_disposer_rejection_keeps_custody_on_site_then_second_accepts(self):
        self._sealed_world()
        wi.pump_to_tank(self.db, "p", "INC-20", "T-9", 3, 22)
        self.assertEqual(wi.create_handoff(
            self.db, "h-bad", "INC-20", "T-9", 25,
            disposer="Shady Disposal", license_no="LIC-X"), "pending")
        self.assertEqual(wi.reject_handoff(
            self.db, "h-bad", 26, reason="damaged tank seal"), "rejected")
        rec = wi.reconcile(self.db, "INC-20")
        self.assertEqual(rec["offsite_disposed"], 0)
        self.assertEqual(rec["intercepted"], 3)
        self.assertIn("h-bad", rec["rejected_handoffs"])
        self.assertEqual(wi.accept_handoff(
            self.db, "h-bad", receipt_no="LATE", net_weight=3),
            "handoff_rejected_cannot_accept")
        # A different licensed disposer takes the same marked tank.
        self.assertEqual(wi.create_handoff(
            self.db, "h-ok", "INC-20", "T-9", 27,
            disposer="Proper Environmental", license_no="LIC-2",
            receipt_no="RCPT-2", gross_weight=11, tare_weight=8,
            accepted=True), "handoff_accepted")
        rec = wi.reconcile(self.db, "INC-20")
        self.assertEqual(rec["offsite_disposed"], 3)
        self.assertEqual(rec["intercepted"], 0)
        self.assertIn("h-ok", rec["accepted_handoffs"])


class TestBypassTreatment(IncidentTestBase):
    def _bypass_world(self, equipment_accepted=True):
        self.build_canonical()
        self.assertEqual(wi.choose_control(
            self.db, "ctl", "INC-20", "bypass_treatment", 21,
            equipment_id="BP-1",
            equipment_accepted=equipment_accepted), "control_selected")
        self.assertEqual(wi.enable_bypass(
            self.db, "bp", "INC-20", 21, equipment_id="BP-1",
            equipment_accepted=equipment_accepted), "bypass_enabled")

    def test_bypass_requires_accepted_equipment(self):
        self.build_canonical()
        self.assertEqual(wi.choose_control(
            self.db, "c", "INC-20", "bypass", 21,
            equipment_accepted=False), "equipment_not_accepted")
        self.assertEqual(wi.enable_bypass(
            self.db, "bp", "INC-20", 21, equipment_accepted=False),
            "equipment_not_accepted")

    def test_compliant_aligned_run_discharges_2_and_holds_residue_1(self):
        self._bypass_world()
        verdict = wi.record_treatment_run(
            self.db, "run-1", "INC-20", 22,
            treated=3, discharged=2, residue=1,
            concentration=8, limit_value=10, sample_id="out-sample-1",
            flow_start=22, flow_end=23, sample_start=22, sample_end=23)
        self.assertEqual(verdict, "discharge_recorded")
        rec = wi.reconcile(self.db, "INC-20")
        self.assertEqual(rec["discharged"], 2)
        self.assertEqual(rec["intercepted"], 1)   # residue tank
        self.assertEqual(rec["recovered"], 1)
        self.assertEqual(rec["unexplained"], 0)
        self.assertTrue(rec["balanced"])
        # Residue can then be disposal-receipted.
        self.assertEqual(wi.create_handoff(
            self.db, "h", "INC-20", "RESIDUE-TANK", 24,
            disposer="Residue Co", license_no="L", receipt_no="R",
            net_weight=1, accepted=True), "handoff_accepted")
        rec = wi.reconcile(self.db, "INC-20")
        self.assertEqual(rec["offsite_disposed"], 1)
        self.assertEqual(rec["intercepted"], 0)
        self.assertEqual(rec["discharged"], 2)

    def test_unaligned_outlet_sample_blocks_discharge(self):
        self._bypass_world()
        verdict = wi.record_treatment_run(
            self.db, "run-bad-align", "INC-20", 22,
            treated=1, discharged=1, residue=0,
            concentration=8, limit_value=10,
            flow_start=22, flow_end=23, sample_start=22, sample_end=30)
        self.assertEqual(verdict, "unaligned_windows")
        rec = wi.reconcile(self.db, "INC-20")
        self.assertEqual(rec["discharged"], 0)
        self.assertEqual(rec["intercepted"], 3)

    def test_noncompliant_outlet_blocks_and_diverts_to_containment(self):
        self._bypass_world()
        verdict = wi.record_treatment_run(
            self.db, "run-hot", "INC-20", 22,
            treated=3, discharged=3, residue=0,
            concentration=15, limit_value=10,
            flow_start=22, flow_end=23, sample_start=22, sample_end=23)
        self.assertEqual(verdict, "outlet_noncompliant")
        rec = wi.reconcile(self.db, "INC-20")
        self.assertEqual(rec["discharged"], 0)
        self.assertEqual(rec["intercepted"], 3)
        # Mandatory switch into containment, then licensed disposal.
        self.assertEqual(wi.divert_to_containment(
            self.db, "div", "INC-20", 23, amount=3,
            tank_no="EMERGENCY-TANK"), "diverted_to_containment")
        self.assertEqual(wi.create_handoff(
            self.db, "h", "INC-20", "EMERGENCY-TANK", 24,
            disposer="D", license_no="L", receipt_no="R",
            net_weight=3, accepted=True), "handoff_accepted")
        rec = wi.reconcile(self.db, "INC-20")
        self.assertEqual(rec["discharged"], 0)
        self.assertEqual(rec["offsite_disposed"], 3)
        self.assertEqual(rec["intercepted"], 0)
        self.assertTrue(rec["balanced"])

    def test_failed_outlet_refuses_later_discharge(self):
        self._bypass_world()
        self.assertEqual(wi.fail_treatment_outlet(
            self.db, "fail", "INC-20", 22,
            reason="online analyzer fault"), "failed")
        verdict = wi.record_treatment_run(
            self.db, "run", "INC-20", 23,
            treated=1, discharged=1, residue=0,
            concentration=1, limit_value=10,
            flow_start=23, flow_end=24, sample_start=23, sample_end=24)
        self.assertEqual(verdict, "treatment_outlet_failed")
        self.assertEqual(wi.reconcile(self.db, "INC-20")["discharged"], 0)

    def test_treatment_run_mass_must_balance(self):
        self._bypass_world()
        self.assertEqual(wi.record_treatment_run(
            self.db, "run", "INC-20", 22,
            treated=3, discharged=2, residue=0,
            concentration=1, limit_value=10,
            flow_start=22, flow_end=23, sample_start=22, sample_end=23),
            "treatment_mass_imbalance")

    def test_discharge_declaration_only_cites_actual_compliant_discharge(self):
        self._bypass_world()
        # Before any compliant run there is nothing declarable -- the
        # unexplained 4 must never be filed as discharged.
        self.assertEqual(wi.file_discharge_declaration(
            self.db, "D0", "INC-20", 22), "no_compliant_aligned_discharge")
        wi.record_treatment_run(
            self.db, "run-ok", "INC-20", 22,
            treated=3, discharged=2, residue=1,
            concentration=8, limit_value=10,
            flow_start=22, flow_end=23, sample_start=22, sample_end=23)
        self.assertEqual(wi.file_discharge_declaration(
            self.db, "D1", "INC-20", 23, run_id="run-ok"), "report_filed")
        version = wi.report_versions(self.db, "INC-20")[0]
        self.assertEqual(version["kind"], "discharge")
        self.assertIn("volume 2", version["text"])
        self.assertIn("pollutant mass 16", version["text"])
        self.assertNotIn("4 units", version["text"])
        # A rejected/non-compliant run cannot anchor a declaration.
        self.assertEqual(wi.file_discharge_declaration(
            self.db, "D2", "INC-20", 24, run_id="does-not-exist"),
            "no_declarable_discharge_run")

    def test_containment_path_has_zero_declarable_discharge(self):
        self.build_canonical()
        wi.choose_control(self.db, "c", "INC-20", "containment", 21)
        wi.seal_sump(self.db, "z", "INC-20", 21)
        self.assertEqual(wi.file_discharge_declaration(
            self.db, "D", "INC-20", 22), "no_compliant_aligned_discharge")


class TestControlOperationRights(IncidentTestBase):
    def test_strategy_decides_which_operations_are_allowed(self):
        self.build_canonical()
        # Containment strategy forbids online discharge booking.
        wi.choose_control(self.db, "c-contain", "INC-20", "containment", 21)
        self.assertEqual(wi.record_treatment_run(
            self.db, "run-x", "INC-20", 22, treated=1, discharged=1,
            residue=0, concentration=1, limit_value=10),
            "bypass_control_required")
        # A second, later decision may switch to accepted bypass treatment.
        self.assertEqual(wi.choose_control(
            self.db, "c-bypass", "INC-20", "bypass", 23,
            equipment_accepted=True), "control_selected")
        self.assertEqual(wi.pump_to_tank(
            self.db, "p", "INC-20", "T", 1, 24),
            "containment_control_required")
        # Control choice alone does not open the outlet: enable_bypass first.
        self.assertEqual(wi.record_treatment_run(
            self.db, "run-y", "INC-20", 25, treated=1, discharged=1,
            residue=0, concentration=1, limit_value=10,
            flow_start=25, flow_end=26, sample_start=25, sample_end=26),
            "bypass_not_enabled")
        self.assertEqual(wi.enable_bypass(
            self.db, "bp", "INC-20", 25, equipment_accepted=True),
            "bypass_enabled")
        self.assertEqual(wi.record_treatment_run(
            self.db, "run-z", "INC-20", 26, treated=1, discharged=1,
            residue=0, concentration=1, limit_value=10,
            flow_start=26, flow_end=27, sample_start=26, sample_end=27),
            "discharge_recorded")


class TestRegulatoryReports(IncidentTestBase):
    def test_served_report_survives_late_data_and_correction_appends(self):
        self.open_case()
        self.add_meters()
        self.add_sump()
        wi.choose_control(self.db, "c", "INC-20", "containment", 21)
        wi.seal_sump(self.db, "seal", "INC-20", 21)

        v1_text = ("Minute 20: suspected coolant release; shared sump rise 3 "
                   "sealed at minute 21; source attribution pending tracer.")
        self.assertEqual(wi.file_report(
            self.db, "R-1", "INC-20", v1_text, at=21, served_at=21,
            kind="suspected"), "report_filed")

        # Late tank reading arrives at 23 and closes the aggregate balance.
        self.add_late_tank()
        rec = wi.reconcile(self.db, "INC-20")
        self.assertEqual(rec["unexplained"], 0)

        # The served version is byte-for-byte the original text.
        versions = wi.report_versions(self.db, "INC-20")
        self.assertEqual(len(versions), 1)
        self.assertEqual(versions[0]["text"], v1_text)
        self.assertEqual(versions[0]["served_at"], 21)

        # Same id + different text cannot rewrite the served report.
        conflict = wi.file_report(
            self.db, "R-1", "INC-20", "rewritten history claiming 0 unknown",
            at=23, kind="suspected")
        self.assertEqual(conflict, "report_id_conflict_immutable")
        self.assertEqual(wi.report_versions(self.db, "INC-20")[0]["text"], v1_text)

        # A correction appends version 2; v1 remains intact.  An independent
        # tracer now supports the accurate source split.
        self.assertEqual(wi.tracer_result(
            self.db, "tr-1", "INC-20", 24,
            fractions={"A": 2, "B": 1}), "source_identified")
        v2_text = ("Correction at 24: late buffer-tank receipt accounts for 1; "
                   "tracer attributes sump 2 to A and 1 to B.")
        self.assertEqual(wi.correct_report(
            self.db, "R-2", "INC-20", v2_text, at=24, corrects="R-1",
            served_at=24), "report_filed")
        versions = wi.report_versions(self.db, "INC-20")
        self.assertEqual([v["version"] for v in versions], [1, 2])
        self.assertEqual(versions[0]["text"], v1_text)
        self.assertEqual(versions[1]["text"], v2_text)
        self.assertEqual(versions[1]["kind"], "correction")
        self.assertEqual(versions[1]["corrects"], "R-1")
        self.assertNotEqual(versions[0]["checksum"], versions[1]["checksum"])

    def test_supplement_and_withdrawal_keep_every_version(self):
        self.open_case()
        text1 = "Initial discharge notification."
        wi.file_report(self.db, "F1", "INC-20", text1, at=1, served_at=1)
        wi.supplement_report(self.db, "F2", "INC-20", "Additional fact.",
                             at=2, corrects="F1")
        wi.withdraw_report(self.db, "F3", "INC-20",
                           "Withdrawing F1 pending verification.",
                           at=3, withdraws="F1")
        versions = wi.report_versions(self.db, "INC-20")
        self.assertEqual([v["kind"] for v in versions],
                         ["initial", "supplement", "withdrawal"])
        # Every original text is still present.
        self.assertEqual(versions[0]["text"], text1)
        self.assertTrue(versions[2]["text"].startswith("Withdrawing"))
        # Withdrawal must name an existing original.
        self.assertEqual(wi.withdraw_report(
            self.db, "F4", "INC-20", "x", at=4, withdraws="missing"),
            "original_report_missing")

    def test_correction_requires_existing_original(self):
        self.open_case()
        self.assertEqual(wi.correct_report(
            self.db, "C", "INC-20", "text", corrects="nope"),
            "original_report_missing")


class TestIdempotencyAndNormalResources(IncidentTestBase):
    def test_open_incident_replay_and_conflict(self):
        self.assertEqual(wi.open_incident(
            self.db, "I", coolant="c", minute=20), "opened")
        self.assertEqual(wi.open_incident(
            self.db, "I", coolant="c", minute=20), "exists")
        self.assertEqual(wi.open_incident(
            self.db, "I", coolant="other", minute=20), "incident_conflict")

    def test_level_reading_replay_conflict(self):
        wi.open_incident(self.db, "I", minute=20)
        self.assertEqual(wi.sump_reading(self.db, "s", "I", 20, 3), "captured")
        self.assertEqual(wi.sump_reading(self.db, "s", "I", 20, 3), "captured") \
            # idempotency table replays 'captured'
        self.assertEqual(wi.sump_reading(self.db, "s", "I", 20, 4),
                         "reading_conflict")

    def test_normal_resource_placement_still_coexists(self):
        # The incident tables must not disturb the resource control plane.
        budget.revise(self.db, "b1", "tenant-A", 8, 8, 1, 0)
        reserve.node(self.db, "n1", "hall-a", 8, 8)
        reserve.request(self.db, "w1", "tenant-A", "gpu", 2, 2)
        self.assertEqual(
            reserve.place(self.db, "ev1", "r1", "w1", lease_until=20, at=1),
            "reserved:n1")
        # And an incident can reference the same tenant without coupling.
        self.assertEqual(wi.open_incident(
            self.db, "INC-1", minute=20, loops={"A": "tenant-A"}), "opened")


if __name__ == "__main__":
    unittest.main()
