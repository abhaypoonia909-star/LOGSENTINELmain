"""Regression tests for the offline detection-evaluation module."""
import json
import unittest
from pathlib import Path

from evaluation.evaluate_detection import DATASET_PATH, evaluate, load_dataset


class DetectionEvaluationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            cls.report = evaluate()
        except ImportError as exc:
            raise unittest.SkipTest("pandas/analyzer unavailable: %s" % exc)

    def test_dataset_covers_implemented_and_unsupported_labels(self):
        cases = load_dataset()
        ids = {case["id"] for case in cases}
        self.assertIn("cmd-whoami", ids)
        self.assertIn("cmd-pipe", ids)
        self.assertIn("cmd-encoded-semi", ids)
        self.assertIn("bf-group", ids)
        self.assertIn("benign-filesystem", ids)
        self.assertIn("unsup-ifs-whoami", ids)
        self.assertTrue(DATASET_PATH.exists())

    def test_metrics_come_from_detector_output_not_hardcoded(self):
        metrics = self.report["metrics"]
        self.assertGreater(metrics["true_positives"], 0)
        self.assertGreaterEqual(metrics["true_negatives"], 1)
        self.assertEqual(metrics["false_positives"], 0)
        self.assertEqual(metrics["false_negatives"], 0)
        expected_f1 = 1.0
        self.assertEqual(metrics["f1_score"], expected_f1)
        self.assertEqual(metrics["precision"], 1.0)
        self.assertEqual(metrics["recall"], 1.0)

    def test_new_command_injection_variants_are_true_positives(self):
        by_id = {row["id"]: row for row in self.report["cases"]}
        for case_id in (
            "cmd-whoami",
            "cmd-pipe",
            "cmd-subshell",
            "cmd-backtick",
            "cmd-encoded-semi",
            "cmd-encoded-pipe",
        ):
            self.assertEqual(by_id[case_id]["status"], "TP", msg=case_id)
            self.assertIn("Command Injection", by_id[case_id]["predicted"])

    def test_overlap_counts_independent_titles_once_each(self):
        row = {item["id"]: item for item in self.report["cases"]}["overlap-cmd-trav"]
        self.assertEqual(row["status"], "TP")
        self.assertEqual(
            set(row["predicted"]),
            {"Command Injection", "Directory Traversal"},
        )

    def test_unsupported_patterns_are_not_counted_as_success(self):
        unsupported = {row["id"]: row for row in self.report["unsupported"]}
        self.assertIn("unsup-ifs-whoami", unsupported)
        self.assertIn("unsup-critical-level", unsupported)
        self.assertIn("unsup-sql-sleep", unsupported)
        for row in unsupported.values():
            self.assertNotEqual(row["status"], "TP")
            self.assertEqual(row["status"], "unsupported_miss")

        metrics = self.report["metrics"]
        self.assertNotIn("unsup-ifs-whoami", [row["id"] for row in self.report["cases"]])
        labeled_success = metrics["true_positives"]
        self.assertLess(
            labeled_success,
            labeled_success + len(unsupported),
        )

    def test_brute_force_is_one_group_finding(self):
        row = {item["id"]: item for item in self.report["cases"]}["bf-group"]
        self.assertEqual(row["status"], "TP")
        self.assertEqual(row["predicted"], ["Brute Force Attack"])
        single = {item["id"]: item for item in self.report["cases"]}["benign-single-fail"]
        self.assertEqual(single["status"], "TN")

    def test_results_json_can_be_written_for_the_audit(self):
        out = Path(__file__).resolve().parent / "_eval_results.json"
        out.write_text(json.dumps(self.report, indent=2), encoding="utf-8")
        saved = json.loads(out.read_text(encoding="utf-8"))
        self.assertEqual(saved["metrics"]["true_positives"], self.report["metrics"]["true_positives"])


if __name__ == "__main__":
    unittest.main()
