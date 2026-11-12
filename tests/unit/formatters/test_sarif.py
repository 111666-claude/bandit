# SPDX-License-Identifier: Apache-2.0
import collections
import json
import tempfile
from unittest import mock

import testtools

import bandit
from bandit.core import config
from bandit.core import constants
from bandit.core import issue
from bandit.core import manager
from bandit.core import metrics
from bandit.formatters import sarif


class SarifFormatterTests(testtools.TestCase):
    def setUp(self):
        super().setUp()
        conf = config.BanditConfig()
        self.manager = manager.BanditManager(conf, "file")
        (tmp_fd, self.tmp_fname) = tempfile.mkstemp()
        self.context = {
            "filename": self.tmp_fname,
            "lineno": 4,
            "linerange": [4],
            "code": (
                "import socket\n\n"
                "s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
                "s.bind(('0.0.0.0', 31137))"
            ),
        }
        self.check_name = "hardcoded_bind_all_interfaces"
        self.issue = issue.Issue(
            severity=bandit.MEDIUM,
            cwe=issue.Cwe.MULTIPLE_BINDS,
            confidence=bandit.MEDIUM,
            text="Possible binding to all interfaces.",
            test_id="B104",
        )

        self.candidates = [
            issue.Issue(
                issue.Cwe.MULTIPLE_BINDS,
                bandit.LOW,
                bandit.LOW,
                "Candidate A",
                lineno=1,
            ),
            issue.Issue(
                bandit.HIGH,
                issue.Cwe.MULTIPLE_BINDS,
                bandit.HIGH,
                "Candiate B",
                lineno=2,
            ),
        ]

        self.manager.out_file = self.tmp_fname

        self.issue.fname = self.context["filename"]
        self.issue.lineno = self.context["lineno"]
        self.issue.linerange = self.context["linerange"]
        self.issue.code = self.context["code"]
        self.issue.test = self.check_name

        self.manager.results.append(self.issue)
        self.manager.metrics = metrics.Metrics()

        # mock up the metrics
        for key in ["_totals", "binding.py"]:
            self.manager.metrics.data[key] = {"loc": 4, "nosec": 2}
            for criteria, default in constants.CRITERIA:
                for rank in constants.RANKING:
                    self.manager.metrics.data[key][f"{criteria}.{rank}"] = 0

    @mock.patch("bandit.core.manager.BanditManager.get_issue_list")
    def test_report(self, get_issue_list):
        self.manager.files_list = ["binding.py"]
        self.manager.scores = [
            {
                "SEVERITY": [0] * len(constants.RANKING),
                "CONFIDENCE": [0] * len(constants.RANKING),
            }
        ]

        get_issue_list.return_value = collections.OrderedDict(
            [(self.issue, self.candidates)]
        )

        with open(self.tmp_fname, "w") as tmp_file:
            sarif.report(
                self.manager,
                tmp_file,
                self.issue.severity,
                self.issue.confidence,
            )

        with open(self.tmp_fname) as f:
            data = json.loads(f.read())
            run = data["runs"][0]
            self.assertEqual(sarif.SCHEMA_URI, data["$schema"])
            self.assertEqual(sarif.SCHEMA_VER, data["version"])
            driver = run["tool"]["driver"]
            self.assertEqual("Bandit", driver["name"])
            self.assertEqual(bandit.__author__, driver["organization"])
            self.assertEqual(bandit.__version__, driver["semanticVersion"])
            self.assertEqual("B104", driver["rules"][0]["id"])
            self.assertEqual(self.check_name, driver["rules"][0]["name"])
            self.assertIn("security", driver["rules"][0]["properties"]["tags"])
            self.assertIn(
                "external/cwe/cwe-605",
                driver["rules"][0]["properties"]["tags"],
            )
            self.assertEqual(
                "medium", driver["rules"][0]["properties"]["precision"]
            )
            invocation = run["invocations"][0]
            self.assertTrue(invocation["executionSuccessful"])
            self.assertIsNotNone(invocation["endTimeUtc"])
            result = run["results"][0]
            # If the level is "warning" like in this case, SARIF will remove
            # from output, as "warning" is the default value.
            self.assertIsNone(result.get("level"))
            self.assertEqual(self.issue.text, result["message"]["text"])
            physicalLocation = result["locations"][0]["physicalLocation"]
            self.assertEqual(
                self.context["linerange"][0],
                physicalLocation["region"]["startLine"],
            )
            self.assertEqual(
                self.context["linerange"][0],
                physicalLocation["region"]["endLine"],
            )
            self.assertIn(
                self.tmp_fname,
                physicalLocation["artifactLocation"]["uri"],
            )

    def _make_issue(
        self,
        test_id,
        test_name,
        text,
        severity,
        confidence,
        cwe,
        fname,
        lineno,
    ):
        new_issue = issue.Issue(
            severity=severity,
            cwe=cwe,
            confidence=confidence,
            text=text,
            test_id=test_id,
        )
        new_issue.fname = fname
        new_issue.test = test_name
        new_issue.lineno = lineno
        new_issue.linerange = [lineno]
        new_issue.code = ""
        return new_issue

    def _write_report(self, issue_list):
        self.manager.get_issue_list = mock.Mock(return_value=issue_list)
        with open(self.tmp_fname, "w") as tmp_file:
            sarif.report(
                self.manager,
                tmp_file,
                constants.LOW,
                constants.LOW,
            )
        with open(self.tmp_fname) as handle:
            return json.loads(handle.read())

    def test_rule_index_matches_driver_rules_order(self):
        # Two distinct rules: ruleIndex on every result must resolve to the
        # rule with the same ruleId in driver.rules.
        first = self._make_issue(
            "B602",
            "subprocess_popen_with_shell_equals_true",
            "shell call",
            bandit.LOW,
            bandit.HIGH,
            issue.Cwe.OS_COMMAND_INJECTION,
            "a.py",
            1,
        )
        second = self._make_issue(
            "B104",
            "hardcoded_bind_all_interfaces",
            "bind all",
            bandit.MEDIUM,
            bandit.MEDIUM,
            issue.Cwe.MULTIPLE_BINDS,
            "a.py",
            2,
        )
        data = self._write_report([first, second, first])
        run = data["runs"][0]
        rules = run["tool"]["driver"]["rules"]
        rule_ids = [rule["id"] for rule in rules]
        self.assertEqual(sorted(rule_ids), rule_ids)
        for result in run["results"]:
            self.assertEqual(
                result["ruleId"], rules[result["ruleIndex"]]["id"]
            )

    def test_severity_and_confidence_are_upper_cased(self):
        # Lower-cased values (as can appear in hand-written baseline JSON)
        # must still be normalized in both the SARIF level and properties.
        low_issue = self._make_issue(
            "B602",
            "subprocess_popen_with_shell_equals_true",
            "shell call",
            "low",
            "high",
            issue.Cwe.OS_COMMAND_INJECTION,
            "a.py",
            1,
        )
        data = self._write_report([low_issue])
        result = data["runs"][0]["results"][0]
        self.assertEqual("note", result["level"])
        self.assertEqual("LOW", result["properties"]["issue_severity"])
        self.assertEqual("HIGH", result["properties"]["issue_confidence"])

    def test_artifact_uri_is_path_normalized(self):
        normalized_issue = self._make_issue(
            "B104",
            "hardcoded_bind_all_interfaces",
            "bind all",
            bandit.MEDIUM,
            bandit.MEDIUM,
            issue.Cwe.MULTIPLE_BINDS,
            "./pkg/./sub/../mod.py",
            3,
        )
        data = self._write_report([normalized_issue])
        location = data["runs"][0]["results"][0]["locations"][0]
        uri = location["physicalLocation"]["artifactLocation"]["uri"]
        self.assertNotIn("/./", uri)
        self.assertNotIn("/../", uri)
        self.assertEqual("pkg/mod.py", uri)

    def test_report_accepts_baseline_marker(self):
        # The CLI only allows a baseline with formatters that opt in.
        self.assertTrue(hasattr(sarif.report, "_accepts_baseline"))

    def test_report_with_baseline_dictionary(self):
        # In baseline mode get_issue_list returns an OrderedDict of issue ->
        # candidate issues; the SARIF formatter must flatten and emit them.
        unmatched = self._make_issue(
            "B602",
            "subprocess_popen_with_shell_equals_true",
            "new shell call",
            bandit.LOW,
            bandit.HIGH,
            issue.Cwe.OS_COMMAND_INJECTION,
            "a.py",
            8,
        )
        candidate = self._make_issue(
            "B602",
            "subprocess_popen_with_shell_equals_true",
            "older shell call",
            bandit.LOW,
            bandit.HIGH,
            issue.Cwe.OS_COMMAND_INJECTION,
            "a.py",
            2,
        )
        baseline_issues = collections.OrderedDict(
            [(unmatched, [unmatched, candidate])]
        )
        data = self._write_report(baseline_issues)
        run = data["runs"][0]
        rule_ids = {
            result["ruleId"] for result in run["results"]
        }
        self.assertEqual({"B602"}, rule_ids)
        self.assertEqual(2, len(run["results"]))
        rules = run["tool"]["driver"]["rules"]
        for result in run["results"]:
            self.assertEqual(
                result["ruleId"], rules[result["ruleIndex"]]["id"]
            )

    def test_report_tolerates_issue_without_line_range(self):
        # Candidate issues may have an empty line range; the region builder
        # should fall back to a safe default instead of raising IndexError.
        sparse_issue = self._make_issue(
            "B602",
            "subprocess_popen_with_shell_equals_true",
            "sparse",
            bandit.LOW,
            bandit.HIGH,
            issue.Cwe.OS_COMMAND_INJECTION,
            "a.py",
            1,
        )
        sparse_issue.linerange = []
        data = self._write_report([sparse_issue])
        region = data["runs"][0]["results"][0]["locations"][0][
            "physicalLocation"
        ]["region"]
        self.assertEqual(1, region["startLine"])
