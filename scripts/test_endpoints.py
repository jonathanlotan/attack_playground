#!/usr/bin/env python3
"""
regression tests for endpoints.py, which hands the shell scripts what
attack_network_endpoints.conf allows so they never repeat a port from it.

stdlib only, no docker and no root. run with:

    python3 -m unittest discover -s scripts -p 'test_*.py'
"""

import contextlib
import io
import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import endpoints  # noqa: E402
import network_common_linux as nc  # noqa: E402


def write_config(text):
    handle = tempfile.NamedTemporaryFile("w", suffix=".conf", delete=False)
    handle.write(text)
    handle.close()
    return handle.name


class AllowedPortsTest(unittest.TestCase):
    def test_walks_the_ranges_in_config_order(self):
        self.assertEqual(endpoints.allowed_ports(["1337-1339", "2337"], 5), [1337, 1338, 1339, 2337])

    def test_stops_at_the_count(self):
        self.assertEqual(endpoints.allowed_ports(["1337-1365", "2337-2345"], 2), [1337, 1338])

    def test_bare_ports_count_as_ranges_of_one(self):
        self.assertEqual(endpoints.allowed_ports(["1337", "2337-2338"], 3), [1337, 2337, 2338])

    def test_nothing_from_nothing(self):
        self.assertEqual(endpoints.allowed_ports([], 2), [])


class MainTest(unittest.TestCase):
    def run_main(self, args, config_text):
        """run the command line against a config of its own; (exit code, stdout, stderr)."""
        path = write_config(config_text) if config_text is not None else None
        if path:
            self.addCleanup(os.unlink, path)
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(endpoints, "find_config", return_value=path), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = endpoints.main(["endpoints.py"] + args)
        return code, out.getvalue(), err.getvalue()

    def test_ranges_come_out_in_iptables_syntax(self):
        code, out, _ = self.run_main(["ranges"], "1337-1365\n# a comment\n2337\n")
        self.assertEqual(code, 0)
        self.assertEqual(out, "1337:1365\n2337\n")

    def test_ports_are_the_first_allowed(self):
        code, out, _ = self.run_main(["ports", "2"], "1337-1365\n")
        self.assertEqual(code, 0)
        self.assertEqual(out, "1337 1338\n")

    def test_missing_config_is_an_error_not_an_empty_answer(self):
        code, out, err = self.run_main(["ranges"], None)
        self.assertEqual(code, 1)
        self.assertEqual(out, "")
        self.assertIn("not found", err)

    def test_config_allowing_nothing_is_an_error(self):
        # the same garbage the chain builder would have refused
        code, out, err = self.run_main(["ports", "1"], "http\n70000\n")
        self.assertEqual(code, 1)
        self.assertEqual(out, "")
        self.assertIn("allows no ports", err)

    def test_parser_warnings_stay_out_of_the_answer(self):
        # the shell scripts capture stdout: a warning there would be read as a range
        code, out, err = self.run_main(["ranges"], "http\n1337-1365\n")
        self.assertEqual(code, 0)
        self.assertEqual(out, "1337:1365\n")
        self.assertIn("warning", err)

    def test_too_few_ports_is_an_error(self):
        # verify_guest.sh needs two: a host listener and a published container
        code, out, err = self.run_main(["ports", "2"], "1337\n")
        self.assertEqual(code, 1)
        self.assertEqual(out, "")
        self.assertIn("only 1 port", err)

    def test_usage(self):
        for args in ([], ["ranges", "extra"], ["ports"], ["ports", "x"], ["ports", "0"], ["nope"]):
            code, out, err = self.run_main(args, "1337\n")
            self.assertEqual(code, 2, args)
            self.assertEqual(out, "")
            self.assertIn("usage", err)


class RepoConfigTest(unittest.TestCase):
    """the tracked config has to give the verify scripts something to work with."""

    def test_agrees_with_the_chain_builder(self):
        config = nc.find_config()
        self.assertIsNotNone(config)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(endpoints.main(["endpoints.py", "ranges"]), 0)
        self.assertEqual(out.getvalue().split(),
                         [nc.port_arg(rng) for rng in nc.parse_config(config)])

    def test_allows_the_two_ports_verify_guest_probes(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(endpoints.main(["endpoints.py", "ports", "2"]), 0)
        first, second = (int(p) for p in out.getvalue().split())
        self.assertLess(first, second)


if __name__ == "__main__":
    unittest.main()
