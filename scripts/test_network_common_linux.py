#!/usr/bin/env python3
"""
regression tests for the pure logic in network_common_linux.py.

stdlib only, and no iptables/docker/root needed - every call into iptables is
recorded instead of run. run with:

    python3 -m unittest discover -s scripts -p 'test_*.py'
"""

import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import network_common_linux as nc  # noqa: E402
import setup_networking_linux as setup  # noqa: E402


def write_config(text):
    handle = tempfile.NamedTemporaryFile("w", suffix=".conf", delete=False)
    handle.write(text)
    handle.close()
    return handle.name


class ParseConfigTest(unittest.TestCase):
    def parse(self, text):
        path = write_config(text)
        try:
            return nc.parse_config(path)
        finally:
            os.unlink(path)

    def test_keeps_single_ports_and_ranges(self):
        self.assertEqual(self.parse("1337\n2337-2340\n"), ["1337", "2337-2340"])

    def test_ignores_comments_and_blank_lines(self):
        self.assertEqual(self.parse("# endpoints\n\n  1337  \n"), ["1337"])

    def test_rejects_reversed_range(self):
        self.assertEqual(self.parse("2000-1000\n"), [])

    def test_rejects_ports_above_65535(self):
        # these match the digit patterns but iptables rejects them, which used to
        # abort the chain rebuild part way through and leave it without its DROP
        self.assertEqual(self.parse("70000\n1337-99999\n"), [])

    def test_rejects_port_zero(self):
        self.assertEqual(self.parse("0\n0-100\n"), [])

    def test_rejects_garbage(self):
        self.assertEqual(self.parse("http\n1337/tcp\n-1\n"), [])

    def test_missing_file_is_empty(self):
        self.assertEqual(nc.parse_config("/nonexistent/endpoints.conf"), [])


class PortArgTest(unittest.TestCase):
    def test_range_uses_iptables_colon_syntax(self):
        self.assertEqual(nc.port_arg("1337-1355"), "1337:1355")

    def test_single_port_passes_through(self):
        self.assertEqual(nc.port_arg("1337"), "1337")


class FailClosedTest(unittest.TestCase):
    """the input chain must never be reachable without a terminal DROP."""

    def setUp(self):
        self.calls = []
        patcher = mock.patch.object(nc, "run_iptables", self.record)
        patcher.start()
        self.addCleanup(patcher.stop)

    def record(self, binary, args, ignore_error=False):
        self.calls.append(list(args))
        # pretend the chain does not exist yet, so ensure_chain creates it
        if args[:1] == ["-n"]:
            return False
        return True

    def test_drop_is_installed_before_any_allow_rule(self):
        nc.ensure_chain_closed(nc.INPUT_CHAIN)
        setup.build_input_chain("172.31.0.1", ["1337-1355", "2337-2340"])

        drop_at = next(i for i, c in enumerate(self.calls)
                       if c[:1] == ["-A"] and c[-2:] == ["-j", "DROP"])
        accepts = [i for i, c in enumerate(self.calls) if c[-2:] == ["-j", "ACCEPT"]]

        self.assertTrue(accepts, "expected the allow rules to be recorded")
        self.assertTrue(all(i > drop_at for i in accepts),
                        "allow rules must be added after the terminal DROP exists")

    def test_allow_rules_are_inserted_above_the_drop(self):
        nc.ensure_chain_closed(nc.INPUT_CHAIN)
        setup.build_input_chain("172.31.0.1", ["1337-1355"])

        for call in self.calls:
            if call[-2:] == ["-j", "ACCEPT"]:
                self.assertEqual(call[0], "-I",
                                 "an appended allow rule would land below the DROP")

    def test_allow_rules_keep_config_order(self):
        nc.ensure_chain_closed(nc.INPUT_CHAIN)
        setup.build_input_chain("172.31.0.1", ["1337-1355", "2337-2340", "3337-3345"])

        positions = [int(c[2]) for c in self.calls
                     if c[0] == "-I" and c[-2:] == ["-j", "ACCEPT"]]
        self.assertEqual(positions, sorted(positions))

    def test_forward_chains_are_built_deny_first_too(self):
        for chain in (nc.FORWARD_CHAIN, nc.FORWARD_IN_CHAIN):
            nc.ensure_chain_closed(chain)
        setup.build_forward_chains("172.31.0.1", ["1337-1355"])

        drops = [i for i, c in enumerate(self.calls)
                 if c[:1] == ["-A"] and c[-2:] == ["-j", "DROP"]]
        accepts = [i for i, c in enumerate(self.calls) if c[-2:] == ["-j", "ACCEPT"]]
        self.assertEqual(len(drops), 2)
        self.assertTrue(accepts)
        self.assertTrue(all(i > max(drops) for i in accepts))
        for call in self.calls:
            if call[-2:] == ["-j", "ACCEPT"]:
                self.assertEqual(call[0], "-I")


class PublishedEndpointTest(unittest.TestCase):
    """
    a docker-published endpoint is DNATed before routing and travels FORWARD, so
    the allowlist has to exist there too - keyed on the *original* destination,
    since after DNAT the packet is addressed to the endpoint container.
    """

    def setUp(self):
        self.calls = []
        patcher = mock.patch.object(nc, "run_iptables",
                                    lambda binary, args, ignore_error=False:
                                    self.calls.append(list(args)) or True)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_forward_allow_matches_original_destination(self):
        setup.build_forward_chains("172.31.0.1", ["1337-1355", "2337"])
        allows = [c for c in self.calls if c[1] == nc.FORWARD_CHAIN and c[-1] == "ACCEPT"]
        self.assertEqual(len(allows), 2)
        for call in allows:
            self.assertIn("DNAT", call)
            self.assertEqual(call[call.index("--ctorigdst") + 1], "172.31.0.1")
        self.assertEqual(allows[0][allows[0].index("--ctorigdstport") + 1], "1337:1355")
        self.assertEqual(allows[1][allows[1].index("--ctorigdstport") + 1], "2337")

    def test_forward_allow_never_matches_by_final_destination(self):
        # "-d <gateway>" in FORWARD can never fire (the packet is already DNATed)
        # and would be a silent no-op that looks like an allow rule
        setup.build_forward_chains("172.31.0.1", ["1337-1355"])
        for call in self.calls:
            if call[1] == nc.FORWARD_CHAIN:
                self.assertNotIn("-d", call)

    def test_replies_are_let_back_in_but_nothing_else(self):
        setup.build_forward_chains("172.31.0.1", ["1337-1355"])
        rules_in = [c for c in self.calls if c[1] == nc.FORWARD_IN_CHAIN]
        self.assertEqual(len(rules_in), 1)
        self.assertIn("ESTABLISHED,RELATED", rules_in[0])
        self.assertEqual(rules_in[0][-1], "ACCEPT")

    def test_no_endpoints_means_no_forward_allow(self):
        setup.build_forward_chains("172.31.0.1", [])
        self.assertFalse([c for c in self.calls if c[1] == nc.FORWARD_CHAIN])


class SshLimitTest(unittest.TestCase):
    """the lan must not be able to mint guests without bound."""

    def setUp(self):
        self.calls = []
        patcher = mock.patch.object(nc, "run_iptables", self.record)
        patcher.start()
        self.addCleanup(patcher.stop)

    def record(self, binary, args, ignore_error=False):
        self.calls.append((binary, list(args)))
        if args[:1] == ["-n"] or args[:1] == ["-C"]:
            return False
        return True

    def test_limit_is_hooked_from_input_on_the_ssh_port(self):
        # the port is whatever .env publishes containerssh on, handed in by
        # start.sh - not a number of this module's own
        self.assertTrue(setup.apply_ssh_limit(2200))
        hooks = [a for b, a in self.calls if a[:2] == ["-I", "INPUT"]]
        self.assertEqual(len(hooks), 1)
        self.assertEqual(hooks[0][-1], nc.SSH_LIMIT_CHAIN)
        self.assertEqual(hooks[0][hooks[0].index("--dport") + 1], "2200")
        self.assertIn("--syn", hooks[0])

    def test_limit_counts_all_sources_together(self):
        setup.apply_ssh_limit(2200)
        rules = [a for b, a in self.calls if a[:2] == ["-A", nc.SSH_LIMIT_CHAIN]]
        self.assertEqual(len(rules), 1)
        self.assertEqual(rules[0][rules[0].index("--connlimit-above") + 1],
                         str(nc.MAX_SSH_CONNECTIONS))
        self.assertEqual(rules[0][rules[0].index("--connlimit-mask") + 1], "0")
        self.assertEqual(rules[0][-1], "DROP")

    def test_missing_connlimit_is_a_warning_not_a_refusal(self):
        # a limit is not a restriction: a kernel without xt_connlimit must not
        # make the playground unstartable
        def fail_on_connlimit(binary, args, ignore_error=False):
            if "connlimit" in args:
                raise nc.IptablesError(binary, args, 2, "No chain/target/match by that name")
            return self.record(binary, args, ignore_error)
        with mock.patch.object(nc, "run_iptables", fail_on_connlimit):
            self.assertFalse(setup.apply_ssh_limit(2200))

    def test_applied_to_ipv6_as_well(self):
        # the ssh port is published on :: too
        with mock.patch.object(setup, "ip6tables_available", return_value=True):
            setup.apply_ipv6_restrictions("br-test", 2200)
        self.assertTrue([a for b, a in self.calls
                         if b == nc.IP6TABLES and a[:2] == ["-A", nc.SSH_LIMIT_CHAIN]])
        hooks = [a for b, a in self.calls if b == nc.IP6TABLES and a[:2] == ["-I", "INPUT"]
                 and a[-1] == nc.SSH_LIMIT_CHAIN]
        self.assertEqual(len(hooks), 1)
        self.assertEqual(hooks[0][hooks[0].index("--dport") + 1], "2200")


class SshPortTest(unittest.TestCase):
    """the cap is keyed on the port .env publishes containerssh on, and on nothing else."""

    def test_reads_the_port_start_sh_passes(self):
        self.assertEqual(nc.ssh_port_from_env({"SSH_PORT": "2200"}), 2200)

    def test_unset_is_an_error_not_a_guess(self):
        with self.assertRaises(ValueError) as caught:
            nc.ssh_port_from_env({})
        self.assertIn("not set", str(caught.exception))
        self.assertIn("start.sh", str(caught.exception))

    def test_garbage_is_an_error(self):
        for bad in ("", "ssh", "0", "70000", "22 22", "2222/tcp"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                nc.ssh_port_from_env({"SSH_PORT": bad})


class BridgeNetfilterTest(unittest.TestCase):
    """both sysctls, not just the ipv4 one."""

    def test_sets_ip6tables_sysctl_too(self):
        written = []

        def fake_get(key):
            return "1" if key in written else "0"

        def fake_run(cmd, **kwargs):
            if cmd[-2:-1] == ["-w"] or (len(cmd) >= 2 and cmd[-2] == "-w"):
                written.append(cmd[-1].split("=")[0])
            return mock.Mock(returncode=0)

        with mock.patch.object(nc, "_sysctl_get", side_effect=fake_get), \
                mock.patch.object(nc.subprocess, "run", side_effect=fake_run):
            self.assertEqual(nc.ensure_bridge_netfilter(), [])
        self.assertIn("net.bridge.bridge-nf-call-iptables", written)
        self.assertIn("net.bridge.bridge-nf-call-ip6tables", written)

    def test_reports_the_ones_that_did_not_stick(self):
        with mock.patch.object(nc, "_sysctl_get", return_value="0"), \
                mock.patch.object(nc.subprocess, "run", return_value=mock.Mock(returncode=0)):
            self.assertEqual(sorted(nc.ensure_bridge_netfilter()),
                             sorted(nc.BRIDGE_NF_SYSCTLS))


class TeardownCoversEveryChainTest(unittest.TestCase):
    def test_teardown_removes_the_ssh_limit_chain(self):
        import teardown_networking_linux as teardown
        self.assertIn(nc.SSH_LIMIT_CHAIN, teardown.CHAINS)


class MissingBinaryTest(unittest.TestCase):
    """the error has to name the binary that is actually missing."""

    def test_missing_sudo_is_not_reported_as_missing_iptables(self):
        with mock.patch.object(nc.os, "geteuid", return_value=1000), \
                mock.patch.object(nc.subprocess, "run", side_effect=FileNotFoundError):
            with self.assertRaises(nc.IptablesError) as caught:
                nc.run_iptables(nc.IPTABLES, ["-n", "-L", "INPUT"])
        self.assertIn("sudo not found", str(caught.exception))

    def test_missing_iptables_is_reported_as_such_when_root(self):
        with mock.patch.object(nc.os, "geteuid", return_value=0), \
                mock.patch.object(nc.subprocess, "run", side_effect=FileNotFoundError):
            with self.assertRaises(nc.IptablesError) as caught:
                nc.run_iptables(nc.IPTABLES, ["-n", "-L", "INPUT"])
        self.assertIn("iptables not found", str(caught.exception))

    def test_ignore_error_still_swallows_it(self):
        with mock.patch.object(nc.subprocess, "run", side_effect=FileNotFoundError):
            self.assertFalse(
                nc.run_iptables(nc.IPTABLES, ["-n", "-L", "INPUT"], ignore_error=True))


class EndpointShadowingTest(unittest.TestCase):
    """
    a container that publishes a host port inside an endpoint range takes that port
    over: docker's nat/PREROUTING DNAT runs before the routing decision, so the guest
    never reaches INPUT and ATTACK_PG_INPUT never sees the packet. the connection
    still succeeds, so this has to be found by reading the nat table.
    """

    # what docker actually writes into nat/DOCKER
    RULES = [
        "-N DOCKER",
        "-A DOCKER -i br-playground -j RETURN",
        "-A DOCKER ! -i br-playground -p tcp -m tcp --dport 2222 "
        "-j DNAT --to-destination 172.18.0.4:2222",
        "-A DOCKER ! -i br-playground -p tcp -m tcp --dport 1337 "
        "-j DNAT --to-destination 172.18.0.15:1337",
        "-A DOCKER -d 127.0.0.1/32 ! -i br-playground -p tcp -m tcp --dport 2223 "
        "-j DNAT --to-destination 172.18.0.3:8080",
    ]

    def test_range_bounds(self):
        self.assertEqual(nc.range_bounds("1337-1355"), (1337, 1355))
        self.assertEqual(nc.range_bounds("1337"), (1337, 1337))

    def test_parses_published_ports(self):
        self.assertEqual(
            nc.parse_published_ports(self.RULES),
            [(2222, "172.18.0.4:2222"), (1337, "172.18.0.15:1337")])

    def test_loopback_publish_is_not_a_conflict(self):
        # "127.0.0.1:2223:8080" can never be reached from the bridge
        ports = [p for p, _ in nc.parse_published_ports(self.RULES)]
        self.assertNotIn(2223, ports)

    def test_reports_a_port_inside_an_endpoint_range(self):
        published = nc.parse_published_ports(self.RULES)
        self.assertEqual(
            nc.endpoint_conflicts(["1337-1355"], published),
            [(1337, "172.18.0.15:1337", "1337-1355")])

    def test_ignores_published_ports_outside_every_range(self):
        published = nc.parse_published_ports(self.RULES)
        self.assertEqual(nc.endpoint_conflicts(["2337-2340"], published), [])

    def test_matches_a_bare_single_port_range(self):
        self.assertEqual(
            nc.endpoint_conflicts(["1337"], [(1337, "172.18.0.15:1337")]),
            [(1337, "172.18.0.15:1337", "1337")])

    def test_range_boundaries_are_inclusive(self):
        published = [(1337, "a:1"), (1355, "b:1"), (1356, "c:1")]
        found = [p for p, _, _ in nc.endpoint_conflicts(["1337-1355"], published)]
        self.assertEqual(found, [1337, 1355])

    def test_no_nat_chain_is_not_a_conflict(self):
        # a host where the DOCKER chain does not exist must not look "clean by error"
        # in a way that raises - it reports nothing and the caller carries on
        with mock.patch.object(nc.subprocess, "check_output",
                               side_effect=FileNotFoundError):
            self.assertEqual(nc.find_endpoint_conflicts(["1337-1355"]), [])


if __name__ == "__main__":
    unittest.main()
