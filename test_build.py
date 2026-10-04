import contextlib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import build

DATE = "2026-10-03"


class ParseDomainsTests(unittest.TestCase):
    def test_comments_blanks_and_trailing_notes(self):
        text = "# header\n\nb.example.com  # why\n  a.example.com\n"
        self.assertEqual(build.parse_domains(text), ["a.example.com", "b.example.com"])

    def test_lowercases_dedupes_and_sorts(self):
        text = "B.Example.com\na.example.com\nb.example.COM\n"
        self.assertEqual(build.parse_domains(text), ["a.example.com", "b.example.com"])

    def test_trailing_dot_is_normalised(self):
        self.assertEqual(build.parse_domains("a.example.com.\n"), ["a.example.com"])

    def test_empty_input(self):
        self.assertEqual(build.parse_domains("# nothing\n\n"), [])

    def assert_domain_error(self, text, lineno, fragment=""):
        with self.assertRaises(build.ListError) as ctx:
            build.parse_domains(text, "lists/domains.txt")
        message = str(ctx.exception)
        self.assertIn("lists/domains.txt:%d:" % lineno, message)
        self.assertIn(fragment, message)

    def test_rejects_single_label(self):
        self.assert_domain_error("ok.example.com\nlocalhost\n", 2, "two labels")

    def test_rejects_bad_characters(self):
        self.assert_domain_error("# c\nbad_name.example.com\n", 2, "invalid label")

    def test_rejects_leading_hyphen(self):
        self.assert_domain_error("-a.example.com\n", 1, "invalid label")

    def test_rejects_empty_label(self):
        self.assert_domain_error("a..example.com\n", 1, "empty label")

    def test_rejects_ip_address(self):
        self.assert_domain_error("1.2.3.4\n", 1, "ips.txt")

    def test_rejects_non_ascii(self):
        self.assert_domain_error("bücher.example\n", 1, "punycode")

    def test_rejects_overlong_label(self):
        self.assert_domain_error("%s.com\n" % ("a" * 64), 1, "63")

    def test_rejects_multiple_tokens(self):
        self.assert_domain_error("a.example.com b.example.com\n", 1, "one domain")

    def test_rejects_url(self):
        self.assert_domain_error("https://a.example.com/x\n", 1)


class ParseIpsTests(unittest.TestCase):
    def test_single_ip(self):
        self.assertEqual(
            build.parse_ips("1.2.3.4  # one\n"),
            [(0x01020304, 0x01020304, "one")],
        )

    def test_cidr_to_range(self):
        (start, end, _), = build.parse_ips("10.0.0.0/8\n")
        self.assertEqual((start, end), (0x0A000000, 0x0AFFFFFF))

    def test_cidr_slash_32_and_slash_24(self):
        rows = build.parse_ips("192.168.1.0/24\n8.8.8.8/32\n")
        self.assertEqual(
            [(s, e) for s, e, _ in rows],
            [(0x08080808, 0x08080808), (0xC0A80100, 0xC0A801FF)],
        )

    def test_range(self):
        (start, end, _), = build.parse_ips("1.2.3.4-1.2.3.255\n")
        self.assertEqual((start, end), (0x01020304, 0x010203FF))

    def test_range_with_spaces_around_dash(self):
        (start, end, _), = build.parse_ips("1.2.3.4 - 1.2.3.9\n")
        self.assertEqual((start, end), (0x01020304, 0x01020309))

    def test_dedupe_and_sort(self):
        rows = build.parse_ips("9.9.9.9\n1.1.1.1 # first\n1.1.1.1 # second\n")
        self.assertEqual(rows, [(0x01010101, 0x01010101, "first"), (0x09090909, 0x09090909, "")])

    def assert_ip_error(self, text, lineno, fragment=""):
        with self.assertRaises(build.ListError) as ctx:
            build.parse_ips(text, "lists/ips.txt")
        message = str(ctx.exception)
        self.assertIn("lists/ips.txt:%d:" % lineno, message)
        self.assertIn(fragment, message)

    def test_rejects_bad_octet(self):
        self.assert_ip_error("1.2.3.4\n1.2.3.256\n", 2, "not a valid IPv4")

    def test_rejects_short_address(self):
        self.assert_ip_error("1.2.3\n", 1)

    def test_rejects_host_bits_in_cidr(self):
        self.assert_ip_error("10.0.0.1/8\n", 1, "CIDR")

    def test_rejects_bad_prefix(self):
        self.assert_ip_error("10.0.0.0/33\n", 1, "CIDR")

    def test_rejects_reversed_range(self):
        self.assert_ip_error("# c\n1.2.3.9-1.2.3.4\n", 2, "after end")

    def test_rejects_ipv6(self):
        self.assert_ip_error("::1\n", 1, "IPv6")

    def test_rejects_garbage(self):
        self.assert_ip_error("not-an-ip\n", 1)


class RenderTests(unittest.TestCase):
    domains = ["a.example.com", "b.example.com"]
    ranges = [
        (0x01020304, 0x010203FF, "Example, Corp: test"),
        (0x0A000000, 0x0AFFFFFF, ""),
    ]

    def test_hosts(self):
        out = build.render_hosts(self.domains, DATE)
        lines = out.splitlines()
        self.assertTrue(lines[0].startswith("# Title: "))
        self.assertIn("# URL: ", out)
        self.assertIn("# Entries: 2", lines)
        self.assertIn("# Last updated: " + DATE, lines)
        self.assertEqual(lines[-2:], ["0.0.0.0 a.example.com", "0.0.0.0 b.example.com"])
        self.assertTrue(out.endswith("\n"))

    def test_domains(self):
        self.assertEqual(build.render_domains(self.domains), "a.example.com\nb.example.com\n")

    def test_adblock(self):
        out = build.render_adblock(self.domains, DATE)
        lines = out.splitlines()
        self.assertTrue(lines[0].startswith("! Title: "))
        self.assertIn("! Last modified: " + DATE, lines)
        self.assertEqual(lines[-2:], ["||a.example.com^", "||b.example.com^"])

    def test_ipfilter_zero_padded_ranges(self):
        out = build.render_ipfilter(self.ranges, DATE)
        data = [l for l in out.splitlines() if not l.startswith("#")]
        self.assertEqual(
            data,
            [
                "001.002.003.004 - 001.002.003.255 , 000 , Example Corp test",
                "010.000.000.000 - 010.255.255.255 , 000 , blocklist",
            ],
        )

    def test_p2p(self):
        out = build.render_p2p(self.ranges, DATE)
        data = [l for l in out.splitlines() if not l.startswith("#")]
        self.assertEqual(
            data,
            [
                "Example Corp test:1.2.3.4-1.2.3.255",
                "blocklist:10.0.0.0-10.255.255.255",
            ],
        )

    def test_lsrules_is_valid_json_group(self):
        group = json.loads(build.render_lsrules(self.domains))
        self.assertEqual(group["name"], build.NAME)
        self.assertIsInstance(group["description"], str)
        self.assertEqual(group["denied-remote-domains"], self.domains)

    def test_empty_ip_outputs_have_only_comments(self):
        for out in (build.render_ipfilter([], DATE), build.render_p2p([], DATE)):
            self.assertTrue(all(l.startswith("#") for l in out.splitlines()))


class BuildDateTests(unittest.TestCase):
    def test_source_date_epoch_pins_date(self):
        self.assertEqual(build.build_date({"SOURCE_DATE_EPOCH": "0"}), "1970-01-01")
        self.assertEqual(build.build_date({"SOURCE_DATE_EPOCH": "1790000000"}), "2026-09-21")

    def test_invalid_epoch(self):
        with self.assertRaises(ValueError):
            build.build_date({"SOURCE_DATE_EPOCH": "yesterday"})

    def test_default_is_iso_date(self):
        value = build.build_date({})
        self.assertRegex(value, r"^\d{4}-\d{2}-\d{2}$")


class BuildEndToEndTests(unittest.TestCase):
    def make_root(self, domains, ips):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        (root / "lists").mkdir()
        (root / "lists" / "domains.txt").write_text(domains, encoding="utf-8")
        (root / "lists" / "ips.txt").write_text(ips, encoding="utf-8")
        return root

    def test_writes_all_files(self):
        root = self.make_root("b.example.com\na.example.com\n", "10.0.0.0/8 # lan\n")
        build.build(root, DATE)
        names = sorted(p.name for p in (root / "dist").iterdir())
        self.assertEqual(
            names,
            ["adblock.txt", "blocklist.lsrules", "domains.txt", "hosts.txt", "ipfilter.dat", "p2p.txt"],
        )
        self.assertIn("0.0.0.0 a.example.com", (root / "dist" / "hosts.txt").read_text())
        self.assertIn("010.000.000.000 - 010.255.255.255 , 000 , lan", (root / "dist" / "ipfilter.dat").read_text())

    def test_deterministic_for_same_date(self):
        root = self.make_root("b.example.com\na.example.com\n", "1.2.3.4\n")
        first = build.build(root, DATE)
        snapshot = {p.name: p.read_bytes() for p in (root / "dist").iterdir()}
        second = build.build(root, DATE)
        self.assertEqual(first, second)
        self.assertEqual(snapshot, {p.name: p.read_bytes() for p in (root / "dist").iterdir()})

    def test_input_order_does_not_change_output(self):
        a = self.make_root("a.example.com\nb.example.com\n", "1.1.1.1\n2.2.2.2\n")
        b = self.make_root("b.example.com\na.example.com\n", "2.2.2.2\n1.1.1.1\n")
        self.assertEqual(build.build(a, DATE), build.build(b, DATE))

    def test_only_date_varies_between_dates(self):
        root = self.make_root("a.example.com\n", "1.2.3.4\n")
        one = build.build(root, "2026-01-01")
        two = build.build(root, "2026-01-02")
        for name in one:
            self.assertEqual(
                one[name].replace("2026-01-01", "D"),
                two[name].replace("2026-01-02", "D"),
                name,
            )

    def test_invalid_list_aborts_before_writing(self):
        root = self.make_root("a.example.com\nbad domain\n", "")
        with self.assertRaises(build.ListError):
            build.build(root, DATE)
        self.assertFalse((root / "dist").exists())


class CommandLineTests(unittest.TestCase):
    def test_cli_reports_error_with_line_number(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "lists").mkdir()
            (root / "lists" / "domains.txt").write_text("ok.example.com\nnope\n")
            (root / "lists" / "ips.txt").write_text("")
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                code = build.main(root)
        self.assertEqual(code, 1)
        self.assertIn("lists/domains.txt:2:", stderr.getvalue())
        self.assertFalse((root / "dist").exists())

    def test_cli_pins_date_with_source_date_epoch(self):
        env = dict(os.environ, SOURCE_DATE_EPOCH="0")
        code = "import build; print(build.build_date())"
        result = subprocess.run(
            [sys.executable, "-c", code],
            cwd=str(Path(build.__file__).parent),
            env=env,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.stdout.strip(), "1970-01-01")


if __name__ == "__main__":
    unittest.main()
