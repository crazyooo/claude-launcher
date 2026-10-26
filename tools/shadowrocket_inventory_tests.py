#!/usr/bin/env python3
import json
import plistlib
import unittest

import shadowrocket_inventory as s


def archive(objects):
    return plistlib.dumps({"$archiver": "NSKeyedArchiver", "$version": 100000,
                          "$objects": ["$null", *objects], "$top": {"root": plistlib.UID(1)}},
                         fmt=plistlib.FMT_BINARY)


def nodes():
    return [{"title": "MEI", "type": "Socks5", "host": "203.0.113.43", "port": "9034",
             "password": "PRIVATE_SECRET", "uuid": "PRIVATE_EXIT", "chain": "PRIVATE_UPSTREAM"},
            {"title": "PRIVATE_TITLE", "type": "VLESS", "host": "private.example", "port": "443",
             "password": "PRIVATE_CREDENTIAL", "uuid": "PRIVATE_UPSTREAM", "tls": True,
             "allowInsecure": False, "obfs": "websocket", "obfsParam": "private.example",
             "peer": "private.example", "pluginParam": {}, "data": "https://private.example/?token=PRIVATE_TOKEN"}]


class InventoryTests(unittest.TestCase):
    def test_actual_shape_inventory_is_redacted_and_not_a_launch_permit(self):
        result = s.inventory(archive([nodes()]))
        self.assertTrue(result["chain_resolved"])
        self.assertTrue(result["exit_node"]["endpoint_matches_expected_ip"])
        self.assertFalse(result["conversion_ready"])
        self.assertFalse(result["network_verified"])
        self.assertIn("websocket_path_not_explicit", result["blockers"])
        for private in ("PRIVATE", "private.example", "203.0.113.43", "9034", "password", "uuid", "obfsParam"):
            self.assertNotIn(private, json.dumps(result))

    def test_ns_container_and_string_decoding(self):
        raw = archive([{"NS.objects": [plistlib.UID(2)]},
                       {"NS.keys": ["title", "host", "type"], "NS.objects": [plistlib.UID(3), "203.0.113.43", "Socks5"]},
                       {"NS.string": "MEI"}])
        self.assertIn("exit_node", s.inventory(raw))

    def test_repeated_uid_is_not_a_second_node(self):
        exit_node, upstream = nodes()
        result = s.inventory(archive([{"NS.objects": [plistlib.UID(2), plistlib.UID(2), plistlib.UID(3)]}, exit_node, upstream]))
        self.assertTrue(result["chain_resolved"])

    def test_duplicate_title_and_identifier_are_ambiguous(self):
        values = nodes()
        self.assertIn("mei_ambiguous", s.inventory(archive([[*values, dict(values[0])]]))["blockers"])
        self.assertIn("upstream_ambiguous", s.inventory(archive([[*values, dict(values[1])]]))["blockers"])

    def test_bad_reference_cycles_and_duplicate_keys(self):
        fixtures = [({"NS.objects": [plistlib.UID(999)]}, "archive_bad_reference"),
                    ({"NS.objects": [plistlib.UID(1)]}, "archive_cycle"),
                    ({"NS.keys": ["x", "x"], "NS.objects": [1, 2]}, "archive_invalid_dictionary")]
        for value, code in fixtures:
            self.assertIn(code, s.inventory(archive([value]))["blockers"])

    def test_limits_and_bad_input_are_redacted(self):
        self.assertIn("archive_too_large", s.inventory(b"x" * (s.MAX_BYTES + 1))["blockers"])
        self.assertNotIn("PRIVATE", json.dumps(s.inventory(b"PRIVATE bad archive")))
        nested = []
        for _ in range(70): nested = [nested]
        self.assertIn("archive_expansion_limit", s.inventory(archive([nested]))["blockers"])

    def test_malformed_xml_returns_a_fixed_error(self):
        result = s.inventory(b'<?xml version="1.0"?><plist><dict><key>PRIVATE_SECRET</key>')
        self.assertEqual(result["blockers"], ["archive_invalid"])
        self.assertNotIn("PRIVATE", json.dumps(result))

    def test_no_insecure_or_unknown_transport_approval(self):
        values = nodes()
        values[1].update(tls="true", allowInsecure=True, obfs="PRIVATE_PROTOCOL")
        result = s.inventory(archive([values]))
        self.assertIn("upstream_tls_not_verified", result["blockers"])
        self.assertIn("upstream_certificate_validation_unconfirmed", result["blockers"])
        self.assertIn("unsupported_upstream_transport", result["blockers"])
        self.assertNotIn("PRIVATE", json.dumps(result))

    def test_path_and_chain_metadata_do_not_imply_conversion(self):
        values = nodes()
        values[1]["pluginParam"] = {"path": "/PRIVATE_PATH"}
        result = s.inventory(archive([values]))
        self.assertTrue(result["upstream_node"]["explicit_websocket_path_present"])
        self.assertFalse(result["conversion_ready"])
        self.assertNotIn("PRIVATE", json.dumps(result))


if __name__ == "__main__":
    unittest.main()
