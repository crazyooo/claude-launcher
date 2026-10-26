#!/usr/bin/env python3
import json
import unittest

from routing_audit import audit, inspect_host, mihomo_fragment, parse


class RoutingAuditTests(unittest.TestCase):
    def inspect(self, rules, host="api.anthropic.com"):
        return inspect_host(parse("[Rule]\n" + rules)[0], host)

    def test_domain_boundary(self):
        rules = "DOMAIN-SUFFIX,anthropic.com,MEI\nFINAL,PROXY"
        for host in ("anthropic.com", "API.ANTHROPIC.COM."):
            self.assertEqual(self.inspect(rules, host)["hostname_candidate"]["policy"], "MEI")
        for host in ("notanthropic.com", "anthropic.com.attacker.example"):
            self.assertEqual(self.inspect(rules, host)["hostname_candidate"]["policy"], "PROXY")

    def test_prior_unresolved_conditions_cannot_pass(self):
        for rule in ("RULE-SET,https://example.invalid/secret,DIRECT", "GEOIP,US,DIRECT",
                     "IP-CIDR,192.0.2.0/24,DIRECT,no-resolve", "USER-AGENT,Claude*,DIRECT",
                     "PROCESS-NAME,Claude,DIRECT", "unknown", "OTHER,x,DIRECT",
                     "DOMAIN,api.anthropic.com,DIRECT,unsupported-option"):
            result = self.inspect(rule + "\nDOMAIN-SUFFIX,anthropic.com,MEI")
            self.assertEqual(result["status"], "indeterminate", rule)
            self.assertEqual(result["earlier_unresolved"][0]["line"], 2)
            self.assertEqual(result["hostname_candidate"]["line"], 3)

    def test_later_rules_do_not_override(self):
        result = self.inspect("DOMAIN-SUFFIX,anthropic.com,MEI\nGEOIP,US,DIRECT")
        self.assertEqual(result["status"], "determinate")

    def test_shadowed_rules_and_statsig_domains(self):
        report = audit("[Rule]\nDOMAIN-SUFFIX,statsigapi.net,MEI\n"
                       "DOMAIN,api.statsig.com,PROXY\n"
                       "DOMAIN-SUFFIX,events.statsigapi.net,PROXY\nFINAL,PROXY")
        self.assertEqual(report["targets"]["api.statsig.com"]["hostname_candidate"]["policy"], "PROXY")
        self.assertEqual(report["targets"]["events.statsigapi.net"]["hostname_candidate"]["policy"], "MEI")
        self.assertTrue(report["shadowed_rules"][0]["different_policy"])

    def test_unsupported_options_do_not_prove_shadowing(self):
        report = audit("[Rule]\nDOMAIN-SUFFIX,claude.ai,MEI,unknown\nDOMAIN,claude.ai,PROXY")
        self.assertEqual(report["shadowed_rules"], [])

    def test_malformed_final_is_unknown_and_cannot_generate_fragment(self):
        for rule in ("FINAL,x,MEI", "FINAL", "FINAL,MEI,unsupported"):
            report = audit("[Rule]\n" + rule + "\nDOMAIN,claude.ai,MEI")
            self.assertEqual(report["targets"]["claude.ai"]["status"], "indeterminate")
            self.assertEqual(report["shadowed_rules"], [])
            self.assertNotIn("DOMAIN,claude.ai,", mihomo_fragment(report))

    def test_secrets_and_rule_urls_never_leave_report(self):
        report = audit("[General]\nipv6=true\ndns-server=223.5.5.5,https://private.invalid/SECRET\n"
                       "[Proxy]\nMEI=socks5,private.invalid,443,password=SECRET\n"
                       "[Rule]\nRULE-SET,https://private.invalid/SECRET,DIRECT\n"
                       "DOMAIN-SUFFIX,anthropic.com,secret-policy-SECRET\nFINAL,PROXY",
                       "203.0.113.43")
        encoded = json.dumps(report)
        for value in ("SECRET", "private.invalid", "password", "secret-policy"):
            self.assertNotIn(value, encoded)
        self.assertTrue(report["mei"]["definition_in_file"])
        self.assertIsNone(report["mei"]["observed_exit"])
        self.assertFalse(report["mei"]["chain_verified"])
        self.assertTrue(report["dns"]["mixed_transport"])

    def test_missing_settings_are_unknown(self):
        report = audit("[Rule]\nFINAL,PROXY")
        self.assertEqual(report["ipv6"]["configured"], "unknown")
        self.assertFalse(report["mei"]["definition_in_file"])
        self.assertFalse(report["protection_verified"])

    def test_fragment_never_invents_coverage(self):
        report = audit("[Rule]\nDOMAIN,claude.ai,MEI\nDOMAIN-SUFFIX,auth0.com,MEI\nFINAL,PROXY")
        fragment = mihomo_fragment(report)
        self.assertIn("INCOMPLETE", fragment)
        self.assertIn("DOMAIN,claude.ai,Claude-Residential", fragment)
        self.assertNotIn("DOMAIN-SUFFIX", fragment)
        self.assertNotIn("auth0.com", fragment)
        self.assertNotIn("DIRECT", fragment)
        self.assertNotIn("api.anthropic.com", fragment)

    def test_ip_and_url_are_not_domain_queries(self):
        for value in ("127.0.0.1", "https://claude.ai", "a..com", "foo@claude.ai"):
            with self.assertRaises(ValueError):
                self.inspect("FINAL,PROXY", value)


if __name__ == "__main__":
    unittest.main()
