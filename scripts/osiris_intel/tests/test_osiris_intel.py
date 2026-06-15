import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

import sys
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import osiris_intel


class OsirisIntelTests(unittest.TestCase):
    def test_rank_events_scores_crypto_and_chokepoint_keywords(self):
        events = [
            {"name": "Bank sanctions near Strait of Hormuz", "type": "conflict", "count": 3, "url": "https://example.test/1"},
            {"name": "Local sports festival", "type": "political", "count": 1, "url": "https://example.test/2"},
        ]
        ranked = osiris_intel.rank_events(events)
        self.assertGreater(ranked[0]["score"], ranked[1]["score"])
        self.assertIn("sanctions", ranked[0]["matched_keywords"])
        self.assertIn("hormuz", ranked[0]["matched_keywords"])

    def test_format_radar_text_contains_sections_and_source_urls(self):
        payload = {
            "health": {"ok": True, "status": "operational"},
            "gdelt_meta": {"total": 1, "source": "GDELT 2.0 DOC API", "errors": []},
            "gdelt": [{"name": "SEC crypto enforcement", "score": 9, "url": "https://example.test/g", "type": "political", "matched_keywords": ["crypto", "sec"]}],
            "news": [{"title": "Exchange withdrawals paused", "risk_score": 8, "link": "https://example.test/n", "source": "t.me/Test"}],
            "kev": [{"id": "CVE-2026-0001", "vendor": "OpenSSH", "product": "Server", "date": "2026-06-01"}],
        }
        text = osiris_intel.format_radar_text(payload)
        self.assertIn("OSINT / Risk radar", text)
        self.assertIn("TL;DR", text)
        self.assertIn("Источники и качество данных", text)
        self.assertIn("Режим принятия решения", text)
        self.assertIn("GDELT", text)
        self.assertIn("https://example.test/g", text)
        self.assertIn("CVE-2026-0001", text)

    def test_format_radar_text_marks_gdelt_degraded(self):
        payload = {
            "health": {"ok": True, "status": "operational"},
            "gdelt_meta": {"total": 0, "source": "GDELT 2.0 DOC API", "errors": ["GDELT DOC HTTP 429"]},
            "gdelt": [],
            "news": [],
            "kev": [],
        }
        text = osiris_intel.format_radar_text(payload)
        self.assertIn("GDELT DEGRADED", text)
        self.assertIn("GDELT DOC HTTP 429", text)
        self.assertIn("Ожидание с активной верификацией", text)

    def test_rank_news_filters_stale_published_items(self):
        recent = datetime.now(timezone.utc).isoformat()
        stale = (datetime.now(timezone.utc) - timedelta(days=365)).isoformat()
        ranked = osiris_intel.rank_news([
            {"title": "old drone attack", "risk_score": 9, "published": stale},
            {"title": "fresh exchange exploit", "risk_score": 5, "published": recent},
        ])
        self.assertEqual(len(ranked), 1)
        self.assertIn("fresh", ranked[0]["title"])

    def test_sanctions_enrichment_warns_on_crypto_risk_keyword(self):
        result = osiris_intel.enrich_sanctions_result({"query": "Tornado Cash", "matches": [], "total": 0}, "Tornado Cash")
        warnings = result["crypto_risk"]["warnings"]
        self.assertTrue(result["crypto_risk"]["needs_address_level_check"])
        self.assertEqual(warnings[0]["term"], "tornado cash")
        self.assertEqual(warnings[0]["severity"], "medium")
        self.assertEqual([w["term"] for w in warnings], ["tornado cash"])

    def test_crypto_risk_covers_garantex_successor_network(self):
        result = osiris_intel.enrich_sanctions_result({"query": "Grinex A7A5 Garantex", "matches": [], "total": 0}, "Grinex A7A5 Garantex")
        warnings = result["crypto_risk"]["warnings"]
        terms = {w["term"] for w in warnings}
        self.assertTrue({"grinex", "a7a5", "garantex"}.issubset(terms))
        self.assertTrue(all(w["severity"] == "high" for w in warnings))

    def test_crypto_risk_covers_iran_exchange_terms(self):
        warnings = osiris_intel.crypto_risk_warnings("Nobitex and Wallex stablecoin flows")
        terms = {w["term"] for w in warnings}
        self.assertTrue({"nobitex", "wallex"}.issubset(terms))
        self.assertEqual({w["severity"] for w in warnings}, {"high"})

    def test_crypto_risk_dedupes_mixer_aliases(self):
        blender_terms = [w["term"] for w in osiris_intel.crypto_risk_warnings("Blender.io mixer")]
        self.assertEqual(blender_terms, ["blender.io"])
        self.assertEqual([w["term"] for w in osiris_intel.crypto_risk_warnings("Hydra Market")], ["hydra market"])
        self.assertEqual([w["term"] for w in osiris_intel.crypto_risk_warnings("Lazarus Group")], ["lazarus group"])

    def test_crypto_risk_warns_on_generic_no_kyc_mixer(self):
        warnings = osiris_intel.crypto_risk_warnings("new no KYC mixer and sanctions evasion bridge")
        terms = {w["term"] for w in warnings}
        self.assertTrue({"no kyc", "mixer", "sanctions evasion"}.issubset(terms))

    def test_crypto_risk_detects_crypto_address_input(self):
        warnings = osiris_intel.crypto_risk_warnings("0x1111111111111111111111111111111111111111")
        self.assertEqual(warnings[0]["term"], "crypto-address")
        self.assertEqual(warnings[0]["severity"], "info")
        self.assertTrue("address" in warnings[0]["label"])

    def test_detect_address_kind_evm_btc_tron(self):
        self.assertEqual(osiris_intel.detect_address_kind("0x1111111111111111111111111111111111111111")["family"], "evm")
        self.assertEqual(osiris_intel.detect_address_kind("bc1q73ffx0fwtdvxhs6cfr5hguxsa3pasyg0txyae8")["family"], "btc")
        self.assertEqual(osiris_intel.detect_address_kind("TJRabPrwbZy45sbavfcjinPJC18kjpRTv8")["family"], "tron")

    @patch("osiris_intel.onchainos_status")
    @patch("osiris_intel.opensanctions_public_check")
    @patch("osiris_intel.scan_evm_address")
    def test_address_analysis_contract_high_risk_from_address_guardrail(self, scan_mock, sanctions_mock, onchain_mock):
        addr = "0x1111111111111111111111111111111111111111"
        scan_mock.return_value = [{
            "chain": "ethereum",
            "chain_id": "1",
            "native": "ETH",
            "explorer": "https://etherscan.io/address/" + addr,
            "is_contract": True,
            "code_size_bytes": 1234,
            "native_balance": 0,
            "token_metadata": {"symbol": "TEST", "name": "Test Token"},
        }]
        sanctions_mock.return_value = {"ok": True, "degraded": False, "count_hint": 0, "exact_mention": False, "url": "https://example.test"}
        onchain_mock.return_value = {"available": False, "error": "onchainos not installed"}
        result = osiris_intel.collect_address_analysis(addr)
        self.assertEqual(result["type"], "contract")
        self.assertEqual(result["verdict"], "clean-ish")
        self.assertEqual(result["contract_chains"], ["ethereum"])
        self.assertTrue(result["token_security"]["degraded"])

    @patch("osiris_intel.onchainos_status")
    @patch("osiris_intel.opensanctions_public_check")
    @patch("osiris_intel.scan_evm_address")
    def test_address_analysis_wallet_cleanish_when_sources_clear(self, scan_mock, sanctions_mock, onchain_mock):
        addr = "0x2222222222222222222222222222222222222222"
        scan_mock.return_value = [{
            "chain": "base",
            "chain_id": "8453",
            "native": "ETH",
            "explorer": "https://basescan.org/address/" + addr,
            "is_contract": False,
            "code_size_bytes": 0,
            "native_balance": 0.1,
        }]
        sanctions_mock.return_value = {"ok": True, "degraded": False, "count_hint": 0, "exact_mention": False, "url": "https://example.test"}
        onchain_mock.return_value = {"available": False, "error": "onchainos not installed"}
        result = osiris_intel.collect_address_analysis(addr)
        self.assertEqual(result["type"], "wallet")
        self.assertEqual(result["verdict"], "clean-ish")
        self.assertEqual(result["native_balances"][0]["chain"], "base")

    @patch("osiris_intel.onchainos_status")
    @patch("osiris_intel.opensanctions_public_check")
    @patch("osiris_intel.scan_evm_address")
    def test_address_analysis_high_risk_on_opensanctions_hit(self, scan_mock, sanctions_mock, onchain_mock):
        addr = "0x3333333333333333333333333333333333333333"
        scan_mock.return_value = [{"chain": "ethereum", "chain_id": "1", "native": "ETH", "is_contract": False, "native_balance": 0}]
        sanctions_mock.return_value = {"ok": True, "degraded": False, "count_hint": 1, "exact_mention": True, "url": "https://example.test"}
        onchain_mock.return_value = {"available": False, "error": "onchainos not installed"}
        result = osiris_intel.collect_address_analysis(addr)
        self.assertEqual(result["verdict"], "high-risk")

    @patch("osiris_intel.onchainos_status")
    @patch("osiris_intel.opensanctions_public_check")
    @patch("osiris_intel.scan_evm_address")
    def test_address_analysis_delegated_account_not_token_contract(self, scan_mock, sanctions_mock, onchain_mock):
        addr = "0x4444444444444444444444444444444444444444"
        scan_mock.return_value = [{
            "chain": "ethereum",
            "chain_id": "1",
            "native": "ETH",
            "is_contract": True,
            "is_delegated_account": True,
            "code_size_bytes": 23,
            "native_balance": 0,
        }]
        sanctions_mock.return_value = {"ok": True, "degraded": False, "count_hint": 0, "exact_mention": False, "url": "https://example.test"}
        onchain_mock.return_value = {"available": False, "error": "onchainos not installed"}
        result = osiris_intel.collect_address_analysis(addr)
        self.assertEqual(result["type"], "smart-account")
        self.assertEqual(result["contract_chains"], [])
        self.assertEqual(result["delegated_chains"], ["ethereum"])

    def test_http_json_error_formats_payload_message(self):
        err = osiris_intel.HttpJsonError(400, "http://example.test", {"error": "Invalid CVE format. Expected: CVE-YYYY-NNNNN"})
        self.assertIn("Invalid CVE format", str(err))

    def test_local_inventory_parses_dpkg_npm_pip_outputs(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            (base / "dpkg.txt").write_text("openssl\t3.0.13-0ubuntu3\nnodejs\t22.22.2\n")
            (base / "npm.json").write_text(json.dumps({"dependencies": {"next": {"version": "16.2.6"}}}))
            (base / "pip.json").write_text(json.dumps([{"name": "requests", "version": "2.32.0"}]))
            inv = osiris_intel.load_inventory_from_files(base / "dpkg.txt", base / "npm.json", base / "pip.json")
        names = {item["name"] for item in inv}
        self.assertTrue({"openssl", "nodejs", "next", "requests"}.issubset(names))

    def test_cve_impact_matches_description_to_inventory(self):
        cve = {"id": "CVE-2026-0002", "description": "OpenSSL memory corruption in vulnerable versions", "affected": [{"product": "OpenSSL", "vendor": "OpenSSL"}]}
        inv = [{"ecosystem": "dpkg", "name": "openssl", "version": "3.0.13"}]
        matches = osiris_intel.match_cve_to_inventory(cve, inv)
        self.assertEqual(matches[0]["name"], "openssl")

    def test_cve_impact_ignores_generic_package_names(self):
        cve = {"id": "CVE-2024-3094", "description": "A disguised test file is used to modify liblzma in xz tarballs", "affected": []}
        inv = [
            {"ecosystem": "dpkg", "name": "file", "version": "1:5.45"},
            {"ecosystem": "dpkg", "name": "xz-utils", "version": "5.4.5"},
            {"ecosystem": "dpkg", "name": "liblzma5:amd64", "version": "5.4.5"},
        ]
        matches = osiris_intel.match_cve_to_inventory(cve, inv)
        names = [m["name"] for m in matches]
        self.assertNotIn("file", names)
        self.assertIn("xz-utils", names)
        self.assertIn("liblzma5:amd64", names)

    def test_security_audit_detects_disabled_webhook_and_no_umami_egress(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            mw = root / "src" / "middleware.ts"
            wh = root / "src" / "app" / "api" / "github-webhook" / "route.ts"
            wh.parent.mkdir(parents=True)
            mw.parent.mkdir(parents=True, exist_ok=True)
            mw.write_text("return NextResponse.next();")
            wh.write_text("GitHub webhook disabled in Hermes sandbox")
            audit = osiris_intel.audit_osiris_repo(root)
        self.assertTrue(audit["webhook_disabled"])
        self.assertTrue(audit["umami_disabled"])

    @patch("osiris_intel.collect_radar")
    @patch("osiris_intel.audit_osiris_repo")
    def test_smoke_reports_gdelt_degraded_separately(self, audit_mock, radar_mock):
        radar_mock.return_value = {
            "health": {"ok": True, "status": "operational"},
            "gdelt": [],
            "gdelt_meta": {"total": 0, "source": "GDELT 2.0 DOC API", "errors": []},
            "news": [{"title": "ok"}],
            "kev": [{"id": "CVE-2026-0001"}],
        }
        audit_mock.return_value = {"webhook_disabled": True, "umami_disabled": True}
        result = osiris_intel.smoke("http://127.0.0.1:3030", Path("/root"))
        self.assertTrue(result["ok"])
        self.assertTrue(result["checks"]["gdelt_endpoint_ok"])
        self.assertFalse(result["checks"]["gdelt_has_events"])
        self.assertTrue(result["checks"]["gdelt_degraded"])

    def test_mstr_watch_confirmed_buy_fixture(self):
        filings = [{
            "filing_date": "2026-06-08",
            "accession": "0000000000-26-000001",
            "url": "https://sec.example/8k",
            "text": "Strategy acquired 1,234 bitcoin for $75 million. As of June 7, 2026, Strategy holds 844,940 bitcoin.",
        }]
        result = osiris_intel.analyze_mstr_watch(filings)
        self.assertEqual(result["status"], "confirmed_buy")
        self.assertEqual(result["buy_events"][0]["amount"], 1234)
        self.assertEqual(result["latest_holding"]["amount"], 844940)

    def test_mstr_watch_sale_update_fixture(self):
        filings = [{
            "filing_date": "2026-06-01",
            "accession": "0000000000-26-000002",
            "url": "https://sec.example/sale",
            "text": "Strategy sold 32 bitcoin between May 26 and May 31. Strategy held 843,706 bitcoin as of May 31.",
        }]
        result = osiris_intel.analyze_mstr_watch(filings)
        self.assertEqual(result["status"], "sale_update")
        self.assertEqual(result["sale_events"][0]["amount"], 32)

    def test_mstr_extracts_sec_table_sale_and_holdings(self):
        text = (
            "BTC Update During Period May 26, 2026 to May 31, 2026* "
            "BTC Sold Aggregate Sale Price (in millions) (2) Average Sale Price (2) "
            "32 (1) $2.5 $77,135 As of May 31, 2026* Aggregate BTC Holdings "
            "Aggregate Purchase Price (in billions) (2) Average Purchase Price (2) "
            "843,706 $63.87 $75,699"
        )
        facts = osiris_intel.extract_mstr_btc_facts(text)
        self.assertEqual(facts["sold"][0]["amount"], 32)
        self.assertEqual(facts["holdings"][0]["amount"], 843706)

    def test_mstr_extracts_sec_table_buy_and_holdings(self):
        text = (
            "BTC Update During Period June 1, 2026 to June 7, 2026 As of June 7, 2026 "
            "BTC Acquired (1) Aggregate Purchase Price (in millions) (2) Average Purchase Price (2) "
            "Aggregate BTC Holdings Aggregate Purchase Price (in billions) (2) Average Purchase Price (2) "
            "1,550 $ 101.3 $ 65,332 845,256 $ 63.97 $ 75,680"
        )
        facts = osiris_intel.extract_mstr_btc_facts(text)
        self.assertEqual(facts["acquired"][0]["amount"], 1550)
        self.assertEqual(facts["holdings"][0]["amount"], 845256)

    def test_mstr_watch_hint_only_fixture(self):
        filings = [{
            "filing_date": "2026-06-01",
            "accession": "0000000000-26-000003",
            "url": "https://sec.example/sale",
            "text": "Strategy sold 32 bitcoin. Strategy held 843,706 bitcoin as of May 31.",
        }]
        hints = [{"title": "Michael Saylor says a good time to add more dots", "domain": "example.test"}]
        result = osiris_intel.analyze_mstr_watch(filings, hints=hints)
        self.assertEqual(result["status"], "hint_only")
        self.assertTrue(result["hints"])

    def test_mstr_watch_no_fresh_filing_fixture(self):
        filings = [{
            "filing_date": "2026-06-03",
            "accession": "0000000000-26-000004",
            "url": "https://sec.example/other",
            "text": "Strategy announced an administrative update with no bitcoin treasury transaction.",
        }]
        result = osiris_intel.analyze_mstr_watch(filings)
        self.assertEqual(result["status"], "no_fresh_filing")
        self.assertFalse(result["buy_events"])

    def test_mstr_watch_degraded_primary_source_fixture(self):
        result = osiris_intel.analyze_mstr_watch([], errors=["SEC submissions failed: timeout"])
        self.assertEqual(result["status"], "degraded")
        self.assertEqual(result["confidence"], "low")


if __name__ == "__main__":
    unittest.main()
