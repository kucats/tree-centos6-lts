"""Fail-closed contract for the intentionally functionality-reducing agent backport."""
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class AgentDenyContract(unittest.TestCase):
    def test_cve_remains_pending(self):
        info = json.loads(
            (ROOT / "security/advisories/CVE-2023-38408.json").read_text()
        )
        self.assertEqual(info["status"], "pending")
        scope = info["candidate_mitigation"]
        self.assertIn("ALL clients", scope["operational_effect"])
        self.assertIn("smartcard", scope["compatibility_impact"])
        self.assertEqual(scope["release_status"],
                         "UNVERIFIED unsigned research candidate; never publish")
        self.assertEqual(scope["tests"]["independent_patch_review"], "pending")

    def test_patch_targets_only_agent_dispatch_and_preserves_regular_keys(self):
        patch = (ROOT / "packages/openssh/CVE-2023-38408-deny-pkcs11.patch").read_text()
        self.assertTrue(patch.startswith("--- a/ssh-agent.c\n+++ b/ssh-agent.c\n"))
        self.assertEqual(patch.count("@@"), 4)  # two unified-diff hunks
        self.assertEqual(patch.count("-\t\tprocess_add_smartcard_key(e);"), 1)
        self.assertEqual(patch.count("-\t\tprocess_remove_smartcard_key(e);"), 1)
        self.assertEqual(patch.count("+\t\tbuffer_put_char(&e->output, SSH_AGENT_FAILURE);"), 2)
        self.assertNotIn("SSH2_AGENTC_ADD_IDENTITY", patch)
        nss_patch = (ROOT / "packages/openssh/CVE-2023-38408-deny-nss-agent.patch").read_text()
        self.assertIn("-\t\tprocess_add_nss_key(e);", nss_patch)
        self.assertIn("-\t\tprocess_remove_nss_key(e);", nss_patch)
        self.assertIn("SSH_AGENT_FAILURE", nss_patch)

    def test_integration_covers_signing_and_three_request_types(self):
        script = (ROOT / "tests/integration/openssh_agent_pkcs11_deny.sh").read_text()
        self.assertIn("normal SSH2 agent RSA signature response retained", script)
        self.assertIn("(20, 21, 26, 30, 31, 32)", script)
        self.assertIn("DT_NEEDED introduces no new libraries", script)
        self.assertIn("libplc4.so", script)
        self.assertIn("rpm2cpio", script)
        yum = (ROOT / "tests/integration/openssh_offline_yum_upgrade.sh").read_text()
        self.assertIn("gpgcheck=0", yum)
        self.assertIn("disablerepo", yum)
        self.assertIn("PASS: offline yum RPM dependency transaction", yum)


if __name__ == "__main__":
    unittest.main()
