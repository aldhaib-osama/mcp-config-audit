import unittest

from mcp_config_audit import audit_config


def issues(findings):
    return [f["issue"] for f in findings]


class AuditTests(unittest.TestCase):
    def test_clean_config_has_no_high_findings(self):
        cfg = {"servers": {"files": {
            "command": "mcp-files", "version": "1.2.3",
            "tools": ["read_file"],
            "transport": {"url": "https://mcp.example.com", "auth": "oauth2"},
            "env": {"LOG_LEVEL": "info"}}}}
        findings = audit_config(cfg)
        self.assertFalse([f for f in findings if f["severity"] == "high"])

    def test_wildcard_tools_flagged(self):
        cfg = {"servers": {"a": {"tools": "*"}}}
        self.assertTrue(any("wildcard" in i for i in issues(audit_config(cfg))))

    def test_plaintext_secret_flagged(self):
        cfg = {"servers": {"a": {"env": {"API_KEY": "abc123"}}}}
        self.assertTrue(any("plaintext env" in i for i in issues(audit_config(cfg))))

    def test_non_secret_env_not_flagged(self):
        cfg = {"servers": {"a": {"env": {"REGION": "eu"}}}}
        self.assertFalse(any("plaintext env" in i for i in issues(audit_config(cfg))))

    def test_http_transport_flagged(self):
        cfg = {"servers": {"a": {"transport": {"url": "http://x.test"}}}}
        self.assertTrue(any("plaintext http" in i for i in issues(audit_config(cfg))))

    def test_missing_auth_flagged_when_url(self):
        cfg = {"servers": {"a": {"transport": {"url": "https://x.test"}}}}
        self.assertTrue(any("no authentication" in i for i in issues(audit_config(cfg))))

    def test_shell_true_flagged(self):
        cfg = {"servers": {"a": {"command": "run", "shell": True}}}
        self.assertTrue(any("shell injection" in i for i in issues(audit_config(cfg))))

    def test_unpinned_version_flagged(self):
        cfg = {"servers": {"a": {"command": "run", "version": "latest"}}}
        self.assertTrue(any("not pinned" in i for i in issues(audit_config(cfg))))

    def test_empty_servers_info(self):
        findings = audit_config({"servers": {}})
        self.assertEqual(findings[0]["severity"], "info")

    def test_mcp_servers_key_supported(self):
        cfg = {"mcpServers": {"a": {"tools": ["*"]}}}
        self.assertTrue(any("wildcard" in i for i in issues(audit_config(cfg))))

    def test_risky_tool_name_medium(self):
        cfg = {"servers": {"a": {"tools": ["execute"]}}}
        findings = audit_config(cfg)
        self.assertTrue(any(f["severity"] == "medium" and "execute" in f["issue"]
                            for f in findings))


if __name__ == "__main__":
    unittest.main()
