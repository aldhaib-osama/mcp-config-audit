"""Audit MCP (Model Context Protocol) server configuration files for common
risky settings. Static, heuristic checks on a config file you supply. It does
not connect to any server and does not certify a setup as safe."""
import json
import sys

SECRET_HINTS = ("key", "token", "secret", "password", "passwd", "credential")
RISKY_NAMES = ("execute", "shell", "bash", "run_command", "delete_all", "admin")


def find_secrets(env, path, findings):
    for k, v in (env or {}).items():
        if any(h in k.lower() for h in SECRET_HINTS) and isinstance(v, str) and v:
            findings.append({
                "severity": "high",
                "path": path + "/env/" + k,
                "issue": "secret-looking value stored in plaintext env",
            })


def audit_server(name, srv, findings):
    base = "/servers/" + name
    if not isinstance(srv, dict):
        findings.append({"severity": "high", "path": base,
                         "issue": "server entry is not an object"})
        return
    perms = srv.get("tools", srv.get("permissions"))
    if perms == "*" or perms == ["*"]:
        findings.append({"severity": "high", "path": base + "/tools",
                         "issue": "wildcard tool permission grants every tool"})
    elif isinstance(perms, list):
        for p in perms:
            if isinstance(p, str) and p.lower() in RISKY_NAMES:
                findings.append({"severity": "medium", "path": base + "/tools",
                                 "issue": "powerful tool allowed: " + p})
    transport = srv.get("transport", {})
    url = transport.get("url", "") if isinstance(transport, dict) else ""
    if isinstance(url, str) and url.startswith("http://"):
        findings.append({"severity": "high", "path": base + "/transport/url",
                         "issue": "plaintext http transport"})
    if isinstance(transport, dict) and transport.get("auth") in (None, "none"):
        if url:
            findings.append({"severity": "medium", "path": base + "/transport",
                             "issue": "no authentication configured for transport"})
    if srv.get("command") and srv.get("shell") is True:
        findings.append({"severity": "high", "path": base + "/shell",
                         "issue": "shell:true with command enables shell injection"})
    version = srv.get("version")
    if version in (None, "latest"):
        findings.append({"severity": "low", "path": base + "/version",
                         "issue": "server version not pinned"})
    find_secrets(srv.get("env"), base, findings)


def audit_config(cfg):
    findings = []
    servers = cfg.get("servers", cfg.get("mcpServers", {}))
    if not isinstance(servers, dict) or not servers:
        findings.append({"severity": "info", "path": "/servers",
                         "issue": "no servers object found"})
        return findings
    for name, srv in servers.items():
        audit_server(name, srv, findings)
    return findings


def main(argv):
    if len(argv) != 2:
        print("usage: python mcp_config_audit.py <config.json>", file=sys.stderr)
        return 2
    with open(argv[1], "r", encoding="utf-8") as fh:
        cfg = json.load(fh)
    findings = audit_config(cfg)
    order = {"high": 0, "medium": 1, "low": 2, "info": 3}
    findings.sort(key=lambda f: order.get(f["severity"], 4))
    print(json.dumps({"findings": findings, "count": len(findings)}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
