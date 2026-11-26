# mcp-config-audit

Static audit of Model Context Protocol (MCP) server configuration files, for learning MCP security basics.

You give it a config JSON. It reports findings as JSON: wildcard tool permissions, plaintext env secrets, plaintext HTTP transport, missing transport authentication, `shell: true` with a command, and unpinned server versions.

## What it is

- An offline educational checker. It reads one file and prints findings.
- A way to practice least-privilege thinking for MCP servers before connecting them to a model.

## What it is NOT

- Not a security certification. A clean run does not mean a setup is safe.
- It never connects to a server. It only reads the file you give it.
- It does not know your threat model. A "finding" can be acceptable in a lab and unacceptable in production.

## Usage

```
python mcp_config_audit.py example.json
```

`example.json` is fictional and intentionally contains several findings so you can see the output shape.

## Tests

```
python -m unittest -v
```

[VERIFY: run the tests yourself before citing the count in an interview.]

## Provenance

Initial code was AI-assisted. [TO FILL: Dahoba's own review notes.]
