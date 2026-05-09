# maskprompt-mcp

[![npm](https://img.shields.io/npm/v/@mukundakatta/maskprompt-mcp.svg)](https://www.npmjs.com/package/@mukundakatta/maskprompt-mcp)
[![mcp](https://img.shields.io/badge/protocol-MCP-blue.svg)](https://modelcontextprotocol.io)
[![license](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

An [MCP](https://modelcontextprotocol.io) server that gives AI assistants
the ability to redact PII (emails, phones, credit cards, SSNs, IPs, common
secrets) from text before it leaves the model's control.

Works with Claude Desktop, Cursor, Cline, Windsurf, Zed, and any other MCP
client.

## Built-in detectors

| Kind | Pattern |
|---|---|
| `EMAIL` | RFC-5322-ish addresses |
| `US_PHONE` | US 10-digit and `+1` formats |
| `US_SSN` | `XXX-XX-XXXX` |
| `IPV4` | dotted quad |
| `CREDIT_CARD` | 13–19-digit candidates that pass Luhn |
| `AWS_ACCESS_KEY` | `AKIA…` 20-char keys |
| `GITHUB_TOKEN` | `ghp_/gho_/ghu_/ghr_/ghs_…` |
| `JWT` | three url-safe base64 segments |

## Tools exposed

### `redact`

Redact PII in a string. Pick a strategy:

| Strategy | Replacement | When to use |
|---|---|---|
| `tag` (default) | `<EMAIL>` | LLM sees the type but not the value |
| `hash` | `<EMAIL:abc12345>` (truncated SHA-256) | Stable cross-run redaction without recovery |
| `fixed` | `███████` | Length-preserving |
| `remove` | _(empty)_ | Both type and value gone |

```json
{ "text": "Email me at alice@example.com about invoice 4111-1111-1111-1111." }
```

→

```json
{
  "masked": "Email me at <EMAIL> about invoice <CREDIT_CARD>.",
  "matches": [
    { "kind": "EMAIL", "start": 12, "end": 29, "value": "alice@example.com" },
    { "kind": "CREDIT_CARD", "start": 42, "end": 61, "value": "4111-1111-1111-1111" }
  ]
}
```

### `find_pii`

Same detection as `redact`, but doesn't rewrite the input — just returns
the matches. Useful when an agent wants to decide whether to refuse based
on detected PII.

## Configure your MCP client

Claude Desktop's `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "maskprompt": {
      "command": "npx",
      "args": ["-y", "@mukundakatta/maskprompt-mcp"]
    }
  }
}
```

## License

MIT.
