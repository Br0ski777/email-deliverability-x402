# Email Deliverability Audit API

[![MCP Server](https://img.shields.io/badge/MCP-server-blue)](https://email-deliverability.api.klymax402.com/mcp)
[![x402](https://img.shields.io/badge/payments-x402-6E56CF)](https://x402.org)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

Audit email domain deliverability: SPF, DKIM, DMARC, MX records, score 0-100. Pay-per-call via [x402](https://x402.org) (USDC on Base L2) -- no API key, no signup, no rate-limit wall.

Part of the [klymax402](https://klymax402.com) marketplace -- 100 x402 micropayment APIs for AI agents, one wallet, USDC on Base.

## Quickstart -- MCP

Add to your MCP client config (Claude Desktop, Cursor, ElizaOS, etc.):

```json
{
  "mcpServers": {
    "email-deliverability": {
      "url": "https://email-deliverability.api.klymax402.com/mcp"
    }
  }
}
```

## Quickstart -- HTTP (x402)

```bash
curl "https://email-deliverability.api.klymax402.com/api/audit?domain=..."
# -> 402 Payment Required, with an x402 payment challenge in the response body
```

Any x402-aware client ([`@x402/fetch`](https://www.npmjs.com/package/@x402/fetch), [`x402-agent-tools`](https://www.npmjs.com/package/x402-agent-tools), ATXP) handles the 402 -> sign -> retry cycle automatically.

## Tools

| Tool | Method | Path | Price | Description |
|---|---|---|---|---|
| `email_audit_deliverability` | GET | `/api/audit` | $0.005 | Audit email deliverability for a domain — checks SPF, DKIM, DMARC, MX records |

### `email_audit_deliverability`

Use this when you need to audit email deliverability for a domain. Checks SPF record validity, DKIM selectors (google, default, selector1), DMARC policy, and MX records. Returns a deliverability score 0-100 with specific recommendations to improve inbox placement. Do NOT use for email validation — use email_verify_address. Do NOT use for email finding — use email_find_by_name.

**Parameters**

| Name | Type | Required | Description |
|---|---|---|---|
| `domain` | string | yes | Domain to audit (e.g. example.com, gmail.com) |

## Example agent prompts

- "Audit email deliverability for a domain"

## Payment

- Protocol: [x402](https://x402.org) -- HTTP-native pay-per-call, no signup, no API key
- Network: Base L2 (`eip155:8453`)
- Asset: USDC
- Facilitator: Coinbase CDP (primary), PayAI (fallback)

## Part of klymax402

100 x402 micropayment APIs for AI agents -- one wallet, USDC on Base, zero signup.

- Catalog: https://klymax402.com/llms.txt
- Full API reference: https://klymax402.com/llms-full.txt
- Live stats: https://klymax402.com/stats

## License

MIT
