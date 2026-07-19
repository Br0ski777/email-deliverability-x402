# Email Deliverability Audit API

[![MCP Server](https://img.shields.io/badge/MCP-server-blue)](https://email-deliverability.api.klymax402.com/mcp)
[![x402](https://img.shields.io/badge/payments-x402-6E56CF)](https://x402.org)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

Email deliverability audit for any domain. SPF, DKIM, DMARC, MX validation with score 0-100 and fix recommendations. Pay-per-call via [x402](https://x402.org) (USDC on Base L2) -- no API key, no signup, no rate-limit wall.

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
| `email_audit_deliverability` | GET | `/api/audit` | $0.012 | Audit email deliverability for a domain — checks SPF, DKIM, DMARC, MX records |
| `email_audit_deliverability` | POST | `/api/audit` | $0.012 | Audit email deliverability for a domain — checks SPF, DKIM, DMARC, MX records (POST variant) |

### `email_audit_deliverability`

Use this when you need to audit email deliverability configuration for a domain. Returns structured JSON with authentication record analysis and a deliverability score 0-100.

**Parameters**

| Name | Type | Required | Description |
|---|---|---|---|
| `domain` | string | yes | Domain to audit (e.g. example.com, gmail.com) |

Example response:

```json
{"score":65,"spf":{"found":true,"valid":true,"record":"v=spf1 include:_spf.google.com ~all"},"dkim":{"google":true,"default":false},"dmarc":{"found":true,"policy":"none","record":"v=DMARC1; p=none"},"mx":[{"priority":10,"exchange":"alt1.gmail-smtp-in.l.google.com"}],"recommendations":["Upgrade DMARC policy from none to quarantine","Add DKIM for default selector"]}
```

**When to use**: launching email campaigns, onboarding new domains for outreach, or diagnosing inbox placement issues. Essential for email marketers, sales teams, and IT admins managing domain reputation.

**Not for**: single email validation (use `email_verify_address`), finding email addresses (use `email_find_by_name`), domain WHOIS/DNS (use `domain_lookup_intelligence`).

### `email_audit_deliverability`

Use this when you need to audit email deliverability configuration for a domain. Returns structured JSON with authentication record analysis and a deliverability score 0-100. POST variant of email_audit_deliverability -- same params passed as JSON body instead of query string.

**Parameters**

| Name | Type | Required | Description |
|---|---|---|---|
| `domain` | string | yes | Domain to audit (e.g. example.com, gmail.com) |

Example response:

```json
{"score":65,"spf":{"found":true,"valid":true,"record":"v=spf1 include:_spf.google.com ~all"},"dkim":{"google":true,"default":false},"dmarc":{"found":true,"policy":"none","record":"v=DMARC1; p=none"},"mx":[{"priority":10,"exchange":"alt1.gmail-smtp-in.l.google.com"}],"recommendations":["Upgrade DMARC policy from none to quarantine","Add DKIM for default selector"]}
```

**When to use**: launching email campaigns, onboarding new domains for outreach, or diagnosing inbox placement issues. Essential for email marketers, sales teams, and IT admins managing domain reputation.

**Not for**: single email validation (use `email_verify_address`), finding email addresses (use `email_find_by_name`), domain WHOIS/DNS (use `domain_lookup_intelligence`).

## Example agent prompts

- "Audit email deliverability configuration for a domain"
- "Audit email deliverability configuration for a domain"

## Payment

- Protocol: [x402](https://x402.org) -- HTTP-native pay-per-call, no signup, no API key
- Network: Base L2 (`eip155:8453`)
- Asset: USDC
- Facilitator: Coinbase CDP (primary), PayAI (fallback)
- Also reachable via [ATXP](https://atxp.ai) (OAuth-wrapped x402, RFC 9728 protected-resource metadata)

## Part of klymax402

100 x402 micropayment APIs for AI agents -- one wallet, USDC on Base, zero signup.

- Catalog: https://klymax402.com/llms.txt
- Full API reference: https://klymax402.com/llms-full.txt
- Live stats: https://klymax402.com/stats

## License

MIT
