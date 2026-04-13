import type { ApiConfig } from "./shared";

export const API_CONFIG: ApiConfig = {
  name: "email-deliverability",
  slug: "email-deliverability",
  description: "Email deliverability audit for any domain. SPF, DKIM, DMARC, MX validation with score 0-100 and fix recommendations.",
  version: "1.0.0",
  routes: [
    {
      method: "GET",
      path: "/api/audit",
      price: "$0.005",
      description: "Audit email deliverability for a domain — checks SPF, DKIM, DMARC, MX records",
      toolName: "email_audit_deliverability",
      toolDescription: `Use this when you need to audit email deliverability configuration for a domain. Returns structured JSON with authentication record analysis and a deliverability score 0-100.

1. score (number 0-100) -- overall deliverability health score
2. spf (object) -- SPF record found, valid syntax, includes count, too-many-lookups flag
3. dkim (object) -- DKIM selectors tested (google, default, selector1, selector2), which ones pass
4. dmarc (object) -- DMARC record found, policy (none/quarantine/reject), rua/ruf reporting addresses
5. mx (object) -- MX records found, priorities, mail server hostnames
6. recommendations (array) -- prioritized list of fixes to improve inbox placement

Example output: {"score":65,"spf":{"found":true,"valid":true,"record":"v=spf1 include:_spf.google.com ~all"},"dkim":{"google":true,"default":false},"dmarc":{"found":true,"policy":"none","record":"v=DMARC1; p=none"},"mx":[{"priority":10,"exchange":"alt1.gmail-smtp-in.l.google.com"}],"recommendations":["Upgrade DMARC policy from none to quarantine","Add DKIM for default selector"]}

Use this BEFORE launching email campaigns, onboarding new domains for outreach, or diagnosing inbox placement issues. Essential for email marketers, sales teams, and IT admins managing domain reputation.

Do NOT use for single email validation -- use email_verify_address instead. Do NOT use for finding email addresses -- use email_find_by_name instead. Do NOT use for domain WHOIS/DNS -- use domain_lookup_intelligence instead.`,
      inputSchema: {
        type: "object",
        properties: {
          domain: {
            type: "string",
            description: "Domain to audit (e.g. example.com, gmail.com)",
          },
        },
        required: ["domain"],
      },
      outputSchema: {
          "type": "object",
          "properties": {
            "domain": {
              "type": "string",
              "description": "Domain audited"
            },
            "spf": {
              "type": "object",
              "properties": {
                "status": {
                  "type": "string"
                },
                "record": {
                  "type": "string"
                }
              }
            },
            "dkim": {
              "type": "object",
              "properties": {
                "status": {
                  "type": "string"
                },
                "selectors": {
                  "type": "array"
                }
              }
            },
            "dmarc": {
              "type": "object",
              "properties": {
                "status": {
                  "type": "string"
                },
                "policy": {
                  "type": "string"
                },
                "record": {
                  "type": "string"
                }
              }
            },
            "mx": {
              "type": "object",
              "properties": {
                "records": {
                  "type": "array"
                },
                "provider": {
                  "type": "string"
                }
              }
            },
            "score": {
              "type": "number",
              "description": "Deliverability score 0-100"
            },
            "issues": {
              "type": "array",
              "items": {
                "type": "string"
              },
              "description": "Issues found"
            }
          },
          "required": [
            "domain",
            "spf",
            "dkim",
            "dmarc"
          ]
        },
    },
  ],
};
