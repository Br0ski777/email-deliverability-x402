import type { ApiConfig } from "./shared";

export const API_CONFIG: ApiConfig = {
  name: "email-deliverability",
  slug: "email-deliverability",
  description: "Audit email domain deliverability: SPF, DKIM, DMARC, MX records, score 0-100.",
  version: "1.0.0",
  routes: [
    {
      method: "GET",
      path: "/api/audit",
      price: "$0.005",
      description: "Audit email deliverability for a domain — checks SPF, DKIM, DMARC, MX records",
      toolName: "email_audit_deliverability",
      toolDescription:
        "Use this when you need to audit email deliverability for a domain. Checks SPF record validity, DKIM selectors (google, default, selector1), DMARC policy, and MX records. Returns a deliverability score 0-100 with specific recommendations to improve inbox placement. Do NOT use for email validation — use email_verify_address. Do NOT use for email finding — use email_find_by_name.",
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
    },
  ],
};
