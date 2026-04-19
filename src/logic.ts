import type { Hono } from "hono";
import { resolve } from "dns/promises";


// ATXP: requirePayment only fires inside an ATXP context (set by atxpHono middleware).
// For raw x402 requests, the existing @x402/hono middleware handles the gate.
// If neither protocol is active (ATXP_CONNECTION unset), tryRequirePayment is a no-op.
async function tryRequirePayment(price: number): Promise<void> {
  if (!process.env.ATXP_CONNECTION) return;
  try {
    const { requirePayment } = await import("@atxp/server");
    const BigNumber = (await import("bignumber.js")).default;
    await requirePayment({ price: BigNumber(price) });
  } catch (e: any) {
    if (e?.code === -30402) throw e;
  }
}

interface AuditResult {
  domain: string;
  spf: { status: "valid" | "found" | "missing"; record?: string };
  dkim: { status: "found" | "missing"; selectors: { name: string; found: boolean }[] };
  dmarc: { status: "valid" | "found" | "missing"; policy?: string; record?: string };
  mx: { status: "found" | "missing"; records: { priority: number; exchange: string }[] };
  score: number;
  recommendations: string[];
}

async function checkSPF(domain: string): Promise<AuditResult["spf"]> {
  try {
    const records = await resolve(domain, "TXT");
    const flat = records.map((r) => (Array.isArray(r) ? r.join("") : r));
    const spfRecord = flat.find((r) => r.startsWith("v=spf1"));
    if (spfRecord) {
      const hasAll = spfRecord.includes("-all") || spfRecord.includes("~all");
      return { status: hasAll ? "valid" : "found", record: spfRecord };
    }
    return { status: "missing" };
  } catch {
    return { status: "missing" };
  }
}

const DKIM_SELECTORS = ["google._domainkey", "default._domainkey", "selector1._domainkey", "selector2._domainkey", "k1._domainkey"];

async function checkDKIM(domain: string): Promise<AuditResult["dkim"]> {
  const selectors: { name: string; found: boolean }[] = [];
  for (const sel of DKIM_SELECTORS) {
    try {
      const records = await resolve(`${sel}.${domain}`, "TXT");
      selectors.push({ name: sel, found: records.length > 0 });
    } catch {
      selectors.push({ name: sel, found: false });
    }
  }
  const anyFound = selectors.some((s) => s.found);
  return { status: anyFound ? "found" : "missing", selectors };
}

async function checkDMARC(domain: string): Promise<AuditResult["dmarc"]> {
  try {
    const records = await resolve(`_dmarc.${domain}`, "TXT");
    const flat = records.map((r) => (Array.isArray(r) ? r.join("") : r));
    const dmarcRecord = flat.find((r) => r.startsWith("v=DMARC1"));
    if (dmarcRecord) {
      const policyMatch = dmarcRecord.match(/p=(\w+)/);
      const policy = policyMatch ? policyMatch[1] : "none";
      return { status: "valid", policy, record: dmarcRecord };
    }
    return { status: "missing" };
  } catch {
    return { status: "missing" };
  }
}

async function checkMX(domain: string): Promise<AuditResult["mx"]> {
  try {
    const records = await resolve(domain, "MX");
    if (records.length > 0) {
      const sorted = records.sort((a: any, b: any) => a.priority - b.priority);
      return {
        status: "found",
        records: sorted.map((r: any) => ({ priority: r.priority, exchange: r.exchange })),
      };
    }
    return { status: "missing", records: [] };
  } catch {
    return { status: "missing", records: [] };
  }
}

function calculateScore(spf: AuditResult["spf"], dkim: AuditResult["dkim"], dmarc: AuditResult["dmarc"], mx: AuditResult["mx"]): number {
  let score = 0;
  if (spf.status === "valid") score += 30;
  else if (spf.status === "found") score += 15;
  if (dkim.status === "found") score += 25;
  if (dmarc.status === "valid") score += 25;
  else if (dmarc.status === "found") score += 10;
  if (mx.status === "found") score += 20;
  return score;
}

function getRecommendations(spf: AuditResult["spf"], dkim: AuditResult["dkim"], dmarc: AuditResult["dmarc"], mx: AuditResult["mx"]): string[] {
  const recs: string[] = [];
  if (spf.status === "missing") recs.push("Add an SPF record (v=spf1 include:... -all) to authorize sending servers.");
  else if (spf.status === "found") recs.push("Strengthen SPF: use -all (hard fail) instead of ~all (soft fail).");
  if (dkim.status === "missing") recs.push("Configure DKIM signing — add a DKIM TXT record for your email provider.");
  if (dmarc.status === "missing") recs.push("Add a DMARC record (_dmarc TXT) with at least p=quarantine to protect against spoofing.");
  else if (dmarc.policy === "none") recs.push("Upgrade DMARC policy from p=none to p=quarantine or p=reject for better protection.");
  if (mx.status === "missing") recs.push("No MX records found — this domain cannot receive email. Add MX records pointing to your mail server.");
  if (recs.length === 0) recs.push("Excellent configuration! All major email authentication protocols are properly set up.");
  return recs;
}

export function registerRoutes(app: Hono) {
  app.get("/api/audit", async (c) => {
    await tryRequirePayment(0.005);
    const domain = c.req.query("domain");
    if (!domain) return c.json({ error: "Missing required parameter: domain" }, 400);

    const cleanDomain = domain.replace(/^https?:\/\//, "").replace(/\/.*$/, "").toLowerCase();

    const [spf, dkim, dmarc, mx] = await Promise.all([
      checkSPF(cleanDomain),
      checkDKIM(cleanDomain),
      checkDMARC(cleanDomain),
      checkMX(cleanDomain),
    ]);

    const score = calculateScore(spf, dkim, dmarc, mx);
    const recommendations = getRecommendations(spf, dkim, dmarc, mx);

    const result: AuditResult = { domain: cleanDomain, spf, dkim, dmarc, mx, score, recommendations };
    return c.json(result);
  });
}
