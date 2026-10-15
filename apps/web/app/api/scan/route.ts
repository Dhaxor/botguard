import { scan, type TargetHint } from "@botguard/core";
import { NextResponse } from "next/server";
import { SITE } from "@/lib/site";

export const runtime = "nodejs";
export const maxDuration = 60;

const MAX_INPUT = 200_000;
const WINDOW_MS = 5 * 60_000;
const MAX_PER_WINDOW = 15;
const HINTS = new Set<TargetHint>(["auto", "github", "npm", "pypi", "solidity"]);
const hits = new Map<string, { count: number; reset: number }>();

function rateLimited(ip: string): boolean {
  const now = Date.now();
  const entry = hits.get(ip);
  if (!entry || entry.reset < now) {
    hits.set(ip, { count: 1, reset: now + WINDOW_MS });
    if (hits.size > 5000) for (const [k, v] of hits) if (v.reset < now) hits.delete(k);
    return false;
  }
  entry.count++;
  return entry.count > MAX_PER_WINDOW;
}

export async function POST(req: Request) {
  const ip = req.headers.get("x-forwarded-for")?.split(",")[0]?.trim() || "local";
  if (rateLimited(ip)) {
    return NextResponse.json({ error: `Too many scans from your network. Try again in a few minutes, or run the CLI from source: github.com/${SITE.repo}` }, { status: 429 });
  }
  let body: { input?: unknown; kind?: unknown };
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "Send JSON: { input, kind }" }, { status: 400 });
  }
  const input = typeof body.input === "string" ? body.input : "";
  const kind = (typeof body.kind === "string" && HINTS.has(body.kind as TargetHint) ? body.kind : "auto") as TargetHint;
  if (!input.trim()) return NextResponse.json({ error: "Paste a GitHub repo, a package name or Solidity code." }, { status: 400 });
  if (input.length > MAX_INPUT) return NextResponse.json({ error: "That's too large to scan here. Use the CLI for big inputs." }, { status: 413 });

  const report = await scan(input, { hint: kind, detonate: true, githubToken: process.env.GITHUB_TOKEN });
  return NextResponse.json(report, { headers: { "cache-control": "no-store" } });
}
