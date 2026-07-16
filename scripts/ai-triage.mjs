#!/usr/bin/env node
// AI-assisted triage: condense the scanners' JSON into a short list, ask Claude to
// prioritize it, and write a markdown summary the CI job posts as a PR comment. Turns a
// wall of findings into "here's what to actually look at first".
//
// Node built-in fetch only — no @anthropic-ai/sdk dependency. This is a one-shot CI helper
// in a supply-chain-security project, so keeping its dependency footprint at zero is the
// point; a single POST to the Messages API doesn't warrant pulling in an SDK + its tree.
//
// Env: ANTHROPIC_API_KEY (required to call the API), ANTHROPIC_MODEL (default below),
//      OUT_DIR (default: artifacts). Reads semgrep + trivy JSON from OUT_DIR.
// Usage: node scripts/ai-triage.mjs         # triage; writes $OUT_DIR/ai-triage.md
//        node scripts/ai-triage.mjs --self-test
import { readFileSync, writeFileSync, existsSync, mkdirSync } from "node:fs";

const OUT = process.env.OUT_DIR || "artifacts";
const MODEL = process.env.ANTHROPIC_MODEL || "claude-opus-4-8";
const MAX_FINDINGS = 40; // cap the prompt so a noisy scan can't blow up cost/latency

const readJson = (p) => (existsSync(p) ? JSON.parse(readFileSync(p, "utf8")) : null);

// Flatten each scanner's shape into a common {tool, severity, id, where, message}.
function collect(dir) {
  const out = [];
  const sg = readJson(`${dir}/semgrep.json`);
  for (const r of sg?.results || []) {
    out.push({
      tool: "semgrep",
      severity: (r.extra?.severity || "INFO").toUpperCase(),
      id: r.check_id,
      where: `${r.path}:${r.start?.line ?? "?"}`,
      message: r.extra?.message || "",
    });
  }
  for (const name of ["trivy-image.json", "trivy-fs.json"]) {
    const tv = readJson(`${dir}/${name}`);
    for (const res of tv?.Results || []) {
      for (const v of res.Vulnerabilities || []) {
        out.push({
          tool: "trivy",
          severity: (v.Severity || "UNKNOWN").toUpperCase(),
          id: v.VulnerabilityID,
          where: `${v.PkgName}@${v.InstalledVersion || "?"}`,
          message: v.Title || "",
        });
      }
    }
  }
  const rank = { CRITICAL: 0, HIGH: 1, ERROR: 1, MEDIUM: 2, WARNING: 2, LOW: 3, INFO: 4, UNKNOWN: 5 };
  out.sort((a, b) => (rank[a.severity] ?? 9) - (rank[b.severity] ?? 9));
  return out;
}

function buildPrompt(findings) {
  const lines = findings
    .slice(0, MAX_FINDINGS)
    .map((f) => `- [${f.severity}] (${f.tool}) ${f.id} @ ${f.where} — ${f.message}`)
    .join("\n");
  return `You are a security engineer triaging CI scan findings for a Node/Express service.
Here are ${findings.length} findings (showing up to ${MAX_FINDINGS}, most severe first):

${lines}

Write a concise markdown triage for a pull-request comment:
1. A one-line risk summary.
2. A "Fix first" list of at most 5 findings that most warrant action, each with a one-line why.
3. A short "Likely noise / lower priority" note.
Do not invent findings that aren't listed. Keep it under ~250 words.`;
}

async function callClaude(prompt) {
  const key = process.env.ANTHROPIC_API_KEY;
  if (!key) throw new Error("ANTHROPIC_API_KEY not set");
  const res = await fetch("https://api.anthropic.com/v1/messages", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-api-key": key,
      "anthropic-version": "2023-06-01",
    },
    body: JSON.stringify({
      model: MODEL,
      max_tokens: 1024,
      messages: [{ role: "user", content: prompt }],
    }),
  });
  if (!res.ok) throw new Error(`Anthropic API ${res.status}: ${await res.text()}`);
  const data = await res.json();
  if (data.stop_reason === "refusal") return "_AI triage declined this content._";
  return (data.content || []).filter((b) => b.type === "text").map((b) => b.text).join("\n").trim();
}

async function main() {
  const findings = collect(OUT);
  let md;
  if (findings.length === 0) {
    md = "### 🤖 AI triage\n\nNo Semgrep/Trivy findings to triage. ✅";
  } else {
    const body = await callClaude(buildPrompt(findings));
    md = `### 🤖 AI triage (${findings.length} findings, model: ${MODEL})\n\n${body}`;
  }
  writeFileSync(`${OUT}/ai-triage.md`, md);
  console.log(md);
}

function selfTest() {
  const dir = process.env.TMPDIR || "/tmp";
  const d = `${dir}/aitriage-selftest-${process.pid}`;
  mkdirSync(d, { recursive: true });
  writeFileSync(`${d}/semgrep.json`, JSON.stringify({ results: [
    { check_id: "x", path: "app/server.js", start: { line: 17 }, extra: { severity: "ERROR", message: "cmd injection" } },
  ] }));
  writeFileSync(`${d}/trivy-fs.json`, JSON.stringify({ Results: [
    { Vulnerabilities: [{ VulnerabilityID: "CVE-1", PkgName: "minimist", InstalledVersion: "1.2.0", Severity: "CRITICAL", Title: "proto pollution" }] },
  ] }));
  const f = collect(d);
  if (f.length !== 2) throw new Error(`expected 2 findings, got ${f.length}`);
  if (f[0].severity !== "CRITICAL") throw new Error(`expected CRITICAL first, got ${f[0].severity}`);
  if (!buildPrompt(f).includes("CVE-1")) throw new Error("prompt missing finding");
  console.log("self-test OK");
}

if (process.argv.includes("--self-test")) selfTest();
else main().catch((e) => { console.error(e.message); process.exit(1); });
