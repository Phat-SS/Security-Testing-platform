#!/usr/bin/env node
// Pull the Atlassian MCP OAuth access token out of the mcp-remote cache and
// write it into .env, so `npm run security:ui` talks to real Jira instead of
// the offline mock.
//
// Why this exists: Atlassian's MCP access tokens are short-lived (~1h), so
// hand-copying the token out of ~/.mcp-auth after every expiry gets old fast.
// Re-run this whenever imports start failing over to the mock.
//
// Prereq: authorize once with
//   npx -y mcp-remote https://mcp.atlassian.com/v1/mcp
"use strict";

const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const root = path.join(__dirname, "..");
const envPath = path.join(root, ".env");
const MCP_URL = process.env.JIRA_MCP_URL || "https://mcp.atlassian.com/v1/mcp";

function die(msg) {
  console.error(`[jira:token] ${msg}`);
  process.exit(1);
}

// Find every *_tokens.json under ~/.mcp-auth/mcp-remote-*/ and take the newest.
// Keying off mtime rather than the server-URL hash keeps this working across
// mcp-remote versions, which have changed both the hash input and the filename.
function findTokenFiles() {
  const base = path.join(os.homedir(), ".mcp-auth");
  if (!fs.existsSync(base)) return [];
  const out = [];
  for (const dir of fs.readdirSync(base)) {
    const full = path.join(base, dir);
    if (!fs.statSync(full).isDirectory()) continue;
    for (const f of fs.readdirSync(full)) {
      if (!f.endsWith("_tokens.json")) continue;
      const p = path.join(full, f);
      out.push({ path: p, mtime: fs.statSync(p).mtimeMs });
    }
  }
  return out.sort((a, b) => b.mtime - a.mtime);
}

const files = findTokenFiles();
if (!files.length) {
  die(
    `no cached token found under ${path.join(os.homedir(), ".mcp-auth")}\n` +
      `           Authorize first:  npx -y mcp-remote ${MCP_URL}`
  );
}

const newest = files[0];
let token;
try {
  token = JSON.parse(fs.readFileSync(newest.path, "utf8")).access_token;
} catch (e) {
  die(`could not parse ${newest.path}: ${e.message}`);
}
if (!token) die(`${newest.path} has no access_token field`);

// Age matters more than the file's own expires_in, which is relative to when
// the token was issued, not to now.
const ageMin = Math.round((Date.now() - newest.mtime) / 60000);

// Rewrite in place: replace the line whether it is currently commented or not,
// so repeat runs stay idempotent instead of stacking duplicate keys.
let env = fs.readFileSync(envPath, "utf8");
function setKey(key, value) {
  const re = new RegExp(`^#?\s*${key}=.*$`, "m");
  const line = `${key}=${value}`;
  env = re.test(env) ? env.replace(re, line) : env.replace(/\n*$/, `\n${line}\n`);
}
setKey("JIRA_MCP_URL", MCP_URL);
setKey("JIRA_MCP_TOKEN", token);
fs.writeFileSync(envPath, env);

const masked = `${token.slice(0, 6)}…${token.slice(-4)} (${token.length} chars)`;
console.log(`[jira:token] source: ${newest.path}`);
console.log(`[jira:token] token:  ${masked}, cached ${ageMin} min ago`);
if (ageMin > 55) {
  console.warn(`[jira:token] WARNING: likely expired (Atlassian tokens last ~60 min).`);
  console.warn(`[jira:token]          Re-run: npx -y mcp-remote ${MCP_URL}`);
}
console.log(`[jira:token] wrote JIRA_MCP_URL + JIRA_MCP_TOKEN to .env — mock is now OFF.`);
