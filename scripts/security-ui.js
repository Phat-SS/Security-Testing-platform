#!/usr/bin/env node
// Convenience launcher for `npm run security:ui` — starts the platform web UI
// (app.api.main) in the project's .venv and opens it in the browser, so you
// don't have to activate the venv / retype the uvicorn command / open
// localhost by hand every time.
"use strict";

const { spawn, spawnSync } = require("node:child_process");
const fs = require("node:fs");
const path = require("node:path");

const root = path.join(__dirname, "..");
const isWin = process.platform === "win32";
const venvPython = path.join(root, ".venv", isWin ? "Scripts" : "bin", isWin ? "python.exe" : "python");
const python = fs.existsSync(venvPython) ? venvPython : "python";

const port = process.env.SECURITY_UI_PORT || "8100";
const url = `http://127.0.0.1:${port}`;

// Minimal .env parser — no dependency, just KEY=VALUE lines. Real shell/CI env
// vars always win over the file, matching standard dotenv precedence.
function loadDotenv(file) {
  if (!fs.existsSync(file)) return {};
  const vars = {};
  for (const line of fs.readFileSync(file, "utf8").split("\n")) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const eq = trimmed.indexOf("=");
    if (eq === -1) continue;
    const key = trimmed.slice(0, eq).trim();
    let value = trimmed.slice(eq + 1).trim();
    if (
      (value.startsWith('"') && value.endsWith('"')) ||
      (value.startsWith("'") && value.endsWith("'"))
    ) {
      value = value.slice(1, -1);
    }
    if (key) vars[key] = value;
  }
  return vars;
}

const env = {
  ...loadDotenv(path.join(root, ".env")),
  ...process.env,
  ENGAGEMENT_CONFIG: process.env.ENGAGEMENT_CONFIG || path.join("config", "engagement.json"),
};

function checkDeps() {
  const res = spawnSync(python, ["-c", "import fastapi, uvicorn"], { cwd: root });
  return res.status === 0;
}

function openBrowser(target) {
  try {
    if (isWin) {
      spawn("cmd", ["/c", "start", "", target], { stdio: "ignore", detached: true }).unref();
    } else if (process.platform === "darwin") {
      spawn("open", [target], { stdio: "ignore", detached: true }).unref();
    } else {
      spawn("xdg-open", [target], { stdio: "ignore", detached: true }).unref();
    }
  } catch {
    // best-effort only — not fatal if the browser doesn't auto-open
  }
}

if (!fs.existsSync(venvPython)) {
  console.warn(`[security:ui] no venv found at ${venvPython} — falling back to "python" on PATH.`);
}

if (!checkDeps()) {
  const pip = path.join(root, ".venv", isWin ? "Scripts" : "bin", isWin ? "pip.exe" : "pip");
  console.error(`[security:ui] fastapi/uvicorn not importable with ${python}.`);
  console.error(`Run:  ${fs.existsSync(pip) ? pip : "pip"} install -r requirements.txt`);
  process.exit(1);
}

console.log(`[security:ui] starting the platform at ${url} (python: ${python})`);
if (!fs.existsSync(path.join(root, env.ENGAGEMENT_CONFIG))) {
  console.log(`[security:ui] no ${env.ENGAGEMENT_CONFIG} yet — execution stays disabled until you add`);
  console.log("               a target via the Environments page (or copy config/engagement.example.json).");
}

const server = spawn(python, ["-m", "uvicorn", "app.api.main:app", "--port", port, "--reload"], {
  cwd: root,
  env,
  stdio: "inherit",
});

setTimeout(() => openBrowser(url), 1500);

server.on("exit", (code) => process.exit(code ?? 0));
