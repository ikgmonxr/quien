const express = require("express");
const cors = require("cors");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json({ limit: "8mb" }));
app.use(express.static(path.join(__dirname, "public")));

// ==================== LÓGICA DARKBOT ====================

const DETECT_RULES = [
  [/This file was protected with MoonSec V3/i, "MoonSec V3", 0.98],
  [/MoonSec V3/i, "MoonSec V3", 0.92],
  [/\bluraph\b|LPH_|Luraph/i, "Luraph", 0.95],
  [/IronBrew|IB2_|ironbrew/i, "IronBrew", 0.93],
  [/newproxy\s*,\s*.*metatable.*select/i, "Prometheus", 0.90],
  [/\bPrometheus\b/i, "Prometheus", 0.88],
  [/WeAreDevs|WRD_/i, "WeAreDevs", 0.90],
  [/PSUObfuscator|\bPSU\b/i, "PSU", 0.87],
  [/luaobfuscator\.com|v0=string\.char;local v1=string\.byte/i, "LuaObfuscator.com", 0.90],
  [/return\s+[A-Za-z0-9_]+\([0-9A-Za-z_]+\(\)\s*,/i, "IronBrew 2", 0.85],
  [/loadstring\s*\(\s*game:HttpGet/i, "HttpGet Loader", 0.80],
  [/getfenv\s*\(|setfenv\s*\(/i, "Env Manipulation", 0.70],
  [/string\.char\s*\(\s*\d+/i, "String Char Encoding", 0.65],
];

function detectObfuscator(code) {
  const found = {};
  for (const [regex, name, score] of DETECT_RULES) {
    if (regex.test(code)) {
      if (!found[name] || score > found[name]) found[name] = score;
    }
  }
  const ordered = Object.entries(found).sort((a, b) => b[1] - a[1]);
  return ordered.length ? ordered : [["Clean / Unknown", 0.4]];
}

function extractStrings(code, minLen = 4) {
  const strings = [];
  const strRegex = /(["'])(?:\\.|[^\\])*?\1/g;
  let m;
  while ((m = strRegex.exec(code)) !== null) {
    const s = m[0].slice(1, -1);
    if (s.length >= minLen && s.trim()) strings.push(s);
  }
  const longRegex = /\[\[(.*?)\]\]/gs;
  while ((m = longRegex.exec(code)) !== null) {
    if (m[1].length >= minLen) strings.push(m[1]);
  }
  const charRegex = /string\.char\s*\(([\d\s,]+)\)/g;
  while ((m = charRegex.exec(code)) !== null) {
    try {
      const nums = m[1]
        .split(",")
        .map((x) => parseInt(x.trim()))
        .filter((n) => !isNaN(n) && n >= 0 && n <= 255);
      const decoded = String.fromCharCode(...nums);
      if (decoded.length >= minLen) strings.push(decoded);
    } catch {}
  }
  return strings;
}

function extractInteresting(code) {
  const urls = [...new Set(code.match(/https?:\/\/[^\s'"\)\]]+/g) || [])];
  const httpgets = [];
  const httpRegex = /HttpGet\s*\(\s*['"]([^'"]+)['"]/gi;
  let m;
  while ((m = httpRegex.exec(code)) !== null) httpgets.push(m[1]);

  const keys = [];
  const keyRegex = /["']([a-f0-9]{16,}|[A-Za-z0-9_\-]{20,})["']/g;
  while ((m = keyRegex.exec(code)) !== null) keys.push(m[1]);

  return {
    urls,
    httpgets: [...new Set(httpgets)],
    keys: [...new Set(keys)],
  };
}

function basicBeautify(code) {
  code = code.replace(/--\[\[.*?\]\]/gs, "");
  code = code.replace(/--[^\n]*/g, "");
  code = code.replace(/[ \t]+/g, " ");
  code = code.replace(/\n{3,}/g, "\n\n");
  return code.trim();
}

function advancedCleanup(code) {
  // Quitar header MoonSec
  code = code.replace(
    /\(\[\[This file was protected with MoonSec V3.*?\]\]\):gsub\(.*?function\(.*?end\)/gis,
    ""
  );
  code = code.replace(/This file was protected with MoonSec V3[^\n]*/gi, "");

  // Quitar comentarios
  code = code.replace(/--\[\[.*?\]\]/gs, "");
  code = code.replace(/--[^\n]*/g, "");

  // Intentar decodificar string.char simples
  code = code.replace(/string\.char\s*\(([\d\s,]+)\)/g, (match, nums) => {
    try {
      const chars = nums
        .split(",")
        .map((x) => parseInt(x.trim()))
        .filter((n) => !isNaN(n) && n >= 32 && n <= 126);
      if (chars.length > 2) {
        return `"${String.fromCharCode(...chars)}"`;
      }
    } catch {}
    return match;
  });

  // Limpiar espacios
  code = code.replace(/[ \t]+/g, " ");
  code = code.replace(/\n{3,}/g, "\n\n");
  code = code.replace(/;\s*;/g, ";");

  return code.trim();
}

// ==================== ENDPOINTS ====================

app.post("/api/detect", (req, res) => {
  const { code } = req.body;
  if (!code) return res.status(400).json({ error: "No code provided" });
  const detected = detectObfuscator(code);
  res.json({ detected });
});

app.post("/api/dump", (req, res) => {
  const { code } = req.body;
  if (!code) return res.status(400).json({ error: "No code provided" });

  const detected = detectObfuscator(code);
  const strings = extractStrings(code, 4);
  const interesting = extractInteresting(code);

  let out = [];
  out.push("-- ══════════════════════════════════════");
  out.push("-- QyrexApi · Advanced Dump");
  out.push("-- Engine based on DarkBot");
  out.push("-- ══════════════════════════════════════\n");
  out.push(`-- Detected: ${detected[0][0]} (${Math.round(detected[0][1] * 100)}%)`);
  out.push(`-- Total strings: ${strings.length}`);
  out.push(`-- URLs found: ${interesting.urls.length}`);
  out.push(`-- Possible keys: ${interesting.keys.length}\n`);

  if (interesting.urls.length) {
    out.push("-- === URLs ===");
    interesting.urls.slice(0, 40).forEach((u) => out.push("-- " + u));
    out.push("");
  }
  if (interesting.httpgets.length) {
    out.push("-- === HttpGet ===");
    interesting.httpgets.slice(0, 20).forEach((h) => out.push("-- " + h));
    out.push("");
  }
  if (interesting.keys.length) {
    out.push("-- === Possible Keys / Tokens ===");
    interesting.keys.slice(0, 30).forEach((k) => out.push("-- " + k));
    out.push("");
  }

  out.push("-- === STRING DUMP ===");
  const seen = new Set();
  let count = 0;
  strings.sort((a, b) => b.length - a.length);
  for (const s of strings) {
    const s2 = s.trim();
    if (s2.length < 4 || seen.has(s2)) continue;
    if (/^[\d\s,\.]+$/.test(s2)) continue;
    seen.add(s2);
    count++;
    out.push(`[${String(count).padStart(3, "0")}] ${s2.slice(0, 220)}`);
    if (count >= 300) break;
  }
  out.push(`\n-- Dump finished · ${count} unique strings`);

  res.json({
    detected: detected[0],
    result: out.join("\n"),
  });
});

app.post("/api/cleanup", (req, res) => {
  const { code } = req.body;
  if (!code) return res.status(400).json({ error: "No code provided" });
  const cleaned = basicBeautify(code);
  res.json({ result: cleaned || "-- Empty after cleanup" });
});

app.post("/api/deobfuscate", (req, res) => {
  const { code } = req.body;
  if (!code) return res.status(400).json({ error: "No code provided" });

  const detected = detectObfuscator(code);
  const cleaned = advancedCleanup(code);

  res.json({
    detected: detected[0],
    result: cleaned || "-- No se pudo limpiar el código",
    note: "Esto es una limpieza avanzada + beautify. No es un desofuscador completo de MoonSec/Luraph.",
  });
});

app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.listen(PORT, () => {
  console.log(`QyrexApi running on port ${PORT}`);
});
