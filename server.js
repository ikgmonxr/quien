'use strict';

/*
 * Qyrex Deobfuscator Fusion — single-file backend
 * Node 20+ / zero runtime dependencies beyond express.
 *
 * Design goal: safely analyze/recover Lua/Luau source without executing the
 * uploaded script. The implementation combines the useful static-analysis
 * ideas from the bundled Prometheus/envlog and LPH-style analyzers:
 * - wrapper / VM family detection
 * - string-table recovery
 * - base64 + hex payload recovery
 * - XOR candidate probing
 * - constant/opcode/function extraction
 * - common Lua string-table substitutions
 * - source cleanup / normalization
 * - fusion scoring and best-candidate selection
 */

const express = require('express');
const crypto = require('crypto');
const path = require('path');

const app = express();
const PORT = Number(process.env.PORT || 8787);
const HOST = process.env.HOST || '0.0.0.0';
const MAX_SCRIPT_CHARS = Number(process.env.MAX_SCRIPT_CHARS || 5_000_000);
const MAX_BODY = process.env.MAX_BODY || '12mb';
const RATE_LIMIT = Number(process.env.RATE_LIMIT || 20);
const RATE_WINDOW_MS = 60_000;
const MAX_CONCURRENT = Number(process.env.MAX_CONCURRENT || 4);
const MAX_ANALYSIS_TIME = Number(process.env.MAX_ANALYSIS_TIME_MS || 25_000);
const VERSION = '2.0.0-fusion';

let activeJobs = 0;
const buckets = new Map();

app.disable('x-powered-by');
app.set('trust proxy', 1);
app.use(express.json({ limit: MAX_BODY, strict: true }));

function ipOf(req) {
  return String(req.headers['x-forwarded-for'] || req.ip || 'unknown').split(',')[0].trim();
}

app.use((req, res, next) => {
  const now = Date.now();
  for (const [ip, item] of buckets) if (item.reset <= now) buckets.delete(ip);
  const ip = ipOf(req);
  const item = buckets.get(ip) || { count: 0, reset: now + RATE_WINDOW_MS };
  item.count++;
  buckets.set(ip, item);
  if (item.count > RATE_LIMIT) {
    res.set('Retry-After', String(Math.max(1, Math.ceil((item.reset - now) / 1000))));
    return res.status(429).json({ ok: false, error: 'Rate limit exceeded.' });
  }
  next();
});

app.use((req, res, next) => {
  const allowed = String(process.env.ALLOWED_ORIGINS || '*').split(',').map(s => s.trim()).filter(Boolean);
  const origin = req.headers.origin;
  if (allowed.includes('*')) res.set('Access-Control-Allow-Origin', '*');
  else if (origin && allowed.includes(origin)) { res.set('Access-Control-Allow-Origin', origin); res.set('Vary', 'Origin'); }
  res.set('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.set('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

const OPCODES = {
  0:'NOP',1:'LOADK',2:'LOADBOOL',3:'LOADNIL',4:'GETUPVAL',5:'GETGLOBAL',6:'GETTABLE',7:'SETGLOBAL',8:'SETUPVAL',9:'SETTABLE',
  10:'NEWTABLE',11:'SELF',12:'ADD',13:'SUB',14:'MUL',15:'DIV',16:'MOD',17:'POW',18:'UNM',19:'NOT',20:'LEN',21:'CONCAT',
  22:'JMP',23:'EQ',24:'LT',25:'LE',26:'TEST',27:'TESTSET',28:'CALL',29:'TAILCALL',30:'RETURN',31:'FORLOOP',32:'FORPREP',
  33:'TFORLOOP',34:'SETLIST',35:'CLOSURE',36:'VARARG',37:'EXTRAARG'
};

const rx = {
  promWrapper: /return\s*\(\s*function\s*\(\s*\.\.\.\s*\)/i,
  promStringTable: /local\s+([A-Za-z_]\w*)\s*=\s*\{\s*["'`\\]/i,
  promReverse: /for\s+\w+\s*,\s*\w+\s+in\s+ipairs\s*\(/i,
  watermark: /_WATERMARK\s*=|prometheus/i,
  lph: /(?:Luraph\s+Obfuscator|LPH_[A-Za-z0-9_]+|anti[-_ ]?tamper)/i,
  vm: /(?:opcode|bytecode|dispatch|handler|vm_?loop|instruction)/i,
  localFn: /\blocal\s+function\s+([A-Za-z_]\w*)\s*\(([^)]*)\)/g,
  globalFn: /\bfunction\s+([A-Za-z_]\w*)\s*\(([^)]*)\)/g,
  localAssign: /\blocal\s+([A-Za-z_]\w*)\s*=\s*([^\n;]+)/g,
  hexByte: /0x([0-9a-f]{2})/gi,
  quoted: /(['"])((?:\\.|(?!\1)[\s\S])*?)\1/g,
  longB64: /['"]([A-Za-z0-9+/_=-]{80,})['"]/g,
  b64Call: /(?:base64|b64)[._]?(?:decode|dec)\s*\(/i,
  xor: /(?:bit32\.)?bxor|xor|XOR/i,
  key: /\b(?:key|xorKey|xorkey|cryptKey|decryptKey|KEY|K)\b\s*=\s*(0x[0-9a-f]+|\d+)/g,
  indexedString: /\[\s*(\d+)\s*\]\s*=\s*(["'])(.*?)\2/g,
  indexedConst: /\[\s*(\d+)\s*\]\s*=\s*([^,}\n]+)/g,
  opcodeIf: /(?:if|elseif)\s+(?:opcode|op)\s*==\s*(\d+)\s+then/gi,
  numericHex: /\b0x[0-9a-f]+\b/gi,
  commentLine: /--[^\n]*/g,
  commentBlock: /--\[\[[\s\S]*?\]\]/g
};

function safeStr(s) { return String(s).replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/\r/g,'\\r').replace(/\n/g,'\\n'); }
function clamp(s, n=1_000_000) { s = String(s ?? ''); return s.length > n ? s.slice(0, n) + '\n-- [QYREX OUTPUT TRUNCATED]' : s; }
function sha(s) { return crypto.createHash('sha256').update(s).digest('hex'); }

function normalizeLineEndings(source) { return String(source).replace(/\r\n?/g, '\n').replace(/\uFEFF/g, ''); }

function decodeB64(str) {
  try {
    let s = str.replace(/[-_]/g, m => m === '-' ? '+' : '/').replace(/\s+/g, '');
    while (s.length % 4) s += '=';
    return Buffer.from(s, 'base64');
  } catch { return Buffer.alloc(0); }
}

function printableScore(buf) {
  if (!buf?.length) return 0;
  const n = Math.min(buf.length, 4000);
  let p = 0;
  for (let i=0;i<n;i++) { const b=buf[i]; if ((b>=32 && b<=126) || b===9 || b===10 || b===13) p++; }
  return p/n;
}

function luaScore(text) {
  if (!text) return -Infinity;
  let score = 0;
  if (/\b(function|local|return|if|then|end|for|while|do)\b/.test(text)) score += 18;
  if (/\b(game|workspace|Players|Instance|Vector3|CFrame|task|table|string|math)\b/.test(text)) score += 8;
  if (/--\[\[/.test(text)) score += 2;
  if (/[^\x00-\x08\x0B\x0E-\x1F\x7F]/.test(text)) score += 4;
  score += Math.min(20, printableScore(Buffer.from(text)) * 20);
  return score;
}

function xorTransform(buf, key, mode) {
  const out = Buffer.allocUnsafe(buf.length);
  let state = key >>> 0;
  for (let i=0;i<buf.length;i++) {
    let k;
    if (mode === 0) k = (key >>> ((i % 4) * 8)) & 255;
    else if (mode === 1) k = (key + i) & 255;
    else if (mode === 2) { state = Math.imul(state, 1103515245) + 12345 | 0; k = state & 255; }
    else k = ((key >>> ((i % 4) * 8)) + i + ((i * 31) & 255)) & 255;
    out[i] = buf[i] ^ k;
  }
  return out;
}

function candidateKeys(source) {
  const keys = new Set([0xDEADBEEF, 0x1337, 0xC0FFEE, 0x5A5A5A5A, 0xA5A5A5A5]);
  let m;
  while ((m = rx.key.exec(source))) {
    const v = m[1];
    keys.add(v.toLowerCase().startsWith('0x') ? parseInt(v,16) : Number(v));
  }
  for (const v of [0,1,255,256,0xFFFFFFFF]) keys.add(v);
  return [...keys].filter(Number.isFinite).slice(0, 24);
}

function extractPayloads(source) {
  const payloads = [];
  for (const m of source.matchAll(rx.longB64)) {
    const b = decodeB64(m[1]);
    if (b.length >= 24) payloads.push({ kind:'base64', data:b, raw:m[1].slice(0,100) });
  }
  const hexes = [];
  for (const m of source.matchAll(/\{([^{}]{20,})\}/g)) {
    const bytes = [...m[1].matchAll(rx.hexByte)].map(x=>parseInt(x[1],16));
    if (bytes.length >= 12) hexes.push(Buffer.from(bytes));
  }
  for (const b of hexes.slice(0,12)) payloads.push({ kind:'hex', data:b, raw:'hex-table' });
  return payloads.slice(0, 20);
}

function extractTables(source) {
  const strings = new Map();
  const constants = new Map();
  for (const m of source.matchAll(rx.indexedString)) strings.set(Number(m[1]), m[3]);
  for (const m of source.matchAll(rx.indexedConst)) {
    const raw = m[2].trim();
    if (strings.has(Number(m[1]))) continue;
    constants.set(Number(m[1]), raw);
  }
  // Capture simple direct table literals: local t = { "a", "b", ... }
  const tableRx = /\blocal\s+([A-Za-z_]\w*)\s*=\s*\{([\s\S]{0,200000})\}/g;
  const named = [];
  for (const m of source.matchAll(tableRx)) {
    const items = [...m[2].matchAll(/(?:^|,)\s*(["'])(.*?)\1/g)].map(x=>x[2]);
    if (items.length >= 2) named.push({ name:m[1], items:items.slice(0,5000) });
  }
  return { strings, constants, namedTables:named };
}

function extractFunctions(source) {
  const f = new Map();
  for (const m of source.matchAll(rx.localFn)) f.set(m[1], { type:'local', params:m[2].trim() });
  for (const m of source.matchAll(rx.globalFn)) if (!f.has(m[1])) f.set(m[1], { type:'global', params:m[2].trim() });
  return f;
}

function extractOpcodes(source) {
  const set = new Map();
  for (const m of source.matchAll(rx.opcodeIf)) { const n=Number(m[1]); set.set(n, OPCODES[n] || `OP_${n}`); }
  return set;
}

function detect(source) {
  const head = source.slice(0, 30000);
  const scores = { prometheus:0, envlog:0, 'legacy-lph':0 };
  if (rx.promWrapper.test(head)) scores.prometheus += 5;
  if (rx.promStringTable.test(head)) scores.prometheus += 2;
  if (rx.promReverse.test(head)) scores.prometheus += 2;
  if (rx.watermark.test(head)) scores.prometheus += 2;
  if (rx.lph.test(head)) scores['legacy-lph'] += 6;
  if (rx.xor.test(head)) scores['legacy-lph'] += 2;
  if (rx.vm.test(head)) { scores.envlog += 2; scores['legacy-lph'] += 1; }
  if (/@?\w+\s*=\s*getfenv\s*\(/.test(head) || /@lune|@luau|apidump/i.test(head)) scores.envlog += 3;
  if (/return\s*function|pcall\s*\(\s*function/i.test(head)) scores.envlog += 1;
  const engine = Object.entries(scores).sort((a,b)=>b[1]-a[1])[0][0];
  return { engine, scores, confidence: Math.min(99, Math.max(20, Object.values(scores).sort((a,b)=>b-a)[0] * 11)) };
}

function substituteIndexedStrings(source, tables) {
  let out = source;
  const candidates = [...tables.strings.entries()].sort((a,b)=>String(b[0]).length-String(a[0]).length);
  for (const [idx, val] of candidates) {
    const escaped = safeStr(val);
    const patterns = [
      new RegExp(`\\bSTR\\s*\\[\\s*${idx}\\s*\\]`, 'g'),
      new RegExp(`\\b(?:strings?|str|_ENV|_G)\\s*\\[\\s*${idx}\\s*\\]`, 'g')
    ];
    for (const p of patterns) out = out.replace(p, `"${escaped}"`);
  }
  return out;
}

function simplifySource(source) {
  let out = normalizeLineEndings(source);
  out = out.replace(rx.commentBlock, '');
  // Preserve useful comments while removing obvious generator banners.
  out = out.replace(/^\s*--\s*(?:PROMETHEUS|LURAPH|LPH|OBFUSCATOR).*$/gim, '');
  out = out.replace(/\n{4,}/g, '\n\n\n');
  return out.trim();
}

function recoverPayloads(source) {
  const payloads = extractPayloads(source);
  const keys = candidateKeys(source);
  const candidates = [];
  for (const p of payloads) {
    const direct = p.data.toString('utf8');
    candidates.push({ source:direct, score:luaScore(direct), label:`${p.kind}:raw` });
    if (p.data.length < 2_000_000) {
      for (const key of keys) for (let mode=0; mode<4; mode++) {
        const dec = xorTransform(p.data, key, mode);
        if (dec[0] === 0x1B && dec[1] === 0x4C && dec[2] === 0x75 && dec[3] === 0x61) {
          candidates.push({ source:dec.toString('utf8'), score:luaScore(dec.toString('utf8')) + 60, label:`${p.kind}:lua-bytecode:key=${key.toString(16)}:mode=${mode}` });
        }
        const text = dec.toString('utf8');
        const s = luaScore(text);
        if (s >= 30 && /\b(function|local|return|game|workspace)\b/.test(text)) candidates.push({ source:text, score:s+10, label:`${p.kind}:xor:key=${key.toString(16)}:mode=${mode}` });
      }
    }
  }
  candidates.sort((a,b)=>b.score-a.score);
  return candidates.slice(0, 8);
}

function inspect(source) {
  const tables = extractTables(source);
  const funcs = extractFunctions(source);
  const ops = extractOpcodes(source);
  const payloads = extractPayloads(source);
  const recovered = recoverPayloads(source);
  const names = [...source.matchAll(/\b[A-Za-z_][A-Za-z0-9_]{2,}\b/g)].map(m=>m[0]);
  const keywordCounts = {};
  for (const k of ['function','local','return','if','then','end','for','while','repeat','until','pcall','xpcall']) keywordCounts[k] = (source.match(new RegExp(`\\b${k}\\b`,'g')) || []).length;
  return { tables, funcs, ops, payloads, recovered, keywordCounts, names: [...new Set(names)].slice(0,2500) };
}

function buildAnalysisBanner(info, detection) {
  const lines = [
    '-- [[ QYREX FUSION DEOBFUSCATION REPORT ]]',
    `-- Engine: ${detection.engine}`,
    `-- Confidence: ${detection.confidence}%`,
    `-- String entries: ${info.tables.strings.size}`,
    `-- Constant entries: ${info.tables.constants.size}`,
    `-- Functions: ${info.funcs.size}`,
    `-- Opcode handlers: ${info.ops.size}`,
    `-- Encoded payloads: ${info.payloads.length}`,
    `-- Recovered payload candidates: ${info.recovered.length}`,
    '-- NOTE: Static analysis only; the submitted script was never executed.',
    ''
  ];
  return lines.join('\n');
}

function renderRecovered(info) {
  if (!info.recovered.length) return '';
  const best = info.recovered[0];
  const body = normalizeLineEndings(best.source).trim();
  if (!body) return '';
  return `-- [[ RECOVERED PAYLOAD: ${best.label} ]]\n${body}`;
}

function renderStaticReport(info) {
  const out=[];
  if (info.tables.strings.size) {
    out.push('-- [RECOVERED STRINGS]');
    for (const [i,v] of [...info.tables.strings.entries()].sort((a,b)=>a[0]-b[0]).slice(0,2000)) out.push(`local QYREX_STR_${i} = "${safeStr(v)}"`);
    out.push('');
  }
  if (info.tables.constants.size) {
    out.push('-- [RECOVERED CONSTANTS]');
    for (const [i,v] of [...info.tables.constants.entries()].sort((a,b)=>a[0]-b[0]).slice(0,2000)) out.push(`-- CONST_${i} = ${v}`);
    out.push('');
  }
  if (info.ops.size) {
    out.push('-- [VM OPCODES]');
    for (const [n,name] of [...info.ops.entries()].sort((a,b)=>a[0]-b[0])) out.push(`-- ${String(name).padEnd(14)} (${n})`);
    out.push('');
  }
  if (info.funcs.size) {
    out.push('-- [FUNCTIONS]');
    for (const [name,meta] of [...info.funcs.entries()].slice(0,2000)) out.push(`-- ${meta.type.padEnd(6)} ${name}(${meta.params})`);
    out.push('');
  }
  return out.join('\n');
}

function scoreCandidate(original, candidate) {
  const a = String(original);
  const b = String(candidate);
  if (!b) return -Infinity;
  let score = luaScore(b);
  if (b.length > 30) score += 8;
  if (b.length < a.length * 2) score += 4;
  if (/\bfunction\b/.test(b)) score += 5;
  if (/\breturn\b/.test(b)) score += 4;
  return score;
}

function deobfuscate(source, requested) {
  const started = Date.now();
  const normalized = normalizeLineEndings(source);
  const detection = detect(normalized);
  const info = inspect(normalized);
  let best = normalized;
  let mode = requested === 'auto' ? detection.engine : requested;
  const notes=[];

  const simplified = simplifySource(normalized);
  const withStrings = substituteIndexedStrings(simplified, info.tables);
  const recovered = renderRecovered(info);
  const staticReport = renderStaticReport(info);

  if (recovered) {
    const recoveredBody = recovered.replace(/^-- \[\[.*?\]\]\n/, '');
    if (scoreCandidate(normalized, recoveredBody) > scoreCandidate(normalized, best)) {
      best = recoveredBody;
      notes.push('Recovered encoded payload selected as best candidate.');
    }
  }

  if (mode === 'prometheus' || mode === 'fusion' || mode === detection.engine) {
    const transformed = substituteIndexedStrings(simplified, info.tables);
    if (scoreCandidate(normalized, transformed) >= scoreCandidate(normalized, best)) {
      best = transformed;
      if (info.tables.strings.size) notes.push('String-table substitutions applied.');
    }
  }

  // A single, stable output format: useful source first, report below.
  const report = buildAnalysisBanner(info, detection);
  const output = [report.trim(), best.trim(), staticReport.trim()].filter(Boolean).join('\n\n');

  const elapsed = Date.now() - started;
  if (elapsed > MAX_ANALYSIS_TIME) throw new Error('Analysis time budget exceeded.');
  return { output: clamp(output), mode, detected:detection, info, notes, elapsed };
}

function stats(input, output, meta) {
  const out = String(output || '');
  const tokensA = new Set((input.match(/[A-Za-z_]\w*/g) || []).slice(0, 50000));
  const tokensB = new Set((out.match(/[A-Za-z_]\w*/g) || []).slice(0, 50000));
  let shared=0; for (const t of tokensA) if (tokensB.has(t)) shared++;
  return {
    inputChars: input.length,
    outputChars: out.length,
    inputLines: input.split('\n').length,
    outputLines: out.split('\n').length,
    functions: meta.info.funcs.size,
    strings: meta.info.tables.strings.size,
    constants: meta.info.tables.constants.size,
    opcodes: meta.info.ops.size,
    payloads: meta.info.payloads.length,
    recoveredPayloads: meta.info.recovered.length,
    tokenOverlap: Math.round(shared / Math.max(1,tokensA.size) * 100),
    sha256: sha(input)
  };
}

app.get('/api/health', (_req,res)=>res.json({
  ok:true,
  name:'Qyrex Deobfuscator',
  version:VERSION,
  runtime:`Node ${process.versions.node}`,
  engines:['auto','fusion','prometheus','envlog','legacy-lph'],
  activeJobs,
  maxConcurrent:MAX_CONCURRENT,
  maxScriptChars:MAX_SCRIPT_CHARS,
  execution:'disabled',
  dependencies:'express only'
}));

app.post('/api/analyze', (req,res)=>{
  const source = typeof req.body?.script === 'string' ? req.body.script : '';
  if (!source.trim()) return res.status(400).json({ok:false,error:'No Lua/Luau source was supplied.'});
  if (source.length > MAX_SCRIPT_CHARS) return res.status(413).json({ok:false,error:`Script exceeds ${MAX_SCRIPT_CHARS.toLocaleString()} characters.`});
  try {
    const started=Date.now();
    const meta = deobfuscate(source, 'auto');
    return res.json({ok:true, detected:meta.detected, analysis:{strings:meta.info.tables.strings.size,constants:meta.info.tables.constants.size,functions:meta.info.funcs.size,opcodes:meta.info.ops.size,payloads:meta.info.payloads.length,recovered:meta.info.recovered.length},ms:Date.now()-started});
  } catch (e) { return res.status(422).json({ok:false,error:e.message || 'Analysis failed.'}); }
});

app.post('/api/deobfuscate', (req,res)=>{
  if (activeJobs >= MAX_CONCURRENT) return res.status(429).json({ok:false,error:'Server is busy. Try again shortly.'});
  const source = typeof req.body?.script === 'string' ? req.body.script : '';
  const requested = String(req.body?.engine || 'auto').toLowerCase();
  const valid = ['auto','fusion','prometheus','envlog','legacy-lph'];
  if (!source.trim()) return res.status(400).json({ok:false,error:'Paste or upload a Lua/Luau script first.'});
  if (source.length > MAX_SCRIPT_CHARS) return res.status(413).json({ok:false,error:`Script exceeds ${MAX_SCRIPT_CHARS.toLocaleString()} characters.`});
  if (!valid.includes(requested)) return res.status(400).json({ok:false,error:'Invalid engine.'});
  activeJobs++;
  try {
    const result = deobfuscate(source, requested === 'auto' ? 'fusion' : requested);
    result.output = clamp(result.output, MAX_SCRIPT_CHARS * 2);
    return res.json({
      ok:true,
      engine: requested === 'auto' ? `fusion:${result.detected.engine}` : requested,
      detected: result.detected,
      output: result.output,
      stats: stats(source,result.output,result),
      notes:result.notes,
      ms:result.elapsed
    });
  } catch (e) {
    console.error('[deobfuscate]',e);
    return res.status(422).json({ok:false,error:e.message || 'Deobfuscation failed.'});
  } finally { activeJobs--; }
});

app.use((req,res,next)=> {
  if (req.path.startsWith('/api/')) return next();
  if (req.method !== 'GET' && req.method !== 'HEAD') return next();
  res.sendFile(path.join(__dirname,'index.html'));
});

app.use((err,_req,res,_next)=>{
  if (err?.type === 'entity.too.large') return res.status(413).json({ok:false,error:'Request body too large.'});
  console.error('[server]',err);
  res.status(500).json({ok:false,error:'Internal server error.'});
});

app.listen(PORT,HOST,()=>console.log(`Qyrex Deobfuscator ${VERSION} listening on http://${HOST}:${PORT}`));
