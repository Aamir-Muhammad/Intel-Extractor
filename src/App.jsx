import { useState, useMemo, useRef, useEffect } from "react";
import * as XLSX from "xlsx";
import {
  Shield, Search, Download, Copy, Check, Loader2, Globe,
  ClipboardPaste, AlertTriangle, ShieldOff, Trash2, Wand2, FileDown,
  Tags, Crosshair, FileText, Linkedin, Github, X, Target, ShieldCheck, Sparkles, ChevronDown, RefreshCw
} from "lucide-react";

// ============================================================
//  Backend proxy
// ============================================================
const WORKER_BASE = "https://ioc-parser.aamirmuhd.workers.dev";

// ============================================================
//  Local IOC engine — refang + classify (fully client-side)
// ============================================================
const TYPE_COLORS = {
  IPV4: "#00e5ff", IPV6: "#22d3ee",
  DOMAIN: "#00ff9c", HOSTNAME: "#34d399",
  URL: "#7c9cff", EMAIL: "#c084fc",
  MD5: "#fbbf24", SHA1: "#fb923c", SHA256: "#ff4d6d", SHA512: "#ff2d78",
  SSDEEP: "#f472b6", IMPHASH: "#f59e0b",
  CVE: "#ff3b3b", BTC: "#f7931a", XMR: "#ff6600", ETH: "#8a92b2",
  ASN: "#2dd4bf", MAC_ADDRESS: "#a3e635",
  REGISTRY: "#e879f9", FILE: "#94a3b8", FILE_PATH: "#a5b4fc",
  MITRE_ATTACK: "#f43f5e", YARA: "#38bdf8",
};
const FALLBACK_PALETTE = ["#00e5ff","#00ff9c","#c084fc","#fbbf24","#ff4d6d","#2dd4bf","#a3e635","#7c9cff","#f59e0b","#e879f9"];
const colorFor = (cat) => {
  const key = String(cat).toUpperCase();
  if (TYPE_COLORS[key]) return TYPE_COLORS[key];
  let h = 0;
  for (let i = 0; i < key.length; i++) h = (h * 31 + key.charCodeAt(i)) >>> 0;
  return FALLBACK_PALETTE[h % FALLBACK_PALETTE.length];
};

const defang = (s) =>
  String(s)
    .replace(/https?/gi, (m) => (m.toLowerCase() === "https" ? "hxxps" : "hxxp"))
    .replace(/:\/\//g, "[://]")
    .replace(/\./g, "[.]")
    .replace(/@/g, "[@]");

const refangSoft = (s) =>
  String(s)
    .replace(/hxxps/gi, "https")
    .replace(/hxxp/gi, "http")
    .replace(/\[:\/\/\]|\[:\/\/|:\/\/\]/g, "://")
    .replace(/\[\/\/\]/g, "//")
    .replace(/\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)|\{dot\}/gi, ".")
    .replace(/\[@\]|\(@\)|\{@\}|\[at\]|\(at\)/gi, "@")
    .replace(/\[:\]/g, ":")
    .replace(/\[\/\]/g, "/")
    .replace(/[\u200B\u200C\u200D\uFEFF]/g, "");

const trimTok = (s) =>
  s.replace(/^[.,;:!?'"`(){}<>\u201c\u201d\u2018\u2019]+/, "")
   .replace(/[.,;:!?'"`(){}<>\u201c\u201d\u2018\u2019]+$/, "");

const stripScheme = (s) => refangSoft(String(s)).replace(/^\s*(?:https?|ftp):\/\//i, "");
const stripUrlArray = (arr) => {
  const out = [], seen = new Set();
  arr.forEach((u) => {
    const s = stripScheme(u);
    if (s && !seen.has(s.toLowerCase())) { seen.add(s.toLowerCase()); out.push(s); }
  });
  return out;
};

const FILE_EXT = /\.(exe|dll|sys|scr|pif|cpl|msi|msp|ps1|psm1|psd1|bat|cmd|vbs|vbe|js|jse|wsf|wsh|hta|sct|jar|py|pyc|pl|rb|elf|bin|deb|rpm|apk|dmg|lnk|inf|reg|iso|img|vhd|vmdk|ova|rar|7z|gz|tgz|bz2|xz|cab|ace|tar|txt|csv|tsv|xml|json|yaml|yml|eml|msg|pdf|rtf|docx?|docm|xlsx?|xlsm|xlsb|pptx?|pptm|odt|ods|odp|tmp|dat|log|db|sqlite|key|pem|crt|cer|p12|pfx|chm)$/i;

const isIPv4 = (t) => {
  const m = t.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  return m && m.slice(1).every((o) => +o >= 0 && +o <= 255);
};

// Registry helpers (your original)
const HIVE_FULL = {
  HKLM: "HKEY_LOCAL_MACHINE", HKCU: "HKEY_CURRENT_USER", HKCR: "HKEY_CLASSES_ROOT",
  HKU: "HKEY_USERS", HKCC: "HKEY_CURRENT_CONFIG",
};

const expandHive = (k) => {
  let s = String(k).trim()
    .replace(/^Registry::/i, "")
    .replace(/^(HKLM|HKCU|HKCR|HKU|HKCC|HKEY_[A-Za-z_]+):(?=\\|$)/i, "$1");
  const m = s.match(/^(HKLM|HKCU|HKCR|HKU|HKCC)(?=\\|$)/i);
  if (m) s = HIVE_FULL[m[1].toUpperCase()] + s.slice(m[1].length);
  s = s.replace(/^(hkey_[a-z_]+)/i, (h) => h.toUpperCase());
  return s.replace(/\\+$/, "");
};

const canonicalReg = (d) => {
  let s = d.key;
  if (d.valueName) s += "\\" + d.valueName;
  if (d.data !== undefined && d.data !== null && d.data !== "") s += " = " + d.data;
  if (d.valueType) s += " (" + String(d.valueType).toUpperCase() + ")";
  return s;
};

const unquote = (s) => String(s).replace(/^["']|["']$/g, "");

const REG_KEY_RE = /(?:HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKEY_CLASSES_ROOT|HKEY_USERS|HKEY_CURRENT_CONFIG|HKLM|HKCU|HKCR|HKCC|HKU):?\\(?:[^\s\\/:*?"<>|,;\r\n]+(?: [^\s\\/:*?"<>|,;\r\n]+){0,3}\\)*[^\s\\/:*?"<>|,;'"`)\]]+/gi;

const REG_ADD_RE = /\breg(?:\.exe)?\s+add\s+("[^"\r\n]+"|\S+)([^\r\n]*)/gi;

const PS_REG_RE = /\b(?:Set-ItemProperty|New-ItemProperty)\b([^\r\n]*)/gi;

const WIN_PATH_RE = /(?:[A-Za-z]:\\|\\\\[A-Za-z0-9._$-]{1,64}\\|%[A-Za-z_][A-Za-z0-9_]*%\\)(?:[^\s\\/:*?"<>|,;\r\n]+(?: [^\s\\/:*?"<>|,;\r\n]+){0,3}\\)*[^\\/:*?"<>|,;\r\n]{0,180}/g;

const NEW_ROOT_RE = /\s+(?:[A-Za-z]:\\|%[A-Za-z_][A-Za-z0-9_]*%\\|\\\\[A-Za-z0-9._$-])/;

const UNIX_PATH_RE = /(^|[\s"'`(>])(\/(?:usr|etc|var|tmp|opt|home|bin|sbin|lib|lib64|dev|proc|srv|root|boot|Users|Library|Applications|System|private)\/[^\s"'`<>|,;)]+)/g;

const cleanupWinPath = (raw) => {
  let s = raw.replace(/[\s.,;:!?)'"`\]]+$/, "");
  const nr = s.match(NEW_ROOT_RE);
  if (nr) s = s.slice(0, nr.index);
  s = s.replace(/[\s.,;:!?)'"`\]]+$/, "");
  const i = s.lastIndexOf("\\");
  if (i < 0) return null;
  let fin = s.slice(i + 1);
  if (/\s/.test(fin)) {
    const toks = fin.split(" ");
    let acc = "", best = null;
    for (let j = 0; j < toks.length; j++) {
      acc = acc ? acc + " " + toks[j] : toks[j];
      if (FILE_EXT.test(acc)) { best = acc; break; }
    }
    fin = best || toks[0];
    s = s.slice(0, i + 1) + fin;
  }
  s = s.replace(/[.,;:!?)'"`\]]+$/, "");
  if (s.length < 4) return null;
  if (/^[A-Za-z]:\\?$/.test(s)) return null;
  if (/^%[A-Za-z_]+%\\?$/.test(s)) return null;
  return s;
};

const maybeFileFromData = (v, files) => {
  const s = String(v);
  if (/^(?:[A-Za-z]:\\|\\\\|%[A-Za-z_][A-Za-z0-9_]*%\\)/.test(s)) {
    const c = cleanupWinPath(s);
    if (c) files.push(c);
  }
};

const extractStructured = (text) => {
  let work = text;
  const regs = [];
  const files = [];
  const blank = (m) => " ".repeat(m.length);

  work = work.replace(REG_ADD_RE, (m, keyRaw, rest) => {
    const key = expandHive(unquote(keyRaw));
    if (!/^HKEY_/i.test(key)) return m;
    const v = rest.match(/\/v\s+("[^"]*"|\S+)/i);
    const t = rest.match(/\/t\s+(\S+)/i);
    const d = rest.match(/\/d\s+("[^"]*"|\S+)/i);
    const det = {
      key,
      valueName: v ? unquote(v[1]) : undefined,
      valueType: t ? t[1] : undefined,
      data: d ? unquote(d[1]) : undefined,
    };
    regs.push(det);
    if (det.data) maybeFileFromData(det.data, files);
    return blank(m);
  });

  work = work.replace(PS_REG_RE, (m, rest) => {
    const p = rest.match(/-(?:Literal)?Path\s+("[^"]*"|'[^']*'|\S+)/i);
    if (!p) return m;
    let key = unquote(p[1]);
    if (!/^(Registry::)?(HKLM|HKCU|HKCR|HKU|HKCC|HKEY_)/i.test(key)) return m;
    key = expandHive(key);
    const n = rest.match(/-Name\s+("[^"]*"|'[^']*'|\S+)/i);
    const v = rest.match(/-Value\s+("[^"]*"|'[^']*'|\S+)/i);
    const t = rest.match(/-(?:PropertyType|Type)\s+(\S+)/i);
    const det = {
      key,
      valueName: n ? unquote(n[1]) : undefined,
      valueType: t ? t[1] : undefined,
      data: v ? unquote(v[1]) : undefined,
    };
    regs.push(det);
    if (det.data) maybeFileFromData(det.data, files);
    return blank(m);
  });

  {
    let rebuilt = "";
    let pos = 0;
    let mm;
    REG_KEY_RE.lastIndex = 0;
    while ((mm = REG_KEY_RE.exec(work))) {
      let keyStr = mm[0].replace(/[.,;:!?)'"`\]]+$/, "");
      let end = mm.index + keyStr.length;
      const ahead = work.slice(end, end + 260);
      const vm = ahead.match(/^\s*(?:=|→|->|:(?=\s))\s*("[^"\r\n]{1,200}"|'[^'\r\n]{1,200}'|[^\s,;"'<>|]{1,200})/);
      let det;
      if (vm) {
        const data = unquote(vm[1]).replace(/[.,;:!?]+$/, "");
        const full = expandHive(keyStr);
        const parts = full.split("\\");
        let key = full, valueName;
        if (parts.length > 2) { valueName = parts.pop(); key = parts.join("\\"); }
        det = { key, valueName, data };
        end += vm[0].length;
        maybeFileFromData(data, files);
      } else {
        det = { key: expandHive(keyStr) };
      }
      regs.push(det);
      rebuilt += work.slice(pos, mm.index) + " ";
      pos = end;
      REG_KEY_RE.lastIndex = end;
    }
    rebuilt += work.slice(pos);
    work = rebuilt;
  }

  {
    let rebuilt = "", pos = 0, mm;
    WIN_PATH_RE.lastIndex = 0;
    while ((mm = WIN_PATH_RE.exec(work))) {
      if (mm.index < pos) { WIN_PATH_RE.lastIndex = pos; continue; }
      const c = cleanupWinPath(mm[0]);
      if (c) {
        files.push(c);
        rebuilt += work.slice(pos, mm.index) + " ";
        pos = mm.index + c.length;
        WIN_PATH_RE.lastIndex = pos;
      }
    }
    rebuilt += work.slice(pos);
    work = rebuilt;
  }

  work = work.replace(UNIX_PATH_RE, (m, pre, path) => {
    const c = path.replace(/[.,;:!?)'"`\]]+$/, "");
    if (c.length > 4) { files.push(c); return pre + blank(path); }
    return m;
  });

  return { cleaned: work, regs, files };
};

const classify = (t) => {
  if (/^CVE-\d{4}-\d{4,7}$/i.test(t)) return ["CVE", t.toUpperCase()];
  if (/^T\d{4}(?:\.\d{3})?$/.test(t)) return ["MITRE_ATTACK", t.toUpperCase()];
  if (/^[A-Za-z0-9._%+-]+@([A-Za-z0-9-]+\.)+[A-Za-z]{2,}$/.test(t)) return ["EMAIL", t.toLowerCase()];
  if (/^(https?|ftp):\/\//i.test(t)) return ["URL", t];
  if (/^([a-z0-9-]+\.)+[a-z]{2,}(:\d+)?\/\S*/i.test(t)) return ["URL", t];
  if (/^\d{1,6}:[A-Za-z0-9/+]{4,}:[A-Za-z0-9/+]{4,}$/.test(t)) return ["SSDEEP", t];
  if (/^0x[a-fA-F0-9]{40}$/.test(t)) return ["ETH", t];
  if (/^[a-fA-F0-9]{32}$/.test(t)) return ["MD5", t.toLowerCase()];
  if (/^[a-fA-F0-9]{40}$/.test(t)) return ["SHA1", t.toLowerCase()];
  if (/^[a-fA-F0-9]{64}$/.test(t)) return ["SHA256", t.toLowerCase()];
  if (/^[a-fA-F0-9]{128}$/.test(t)) return ["SHA512", t.toLowerCase()];
  if (isIPv4(t)) return ["IPV4", t];
  if (/^([0-9a-f]{2}[:-]){5}[0-9a-f]{2}$/i.test(t)) return ["MAC_ADDRESS", t.toLowerCase()];
  if (/^(?:[0-9a-f]{1,4}:){2,7}[0-9a-f]{0,4}$/i.test(t) && (t.match(/:/g) || []).length >= 2) return ["IPV6", t.toLowerCase()];
  if (/^4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}(?:[1-9A-HJ-NP-Za-km-z]{11})?$/.test(t)) return ["XMR", t];
  if (/^(bc1[ac-hj-np-z02-9]{11,71}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})$/.test(t)) return ["BTC", t];
  if (/^ASN?\d{2,}$/i.test(t)) return ["ASN", t.toUpperCase().replace(/^ASN/, "AS")];
  if (/^(HKLM|HKCU|HKCR|HKU|HKCC|HKEY_[A-Z_]+)[\\/]/i.test(t)) return ["REGISTRY", t];
  if (/\\/.test(t)) return ["FILE_PATH", t];
  if (FILE_EXT.test(t)) return ["FILE", t];
  if (/^([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/i.test(t)) return ["DOMAIN", t.toLowerCase()];
  return null;
};

const ORDER = ["IPV4","IPV6","DOMAIN","URL","EMAIL","MD5","SHA1","SHA256","SHA512","SSDEEP","CVE","MITRE_ATTACK","YARA","ASN","MAC_ADDRESS","BTC","XMR","ETH","REGISTRY","FILE","FILE_PATH"];

const DISPLAY_PRIORITY = ["DOMAIN","URL","IPV4","IPV6","MD5","SHA1","SHA256","SHA512","SSDEEP","IMPHASH"];
const catRank = (cat) => {
  const p = DISPLAY_PRIORITY.indexOf(cat);
  if (p !== -1) return p;
  const o = ORDER.indexOf(cat);
  return o === -1 ? 999 : 100 + o;
};

const extractIocs = (text) => {
  const buckets = {};
  const add = (cat, val) => (buckets[cat] || (buckets[cat] = new Set())).add(val);
  const regDetails = [];
  const seenReg = new Set();
  const pushReg = (d) => {
    const c = canonicalReg(d);
    if (!seenReg.has(c)) { seenReg.add(c); regDetails.push(d); }
    add("REGISTRY", c);
  };

  let work = refangSoft(text);

  work = work.replace(/\[([^\]\n]+)\]\(([^)\n]*)\)/g, (_m, label) => {
    const t = trimTok(label.trim());
    if (t) {
      const r = classify(t);
      if (r) {
        if (r[0] === "REGISTRY") pushReg({ key: expandHive(r[1].replace(/\//g, "\\")) });
        else add(r[0], r[1]);
      }
    }
    return "\n";
  });

  const structured = extractStructured(work);
  work = structured.cleaned;
  structured.regs.forEach(pushReg);
  structured.files.forEach((f) => add("FILE_PATH", f));

  const segments = work.replace(/[\[\]]/g, "").split(/[\n\r;,|]+/);

  for (let seg of segments) {
    let s = seg
      .replace(/^[\s\-*•·\u2022>]+/, "")
      .replace(/^\d+[.)]\s+/, "")
      .replace(/^["'`]+|["'`]+$/g, "")
      .trim();
    if (!s) continue;

    const tokens = s.split(/[\s"'`<>]+/).map(trimTok).filter(Boolean);
    const hasOtherIoc = tokens.some((t) => { const r = classify(t); return r && r[0] !== "FILE" && r[0] !== "FILE_PATH"; });
    const extTokens = tokens.filter((t) => FILE_EXT.test(t));

    const spacedFilename =
      /\s/.test(s) && !s.includes("/") && !/:\/\//.test(s) && !s.includes("=") &&
      tokens.length <= 4 &&
      FILE_EXT.test(s) && !hasOtherIoc && extTokens.length === 1;

    if (spacedFilename) { add("FILE", s); continue; }

    for (const t of tokens) {
      const r = classify(t);
      if (!r) continue;
      if (r[0] === "REGISTRY") pushReg({ key: expandHive(r[1].replace(/\//g, "\\")) });
      else add(r[0], r[1]);
    }
  }

  const out = {};
  ORDER.forEach((k) => { if (buckets[k]) out[k] = Array.from(buckets[k]); });
  Object.keys(buckets).forEach((k) => { if (!out[k]) out[k] = Array.from(buckets[k]); });
  if (out.URL) out.URL = stripUrlArray(out.URL);
  return { data: out, registryDetails: regDetails };
};

const API_KEY_MAP = {
  "FILE_HASH_MD5": "MD5", "FILE_HASH_SHA1": "SHA1", "FILE_HASH_SHA256": "SHA256", "FILE_HASH_SHA512": "SHA512",
  "MITRE_ATT&CK": "MITRE_ATTACK", "BITCOIN_ADDRESS": "BTC", "EMAIL_ADDRESS": "EMAIL",
  "YARA_RULE": "YARA", "FILE_NAME": "FILE",
};
const normCat = (k) => {
  const u = String(k).toUpperCase().trim();
  return API_KEY_MAP[u] || u;
};

const API_SUPPORTED_CATS = new Set([
  "IPV4", "IPV6", "URL", "DOMAIN", "MD5", "SHA1", "SHA256", "EMAIL", "CVE", "MITRE_ATTACK", "YARA",
]);

const parseIocs = (raw) => {
  let d = raw;
  if (raw && typeof raw === "object" && raw.data && typeof raw.data === "object") d = raw.data;
  const out = {};
  if (d && typeof d === "object") {
    Object.entries(d).forEach(([k, v]) => {
      if (Array.isArray(v)) {
        const cat = normCat(k);
        const uniq = Array.from(new Set(v.map((x) => String(x).trim()).filter(Boolean)));
        if (uniq.length) out[cat] = Array.from(new Set([...(out[cat] || []), ...uniq]));
      }
    });
  }
  if (out.URL) out.URL = stripUrlArray(out.URL);
  return out;
};

const parseCanonicalReg = (s) => {
  let t = refangSoft(String(s)).trim();
  let valueType;
  const tm = t.match(/\((REG_[A-Z_0-9]+|DWORD|QWORD|SZ|EXPAND_SZ|MULTI_SZ|BINARY)\)\s*$/i);
  if (tm) { valueType = tm[1]; t = t.slice(0, tm.index).trim(); }
  const eq = t.indexOf(" = ");
  if (eq > 0) {
    const left = expandHive(t.slice(0, eq).trim());
    const data = t.slice(eq + 3).trim();
    const parts = left.split("\\");
    let key = left, valueName;
    if (parts.length > 2) { valueName = parts.pop(); key = parts.join("\\"); }
    return { key, valueName, valueType, data };
  }
  return { key: expandHive(t), valueType };
};

const CASE_SENSITIVE_CATS = new Set(["FILE", "FILE_PATH", "REGISTRY", "URL", "BTC", "XMR", "ETH", "SSDEEP"]);
const normVal = (cat, v) => (CASE_SENSITIVE_CATS.has(cat) ? v : String(v).toLowerCase());

const mergeIocs = (apiData, engData) => {
  const data = {};
  const origin = {};
  const maps = {};
  const put = (cat, v, src) => {
    if (!maps[cat]) { maps[cat] = new Map(); data[cat] = []; origin[cat] = {}; }
    const nk = normVal(cat, v);
    if (maps[cat].has(nk)) {
      const existing = maps[cat].get(nk);
      if (origin[cat][existing] !== src) origin[cat][existing] = "both";
    } else {
      maps[cat].set(nk, v);
      data[cat].push(v);
      origin[cat][v] = src;
    }
  };
  Object.entries(apiData).forEach(([c, arr]) => arr.forEach((v) => put(c, v, "api")));
  Object.entries(engData).forEach(([c, arr]) => arr.forEach((v) => put(c, v, "eng")));
  const ordered = {};
  ORDER.forEach((k) => { if (data[k]) ordered[k] = data[k]; });
  Object.keys(data).forEach((k) => { if (!ordered[k]) ordered[k] = data[k]; });
  return { data: ordered, origin };
};

const TAG_LABEL = { api: "API Parsed", eng: "Engine Parsed", both: "API + Engine Parsed" };

// Hunt queries (your original)
const uniqDetails = (details) => {
  const seen = new Set();
  return details.filter((d) => {
    const c = canonicalReg(d);
    if (seen.has(c)) return false;
    seen.add(c);
    return true;
  });
};
const stripHive = (k) => String(k).replace(/^HKEY_[A-Z_]+\\/i, "");
const kqlStr = (s) => `@"${String(s).replace(/"/g, '""')}"`;
const reEsc = (s) => String(s).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

const buildKQL = (details) => {
  const clauses = uniqDetails(details).map((d) => {
    const parts = [`RegistryKey has ${kqlStr(d.key)}`];
    if (d.valueName) parts.push(`RegistryValueName =~ "${String(d.valueName).replace(/"/g, '\\"')}"`);
    if (d.data !== undefined && d.data !== null && d.data !== "") parts.push(`RegistryValueData has ${kqlStr(d.data)}`);
    return parts.length > 1 ? `(${parts.join(" and ")})` : parts[0];
  });
  return `DeviceRegistryEvents
| where ActionType in ("RegistryValueSet", "RegistryKeyCreated")
| where ${clauses.join("\n    or ")}
| project Timestamp, DeviceName, ActionType, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName, InitiatingProcessCommandLine`;
};

const buildCQL = (details) => {
  const clauses = uniqDetails(details).map((d) => {
    const parts = [`RegObjectName=/(${reEsc(stripHive(d.key))})$/i`];
    if (d.valueName) parts.push(`RegValueName=/^(${reEsc(d.valueName)})$/i`);
    if (d.data !== undefined && d.data !== null && d.data !== "") parts.push(`RegStringValue=/^(${reEsc(d.data)})$/i`);
    return parts.length > 1 ? `(${parts.join(" and ")})` : parts[0];
  });
  const body = clauses.length > 1 ? clauses.map((c) => `(${c})`).join("\n   or ") : clauses[0];
  return `#event_simpleName=/^(AsepValueUpdate|RegGenericValueUpdate|RegSystemConfigValueUpdate)$/
| ${body}
| table([@timestamp, ComputerName, ImageFileName, RegObjectName, RegValueName, RegStringValue])`;
};

const buildSPL = (details) => {
  const clauses = uniqDetails(details).map((d) => {
    const to = `TargetObject="*\\${stripHive(d.key)}${d.valueName ? "\\" + d.valueName : "\\*"}"`;
    return (d.data !== undefined && d.data !== null && d.data !== "")
      ? `(${to} Details="${String(d.data)}")`
      : to;
  });
  return `index=* source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=13
    (${clauses.join("\n     OR ")})
| table _time, host, Image, TargetObject, Details`;
};

// Page scrape helpers
const extractArticleBody = (html) => {
  let h = html;
  h = h.replace(/<(script|style|noscript|iframe|svg|form|button|input|select|textarea|label)\b[\s\S]*?<\/\1>/gi, " ");
  h = h.replace(/<(nav|header|footer|aside|menu|menuitem)\b[\s\S]*?<\/\1>/gi, " ");
  h = h.replace(/<[^>]+(?:class|id)=["'][^"']*(?:cookie|consent|gdpr|banner|popup|modal|sidebar|widget|share|social|newsletter|subscribe|comment|ad-|advertisement|masthead|top-bar|site-header|site-footer|breadcrumb|pagination|related-post|recommended)[^"']*["'][^>]*>[\s\S]*?<\/[^>]+>/gi, " ");

  const articleMatch = h.match(/<article\b[^>]*>([\s\S]*?)<\/article>/i);
  if (articleMatch && articleMatch[1].length > 500) return htmlToText(articleMatch[1]);

  const mainMatch = h.match(/<main\b[^>]*>([\s\S]*?)<\/main>/i);
  if (mainMatch && mainMatch[1].length > 500) return htmlToText(mainMatch[1]);

  const roleMatch = h.match(/<[^>]+role=["'](?:main|article)["'][^>]*>([\s\S]*?)<\/[^>]+>/i);
  if (roleMatch && roleMatch[1].length > 500) return htmlToText(roleMatch[1]);

  return htmlToText(h);
};

const htmlToText = (html) =>
  html
    .replace(/<script[\s\S]*?<\/script>/gi, " ")
    .replace(/<style[\s\S]*?<\/style>/gi, " ")
    .replace(/<a\b[^>]*?href=["']([^"']+)["'][^>]*>([\s\S]*?)<\/a>/gi, " $2 $1 ")
    .replace(/<br\s*\/?>/gi, "\n")
    .replace(/<\/(td|th|tr|p|div|li|h[1-6]|pre|blockquote|section|table)>/gi, "\n")
    .replace(/<[^>]+>/g, " ")
    .replace(/&nbsp;/gi, " ").replace(/&amp;/gi, "&")
    .replace(/&lt;/gi, "<").replace(/&gt;/gi, ">")
    .replace(/&#0?39;|&apos;/gi, "'").replace(/&quot;/gi, '"')
    .replace(/&#92;|&bsol;/gi, "\\")
    .replace(/[ \t]+\n/g, "\n");

const SCRAPE_DENY = ["w3.org","schema.org","googleapis.com","gstatic.com","google.com","google-analytics.com","googletagmanager.com","doubleclick.net","facebook.com","twitter.com","x.com","t.co","linkedin.com","youtube.com","youtu.be","instagram.com","cloudflare.com","cloudfront.net","jsdelivr.net","cdnjs.com","fontawesome.com","wordpress.org","wp.com","gravatar.com","cookiebot.com","onetrust.com","gmpg.org","bit.ly","gist.github.com"];
const hostOf = (s) => {
  try { return new URL(s.includes("://") ? s : "http://" + s).hostname.toLowerCase(); }
  catch { return String(s).toLowerCase(); }
};
const filterScraped = (data, articleUrl) => {
  const self = hostOf(articleUrl);
  const deny = (h) => h === self || SCRAPE_DENY.some((d) => h === d || h.endsWith("." + d));
  const out = {};
  Object.entries(data).forEach(([k, arr]) => {
    let v = arr;
    if (k === "DOMAIN") v = arr.filter((x) => !deny(x));
    if (k === "URL") v = arr.filter((x) => !deny(hostOf(x)));
    if (v.length) out[k] = v;
  });
  return out;
};

// Export helpers (your original)
const csvCell = (v) => { const s = String(v ?? ""); return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s; };
const toCSV = (rows) => rows.map((r) => r.map(csvCell).join(",")).join("\n");
const downloadBlob = (blob, filename) => {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url; a.download = filename;
  document.body.appendChild(a); a.click(); document.body.removeChild(a);
  setTimeout(() => URL.revokeObjectURL(url), 1500);
};
const sanitizeSheet = (name, used) => {
  let n = String(name).replace(/[\\/?*[\]:]/g, "_").slice(0, 28) || "Sheet";
  let base = n, i = 1;
  while (used.has(n)) n = `${base}_${i++}`.slice(0, 31);
  used.add(n); return n;
};
const buildWorkbook = (sheets) => {
  const wb = XLSX.utils.book_new();
  const used = new Set();
  sheets.forEach(({ name, rows }) => {
    const ws = XLSX.utils.aoa_to_sheet(rows);
    XLSX.utils.book_append_sheet(wb, ws, sanitizeSheet(name, used));
  });
  const out = XLSX.write(wb, { bookType: "xlsx", type: "array" });
  return new Blob([out], { type: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" });
};

export default function App() {
  const [mode, setMode] = useState("url");
  const [url, setUrl] = useState("");
  const [jsonText, setJsonText] = useState("");
  const [rawText, setRawText] = useState("");
  const [iocData, setIocData] = useState(null);
  const [originData, setOriginData] = useState(null);
  const [registryDetails, setRegistryDetails] = useState([]);
  const [meta, setMeta] = useState(null);
  const [aiSummary, setAiSummary] = useState(null);
  const [aiState, setAiState] = useState("idle");
  const [aiOpen, setAiOpen] = useState(false);
  const [retryCount, setRetryCount] = useState(0);
  const [cooldown, setCooldown] = useState(0);
  const [sourceUrl, setSourceUrl] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [rawArticle, setRawArticle] = useState("");
  const [articleClean, setArticleClean] = useState("");
  const [defangMap, setDefangMap] = useState({});
  const [defangAll, setDefangAll] = useState(false);
  const [copied, setCopied] = useState("");
  const [showTags, setShowTags] = useState(() => {
    try { return localStorage.getItem("ioc_show_tags") === "1"; } catch { return false; }
  });
  const copyTimer = useRef(null);

  const toggleTags = () =>
    setShowTags((v) => {
      try { localStorage.setItem("ioc_show_tags", v ? "0" : "1"); } catch {}
      return !v;
    });

  const displayData = iocData;

  const entries = useMemo(
    () => (displayData ? Object.entries(displayData).sort((a, b) => catRank(a[0]) - catRank(b[0])) : []),
    [displayData]
  );
  const total = useMemo(() => entries.reduce((s, [, v]) => s + v.length, 0), [entries]);

  const visibleRegDetails = useMemo(() => {
    if (!registryDetails.length || !displayData?.REGISTRY) return [];
    const vis = new Set(displayData.REGISTRY);
    const seen = new Set();
    return registryDetails.filter((d) => {
      const c = canonicalReg(d);
      if (!vis.has(c) || seen.has(c)) return false;
      seen.add(c);
      return true;
    });
  }, [registryDetails, displayData]);

  const huntReadySet = useMemo(
    () => new Set(registryDetails.filter((d) => d.valueName || (d.data !== undefined && d.data !== null && d.data !== "")).map((d) => canonicalReg(d))),
    [registryDetails]
  );

  const catTag = (cat, arr) => {
    if (!originData?.[cat]) return null;
    let api = false, eng = false;
    arr.forEach((v) => {
      const o = originData[cat][v];
      if (o === "api") api = true;
      else if (o === "eng") eng = true;
      else if (o === "both") { api = true; eng = true; }
    });
    if (api && eng) return TAG_LABEL.both;
    if (api) return TAG_LABEL.api;
    if (eng) return TAG_LABEL.eng;
    return null;
  };
  const tagFor = (cat, v) => {
    const o = originData?.[cat]?.[v];
    return o ? TAG_LABEL[o] : "";
  };

  const proc = (arr, cat) => ((defangAll || defangMap[cat]) ? arr.map(defang) : arr);
  const toggleDefang = (cat) => setDefangMap((m) => ({ ...m, [cat]: !m[cat] }));

  const removeIoc = (cat, value) => {
    setIocData((prev) => {
      if (!prev?.[cat]) return prev;
      const arr = prev[cat].filter((v) => v !== value);
      const next = { ...prev };
      if (arr.length) next[cat] = arr;
      else delete next[cat];
      return next;
    });
    if (cat === "REGISTRY") {
      setRegistryDetails((prev) => prev.filter((d) => canonicalReg(d) !== value));
    }
  };

  const flash = (key) => {
    setCopied(key);
    clearTimeout(copyTimer.current);
    copyTimer.current = setTimeout(() => setCopied(""), 1300);
  };
  const copyText = async (text, key) => {
    try { await navigator.clipboard.writeText(text); flash(key); }
    catch {
      const ta = document.createElement("textarea");
      ta.value = text; ta.style.position = "fixed"; ta.style.opacity = "0";
      document.body.appendChild(ta); ta.select();
      try { document.execCommand("copy"); flash(key); } catch {}
      document.body.removeChild(ta);
    }
  };

  const resetResults = () => {
    setError(""); setIocData(null); setOriginData(null); setRegistryDetails([]);
    setMeta(null); setAiSummary(null); setAiState("idle"); setAiOpen(false);
    setRetryCount(0); setCooldown(0); setRawArticle(""); setArticleClean(""); setDefangAll(false);
  };

  const runFetch = async () => {
    resetResults();
    setLoading(true);

    const apiP = fetch(`${WORKER_BASE}/parse`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
    })
      .then((r) => { if (!r.ok) throw new Error(`API HTTP ${r.status}`); return r.json(); });

    const pageP = fetch(`${WORKER_BASE}/fetch?url=${encodeURIComponent(url)}`)
      .then((r) => { if (!r.ok) throw new Error(`page HTTP ${r.status}`); return r.text(); });

    const [aRes, pRes] = await Promise.allSettled([apiP, pageP]);

    const apiJson = aRes.status === "fulfilled" ? aRes.value : null;
    const apiData = apiJson ? (() => { const d = parseIocs(apiJson); return Object.keys(d).length ? d : null; })() : null;
    const apiMeta = apiJson && apiJson.meta && typeof apiJson.meta === "object" ? apiJson.meta : null;

    let engFull = null, engDetails = [], articleText = "", articleBody = "";
    if (pRes.status === "fulfilled" && pRes.value && pRes.value.length >= 50) {
      articleText = htmlToText(pRes.value);
      articleBody = extractArticleBody(pRes.value);
      if (articleBody.length < 800) articleBody = articleText;

      const ex = extractIocs(articleText);
      engFull = ex.data;
      engDetails = ex.registryDetails;
    }

    if (!apiData && (!engFull || !Object.keys(filterScraped(engFull, url)).length)) {
      setError(`The API call and page fetch both returned no IOCs. Try the "Paste IOCs" tab.`);
      setLoading(false);
      return;
    }

    let data, origin, usedDetails = [];
    if (apiData) {
      const engExtra = {};
      if (engFull) {
        Object.entries(engFull).forEach(([cat, arr]) => {
          if (!API_SUPPORTED_CATS.has(cat) && arr.length) engExtra[cat] = arr;
        });
      }
      if (Object.keys(engExtra).length) {
        ({ data, origin } = mergeIocs(apiData, engExtra));
        usedDetails = engExtra.REGISTRY ? engDetails : [];
      } else {
        data = apiData;
        origin = {};
        Object.entries(data).forEach(([c, arr]) => { origin[c] = {}; arr.forEach((v) => { origin[c][v] = "api"; }); });
      }
    } else {
      data = filterScraped(engFull, url);
      origin = {};
      Object.entries(data).forEach(([c, arr]) => { origin[c] = {}; arr.forEach((v) => { origin[c][v] = "eng"; }); });
      usedDetails = engDetails;
    }

    setRegistryDetails(usedDetails);
    setIocData(data);
    setOriginData(origin);
    setMeta(apiMeta);
    setSourceUrl(url);
    if (articleText) setRawArticle(articleText);
    if (articleBody) setArticleClean(articleBody);
    setLoading(false);
  };

  const summarizeNow = () => {
    const text = articleClean || rawArticle;
    if (!text || text.trim().length < 300) { setAiState("error"); return; }
    setAiState("loading");
    fetch(`${WORKER_BASE}/summarize`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ text, title: meta?.title || "" }),
    })
      .then((r) => (r.ok ? r.json() : Promise.reject(new Error(`HTTP ${r.status}`))))
      .then((j) => {
        if (j && typeof j.headline === "string" && typeof j.summary === "string") {
          setAiSummary({
            headline: j.headline,
            summary: j.summary,
            recommendations: Array.isArray(j.recommendations) ? j.recommendations : [],
          });
          setAiState("done");
        } else {
          throw new Error("bad payload");
        }
      })
      .catch(() => setAiState("error"));
  };

  const toggleAiPanel = () => {
    const opening = !aiOpen;
    setAiOpen(opening);
    if (opening && aiState === "idle") summarizeNow();
  };

  const retryAi = () => {
    if (cooldown > 0 || aiState === "loading") return;
    const n = retryCount + 1;
    setRetryCount(n);
    if (n >= 3) setCooldown(25 + 5 * (n - 3));
    summarizeNow();
  };

  useEffect(() => {
    if (cooldown <= 0) return;
    const t = setTimeout(() => setCooldown((c) => (c > 0 ? c - 1 : 0)), 1000);
    return () => clearTimeout(t);
  }, [cooldown]);

  const runPaste = () => {
    resetResults();
    try {
      const parsed = parseIocs(JSON.parse(jsonText));
      if (!Object.keys(parsed).length) throw new Error("No IOC arrays found in the pasted JSON.");
      let details = [];
      if (parsed.REGISTRY) {
        const seen = new Set();
        const canon = [];
        parsed.REGISTRY.forEach((s) => {
          const d = parseCanonicalReg(s);
          const c = canonicalReg(d);
          if (!seen.has(c)) { seen.add(c); details.push(d); canon.push(c); }
        });
        parsed.REGISTRY = canon;
      }
      const origin = {};
      Object.entries(parsed).forEach(([c, arr]) => { origin[c] = {}; arr.forEach((v) => { origin[c][v] = "api"; }); });
      setIocData(parsed); setOriginData(origin); setRegistryDetails(details);
      setSourceUrl("(pasted JSON)");
    } catch (e) { setError(`Could not parse JSON: ${e.message}`); }
  };

  const runRaw = () => {
    resetResults();
    const ex = extractIocs(rawText);
    if (!Object.keys(ex.data).length) {
      setError("No recognizable IOCs found.");
      return;
    }
    const origin = {};
    Object.entries(ex.data).forEach(([c, arr]) => { origin[c] = {}; arr.forEach((v) => { origin[c][v] = "eng"; }); });
    setIocData(ex.data); setOriginData(origin); setRegistryDetails(ex.registryDetails);
    setSourceUrl("(raw paste)");
  };

  const saveArticle = () =>
    downloadBlob(new Blob([rawArticle], { type: "text/plain;charset=utf-8" }), `article_${Date.now()}.txt`);

  const exportAllCSV = () => {
    const rows = [["Type", "IOC", "Source"]];
    entries.forEach(([cat, arr]) => {
      const shown = proc(arr, cat);
      arr.forEach((orig, i) => rows.push([cat, shown[i], tagFor(cat, orig)]));
    });
    downloadBlob(new Blob([toCSV(rows)], { type: "text/csv;charset=utf-8" }), "all_iocs.csv");
  };

  const exportAllXLSX = () => {
    const all = [["Type", "IOC", "Source"]];
    entries.forEach(([cat, arr]) => {
      const shown = proc(arr, cat);
      arr.forEach((orig, i) => all.push([cat, shown[i], tagFor(cat, orig)]));
    });
    const sheets = [{ name: "All_IOCs", rows: all }];
    entries.forEach(([cat, arr]) => {
      const shown = proc(arr, cat);
      sheets.push({ name: cat, rows: [["IOC", "Source"], ...arr.map((orig, i) => [shown[i], tagFor(cat, orig)])] });
    });
    downloadBlob(buildWorkbook(sheets), "all_iocs.xlsx");
  };

  const exportTypeCSV = (cat, arr) => {
    const shown = proc(arr, cat);
    const rows = [["Type", "IOC", "Source"], ...arr.map((orig, i) => [cat, shown[i], tagFor(cat, orig)])];
    downloadBlob(new Blob([toCSV(rows)], { type: "text/csv;charset=utf-8" }), `${cat.toLowerCase()}_iocs.csv`);
  };

  const exportTypeXLSX = (cat, arr) => {
    const shown = proc(arr, cat);
    const rows = [["IOC", "Source"], ...arr.map((orig, i) => [shown[i], tagFor(cat, orig)])];
    downloadBlob(buildWorkbook([{ name: cat, rows }]), `${cat.toLowerCase()}_iocs.xlsx`);
  };

  const rootStyle = {
    minHeight: "100vh", color: "#e6f0f3", backgroundColor: "#05070a",
    backgroundImage:
      "radial-gradient(1200px 600px at 80% -10%, rgba(0,229,255,0.10), transparent 60%)," +
      "radial-gradient(900px 500px at 0% 10%, rgba(0,255,156,0.08), transparent 55%)," +
      "linear-gradient(rgba(255,255,255,0.025) 1px, transparent 1px)," +
      "linear-gradient(90deg, rgba(255,255,255,0.025) 1px, transparent 1px)",
    backgroundSize: "auto, auto, 38px 38px, 38px 38px",
  };
  const panel = { backgroundColor: "rgba(10,14,20,0.72)", border: "1px solid rgba(120,160,180,0.16)", backdropFilter: "blur(6px)" };

  return (
    <div style={rootStyle} className="font-mono">
      <style>{`
        * { scrollbar-width: thin; scrollbar-color: #0e7490 #070b10; }
        *::-webkit-scrollbar { width: 10px; height: 10px; }
        *::-webkit-scrollbar-track { background: #070b10; border-radius: 8px; }
        *::-webkit-scrollbar-thumb {
          background: linear-gradient(180deg, #00e5ff66, #0e7490);
          border-radius: 8px;
          border: 2px solid #070b10;
        }
        *::-webkit-scrollbar-thumb:hover { background: #00e5ffaa; }
        *::-webkit-scrollbar-corner { background: #070b10; }
      `}</style>
      <div className="mx-auto max-w-6xl px-4 py-6 sm:px-6">
        <div className="flex items-start gap-3 mb-5 flex-wrap">
          <div className="flex h-11 w-11 items-center justify-center rounded-lg shrink-0"
            style={{ backgroundColor: "rgba(0,229,255,0.08)", border: "1px solid rgba(0,229,255,0.35)", boxShadow: "0 0 22px rgba(0,229,255,0.25)" }}>
            <Shield size={22} style={{ color: "#00e5ff" }} />
          </div>
          <div className="min-w-0">
            <h1 className="text-xl sm:text-2xl font-bold tracking-tight" style={{ color: "#eafcff", textShadow: "0 0 18px rgba(0,229,255,0.35)" }}>
              Threat Intel Article IOC Extractor
            </h1>
            <p className="text-xs sm:text-sm" style={{ color: "#7f95a3" }}>
              Extract IOCs, capture hunt artifacts, generate ready-to-run queries.
            </p>
          </div>
          <div className="sm:ml-auto flex flex-col sm:items-end gap-1.5">
            <p className="text-xs" style={{ color: "#7f95a3" }}>
              Author — <span style={{ color: "#eafcff", fontWeight: 700 }}>Aamir Muhammad</span>
              <span style={{ color: "#5d7382" }}> · Threat Hunter | Incident Responder</span>
            </p>
            <div className="flex flex-wrap gap-1.5 sm:justify-end">
              <a href="https://www.linkedin.com/in/aamirmohammad/" target="_blank" rel="noreferrer noopener"
                className="flex items-center gap-1.5 rounded-md px-2 py-1 text-xs font-semibold"
                style={{ color: "#38bdf8", border: "1px solid rgba(56,189,248,0.4)", backgroundColor: "rgba(56,189,248,0.08)" }}>
                <Linkedin size={13} /> LinkedIn
              </a>
              <a href="https://github.com/Aamir-Muhammad/CrowdStrike-Queries" target="_blank" rel="noreferrer noopener"
                className="flex items-center gap-1.5 rounded-md px-2 py-1 text-xs font-semibold"
                style={{ color: "#ff4d4d", border: "1px solid rgba(255,77,77,0.4)", backgroundColor: "rgba(255,77,77,0.08)" }}>
                <Github size={13} /><Target size={13} /> CrowdStrike Queries
              </a>
              <a href="https://github.com/Aamir-Muhammad/KQL-Queries" target="_blank" rel="noreferrer noopener"
                className="flex items-center gap-1.5 rounded-md px-2 py-1 text-xs font-semibold"
                style={{ color: "#00b7ff", border: "1px solid rgba(0,183,255,0.4)", backgroundColor: "rgba(0,183,255,0.08)" }}>
                <Github size={13} /><ShieldCheck size={13} /> Defender XDR Queries
              </a>
            </div>
          </div>
        </div>

        <div className="rounded-xl p-3 mb-4 flex flex-wrap items-center gap-2" style={panel}>
          {total > 0 && (
            <div className="flex items-baseline gap-2 rounded-lg px-3 py-1.5"
              style={{ border: "1px solid rgba(0,255,156,0.5)", backgroundColor: "rgba(0,255,156,0.08)", boxShadow: "0 0 18px rgba(0,255,156,0.15)" }}>
              <span className="text-lg font-extrabold leading-none" style={{ color: "#00ff9c" }}>IOCs:</span>
              <span className="text-lg font-extrabold tabular-nums leading-none" style={{ color: "#00ff9c" }}>{total}</span>
            </div>
          )}
          <span className="text-xs uppercase tracking-widest mr-1" style={{ color: "#7f95a3" }}>Export all</span>
          <GButton onClick={exportAllCSV} disabled={!total} color="#00ff9c" icon={<Download size={15} />}>All IOCs · CSV</GButton>
          <GButton onClick={exportAllXLSX} disabled={!total} color="#00e5ff" icon={<Download size={15} />}>All IOCs · XLSX</GButton>
          {total > 0 && (
            <button onClick={() => setDefangAll((v) => !v)}
              className="ml-auto flex items-center gap-1.5 rounded-md px-2.5 py-1.5 text-xs font-semibold"
              style={{
                color: defangAll ? "#04111a" : "#ffb84d",
                backgroundColor: defangAll ? "#ffb84d" : "rgba(255,184,77,0.10)",
                border: "1px solid rgba(255,184,77,0.5)",
              }}>
              <ShieldOff size={13} /> {defangAll ? "Defang All: On" : "Defang All: Off"}
            </button>
          )}
        </div>

        <div className="rounded-xl p-4 mb-5" style={panel}>
          <div className="flex flex-wrap gap-1 mb-3">
            <Tab active={mode === "url"} onClick={() => setMode("url")} icon={<Globe size={14} />}>Fetch URL</Tab>
            <Tab active={mode === "paste"} onClick={() => setMode("paste")} icon={<ClipboardPaste size={14} />}>Paste JSON</Tab>
            <Tab active={mode === "raw"} onClick={() => setMode("raw")} icon={<Wand2 size={14} />}>Paste IOCs</Tab>
          </div>

          {mode === "url" && (
            <div className="flex flex-col gap-2">
              <div className="flex flex-col sm:flex-row gap-2">
                <div className="relative flex-1">
                  <Search size={16} className="absolute left-3 top-1/2 -translate-y-1/2" style={{ color: "#5d7382" }} />
                  <input
                    value={url}
                    onChange={(e) => setUrl(e.target.value)}
                    onKeyDown={(e) => e.key === "Enter" && url && !loading && runFetch()}
                    placeholder="https://threat-report.example/article"
                    className="w-full rounded-lg pl-9 pr-3 py-2.5 text-sm outline-none"
                    style={{ backgroundColor: "rgba(0,0,0,0.45)", border: "1px solid rgba(120,160,180,0.22)", color: "#dff" }}
                  />
                </div>
                <GButton onClick={runFetch} disabled={!url || loading} color="#00e5ff" solid icon={loading ? <Loader2 size={16} className="animate-spin" /> : <Search size={16} />}>
                  {loading ? "Fetching…" : "Fetch & Extract"}
                </GButton>
              </div>
            </div>
          )}

          {mode === "paste" && (
            <div className="flex flex-col gap-2">
              <textarea
                value={jsonText}
                onChange={(e) => setJsonText(e.target.value)}
                placeholder='Paste JSON with arrays per type, e.g. {"IPV4":["1.2.3.4"],"DOMAIN":["evil.com"]} or {"data":{...}}'
                rows={5}
                className="w-full rounded-lg px-3 py-2.5 text-sm outline-none resize-y"
                style={{ backgroundColor: "rgba(0,0,0,0.45)", border: "1px solid rgba(120,160,180,0.22)", color: "#dff" }}
              />
              <div className="flex gap-2">
                <GButton onClick={runPaste} disabled={!jsonText.trim()} color="#00ff9c" solid icon={<ClipboardPaste size={16} />}>Parse JSON</GButton>
                {jsonText && <GButton onClick={() => setJsonText("")} color="#94a3b8" icon={<Trash2 size={15} />}>Clear</GButton>}
              </div>
            </div>
          )}

          {mode === "raw" && (
            <div className="flex flex-col gap-2">
              <textarea
                value={rawText}
                onChange={(e) => setRawText(e.target.value)}
                placeholder={"Paste IOCs in ANY format — markdown reports, defanged, or messy:\n\n[c7f38cbb99c8b74fa0465293feeba700](https://opentip.kaspersky.com/…) Financial Reports.vbs\ntemu.baskwms[.]top   202.61.160[.]202\nhxxps://evil[.]com/payload   CVE-2025-1234   T1059.005\nreg add \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\" /v Updater /t REG_SZ /d \"C:\\Users\\x\\evil.exe\""}
                rows={7}
                className="w-full rounded-lg px-3 py-2.5 text-sm outline-none resize-y"
                style={{ backgroundColor: "rgba(0,0,0,0.45)", border: "1px solid rgba(120,160,180,0.22)", color: "#dff" }}
              />
              <div className="flex items-center gap-2">
                <GButton onClick={runRaw} disabled={!rawText.trim()} color="#c084fc" solid icon={<Wand2 size={16} />}>Refang &amp; Parse</GButton>
                {rawText && <GButton onClick={() => setRawText("")} color="#94a3b8" icon={<Trash2 size={15} />}>Clear</GButton>}
              </div>
            </div>
          )}

          {error && (
            <div className="mt-3 flex items-start gap-2 rounded-lg px-3 py-2.5 text-xs" style={{ backgroundColor: "rgba(255,59,59,0.08)", border: "1px solid rgba(255,59,59,0.3)", color: "#ffb4b4" }}>
              <AlertTriangle size={15} className="mt-0.5 shrink-0" /> <span>{error}</span>
            </div>
          )}
        </div>

        {meta && (meta.title || meta.description) && (
          <div className="rounded-xl p-4 mb-3 flex gap-3" style={{ ...panel, borderColor: "rgba(0,229,255,0.28)", boxShadow: "0 0 24px rgba(0,229,255,0.08)" }}>
            <div className="mt-0.5 shrink-0 flex h-9 w-9 items-center justify-center rounded-lg"
              style={{ backgroundColor: "rgba(0,229,255,0.08)", border: "1px solid rgba(0,229,255,0.3)" }}>
              <FileText size={17} style={{ color: "#00e5ff" }} />
            </div>
            <div className="min-w-0 flex-1">
              {meta.title && (
                <h2 className="text-sm sm:text-base font-bold leading-snug" style={{ color: "#eafcff" }}>{meta.title}</h2>
              )}
              {meta.description && (
                <p className="text-xs sm:text-sm mt-1 leading-relaxed" style={{ color: "#9fb3bd" }}>{meta.description}</p>
              )}
              <div className="flex flex-wrap items-center gap-2 mt-2">
                {meta.url && (
                  <a href={meta.url} target="_blank" rel="noreferrer noopener"
                    className="inline-flex items-center gap-1 text-xs rounded-md px-2 py-0.5 truncate max-w-full"
                    style={{ color: "#00e5ff", border: "1px solid rgba(0,229,255,0.3)", backgroundColor: "rgba(0,229,255,0.06)" }}>
                    <Globe size={11} className="shrink-0" /> <span className="truncate">{stripScheme(meta.url)}</span>
                  </a>
                )}
                {Array.isArray(meta.tags) && meta.tags.filter(Boolean).map((t, i) => (
                  <span key={i} className="text-[11px] rounded-full px-2 py-0.5"
                    style={{ color: "#c084fc", border: "1px solid rgba(192,132,252,0.35)", backgroundColor: "rgba(192,132,252,0.08)" }}>
                    #{String(t)}
                  </span>
                ))}
              </div>
            </div>
          </div>
        )}

        {(articleClean || rawArticle) && sourceUrl && (
          <div className="rounded-xl mb-4 overflow-hidden" style={{ ...panel, borderColor: "rgba(192,132,252,0.35)", boxShadow: aiOpen ? "0 0 24px rgba(192,132,252,0.10)" : "none" }}>
            <button onClick={toggleAiPanel}
              className="w-full flex items-center justify-between px-4 py-3 text-left"
              style={{ backgroundColor: aiOpen ? "rgba(192,132,252,0.06)" : "transparent" }}>
              <span className="flex items-center gap-2.5 min-w-0">
                <span className="shrink-0 flex h-7 w-7 items-center justify-center rounded-lg"
                  style={{ backgroundColor: "rgba(192,132,252,0.08)", border: "1px solid rgba(192,132,252,0.35)" }}>
                  <Sparkles size={14} style={{ color: "#c084fc" }} />
                </span>
                <span className="text-sm font-bold tracking-wide" style={{ color: "#c084fc" }}>AI Summary</span>
              </span>
              <ChevronDown size={18} className="shrink-0 transition-transform"
                style={{ color: "#c084fc", transform: aiOpen ? "rotate(180deg)" : "rotate(0deg)" }} />
            </button>

            {aiOpen && (
              <div className="px-4 pb-4 pt-1" style={{ borderTop: "1px solid rgba(192,132,252,0.2)" }}>
                {aiState === "loading" && (
                  <p className="text-xs sm:text-sm animate-pulse pt-2" style={{ color: "#9fb3bd" }}>
                    Analyzing article and generating technical summary…
                  </p>
                )}

                {aiState === "done" && aiSummary && (
                  <div className="pt-2">
                    <h2 className="text-sm sm:text-base font-bold leading-snug" style={{ color: "#eafcff" }}>{aiSummary.headline}</h2>
                    <p className="text-xs sm:text-sm mt-1.5 leading-relaxed" style={{ color: "#b8c9d1" }}>{aiSummary.summary}</p>
                    {aiSummary.recommendations.length > 0 && (
                      <div className="mt-2.5">
                        <p className="text-[10px] uppercase tracking-widest mb-1" style={{ color: "#8aa0ad" }}>Recommendations</p>
                        {aiSummary.recommendations.map((rec, i) => (
                          <div key={i} className="flex items-start gap-1.5 text-xs sm:text-sm py-0.5 leading-relaxed" style={{ color: "#9fb3bd" }}>
                            <span className="shrink-0" style={{ color: "#c084fc" }}>▸</span> <span>{rec}</span>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                )}

                {aiState === "error" && (
                  <div className="pt-2">
                    <p className="text-xs sm:text-sm leading-relaxed" style={{ color: "#ffb4b4" }}>
                      Failed to generate summary. This can happen on protected pages.
                    </p>
                    <button onClick={retryAi} disabled={cooldown > 0}
                      className="mt-2.5 flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs font-semibold"
                      style={{
                        color: cooldown > 0 ? "#5d7382" : "#c084fc",
                        border: `1px solid ${cooldown > 0 ? "rgba(120,160,180,0.25)" : "rgba(192,132,252,0.45)"}`,
                        backgroundColor: cooldown > 0 ? "rgba(120,160,180,0.06)" : "rgba(192,132,252,0.10)",
                      }}>
                      <RefreshCw size={13} />
                      {cooldown > 0 ? `Retry in ${cooldown}s` : "Retry AI Summary"}
                    </button>
                  </div>
                )}
              </div>
            )}
          </div>
        )}

        {entries.length > 0 && (
          <div className="flex flex-wrap gap-2 mb-5">
            {entries.map(([cat, arr]) => {
              const c = colorFor(cat);
              return (
                <a key={cat} href={`#cat-${cat}`} className="flex items-center gap-2 rounded-full px-3 py-1 text-xs" style={{ border: `1px solid ${c}55`, backgroundColor: `${c}14`, color: c }}>
                  <span style={{ width: 7, height: 7, borderRadius: 99, backgroundColor: c, boxShadow: `0 0 8px ${c}` }} />
                  {cat} <span className="font-bold" style={{ opacity: 0.85 }}>· {arr.length}</span>
                </a>
              );
            })}
          </div>
        )}

        {iocData && (
          <div className="flex items-center gap-2 mb-4 flex-wrap">
            <p className="text-xs truncate" style={{ color: "#5d7382" }}>
              source: <span style={{ color: "#8aa0ad" }}>{sourceUrl}</span>
            </p>
            <div className="flex items-center gap-2 ml-auto flex-wrap">
              <ToggleBtn on={showTags} onClick={toggleTags} icon={<Tags size={12} />}>
                {showTags ? "Tags: On" : "Tags: Off"}
              </ToggleBtn>
              {rawArticle && (
                <button onClick={saveArticle} className="flex items-center gap-1 text-xs rounded-md px-2 py-1"
                  style={{ color: "#00e5ff", border: "1px solid rgba(0,229,255,0.4)", backgroundColor: "rgba(0,229,255,0.07)" }}>
                  <FileDown size={12} /> Save article ({Math.round(rawArticle.length / 1024)} KB)
                </button>
              )}
            </div>
          </div>
        )}

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          {entries.map(([cat, arr]) => {
            const c = colorFor(cat);
            const isDefanged = defangAll || !!defangMap[cat];
            const shown = proc(arr, cat);
            const fmt = {
              lines: shown.join("\n"),
              pipe: shown.join("|"),
              quoted: shown.map((v) => `"${v}"`).join(", "),
              comma: shown.join(", "),
            };
            const tag = showTags ? catTag(cat, arr) : null;
            const isReg = cat === "REGISTRY";
            return (
              <div key={cat} id={`cat-${cat}`} className="rounded-xl overflow-hidden flex flex-col" style={{ ...panel, borderColor: `${c}40` }}>
                <div className="flex items-center justify-between px-4 py-2.5 gap-2" style={{ borderBottom: `1px solid ${c}33`, backgroundColor: `${c}0d` }}>
                  <div className="flex items-center gap-2 min-w-0">
                    <span style={{ width: 9, height: 9, borderRadius: 99, backgroundColor: c, boxShadow: `0 0 10px ${c}` }} />
                    <span className="font-bold tracking-wide truncate" style={{ color: c, textShadow: `0 0 12px ${c}55` }}>{cat}</span>
                    {tag && (
                      <span className="text-[10px] rounded-full px-1.5 py-0.5 whitespace-nowrap"
                        style={{ color: "#8aa0ad", border: "1px solid rgba(138,160,173,0.35)", backgroundColor: "rgba(138,160,173,0.08)" }}>
                        {tag}
                      </span>
                    )}
                  </div>
                  <div className="flex items-center gap-2 shrink-0">
                    <button onClick={() => toggleDefang(cat)} className="flex items-center gap-1 rounded-md px-2 py-1 text-xs"
                      title="Defang this type for safe sharing (display, copy & export)"
                      style={{ color: isDefanged ? "#04111a" : "#ffb84d", backgroundColor: isDefanged ? "#ffb84d" : "rgba(255,184,77,0.10)", border: "1px solid rgba(255,184,77,0.5)" }}>
                      <ShieldOff size={12} /> {isDefanged ? "Defanged" : "Defang"}
                    </button>
                    <span className="flex items-center justify-center text-base font-extrabold tabular-nums rounded-lg px-2.5 py-0.5 min-w-[2.2rem]"
                      style={{ backgroundColor: `${c}22`, color: c, border: `1px solid ${c}66`, textShadow: `0 0 10px ${c}66` }}>
                      {arr.length}
                    </span>
                  </div>
                </div>

                <div className="px-4 py-2 overflow-y-auto" style={{ maxHeight: 240 }}>
                  {shown.map((ioc, i) => {
                    const huntReady = isReg && huntReadySet.has(arr[i]);
                    const rowKey = `${cat}-i-${i}`;
                    const isCopied = copied === rowKey;
                    return (
                      <div key={i} className="group flex items-start gap-1.5 py-0.5 leading-relaxed"
                        title={huntReady ? "Hunt-ready: key + value captured — enriches the hunt queries below" : undefined}>
                        <span className="text-xs shrink-0" style={{ color: `${c}aa`, userSelect: "none" }}>›</span>
                        <span className="text-xs break-all flex-1 min-w-0"
                          style={{ color: huntReady ? "#f3ddfa" : "#c8d6dd", fontWeight: huntReady ? 600 : 400 }}>
                          {ioc}
                        </span>
                        <button onClick={() => copyText(ioc, rowKey)}
                          title="Copy this indicator"
                          className="shrink-0 rounded-md p-1 opacity-50 hover:opacity-100 transition-opacity"
                          style={{ color: isCopied ? c : "#8aa0ad" }}>
                          {isCopied ? <Check size={16} /> : <Copy size={16} />}
                        </button>
                        <button onClick={() => removeIoc(cat, arr[i])}
                          title="Discard this indicator — removed from copy formats, exports & hunt queries"
                          className="shrink-0 rounded-md p-1 opacity-50 hover:opacity-100 transition-opacity"
                          style={{ color: "#ff6b6b" }}>
                          <X size={16} />
                        </button>
                      </div>
                    );
                  })}
                </div>

                {isReg && visibleRegDetails.length > 0 && (
                  <div className="px-3 py-2 flex flex-wrap items-center gap-1.5" style={{ borderTop: `1px solid ${c}22`, backgroundColor: `${c}08` }}>
                    <span className="text-[10px] uppercase tracking-wider flex items-center gap-1 mr-1" style={{ color: "#8aa0ad" }}>
                      <Crosshair size={11} /> Hunt
                    </span>
                    <CopyBtn label="Defender KQL" copied={copied === "reg-kql"} onClick={() => copyText(buildKQL(visibleRegDetails), "reg-kql")} color={c} />
                    <CopyBtn label="CrowdStrike CQL" copied={copied === "reg-cql"} onClick={() => copyText(buildCQL(visibleRegDetails), "reg-cql")} color={c} />
                    <CopyBtn label="Splunk SPL" copied={copied === "reg-spl"} onClick={() => copyText(buildSPL(visibleRegDetails), "reg-spl")} color={c} />
                  </div>
                )}

                <div className="px-3 py-2.5 flex flex-wrap gap-1.5" style={{ borderTop: `1px solid ${c}22` }}>
                  <CopyBtn label="Lines" copied={copied === `${cat}-lines`} onClick={() => copyText(fmt.lines, `${cat}-lines`)} color={c} />
                  <CopyBtn label="Comma" copied={copied === `${cat}-comma`} onClick={() => copyText(fmt.comma, `${cat}-comma`)} color={c} />
                  <CopyBtn label="Pipe |" copied={copied === `${cat}-pipe`} onClick={() => copyText(fmt.pipe, `${cat}-pipe`)} color={c} />
                  <CopyBtn label={`Quoted "`} copied={copied === `${cat}-quoted`} onClick={() => copyText(fmt.quoted, `${cat}-quoted`)} color={c} />
                </div>
                <div className="px-3 pb-3 flex gap-1.5">
                  <ExpBtn label="CSV" onClick={() => exportTypeCSV(cat, arr)} color={c} />
                  <ExpBtn label="XLSX" onClick={() => exportTypeXLSX(cat, arr)} color={c} />
                </div>
              </div>
            );
          })}
        </div>

        {!iocData && !loading && !error && (
          <div className="rounded-xl p-10 text-center" style={panel}>
            <Shield size={34} className="mx-auto mb-3" style={{ color: "#1f4754" }} />
            <p className="text-sm" style={{ color: "#5d7382" }}>
              Fetch a threat-intel article URL, paste JSON, or paste raw IOCs.
            </p>
          </div>
        )}

        <p className="text-center text-xs mt-8" style={{ color: "#3a4a54" }}>
          IOC Extraction · Threat Hunting Artifacts · Hunting Query Generation
        </p>
      </div>
    </div>
  );
}

function GButton({ children, onClick, disabled, color, icon, solid }) {
  return (
    <button onClick={onClick} disabled={disabled}
      className="flex items-center gap-1.5 rounded-lg px-3 py-2 text-sm font-semibold transition-opacity"
      style={{ color: solid ? "#04111a" : color, backgroundColor: solid ? color : `${color}14`, border: `1px solid ${color}${solid ? "" : "55"}`, boxShadow: solid ? `0 0 18px ${color}55` : "none", opacity: disabled ? 0.4 : 1, cursor: disabled ? "not-allowed" : "pointer" }}>
      {icon}{children}
    </button>
  );
}

function Tab({ children, active, onClick, icon }) {
  return (
    <button onClick={onClick} className="flex items-center gap-1.5 rounded-md px-3 py-1.5 text-xs font-semibold"
      style={{ color: active ? "#04111a" : "#8aa0ad", backgroundColor: active ? "#00e5ff" : "transparent", boxShadow: active ? "0 0 14px rgba(0,229,255,0.4)" : "none" }}>
      {icon} {children}
    </button>
  );
}

function ToggleBtn({ children, on, onClick, icon }) {
  return (
    <button onClick={onClick} className="flex items-center gap-1 rounded-md px-2 py-1 text-xs"
      style={{
        color: on ? "#04111a" : "#8aa0ad",
        backgroundColor: on ? "#8aa0ad" : "rgba(138,160,173,0.08)",
        border: "1px solid rgba(138,160,173,0.4)",
      }}>
      {icon} {children}
    </button>
  );
}

function CopyBtn({ label, onClick, copied, color }) {
  return (
    <button onClick={onClick} className="flex items-center gap-1 rounded-md px-2 py-1 text-xs"
      style={{ color: copied ? "#04111a" : color, backgroundColor: copied ? color : `${color}12`, border: `1px solid ${color}44` }}>
      {copied ? <Check size={12} /> : <Copy size={12} />} {copied ? "Copied" : label}
    </button>
  );
}

function ExpBtn({ label, onClick, color }) {
  return (
    <button onClick={onClick} className="flex items-center gap-1 rounded-md px-2.5 py-1 text-xs flex-1 justify-center"
      style={{ color: "#9fb3bd", backgroundColor: "rgba(255,255,255,0.03)", border: "1px solid rgba(120,160,180,0.2)" }}>
      <Download size={12} /> {label}
    </button>
  );
}
