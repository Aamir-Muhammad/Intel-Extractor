import { useState, useMemo, useRef, useEffect } from "react";
import * as XLSX from "xlsx";
import {
  Shield, Search, Download, Copy, Check, Loader2, Globe,
  ClipboardPaste, AlertTriangle, ShieldOff, Trash2, Wand2,
  Crosshair, FileText, Linkedin, Github, X, Target, ShieldCheck, Sparkles, ChevronDown, RefreshCw
} from "lucide-react";

// ============================================================
//  Backend proxy
// ============================================================
const WORKER_BASE = "https://ioc-parser.aamirmuhd.workers.dev";

// ============================================================
//  IOC Whitelist — exact-match auto-removal from parsed results
// ============================================================
const isPrivateIP = (ip) => {
  const m = ip.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
  if (!m) return false;
  const [, a, b] = m.map(Number);
  return a === 10 || a === 127 || a === 0 || (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) || (a === 169 && b === 254) || (a === 255);
};
// DOMAIN whitelist — github.com IS filtered here (bare github.com domain is noise)
const WL_DOMAINS = new Set(["github.com","www.github.com","localhost","example.com","www.example.com","kaspersky.com","www.kaspersky.com","fbi.gov","www.fbi.gov","mitre.org","attack.mitre.org","www.mitre.org"]);
// URL whitelist — github.com is intentionally NOT here: full GitHub URLs are
// often real IOCs (payload hosting, raw.githubusercontent staging) and must
// survive into the URL card. Only the bare DOMAIN entry gets filtered.
const WL_URL_HOSTS = new Set(["localhost","example.com","www.example.com","kaspersky.com","www.kaspersky.com","fbi.gov","www.fbi.gov","mitre.org","attack.mitre.org","www.mitre.org"]);
// Domain suffixes to filter (any domain ending in these gets removed)
const WL_DOMAIN_SUFFIXES = [".mitre.org"];
const WL_EMAIL_SUFFIXES = ["@kaspersky.com"];
const WL_FILES = new Set([
  "cmd.exe","powershell.exe","pwsh.exe","mshta.exe","certutil.exe","regsvr32.exe",
  "rundll32.exe","wscript.exe","cscript.exe","msiexec.exe","bitsadmin.exe",
  "schtasks.exe","wmic.exe","net.exe","net1.exe","netsh.exe","sc.exe","reg.exe",
  "attrib.exe","bcdedit.exe","vssadmin.exe","explorer.exe","conhost.exe",
  "svchost.exe","services.exe","lsass.exe","csrss.exe","smss.exe","winlogon.exe",
  "wininit.exe","dllhost.exe","taskhostw.exe","taskhost.exe","control.exe",
  "cmstp.exe","forfiles.exe","msbuild.exe","installutil.exe","hh.exe","bash.exe",
  "wsl.exe","nslookup.exe","ipconfig.exe","systeminfo.exe","whoami.exe",
  "hostname.exe","findstr.exe","xcopy.exe","robocopy.exe","expand.exe",
  "extrac32.exe","nltest.exe","gpresult.exe","ping.exe","tracert.exe","ftp.exe",
  "curl.exe","certreq.exe","msdt.exe","odbcconf.exe","esentutl.exe","pcalua.exe",
  "eventvwr.exe","mmc.exe","regedit.exe","tasklist.exe","taskkill.exe",
  "\\","/"
]);
const WL_IPS6 = new Set(["::1","::","fe80::1","0:0:0:0:0:0:0:1","0:0:0:0:0:0:0:0"]);
const applyWhitelist = (data) => {
  const out = {};
  Object.entries(data).forEach(([cat, arr]) => {
    let filtered = arr;
    if (cat === "IPV4") filtered = arr.filter(v => !isPrivateIP(v));
    else if (cat === "IPV6") filtered = arr.filter(v => !WL_IPS6.has(v.toLowerCase()));
    else if (cat === "DOMAIN") filtered = arr.filter(v => {
      const vl = v.toLowerCase();
      if (WL_DOMAINS.has(vl)) return false;
      if (WL_DOMAIN_SUFFIXES.some(sfx => vl === sfx.slice(1) || vl.endsWith(sfx))) return false;
      return true;
    });
    else if (cat === "URL") filtered = arr.filter(v => {
      try {
        const host = new URL(v.includes("://") ? v : "http://" + v).hostname.toLowerCase();
        if (WL_URL_HOSTS.has(host)) return false;
        if (WL_DOMAIN_SUFFIXES.some(sfx => host === sfx.slice(1) || host.endsWith(sfx))) return false;
      } catch { /* keep on parse failure */ }
      return true;
    });
    else if (cat === "EMAIL") filtered = arr.filter(v => {
      const vl = v.toLowerCase();
      return !WL_EMAIL_SUFFIXES.some(sfx => vl.endsWith(sfx));
    });
    else if (cat === "FILE_NAME") filtered = arr.filter(v => !WL_FILES.has(v.toLowerCase()));
    else if (cat === "FILE_PATH") filtered = arr.filter(v => {
      const vl = v.trim();
      if (vl.length < 4) return false;
      if (vl === "\\" || vl === "/" || vl === "\\\\") return false;
      // Reject HTTP protocol fragments
      if (/HTTP\/[\d.]/i.test(vl)) return false;
      if (/\\r\\n|\r\n/.test(vl)) return false;
      // Reject base64-like content (mostly consecutive base64 chars, no realistic path separators)
      // Base64 is 60+ chars of [A-Za-z0-9+/=] with high entropy
      if (vl.length > 40 && /^[A-Za-z0-9+/=_-]+$/.test(vl)) return false;
      // Reject strings with high base64 density (>70% base64-safe chars in long strings without normal path separators)
      if (vl.length > 30 && !vl.includes("\\") && !vl.includes(":\\") && !/\.\w{1,5}$/.test(vl)) return false;
      // Reject web URI paths (contain URI-typical characters like ?, &, =, %)
      if (/[?&=%#]/.test(vl) && !/^[A-Za-z]:\\/.test(vl) && !vl.startsWith("\\\\")) return false;
      // Reject strings that look like URL paths (start with / and contain URL-like patterns)
      if (/^\/[^/]*\/[^/]*\/.*[?&=]/.test(vl)) return false;
      return true;
    });
    if (filtered.length) out[cat] = filtered;
  });
  return out;
};

// Country code (ISO alpha-2) → flag emoji, e.g. "RU" → 🇷🇺
const countryFlag = (cc) => {
  if (!cc || !/^[A-Za-z]{2}$/.test(cc)) return "";
  return String.fromCodePoint(...[...cc.toUpperCase()].map((ch) => 0x1f1e6 + ch.charCodeAt(0) - 65));
};

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
  REGISTRY: "#e879f9", FILE_NAME: "#94a3b8", FILE_PATH: "#a5b4fc",
  SCHEDULED_TASK: "#fb7185", SERVICE: "#c4b5fd", COMMAND_LINE: "#fde047",
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

// Smart defang: only defangs IOC-like patterns (IPs, URLs, domains) in prose text,
// leaving normal sentences untouched (no replacing every . with [.])
const defangProse = (s) =>
  String(s)
    .replace(/https?:\/\/[^\s<>"]+/gi, (m) => defang(m))
    .replace(/\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?::\d+)?\b/g, (m) => defang(m))
    .replace(/\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|ru|cn|top|xyz|info|biz|cc|tk|pw|ml|ga|cf|gq|co|me|pro|dev|app|cloud|online|site|live|store|tech|space|fun|icu|one|click)\b/gi, (m) => defang(m));

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

// Drop leading scheme from URLs (http:// https:// ftp://) for display/copy/export.
// Defanged variants are refanged first so hxxp[://] forms are handled too.
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

// ============================================================
//  Registry / file-path structured extraction (pre-tokenization)
// ============================================================
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

// Registry key: hive + backslash segments. Mid segments may contain up to 3 spaces
// (e.g. "Windows NT", "Internet Settings"); final segment has no spaces so prose
// after the key isn't swallowed.
const REG_KEY_RE = /(?:HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKEY_CLASSES_ROOT|HKEY_USERS|HKEY_CURRENT_CONFIG|HKLM|HKCU|HKCR|HKCC|HKU):?\\(?:[^\s\\/:*?"<>|,;\r\n]+(?: [^\s\\/:*?"<>|,;\r\n]+){0,3}\\)*[^\s\\/:*?"<>|,;'"`)\]]+/gi;

// reg add "<key>" /v name /t type /d data
const REG_ADD_RE = /\breg(?:\.exe)?\s+add\s+("[^"\r\n]+"|\S+)([^\r\n]*)/gi;

// Set-ItemProperty / New-ItemProperty -Path ... -Name ... -Value ...
const PS_REG_RE = /\b(?:Set-ItemProperty|New-ItemProperty)\b([^\r\n]*)/gi;

// Windows paths: C:\..., \\server\share\..., %ENVVAR%\...
const WIN_PATH_RE = /(?:[A-Za-z]:\\|\\\\[A-Za-z0-9._$-]{1,64}\\|%[A-Za-z_][A-Za-z0-9_]*%\\)(?:[^\s\\/:*?"<>|,;\r\n]+(?: [^\s\\/:*?"<>|,;\r\n]+){0,3}\\)*[^\\/:*?"<>|,;\r\n]{0,180}/g;

// A new drive/UNC/env root embedded mid-match means the regex bridged two paths
// (e.g. "...payload.dll and %APPDATA%\..."). Cut before the second root.
const NEW_ROOT_RE = /\s+(?:[A-Za-z]:\\|%[A-Za-z_][A-Za-z0-9_]*%\\|\\\\[A-Za-z0-9._$-])/;

// Unix paths anchored to common roots
const UNIX_PATH_RE = /(^|[\s"'`(>])(\/(?:usr|etc|var|tmp|opt|home|bin|sbin|lib|lib64|dev|proc|srv|root|boot|Users|Library|Applications|System|private)\/[^\s"'`<>|,;)]+)/g;

const cleanupWinPath = (raw) => {
  let s = raw.replace(/[\s.,;:!?)'"`\]]+$/, "");
  // If the match bridged into a second path root, keep only the first path
  const nr = s.match(NEW_ROOT_RE);
  if (nr) s = s.slice(0, nr.index);
  s = s.replace(/[\s.,;:!?)'"`\]]+$/, "");
  const i = s.lastIndexOf("\\");
  if (i < 0) return null;
  let fin = s.slice(i + 1);
  if (/\s/.test(fin)) {
    // Keep spaces in the filename only when a known extension proves it's one
    // file — take the SHORTEST prefix ending in an extension so trailing prose
    // ("bad.vbs then ran evil.exe") isn't glued on.
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

// Extracts registry keys (incl. values) and file paths from full text BEFORE
// whitespace tokenization, blanking consumed matches so the tokenizer doesn't
// shred multi-word paths like `C:\Program Files\...` or `...\Windows NT\...`.
const extractStructured = (text) => {
  let work = text;
  const regs = [];
  const files = [];
  const blank = (m) => " ".repeat(m.length);

  // 1) reg add command lines (fully structured: key + /v + /t + /d)
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

  // 2) PowerShell Set-ItemProperty / New-ItemProperty
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

  // 3) Plain registry keys + prose values (`key\Name = data`, `→ 0`, ` : 4`)
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

  // 4) Windows file paths (drive, UNC, %ENVVAR%). Consume ONLY the cleaned
  // path (always a prefix of the raw match) so a second path or filename in
  // the same greedy match is re-scanned instead of blanked away.
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

  // 5) Unix paths
  work = work.replace(UNIX_PATH_RE, (m, pre, path) => {
    const c = path.replace(/[.,;:!?)'"`\]]+$/, "");
    if (c.length > 4) { files.push(c); return pre + blank(path); }
    return m;
  });

  // 6) Scheduled tasks and services (EDR-telemetry-visible persistence)
  const tasks = [];
  const services = [];

  // schtasks /create /tn "Name" [/tr "cmd"] [/sc daily] [/ru user]
  const SCHTASKS_RE = /\bschtasks(?:\.exe)?\s+[^"\n]{0,50}?\/create\s+([^\n]{5,500})/gi;
  work = work.replace(SCHTASKS_RE, (m, rest) => {
    const tn = rest.match(/\/tn\s+("[^"]{1,120}"|'[^']{1,120}'|[^\s]+)/i);
    const tr = rest.match(/\/tr\s+("[^"]{1,200}"|'[^']{1,200}'|[^\s]+)/i);
    if (tn) {
      const name = unquote(tn[1]);
      const target = tr ? unquote(tr[1]) : null;
      tasks.push({ name, target, source: "schtasks" });
    }
    return blank(m);
  });

  // PowerShell New-ScheduledTask, Register-ScheduledTask
  const PS_TASK_RE = /\b(?:Register|New)-ScheduledTask\s+([^\n]{5,500})/gi;
  work = work.replace(PS_TASK_RE, (m, rest) => {
    const tn = rest.match(/-TaskName\s+("[^"]{1,120}"|'[^']{1,120}'|\S+)/i);
    if (tn) {
      tasks.push({ name: unquote(tn[1]), source: "powershell" });
    }
    return blank(m);
  });

  // Prose: "creates a scheduled task named 'X'" / "task named X" / "Task Scheduler entry X"
  const PROSE_TASK_RE = /\b(?:scheduled\s+task|task\s+scheduler(?:\s+entry)?)\s+(?:named|called|entry)?\s*["'`]([^"'`\n]{3,120})["'`]/gi;
  let ptm;
  while ((ptm = PROSE_TASK_RE.exec(work))) {
    tasks.push({ name: ptm[1], source: "prose" });
  }

  // sc create / sc.exe create ServiceName binPath= "..."
  const SC_CREATE_RE = /\bsc(?:\.exe)?\s+create\s+(\S{3,80})\s+([^\n]{0,300})/gi;
  work = work.replace(SC_CREATE_RE, (m, name, rest) => {
    const bp = rest.match(/binPath\s*=\s*("[^"]{1,300}"|'[^']{1,300}'|\S+)/i);
    services.push({ name: unquote(name), binPath: bp ? unquote(bp[1]) : null, source: "sc" });
    return blank(m);
  });

  // PowerShell New-Service -Name X -BinaryPathName "..."
  const PS_SVC_RE = /\bNew-Service\s+([^\n]{5,300})/gi;
  work = work.replace(PS_SVC_RE, (m, rest) => {
    const n = rest.match(/-Name\s+("[^"]{1,80}"|'[^']{1,80}'|\S+)/i);
    if (n) {
      const bp = rest.match(/-BinaryPathName\s+("[^"]{1,300}"|'[^']{1,300}'|\S+)/i);
      services.push({ name: unquote(n[1]), binPath: bp ? unquote(bp[1]) : null, source: "powershell" });
    }
    return blank(m);
  });

  // High-value command lines: encoded PowerShell, LOLBin invocations, staging
  // These are separate from scheduled task / service creation commands, which
  // already get captured with their associated task/service above.
  const commands = [];
  const seenCmds = new Set();
  const addCmd = (c) => {
    const s = c.replace(/\s+/g, " ").trim();
    if (s.length > 8 && s.length < 2500 && !seenCmds.has(s)) {
      seenCmds.add(s);
      commands.push(s);
    }
  };

  // 1) Encoded PowerShell: powershell/pwsh with -enc / -encodedcommand / -e followed by base64
  const PS_ENC_RE = /\b(?:powershell(?:\.exe)?|pwsh(?:\.exe)?)\s+[^\n]{0,300}?-(?:enc(?:odedcommand)?|e)\s+["']?([A-Za-z0-9+/=]{40,})/gi;
  work = work.replace(PS_ENC_RE, (m) => { addCmd(m); return blank(m); });

  // 2) PowerShell one-liners with download cradles (IEX + Net.WebClient / Invoke-WebRequest)
  const PS_CRADLE_RE = /\b(?:powershell(?:\.exe)?|pwsh(?:\.exe)?)\s+[^\n]{0,50}?(?:IEX|Invoke-Expression|Invoke-WebRequest|Net\.WebClient|DownloadString|DownloadFile)[^\n]{0,400}/gi;
  work = work.replace(PS_CRADLE_RE, (m) => { addCmd(m); return blank(m); });

  // 3) cmd /c or cmd.exe /c with an executable invocation
  const CMD_EXEC_RE = /\bcmd(?:\.exe)?\s+\/[cCkK]\s+[^\n]{5,400}/gi;
  work = work.replace(CMD_EXEC_RE, (m) => {
    // Only capture if it contains a meaningful pattern (path, LOLBin, PowerShell, etc.)
    if (/(?:powershell|pwsh|certutil|bitsadmin|mshta|rundll32|regsvr32|wmic|schtasks|sc\.exe|reg\s+add|cscript|wscript|http|\.exe|\.dll|\.bat|\.ps1|\.vbs|\.js)/i.test(m)) {
      addCmd(m);
      return blank(m);
    }
    return m;
  });

  // 4) Common LOLBins invoked with args (certutil -urlcache, bitsadmin /transfer, etc.)
  const LOLBIN_RE = /\b(?:certutil|bitsadmin|mshta|rundll32|regsvr32|wmic|installutil|msbuild|msdt|forfiles|cmstp)(?:\.exe)?\s+[-/][a-z]+[^\n]{5,300}/gi;
  work = work.replace(LOLBIN_RE, (m) => { addCmd(m); return blank(m); });

  return { cleaned: work, regs, files, tasks, services, commands };
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
  if (/^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$/i.test(t) || /^(?:[0-9a-f]{2}-){5}[0-9a-f]{2}$/i.test(t)) return ["MAC_ADDRESS", t.toLowerCase()];
  if (/^(?:[0-9a-f]{1,4}:){2,7}[0-9a-f]{0,4}$/i.test(t) && (t.match(/:/g) || []).length >= 2) return ["IPV6", t.toLowerCase()];
  if (/^4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}(?:[1-9A-HJ-NP-Za-km-z]{11})?$/.test(t)) return ["XMR", t];
  if (/^(bc1[ac-hj-np-z02-9]{11,71}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})$/.test(t)) return ["BTC", t];
  if (/^ASN?\d{2,}$/i.test(t)) return ["ASN", t.toUpperCase().replace(/^ASN/, "AS")];
  if (/^(HKLM|HKCU|HKCR|HKU|HKCC|HKEY_[A-Z_]+)[\\/]/i.test(t)) return ["REGISTRY", t];
  if (/\\/.test(t)) return ["FILE_PATH", t];
  if (FILE_EXT.test(t)) return ["FILE_NAME", t];
  if (/^([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/i.test(t)) return ["DOMAIN", t.toLowerCase()];
  return null;
};

const ORDER = ["IPV4","IPV6","DOMAIN","URL","EMAIL","MD5","SHA1","SHA256","SHA512","SSDEEP","CVE","MITRE_ATTACK","YARA","ASN","MAC_ADDRESS","BTC","XMR","ETH","REGISTRY","SCHEDULED_TASK","SERVICE","COMMAND_LINE","FILE_NAME","FILE_PATH"];

// Fixed on-screen card order: Domain, URL, IPs, all hashes first — then the rest.
// Static (not count-based) so discarding IOCs never shuffles box positions.
const DISPLAY_PRIORITY = ["DOMAIN","URL","IPV4","IPV6","MD5","SHA1","SHA256","SHA512","SSDEEP","IMPHASH"];
const catRank = (cat) => {
  const p = DISPLAY_PRIORITY.indexOf(cat);
  if (p !== -1) return p;
  const o = ORDER.indexOf(cat);
  return o === -1 ? 999 : 100 + o;
};

// Returns { data, registryDetails } — data is category → array of strings;
// registryDetails is [{ key, valueName?, valueType?, data? }] powering hunt queries.
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

  // Structured pass: registry keys w/ spaces + values, file paths — before tokenizing
  const structured = extractStructured(work);
  work = structured.cleaned;
  structured.regs.forEach(pushReg);
  structured.files.forEach((f) => add("FILE_PATH", f));

  // Scheduled tasks and services — structured artifacts for EDR hunting
  const taskDetails = [];
  const serviceDetails = [];
  const seenTasks = new Set();
  const seenSvcs = new Set();
  (structured.tasks || []).forEach((t) => {
    const canon = t.target ? `${t.name} → ${t.target}` : t.name;
    if (!seenTasks.has(canon)) { seenTasks.add(canon); taskDetails.push(t); add("SCHEDULED_TASK", canon); }
  });
  (structured.services || []).forEach((s) => {
    const canon = s.binPath ? `${s.name} → ${s.binPath}` : s.name;
    if (!seenSvcs.has(canon)) { seenSvcs.add(canon); serviceDetails.push(s); add("SERVICE", canon); }
  });
  (structured.commands || []).forEach((c) => add("COMMAND_LINE", c));

  const segments = work.replace(/[\[\]]/g, "").split(/[\n\r;,|]+/);

  for (let seg of segments) {
    let s = seg
      .replace(/^[\s\-*•·\u2022>]+/, "")
      .replace(/^\d+[.)]\s+/, "")
      .replace(/^["'`]+|["'`]+$/g, "")
      .trim();
    if (!s) continue;

    const tokens = s.split(/[\s"'`<>]+/).map(trimTok).filter(Boolean);
    const hasOtherIoc = tokens.some((t) => { const r = classify(t); return r && r[0] !== "FILE_NAME" && r[0] !== "FILE_PATH"; });
    const extTokens = tokens.filter((t) => FILE_EXT.test(t));

    // A filename containing spaces (e.g. "Financial Reports.vbs"). Rejects
    // segments with '=' (URL/query params like icid=...) or too many words,
    // which previously glued tracking junk onto the real filename.
    const spacedFilename =
      /\s/.test(s) && !s.includes("/") && !/:\/\//.test(s) && !s.includes("=") &&
      tokens.length <= 4 &&
      FILE_EXT.test(s) && !hasOtherIoc && extTokens.length === 1;

    if (spacedFilename) { add("FILE_NAME", s); continue; }

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

// Normalize API category names to the engine's, so merged results dedupe
const API_KEY_MAP = {
  "FILE_HASH_MD5": "MD5", "FILE_HASH_SHA1": "SHA1", "FILE_HASH_SHA256": "SHA256", "FILE_HASH_SHA512": "SHA512",
  "MITRE_ATT&CK": "MITRE_ATTACK", "BITCOIN_ADDRESS": "BTC", "EMAIL_ADDRESS": "EMAIL",
  "YARA_RULE": "YARA", "FILE_NAME": "FILE_NAME",
};
const normCat = (k) => {
  const u = String(k).toUpperCase().trim();
  return API_KEY_MAP[u] || u;
};

// Categories the API call is authoritative for. When the API succeeds, the local
// engine contributes ONLY the categories NOT in this set. FILE (filenames) is
// deliberately excluded so engine-found filenames merge with the API's FILE_NAME
// results; FILE_PATH, REGISTRY, SHA512, ssdeep, ASN, MAC & wallets are engine-only.
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

// Light parser for registry strings pasted as JSON (canonical or bare-key form)
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

// ============================================================
//  Dual-source merge (API call + local engine)
// ============================================================
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


// ============================================================
//  Hunt query generators (per-entry clauses OR'd into one query)
// ============================================================
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

// ---- Universal hunt query builders: per-category KQL / CQL / SPL ----
const kqlList = (arr) => arr.map((v) => `"${v.replace(/"/g, '\\"')}"`).join(", ");
const cqlPat = (arr) => arr.map((v) => reEsc(v)).join("|");

// CrowdStrike hash hunt template — coalesces written-file vs process image,
// groups across event types, and renders First/Last seen in Asia/Dubai time.
const cqlHashHunt = (field, arr) => {
  const vals = arr.map((v) => `"${v}"`).join(",");
  return `| in(field="${field}", values=[${vals}], ignoreCase=true)\n|ImageFileName:=coalesce(TargetFileName,ImageFileName)\n| groupBy([#event_simpleName,ComputerName,ContextImageFileName, ImageFileName, CommandLine, ${field}], function=stats([count(as=Total), min(@timestamp, as=FirstTime), max(@timestamp, as=LastTime)]), limit=max)\n| FirstTime := formatTime("%e %b %Y %r", field=FirstTime, locale=en_UAE, timezone="Asia/Dubai")\n| LastTime  := formatTime("%e %b %Y %r", field=LastTime, locale=en_UAE, timezone="Asia/Dubai")`;
};

const huntKQL = (cat, arr) => {
  const dyn = `dynamic([${kqlList(arr)}])`;
  switch (cat) {
    case "IPV4": case "IPV6":
      return `DeviceNetworkEvents\n| where RemoteIP in (${kqlList(arr)})\n| project Timestamp, DeviceName, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessCommandLine`;
    case "DOMAIN":
      return `let IOCs=${dyn};\nDeviceNetworkEvents\n| where RemoteUrl has_any (IOCs) or AdditionalFields has_any (IOCs)\n| where ActionType has_any (\n    "HttpConnectionInspected",\n    "SslConnectionInspected",\n    "DnsConnectionInspected",\n    "ConnectionSuccess",\n    "ConnectionFailed"\n  )\n| extend AF = parse_json(AdditionalFields)\n| extend Host = case(\n    ActionType == "HttpConnectionInspected",  tostring(AF["host"]),\n    ActionType == "SslConnectionInspected",   tostring(AF["server_name"]),\n    ActionType == "DnsConnectionInspected",   tostring(AF["query"]),\n    ""\n  )\n| extend URI = case(\n      ActionType == "HttpConnectionInspected",   tostring(AF["uri"]),\n    ""\n  )\n| extend HTTPMethod = case(\n      ActionType == "HttpConnectionInspected",   tostring(AF["method"]),\n    ""\n  )\n| extend Direction = case(\n      ActionType == "HttpConnectionInspected",   tostring(AF["direction"]),\n    ""\n  )\n|extend RemoteUrl=coalesce(RemoteUrl,Host)\n| summarize AntionType=make_set(ActionType),URI=make_set(URI),FirstTime=min(Timestamp), LastTime=max(Timestamp),Direction=make_set(Direction),HTTPMethod=make_set(HTTPMethod) by DeviceName,RemoteUrl`;
    case "URL": {
      const hostExtract = arr.map((u) => { try { const h = u.replace(/^https?:\/\//i, "").split("/")[0].split(":")[0]; return h; } catch { return u; } });
      const hosts = [...new Set(hostExtract)];
      const hostsDyn = `dynamic([${hosts.map((h) => `"${h}"`).join(", ")}])`;
      return `let IOCs = ${dyn};\nlet IOC_Hosts = ${hostsDyn};\nDeviceNetworkEvents\n| where Timestamp > ago(30d)\n| where ActionType has_any (\n    "HttpConnectionInspected",\n    "SslConnectionInspected",\n    "DnsConnectionInspected",\n    "ConnectionSuccess",\n    "ConnectionFailed"\n  )\n| where RemoteUrl has_any (IOC_Hosts)\n    or AdditionalFields has_any (IOC_Hosts)\n| extend AF = parse_json(AdditionalFields)\n| extend\n    Host       = case(\n        ActionType == "HttpConnectionInspected", tostring(AF["host"]),\n        ActionType == "SslConnectionInspected",  tostring(AF["server_name"]),\n        ActionType == "DnsConnectionInspected",  tostring(AF["query"]),\n        ""),\n    URI        = tostring(AF["uri"]),\n    HTTPMethod = tostring(AF["method"]),\n    Direction  = tostring(AF["direction"])\n| extend ReconstructedURL = strcat(Host, URI)\n| extend EffectiveURL = iff(isnotempty(RemoteUrl), RemoteUrl, ReconstructedURL)\n| where EffectiveURL has_any (IOCs)\n    or (EffectiveURL has_any (IOC_Hosts))\n| project\n    Timestamp,\n    DeviceName,\n    AccountName              = InitiatingProcessAccountName,\n    ActionType,\n    EffectiveURL,\n    ReconstructedURL,\n    Host,\n    URI,\n    HTTPMethod,\n    Direction,\n    RemoteIP,\n    RemotePort,\n    InitiatingProcessFileName,\n    InitiatingProcessCommandLine`;
    }
    case "MD5": case "SHA1": case "SHA256": {
      const hashField = cat;
      const initField = `InitiatingProcess${cat}`;
      const varName = `${cat}_IOCs`;
      const hashDyn = `dynamic([${kqlList(arr)}])`;
      return `let ${varName} = ${hashDyn};\nlet ProcEvents =\n    DeviceProcessEvents\n    | where Timestamp > ago(30d)\n    | where ${hashField} in~ (${varName}) or ${initField} in~ (${varName})\n    | extend\n        MatchedHash  = iff(${hashField} in~ (${varName}), ${hashField}, ${initField}),\n        MatchedField = iff(${hashField} in~ (${varName}), "${hashField}", "${initField}"),\n        Detail       = strcat(FolderPath, FileName),\n        ProcessTree  = strcat(InitiatingProcessParentFileName, " > ", InitiatingProcessFileName, " > ", FileName)\n    | project Timestamp, DeviceName, AccountName, SourceTable="DeviceProcessEvents",\n        MatchedHash, MatchedField, Detail, ProcessTree,\n        CommandLine = ProcessCommandLine;\nlet FileEvents =\n    DeviceFileEvents\n    | where Timestamp > ago(30d)\n    | where ${hashField} in~ (${varName}) or ${initField} in~ (${varName})\n    | extend\n        MatchedHash  = iff(${hashField} in~ (${varName}), ${hashField}, ${initField}),\n        MatchedField = iff(${hashField} in~ (${varName}), "${hashField}", "${initField}"),\n        Detail       = strcat(FolderPath, FileName),\n        ProcessTree  = strcat(InitiatingProcessParentFileName, " > ", InitiatingProcessFileName)\n    | project Timestamp, DeviceName, InitiatingProcessAccountName, SourceTable="DeviceFileEvents",\n        MatchedHash, MatchedField, Detail, ProcessTree,\n        CommandLine = InitiatingProcessCommandLine;\nlet ImageLoadEvents =\n    DeviceImageLoadEvents\n    | where Timestamp > ago(30d)\n    | where ${hashField} in~ (${varName}) or ${initField} in~ (${varName})\n    | extend\n        MatchedHash  = iff(${hashField} in~ (${varName}), ${hashField}, ${initField}),\n        MatchedField = iff(${hashField} in~ (${varName}), "${hashField}", "${initField}"),\n        Detail       = strcat(FolderPath, FileName),\n        ProcessTree  = strcat(InitiatingProcessParentFileName, " > ", InitiatingProcessFileName)\n    | project Timestamp, DeviceName, InitiatingProcessAccountName, SourceTable="DeviceImageLoadEvents",\n        MatchedHash, MatchedField, Detail, ProcessTree,\n        CommandLine = InitiatingProcessCommandLine;\nlet NetworkEvents =\n    DeviceNetworkEvents\n    | where Timestamp > ago(30d)\n    | where ${initField} in~ (${varName})\n    | extend\n        MatchedHash  = ${initField},\n        MatchedField = "${initField}",\n        Detail       = strcat(RemoteIP, ":", tostring(RemotePort), " ", RemoteUrl),\n        ProcessTree  = strcat(InitiatingProcessParentFileName, " > ", InitiatingProcessFileName)\n    | project Timestamp, DeviceName, InitiatingProcessAccountName, SourceTable="DeviceNetworkEvents",\n        MatchedHash, MatchedField, Detail, ProcessTree,\n        CommandLine = InitiatingProcessCommandLine;\nlet RegistryEvents =\n    DeviceRegistryEvents\n    | where Timestamp > ago(30d)\n    | where ${initField} in~ (${varName})\n    | extend\n        MatchedHash  = ${initField},\n        MatchedField = "${initField}",\n        Detail       = strcat(RegistryKey, " \\\\ ", RegistryValueName),\n        ProcessTree  = strcat(InitiatingProcessParentFileName, " > ", InitiatingProcessFileName)\n    | project Timestamp, DeviceName, InitiatingProcessAccountName, SourceTable="DeviceRegistryEvents",\n        MatchedHash, MatchedField, Detail, ProcessTree,\n        CommandLine = InitiatingProcessCommandLine;\nlet LogonEvents =\n    DeviceLogonEvents\n    | where Timestamp > ago(30d)\n    | where ${initField} in~ (${varName})\n    | extend\n        MatchedHash  = ${initField},\n        MatchedField = "${initField}",\n        Detail       = strcat(LogonType, " | ", RemoteIP),\n        ProcessTree  = strcat(InitiatingProcessParentFileName, " > ", InitiatingProcessFileName)\n    | project Timestamp, DeviceName, AccountName, SourceTable="DeviceLogonEvents",\n        MatchedHash, MatchedField, Detail, ProcessTree,\n        CommandLine = InitiatingProcessCommandLine;\nlet MiscEvents =\n    DeviceEvents\n    | where Timestamp > ago(30d)\n    | where ${initField} in~ (${varName})\n    | extend\n        MatchedHash  = ${initField},\n        MatchedField = "${initField}",\n        Detail       = ActionType,\n        ProcessTree  = strcat(InitiatingProcessParentFileName, " > ", InitiatingProcessFileName)\n    | project Timestamp, DeviceName, AccountName, SourceTable="DeviceEvents",\n        MatchedHash, MatchedField, Detail, ProcessTree,\n        CommandLine = InitiatingProcessCommandLine;\nunion ProcEvents, FileEvents, ImageLoadEvents,\n      NetworkEvents, RegistryEvents, LogonEvents, MiscEvents\n| summarize\n    FirstSeen    = min(Timestamp),\n    LastSeen     = max(Timestamp),\n    EventCount   = count(),\n    Accounts     = make_set(AccountName),\n    Details      = make_set(Detail),\n    ProcessTrees = make_set(ProcessTree),\n    CommandLines = make_set(CommandLine)\n    by DeviceName, SourceTable, MatchedHash, MatchedField\n| sort by FirstSeen desc`;
    }
    case "FILE_NAME":
      return `DeviceFileEvents\n| where FileName in~ (${kqlList(arr)})\n| project-reorder Timestamp, DeviceName, FileName, FolderPath, SHA256, ActionType, InitiatingProcessFileName\nunion DeviceProcessEvents\n| where FileName in~ (${kqlList(arr)}) or ProcessCommandLine has_any (${kqlList(arr)})\n| project-reorder Timestamp, DeviceName, FileName, ProcessCommandLine, SHA256`;
    case "FILE_PATH":
      return `DeviceFileEvents\n| where ${arr.map((p) => `FolderPath has @"${p.replace(/"/g, '\\"')}"`).join("\n    or ")}\n| project Timestamp, DeviceName, FileName, FolderPath, SHA256, InitiatingProcessFileName`;
    case "EMAIL":
      return `EmailEvents\n| where SenderFromAddress in~ (${kqlList(arr)})\n| project Timestamp, Subject, SenderFromAddress, RecipientEmailAddress, DeliveryAction, NetworkMessageId`;
    case "CVE":
      return `DeviceTvmSoftwareVulnerabilities\n| where CveId in~ (${kqlList(arr)})\n| project DeviceName, SoftwareName, SoftwareVersion, CveId, VulnerabilitySeverityLevel`;
    case "SCHEDULED_TASK": {
      // Extract names from "Name" or "Name → target" canonical strings
      const names = arr.map((v) => v.split(" → ")[0].trim());
      return `let TaskNames = dynamic([${names.map((n) => `"${n.replace(/"/g, '\\"')}"`).join(", ")}]);\nDeviceProcessEvents\n| where FileName in~ ("schtasks.exe", "at.exe", "wmic.exe", "powershell.exe", "pwsh.exe")\n| where ProcessCommandLine has_any (TaskNames)\n| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine\nunion (\n    DeviceRegistryEvents\n    | where RegistryKey has "Schedule\\\\TaskCache\\\\Tasks"\n    | where RegistryValueData has_any (TaskNames) or RegistryValueName has_any (TaskNames)\n    | project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName\n)`;
    }
    case "SERVICE": {
      const names = arr.map((v) => v.split(" → ")[0].trim());
      return `let SvcNames = dynamic([${names.map((n) => `"${n.replace(/"/g, '\\"')}"`).join(", ")}]);\nDeviceProcessEvents\n| where FileName in~ ("sc.exe", "powershell.exe", "pwsh.exe","cmd.exe", "services.exe")\n| where ProcessCommandLine has_any (SvcNames)\n| project-reorder Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName;\nunion (\n    DeviceRegistryEvents\n    | where RegistryKey has "SYSTEM\\\\CurrentControlSet\\\\Services"\n    | where RegistryKey has_any (SvcNames)\n    | project-reorder Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData, ActionType, InitiatingProcessFileName\n)`;
    }
    case "COMMAND_LINE": {
      // Extract distinctive tokens: quoted strings, paths, flags after / or -
      const tokens = new Set();
      arr.forEach((cl) => {
        const s = String(cl);
        // Quoted strings
        (s.match(/"[^"]{4,80}"/g) || []).forEach(m => tokens.add(m.slice(1, -1)));
        // Paths
        (s.match(/[A-Za-z]:\\[^\s"']{3,150}/g) || []).forEach(m => tokens.add(m));
        (s.match(/%[A-Z_]+%\\[^\s"']{2,100}/gi) || []).forEach(m => tokens.add(m));
        // Distinctive flags / suffixes
        (s.match(/\/tn\s+\S+/gi) || []).forEach(m => tokens.add(m));
      });
      const distinctive = [...tokens].filter((t) => t.length > 3 && !/^\/?[a-z]+$/i.test(t)).slice(0, 20);
      const search = distinctive.length ? distinctive : arr.slice(0, 10);
      return `let CmdPatterns = dynamic([${search.map((t) => `"${String(t).replace(/"/g, '\\"')}"`).join(", ")}]);\nDeviceProcessEvents\n| where ProcessCommandLine has_any (CmdPatterns) or InitiatingProcessCommandLine has_any (CmdPatterns)\n| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine`;
    }
    default: return null;
  }
};

const huntCQL = (cat, arr) => {
  const cqlIn = (field) => `in(field="${field}", values=[${arr.map((v) => `"${v}"`).join(",")}], ignoreCase=true)`;
  const cqlInWild = (field) => `in(field="${field}", values=[${arr.map((v) => `"*${v}*"`).join(",")}], ignoreCase=true)`;
  switch (cat) {
    case "IPV4":
      return `#event_simpleName=NetworkConnectIP4\n| ${cqlIn("RemoteAddressIP4")}\n| groupBy([ComputerName, RemoteAddressIP4, RemotePort, ImageFileName], function=stats([count(as=Total), min(@timestamp, as=FirstSeen), max(@timestamp, as=LastSeen)]), limit=max)`;
    case "IPV6":
      return `#event_simpleName=NetworkConnectIP6\n| ${cqlIn("RemoteAddressIP6")}\n| groupBy([ComputerName, RemoteAddressIP6, RemotePort, ImageFileName], function=stats([count(as=Total), min(@timestamp, as=FirstSeen), max(@timestamp, as=LastSeen)]), limit=max)`;
    case "DOMAIN":
      return `#event_simpleName=DnsRequest\n| ${cqlInWild("DomainName")}\n| groupBy([ComputerName, DomainName, RespondingDnsServer, ImageFileName], function=stats([count(as=Total), min(@timestamp, as=FirstSeen), max(@timestamp, as=LastSeen)]), limit=max)`;
    case "URL": {
      // defineTable-based URL hunt: builds an in-memory URLHunt lookup from the
      // IOC URLs, then correlates DnsRequest (domain match) and HttpRequest
      // (full URL match, query string excluded) against it.
      const withScheme = arr.map((u) => (u.includes("://") ? u : "https://" + u));
      const urlList = withScheme.map((u) => `        "${u.replace(/"/g, '\\"')}"`).join(",\n");
      return `defineTable(query={\n| createEvents([\n${urlList}\n      ])\n|parseUrl(@rawstring)\n|rename(field="@rawstring.host", as="DomainName")\n|rename(field="@rawstring.path", as="Uri")\n|rename(field="@rawstring", as="IOC-Reference")\n}, include=["IOC-Reference",DomainName,Uri], name="URLHunt")\n|#event_simpleName=/HttpRequest|DnsRequest/iF\n|case{\n  #event_simpleName=HttpRequest |rename(field="FileName", as="ContextBaseFileName")|FullURL:= format(format="htps://%s%s", field=[HttpHost,HttpPath])|parseUrl(FullURL);*\n}\n|case{\n  #event_simpleName=/DnsRequest/iF |match(file="URLHunt", field=[DomainName],column=[DomainName],ignoreCase=true,nrows=max,strict=true)|drop([Uri])|Hunt1:=" Domain Match ";\n  #event_simpleName=/HttpRequest/iF |match(file="URLHunt", field=[HttpHost,FullURL.path],column=[DomainName,Uri],ignoreCase=true,nrows=max,strict=true)|Hunt2:=" Full URL Match (except query) ";\n  // #event_simpleName=/HttpRequest/iF |match(file="URLHunt", field=[HttpHost],column=[DomainName],ignoreCase=true,nrows=max,strict=true)|Hunt3:="  Domain Match  "; //Uncomment for advanced Hunting (Only domain match for HttpRequest)\n}\n|Hunt:=concat(Hunt1,Hunt2,Hunt3)\n|DomainName:=coalesce(DomainName,HttpHost)\n|groupBy([@timestamp,ComputerName,ContextBaseFileName,#event_simpleName,DomainName,HttpPath,HttpMethod],function=collect([Hunt]),limit=max)`;
    }
    case "MD5":
      return cqlHashHunt("MD5HashData", arr);
    case "SHA1":
      return cqlHashHunt("SHA1HashData", arr);
    case "SHA256":
      return cqlHashHunt("SHA256HashData", arr);
    case "FILE_NAME":
      return `#event_simpleName=/ProcessRollup2|Written/iF\n|case{\n\t#event_simpleName=/Written/iF| FileName=/(${cqlPat(arr)})/iF |HuntObject:= FileName |HuntLogic:= "File written to disk";\n\t#event_simpleName=/ProcessRollup2/iF| CommandLine=/(${cqlPat(arr)})/iF |HuntObject:= CommandLine |HuntLogic:= "File / Payload execution via commandline";\n}\n|groupBy([@timetamp,ComputerName,UserName,HuntLogic,HuntObject,ContextBaseFileName,IsOnRemovableDisk,ZoneIdentifier,ParentBaseFileName], limit=max)`;
    case "FILE_PATH":
      return `#event_simpleName=ProcessRollup2 OR #event_simpleName=NewExecutableWritten\n| ImageFileName=/(${cqlPat(arr)})/i\n| groupBy([ComputerName, ImageFileName, CommandLine, SHA256HashData], function=stats([count(as=Total), min(@timestamp, as=FirstSeen), max(@timestamp, as=LastSeen)]), limit=max)`;
    case "EMAIL":
      return `#event_simpleName=UserLogon OR #event_simpleName=SSOLogin\n| ${cqlIn("UserPrincipal")}\n| groupBy([ComputerName, UserPrincipal, LogonType], function=stats([count(as=Total), min(@timestamp, as=FirstSeen), max(@timestamp, as=LastSeen)]), limit=max)`;
    case "SCHEDULED_TASK": {
      const names = arr.map((v) => v.split(" → ")[0].trim());
      const namePat = names.map(reEsc).join("|");
      return `#event_simpleName=/ProcessRollup2/iF\n|case{\n\tImageFileName=/(schtasks\\.exe|at\\.exe|wmic\\.exe|powershell\\.exe|pwsh\\.exe)/iF| CommandLine=/(${namePat})/iF |HuntObject:= CommandLine |HuntLogic:= "Scheduled task created/modified via commandline";\n}\n|groupBy([@timestamp,ComputerName,UserName,HuntLogic,HuntObject,ImageFileName,ParentBaseFileName], limit=max)`;
    }
    case "SERVICE": {
      const names = arr.map((v) => v.split(" → ")[0].trim());
      const namePat = names.map(reEsc).join("|");
      return `#event_simpleName=/ProcessRollup2/iF\n|case{\n\tImageFileName=/(sc\\.exe|powershell\\.exe|pwsh\\.exe)/iF| CommandLine=/(${namePat})/iF |HuntObject:= CommandLine |HuntLogic:= "Service created/modified via commandline";\n}\n|groupBy([@timestamp,ComputerName,UserName,HuntLogic,HuntObject,ImageFileName,ParentBaseFileName], limit=max)`;
    }
    case "COMMAND_LINE": {
      // Extract distinctive tokens for regex hunting
      const tokens = new Set();
      arr.forEach((cl) => {
        const s = String(cl);
        (s.match(/"[^"]{4,80}"/g) || []).forEach(m => tokens.add(m.slice(1, -1)));
        (s.match(/[A-Za-z]:\\[^\s"']{3,150}/g) || []).forEach(m => tokens.add(m));
      });
      const distinctive = [...tokens].filter((t) => t.length > 3).slice(0, 15);
      const pat = (distinctive.length ? distinctive : arr.slice(0, 10)).map(reEsc).join("|");
      return `#event_simpleName=/ProcessRollup2/iF\n| CommandLine=/(${pat})/iF\n|groupBy([@timestamp,ComputerName,UserName,ImageFileName,CommandLine,ParentBaseFileName], limit=max)`;
    }
    default: return null;
  }
};

const huntSPL = (cat, arr) => {
  const quoted = arr.map((v) => `"${v}"`).join(", ");
  switch (cat) {
    case "IPV4": case "IPV6":
      return `index=* (dest_ip IN (${quoted}) OR src_ip IN (${quoted}))\n| table _time, host, src_ip, dest_ip, dest_port, process_name, app`;
    case "DOMAIN":
      return `index=* sourcetype=stream:dns OR sourcetype=dns\n| search query IN (${arr.map((d) => `"*${d}*"`).join(", ")})\n| table _time, host, query, answer, src_ip`;
    case "URL":
      return `index=* sourcetype=proxy OR sourcetype=web\n| search url IN (${arr.map((u) => `"*${u}*"`).join(", ")})\n| table _time, host, url, dest_ip, status, user`;
    case "MD5":
      return `index=* (file_hash IN (${quoted}) OR MD5 IN (${quoted}))\n| table _time, host, file_name, file_path, file_hash, process_name`;
    case "SHA1":
      return `index=* (file_hash IN (${quoted}) OR SHA1 IN (${quoted}))\n| table _time, host, file_name, file_path, file_hash, process_name`;
    case "SHA256":
      return `index=* (file_hash IN (${quoted}) OR SHA256 IN (${quoted}))\n| table _time, host, file_name, file_path, file_hash, process_name`;
    case "FILE_NAME": case "FILE_PATH":
      return `index=* source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"\n| search (TargetFilename IN (${arr.map((f) => `"*${f}*"`).join(", ")}) OR Image IN (${arr.map((f) => `"*${f}*"`).join(", ")}))\n| table _time, host, Image, TargetFilename, EventCode`;
    case "EMAIL":
      return `index=* sourcetype=ms:o365:management:activity OR sourcetype=exchange\n| search (SenderAddress IN (${quoted}) OR UserId IN (${quoted}))\n| table _time, SenderAddress, RecipientAddress, Subject, Operation`;
    case "CVE":
      return `index=* sourcetype=tenable:sc:vuln OR sourcetype=qualys\n| search cve IN (${quoted})\n| table _time, host, cve, severity, plugin_name`;
    case "SCHEDULED_TASK": {
      const names = arr.map((v) => `"*${v.split(" → ")[0].trim()}*"`).join(", ");
      return `index=* source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1\n| search (Image="*schtasks.exe" OR Image="*at.exe" OR Image="*powershell.exe" OR Image="*wmic.exe")\n| search CommandLine IN (${names})\n| table _time, host, Image, CommandLine, ParentImage, User`;
    }
    case "SERVICE": {
      const names = arr.map((v) => `"*${v.split(" → ")[0].trim()}*"`).join(", ");
      return `index=* source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1\n| search (Image="*sc.exe" OR Image="*powershell.exe")\n| search CommandLine IN (${names})\n| table _time, host, Image, CommandLine, ParentImage, User`;
    }
    case "COMMAND_LINE": {
      const tokens = new Set();
      arr.forEach((cl) => {
        (String(cl).match(/"[^"]{4,80}"/g) || []).forEach(m => tokens.add(m.slice(1, -1)));
        (String(cl).match(/[A-Za-z]:\\[^\s"']{3,150}/g) || []).forEach(m => tokens.add(m));
      });
      const distinctive = [...tokens].filter((t) => t.length > 3).slice(0, 15);
      const patterns = (distinctive.length ? distinctive : arr.slice(0, 10)).map((t) => `"*${t}*"`).join(", ");
      return `index=* source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1\n| search CommandLine IN (${patterns})\n| table _time, host, Image, CommandLine, ParentImage, User`;
    }
    default: return null;
  }
};

// Categories that support hunt queries
const HUNT_CATS = new Set(["IPV4","IPV6","DOMAIN","URL","MD5","SHA1","SHA256","FILE_NAME","FILE_PATH","EMAIL","CVE","SCHEDULED_TASK","SERVICE","COMMAND_LINE"]);

// ============================================================
//  Page scrape helpers
// ============================================================
// Extract just the article body from raw HTML, stripping navigation chrome,
// footers, sidebars, cookie banners etc. so the AI summarizer gets clean
// prose instead of menu text. IOC extraction still uses the full-page text.
const extractArticleBody = (html) => {
  let h = html;
  // 1) Strip elements that are never article content
  h = h.replace(/<(script|style|noscript|iframe|svg|form|button|input|select|textarea|label)\b[\s\S]*?<\/\1>/gi, " ");
  h = h.replace(/<(nav|header|footer|aside|menu|menuitem)\b[\s\S]*?<\/\1>/gi, " ");
  // 2) Strip common non-content class/id patterns (cookie banners, share widgets, nav bars)
  h = h.replace(/<[^>]+(?:class|id)=["'][^"']*(?:cookie|consent|gdpr|banner|popup|modal|sidebar|widget|share|social|newsletter|subscribe|comment|ad-|advertisement|masthead|top-bar|site-header|site-footer|breadcrumb|pagination|related-post|recommended)[^"']*["'][^>]*>[\s\S]*?<\/[^>]+>/gi, " ");
  // 3) Find ALL <article> blocks and pick the LONGEST. The old lazy *? grabbed the
  // shortest match — on sites with nested <article> cards (related posts, sidebars)
  // that returned a tiny blurb, which produced < 300 chars and no API call fired.
  const articleAll = [...h.matchAll(/<article\b[^>]*>([\s\S]*?)<\/article>/gi)];
  if (articleAll.length) {
    const longest = articleAll.reduce((a, b) => (a[1].length >= b[1].length ? a : b));
    if (longest[1].length > 500) return htmlToText(longest[1]);
  }
  // 4) Same for <main>
  const mainAll = [...h.matchAll(/<main\b[^>]*>([\s\S]*?)<\/main>/gi)];
  if (mainAll.length) {
    const longest = mainAll.reduce((a, b) => (a[1].length >= b[1].length ? a : b));
    if (longest[1].length > 500) return htmlToText(longest[1]);
  }
  // 5) Try role="main" or role="article"
  const roleMatch = h.match(/<[^>]+role=["'](?:main|article)["'][^>]*>([\s\S]*?)<\/[^>]+>/i);
  if (roleMatch && roleMatch[1].length > 500) return htmlToText(roleMatch[1]);
  // 6) Fallback: return the stripped HTML (nav/header/footer already removed above)
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

// PDF text extraction using pdf.js loaded from CDN at runtime (no bundling — the
// dynamic import URL is resolved by the browser, never by Rollup, so the build
// never tries to resolve a "pdfjs-dist" package). Extracts the PDF's real text
// layer — unlike ASCII scraping which can't see compressed content.
const PDFJS_CDN = "https://cdnjs.cloudflare.com/ajax/libs/pdf.js/4.7.76";
let pdfjsPromise = null;
const loadPdfJs = () => {
  if (typeof window !== "undefined" && window.pdfjsLib) return Promise.resolve(window.pdfjsLib);
  if (pdfjsPromise) return pdfjsPromise;
  pdfjsPromise = import(/* @vite-ignore */ `${PDFJS_CDN}/pdf.min.mjs`)
    .then((mod) => {
      const lib = mod && mod.getDocument ? mod : (typeof window !== "undefined" ? window.pdfjsLib : null);
      if (!lib) throw new Error("pdf.js module has no getDocument");
      lib.GlobalWorkerOptions.workerSrc = `${PDFJS_CDN}/pdf.worker.min.mjs`;
      return lib;
    })
    .catch((e) => { pdfjsPromise = null; console.warn("pdf.js CDN load failed:", e.message || e); return null; });
  return pdfjsPromise;
};

const extractPdfText = async (arrayBuffer) => {
  try {
    if (!arrayBuffer || arrayBuffer.byteLength < 1000) return null; // too small to be a real PDF
    const pdfjs = await loadPdfJs();
    if (!pdfjs) return null;
    const loadingTask = pdfjs.getDocument({ data: arrayBuffer, isEvalSupported: false });
    const pdf = await loadingTask.promise;
    const parts = [];
    for (let i = 1; i <= pdf.numPages; i++) {
      const page = await pdf.getPage(i);
      const content = await page.getTextContent();
      const line = content.items.map((it) => (typeof it.str === "string" ? it.str : "")).join(" ");
      if (line.trim()) parts.push(line);
    }
    const out = parts.join("\n\n");
    // Guard: a scanned/image-only PDF has no text layer — return null so the
    // caller falls back cleanly instead of surfacing an empty result.
    return out.trim().length > 40 ? out : null;
  } catch (e) {
    console.warn("pdf.js extraction failed:", e.message || e);
    return null;
  }
};

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

// ============================================================
//  Export helpers
// ============================================================
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
  const [url, setUrl] = useState("https://securelist.com/whatsapp-vbs-rmm-campaign/120290/");
  const [jsonText, setJsonText] = useState("");
  const [rawText, setRawText] = useState("");
  const [iocData, setIocData] = useState(null);
  const [originData, setOriginData] = useState(null);           // cat → { value: "api"|"eng"|"both" }
  const [registryDetails, setRegistryDetails] = useState([]);   // [{ key, valueName?, valueType?, data? }]
  const [meta, setMeta] = useState(null);                       // { title, description, url, tags[] }
  const [aiSummary, setAiSummary] = useState(null);             // { headline, summary, recommendations[] }
  const [aiState, setAiState] = useState("idle");               // idle | loading | done | error
  const [aiOpen, setAiOpen] = useState(false);
  const [retryCount, setRetryCount] = useState(0);
  const [cooldown, setCooldown] = useState(0);                  // seconds until retry re-enabled
  const [enrichCache, setEnrichCache] = useState({});             // {iocKey: {loading,data,error}}
  const [aiScanState, setAiScanState] = useState("idle");         // idle | loading | done | error
  const [aiScanCounts, setAiScanCounts] = useState(null);         // {scheduled_tasks, services, registry_ops, command_lines, file_paths}
  const [aiScanError, setAiScanError] = useState("");

  // ---- AI Scan: on-demand deep artifact extraction ----
  // Sends article text to Worker /artifacts which uses same 4-tier model chain as /summarize.
  // Merges AI-found artifacts into existing IOC categories, deduped against regex-extracted ones.
  const runAIScan = async () => {
    const text = (articleClean || rawArticle || "").trim();
    if (!text || text.length < 300) {
      setAiScanError("Not enough article text to scan.");
      setAiScanState("error");
      return;
    }
    setAiScanState("loading");
    setAiScanError("");
    try {
      const res = await fetch(`${WORKER_BASE}/artifacts`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ text: text.slice(0, 16000) }),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const j = await res.json();
      if (j.error) throw new Error(j.error);

      // Merge into iocData + registryDetails
      let added = { scheduled_tasks: 0, services: 0, registry_ops: 0, command_lines: 0, file_paths: 0 };
      setIocData((prev) => {
        const out = { ...prev };
        const push = (cat, val) => {
          const existing = out[cat] || [];
          if (!existing.some((e) => e.toLowerCase() === String(val).toLowerCase())) {
            out[cat] = [...existing, val];
            return true;
          }
          return false;
        };

        // Scheduled tasks: canonical string "name → target" or just "name"
        (j.scheduled_tasks || []).forEach((t) => {
          if (!t || !t.name) return;
          let canon = String(t.name);
          if (t.target) canon += ` → ${t.target}`;
          if (t.trigger) canon += ` [${t.trigger}]`;
          if (push("SCHEDULED_TASK", canon)) added.scheduled_tasks++;
          if (t.command_line) push("COMMAND_LINE", String(t.command_line));
        });

        // Services
        (j.services || []).forEach((s) => {
          if (!s || !s.name) return;
          let canon = String(s.name);
          if (s.bin_path) canon += ` → ${s.bin_path}`;
          if (push("SERVICE", canon)) added.services++;
          if (s.command_line) push("COMMAND_LINE", String(s.command_line));
        });

        // Registry ops
        (j.registry_ops || []).forEach((r) => {
          if (!r || !r.key) return;
          let canon = String(r.key);
          if (r.value_name) canon += "\\" + r.value_name;
          if (r.data !== undefined && r.data !== null && r.data !== "") canon += " = " + r.data;
          if (r.value_type) canon += " (" + String(r.value_type).toUpperCase() + ")";
          if (push("REGISTRY", canon)) added.registry_ops++;
          if (r.command_line) push("COMMAND_LINE", String(r.command_line));
        });

        // Standalone command lines
        (j.command_lines || []).forEach((cl) => {
          if (typeof cl === "string" && cl.trim().length > 3) {
            if (push("COMMAND_LINE", cl.trim())) added.command_lines++;
          }
        });

        // File paths (only if legitimate — reject URL-like and short garbage)
        (j.file_paths || []).forEach((fp) => {
          if (typeof fp === "string" && fp.trim().length > 3) {
            const s = fp.trim();
            // Basic sanity: must look like a path
            if (/^[A-Za-z]:\\/.test(s) || s.startsWith("\\\\") || s.startsWith("%") || /^\/[^/].+\/[^/]+/.test(s)) {
              if (push("FILE_PATH", s)) added.file_paths++;
            }
          }
        });

        // Reorder by ORDER
        const ordered = {};
        ORDER.forEach((k) => { if (out[k]?.length) ordered[k] = out[k]; });
        Object.keys(out).forEach((k) => { if (!ordered[k] && out[k]?.length) ordered[k] = out[k]; });
        return applyWhitelist(ordered);
      });

      // Also merge structured registry details for hunt queries
      setRegistryDetails((prev) => {
        const seen = new Set(prev.map((d) => canonicalReg(d)));
        const added = [];
        (j.registry_ops || []).forEach((r) => {
          if (!r || !r.key) return;
          const det = { key: r.key, valueName: r.value_name || undefined, valueType: r.value_type || undefined, data: r.data !== undefined && r.data !== null ? String(r.data) : undefined };
          const c = canonicalReg(det);
          if (!seen.has(c)) { seen.add(c); added.push(det); }
        });
        return added.length ? [...prev, ...added] : prev;
      });

      setAiScanCounts(added);
      setAiScanState("done");
    } catch (e) {
      setAiScanError(e.message || String(e));
      setAiScanState("error");
    }
  };

  // ---- IOC Enrichment: ThreatFox + URLhaus + MalwareBazaar via Worker proxy ----
  const enrichIOC = async (cat, value) => {
    const key = `${cat}::${value}`;
    if (enrichCache[key]) return;
    setEnrichCache((c) => ({ ...c, [key]: { loading: true } }));
    const results = {};
    const callEnrich = async (api, otxType, otxSection, overrideValue) => {
      const body = { api, value: overrideValue || value };
      if (otxType) body.otx_type = otxType;
      if (otxSection) body.otx_section = otxSection;
      const r = await fetch(`${WORKER_BASE}/enrich`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      const text = await r.text();
      try { return JSON.parse(text); } catch {
        throw new Error(text.slice(0, 100)); // Surface the raw error (e.g. "ERROR: invalid auth key")
      }
    };

    // Generic OTX tags to filter out (low signal)
    const GENERIC_TAGS = new Set(["malware","threat","ioc","indicator","phishing","spam","suspicious",
      "malicious","trojan","virus","botnet","c2","cnc","rat","apt","exploit","attack","campaign",
      "cybercrime","hacking","intel","osint","scan","scanner","scanning",
      "nothreats","no_threats","clean","safe","benign","legitimate","whitelisted","trusted",
      "harmless","undetected","not_malicious","false_positive","good","allowed"]);

    try {
      // ThreatFox — IPs, domains, URLs, hashes
      if (["IPV4","IPV6","DOMAIN","URL","MD5","SHA1","SHA256","SHA512"].includes(cat)) {
        try {
          const j = await callEnrich("threatfox");
          if (j.query_status === "ok" && Array.isArray(j.data) && j.data.length > 0) {
            const d = j.data[0];
            results.threatfox = {
              malware: d.malware_printable || d.malware || "—",
              threat: d.threat_type_desc || d.threat_type || "—",
              confidence: d.confidence_level,
              first: d.first_seen ? d.first_seen.split(" ")[0] : null,
              tags: Array.isArray(d.tags) ? d.tags.filter((t) => t && !GENERIC_TAGS.has(t.toLowerCase())).slice(0, 4).join(", ") : null,
            };
          }
        } catch (e) { console.warn("Enrich ThreatFox failed:", e.message); }
      }
      // URLhaus — host lookup (IPs, domains)
      if (["IPV4","DOMAIN"].includes(cat)) {
        try {
          const j = await callEnrich("urlhaus_host");
          if (j.query_status === "ok" && j.urls && j.urls.length > 0) {
            const online = j.urls.filter((u) => u.url_status === "online").length;
            const offline = j.urls.filter((u) => u.url_status === "offline").length;
            results.urlhaus = {
              urls_total: j.urls.length, online, offline,
              status: online > 0 ? "online" : "offline",
              tags: [...new Set(j.urls.flatMap((u) => u.tags || []).filter((t) => t && !GENERIC_TAGS.has(t.toLowerCase())))].slice(0, 4).join(", ") || null,
            };
          }
        } catch (e) { console.warn("Enrich URLhaus failed:", e.message); }
      }
      // URLhaus — URL lookup
      if (cat === "URL") {
        try {
          const j = await callEnrich("urlhaus_url");
          if (j.query_status !== "no_results" && j.id) {
            results.urlhaus = {
              status: j.url_status || "unknown",
              threat: j.threat || null,
              tags: Array.isArray(j.tags) ? j.tags.filter((t) => t && !GENERIC_TAGS.has(t.toLowerCase())).slice(0, 4).join(", ") : null,
              payloads: Array.isArray(j.payloads) ? j.payloads.length : 0,
            };
          }
        } catch (e) { console.warn("Enrich URLhaus URL failed:", e.message); }
      }
      // MalwareBazaar — hashes (includes vendor_intel for detection names)
      if (["MD5","SHA1","SHA256","SHA512"].includes(cat)) {
        try {
          const j = await callEnrich("malwarebazaar");
          if (j.query_status === "ok" && Array.isArray(j.data) && j.data.length > 0) {
            const d = j.data[0];
            // Extract detection names from vendor_intel (e.g. Trojan.Win32.Agentb.tpwa)
            let detections = [], mbVerdict = null;
            if (d.vendor_intel && typeof d.vendor_intel === "object") {
              Object.entries(d.vendor_intel).forEach(([vendor, info]) => {
                if (info && typeof info === "object") {
                  if (info.verdict && info.verdict.toUpperCase() !== "UNKNOWN") mbVerdict = info.verdict;
                  if (Array.isArray(info.detections)) detections.push(...info.detections);
                  else if (typeof info.detection === "string") detections.push(info.detection);
                  // Kaspersky-style: detections array at top level
                  if (Array.isArray(info.detections)) detections.push(...info.detections);
                }
              });
            }
            detections = [...new Set(detections.filter(Boolean))].slice(0, 3);
            results.malwarebazaar = {
              family: d.signature || "unknown",
              type: d.file_type || "—",
              size: d.file_size ? `${Math.round(d.file_size / 1024)}KB` : null,
              first: d.first_seen ? d.first_seen.split(" ")[0] : null,
              delivery: d.delivery_method || null,
              tags: Array.isArray(d.tags) ? d.tags.filter((t) => t && !GENERIC_TAGS.has(t.toLowerCase())).slice(0, 4).join(", ") : null,
              detections: detections.length ? detections.join(" | ") : null,
              verdict: mbVerdict,
            };
          }
        } catch (e) { console.warn("Enrich MalwareBazaar failed:", e.message); }
      }
      // AlienVault OTX — general (pulses, reputation, ASN, country, high-fidelity tags)
      if (["IPV4","IPV6","DOMAIN","URL","MD5","SHA1","SHA256","SHA512","CVE"].includes(cat)) {
        try {
          const otxTypeMap = { IPV4: "IPv4", IPV6: "IPv6", DOMAIN: "domain", URL: "url", CVE: "cve",
            MD5: "file", SHA1: "file", SHA256: "file", SHA512: "file" };
          let j = await callEnrich("otx", otxTypeMap[cat]);

          // For subdomains with 0 pulses AND no tags AND no validation, query
          // the parent/base domain as fallback. If the FQDN itself has tags or
          // validation flags, keep FQDN data — even with 0 pulses it's specific.
          const fqdnTags = (j?.pulse_info?.pulses || []).flatMap((p) => p.tags || []).filter(Boolean);
          const fqdnVal = Array.isArray(j?.validation) ? j.validation.filter(Boolean) : [];
          if (cat === "DOMAIN" && j && !j.error && (j.pulse_info?.count ?? 0) === 0 && fqdnTags.length === 0 && fqdnVal.length === 0) {
            const parts = value.split(".");
            if (parts.length > 2) {
              const parentDomain = parts.slice(-2).join(".");
              try {
                const pj = await callEnrich("otx", "domain", null, parentDomain);
                // Use parent data if it has more pulses
                if (pj && !pj.error && (pj.pulse_info?.count ?? 0) > 0) {
                  // Keep the original response but merge parent pulse data
                  j = { ...j, pulse_info: pj.pulse_info, country_name: pj.country_name || j.country_name,
                    country_code: pj.country_code || j.country_code,
                    asn: pj.asn || j.asn, as: pj.as || j.as, _parentFallback: parentDomain };
                }
              } catch {}
            }
          }

          if (j && !j.error) {
            // High-fidelity tags: collect from pulses, filter generics
            const pulseTags = (j.pulse_info?.pulses || [])
              .flatMap((p) => [...(p.tags || []), ...(p.targeted_countries || []), p.name || ""])
              .filter(Boolean);
            const hiFiTags = [...new Set(pulseTags)]
              .filter((t) => t.length > 2 && !GENERIC_TAGS.has(t.toLowerCase()))
              .slice(0, 5);

            // Check validation array for malicious indicators (DGA, blocklist, etc.)
            const valFlags = Array.isArray(j.validation)
              ? j.validation.map((v) => typeof v === "string" ? v : v?.source || "").filter(Boolean)
              : [];

            const cc = j.country_code2 || j.country_code || null;
            results.otx = {
              pulses: j.pulse_info?.count ?? 0,
              reputation: j.reputation ?? null,
              country: j.country_name || cc || null,
              countryCode: cc,
              flag: countryFlag(cc),
              // ASN info intentionally omitted from OTX chip — shown in dedicated WHOIS/ASN chip instead
              tags: hiFiTags.length ? hiFiTags.join(", ") : null,
              whitelisted: j.whitelisted ?? null,
              validation: valFlags.length ? valFlags.join(", ") : null,
              parentDomain: j._parentFallback || null,
            };
          }
        } catch (e) { console.warn("Enrich OTX failed:", e.message); }
      }
      // Dedicated WHOIS/ASN + Geo lookup for IP addresses — OTX geo section
      // returns country, city and the registered ASN/org for the IP.
      if (["IPV4","IPV6"].includes(cat)) {
        try {
          const g = await callEnrich("otx", cat === "IPV4" ? "IPv4" : "IPv6", "geo");
          if (g && !g.error) {
            const cc = g.country_code2 || g.country_code || null;
            const asnRaw = g.asn || null; // OTX geo asn is usually "AS15169 Google LLC"
            if (cc || asnRaw || g.country_name || g.city) {
              results.whoisASN = {
                asn: asnRaw,
                country: g.country_name || cc || null,
                countryCode: cc,
                flag: countryFlag(cc),
                city: g.city || null,
              };
            }
          }
        } catch (e) { console.warn("Enrich Geo/ASN failed:", e.message); }
      }
      // OTX WHOIS for domains — registrant org, country, registration age
      if (cat === "DOMAIN") {
        try {
          const w = await callEnrich("otx", "domain", "whois");
          // OTX WHOIS returns data in varying formats — check multiple field names
          let whoisData = null;
          if (w && w.data && Array.isArray(w.data) && w.data.length > 0) {
            whoisData = w.data[0];
          } else if (w && typeof w === "object" && (w.registrar || w.creation_date || w.registrant)) {
            whoisData = w;
          }
          if (whoisData) {
            const regOrg = whoisData.registrant_org || whoisData.admin_org || whoisData.registrar ||
              whoisData.registrant?.organization || whoisData.registrant?.name || null;
            const regCountry = whoisData.registrant_country || whoisData.admin_country ||
              whoisData.registrant?.country || null;
            const created = whoisData.creation_date || whoisData.create_date || whoisData.created || null;
            let ageDays = null;
            if (created) {
              const d = new Date(created);
              if (!isNaN(d)) ageDays = Math.floor((Date.now() - d.getTime()) / 86400000);
            }
            if (regOrg || regCountry || ageDays !== null) {
              results.whois = { org: regOrg, country: regCountry, ageDays };
            }
          }
        } catch (e) { console.warn("Enrich OTX WHOIS failed:", e.message); }
      }

      // ---- Validin (fallback — only when other engines returned nothing useful) ----
      // For DOMAIN and IP types, if ThreatFox + URLhaus + MalwareBazaar returned
      // nothing and OTX had 0 pulses + no validation, call Validin as last resort.
      if (["IPV4","IPV6","DOMAIN"].includes(cat)) {
        const hasUsefulOther = results.threatfox || results.urlhaus || results.malwarebazaar
          || (results.otx && ((results.otx.pulses || 0) > 0 || results.otx.validation));
        if (!hasUsefulOther) {
          try {
            const vApi = cat === "DOMAIN" ? "validin_domain" : "validin_ip";
            const vj = await callEnrich(vApi);
            if (vj && !vj.error && vj.annotations && Array.isArray(vj.annotations)) {
              // For IP: show all annotation titles
              // For DOMAIN: show annotation titles except when risk_cat contains "popularity"
              const isDomain = cat === "DOMAIN";
              const relevant = vj.annotations.filter((a) => {
                if (!a || !a.title) return false;
                if (isDomain && a.risk_cat && String(a.risk_cat).toLowerCase().includes("popularity")) return false;
                return true;
              });
              const malicious = relevant.filter((a) => a.risk_cat === "malicious" || (a.score && a.score >= 7));
              const titles = relevant.map((a) => a.title).slice(0, 6);
              if (relevant.length > 0) {
                results.validin = {
                  verdict: vj.verdict || null,
                  score: vj.score ?? null,
                  titles,
                  maliciousCount: malicious.length,
                };
              }
            }
          } catch (e) { console.warn("Enrich Validin failed:", e.message); }
        }
      }

      // ---- Derive combined verdict ----
      let verdict = "Unknown";
      if (results.threatfox) verdict = "Malicious";
      else if (results.urlhaus?.status === "online") verdict = "Malicious";
      else if (results.malwarebazaar) {
        verdict = results.malwarebazaar.verdict || "Malicious"; // MalBazaar only indexes malware
      }
      else if (results.urlhaus?.status === "offline") verdict = "Suspicious";
      else if (results.otx?.whitelisted === true) verdict = "Whitelisted";
      else if (results.otx?.validation) verdict = "Suspicious"; // OTX flagged (DGA, blocklist, etc.)
      else if ((results.otx?.pulses || 0) > 20) verdict = "Malicious";
      else if ((results.otx?.pulses || 0) > 5) verdict = "Suspicious";
      else if ((results.otx?.pulses || 0) > 0) verdict = "Suspicious";
      // Recently registered domain with OTX data = suspicious
      else if (results.whois && results.whois.ageDays !== null && results.whois.ageDays < 90 && results.otx) verdict = "Suspicious";
      // Parent domain had pulses (subdomain fallback hit)
      else if (results.otx?.parentDomain && results.otx.pulses > 0) verdict = "Suspicious";

      // Validin verdict override
      else if (results.validin) {
        if (results.validin.verdict === "malicious" || results.validin.maliciousCount > 0) verdict = "Malicious";
        else if (results.validin.verdict === "suspicious") verdict = "Suspicious";
      }

      // OTX-only with 0 pulses and no other signals → Unknown
      const hasNonOtx = results.threatfox || results.urlhaus || results.malwarebazaar || results.whois || results.validin;
      if (!hasNonOtx && results.otx && results.otx.pulses === 0 && !results.otx.validation) verdict = "Unknown";

      const hasData = Object.keys(results).length > 0;
      if (hasData) results._verdict = verdict;
      setEnrichCache((c) => ({ ...c, [key]: { loading: false, data: hasData ? results : null, error: !hasData } }));
    } catch (e) {
      console.warn("Enrich overall failed:", e.message);
      setEnrichCache((c) => ({ ...c, [key]: { loading: false, data: null, error: true } }));
    }
  };

  // VT link builder (opens VirusTotal page for the IOC — no API key needed)
  const vtLink = (cat, value) => {
    const v = encodeURIComponent(value);
    if (["MD5","SHA1","SHA256","SHA512"].includes(cat)) return `https://www.virustotal.com/gui/file/${v}`;
    if (cat === "IPV4" || cat === "IPV6") return `https://www.virustotal.com/gui/ip-address/${v}`;
    if (cat === "DOMAIN") return `https://www.virustotal.com/gui/domain/${v}`;
    if (cat === "URL") return `https://www.virustotal.com/gui/url/${btoa(value).replace(/=/g, "")}`;
    return null;
  };
  const [sourceUrl, setSourceUrl] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [rawArticle, setRawArticle] = useState("");
  const [articleClean, setArticleClean] = useState("");           // nav-stripped body for AI summary
  const [defangMap, setDefangMap] = useState({});
  const [defangAll, setDefangAll] = useState(false);
  const [copied, setCopied] = useState("");
  const copyTimer = useRef(null);


  const displayData = iocData;

  const entries = useMemo(
    () => (displayData ? Object.entries(displayData).sort((a, b) => catRank(a[0]) - catRank(b[0])) : []),
    [displayData]
  );
  const total = useMemo(() => entries.reduce((s, [, v]) => s + v.length, 0), [entries]);

  // Registry details visible under the current scraped filter — hunt queries
  // regenerate from exactly these, so toggling off garbage rebuilds the query
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

  const proc = (arr, cat) => ((defangAll || defangMap[cat]) ? arr.map(defang) : arr);
  const toggleDefang = (cat) => setDefangMap((m) => ({ ...m, [cat]: !m[cat] }));

  // Discard a bogus IOC. Copy formats, CSV/XLSX exports and hunt queries all
  // derive from iocData, so removal propagates everywhere automatically.
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
      try { document.execCommand("copy"); flash(key); } catch { /* ignore */ }
      document.body.removeChild(ta);
    }
  };

  const resetResults = () => {
    setError(""); setIocData(null); setOriginData(null); setRegistryDetails([]);
    setMeta(null); setAiSummary(null); setAiState("idle"); setAiOpen(false);
    setAiScanState("idle"); setAiScanCounts(null); setAiScanError("");
    setRetryCount(0); setCooldown(0); setRawArticle(""); setArticleClean(""); setDefangAll(false);
  };

  // ---- URL mode: API call AND page fetch in parallel ----
  // API is authoritative for its supported categories; the local engine only
  // contributes the types the API can't return (registry+values, file paths,
  // sha512, ssdeep, asn, mac, btc/xmr/eth). If the API fails, the engine runs in
  // full as a fallback.
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

    // Local engine over the fetched page text
    let engFull = null, engDetails = [], articleText = "", articleBody = "";
    if (pRes.status === "fulfilled" && pRes.value && pRes.value.length >= 50) {
      // Detect PDF binary content
      const isPDF = pRes.value.trimStart().startsWith("%PDF") || /\.pdf(\?|#|$)/i.test(url);
      if (isPDF) {
        // Refetch as binary (raw=1 = untouched bytes from the Worker) and extract
        // text via pdf.js — proper PDF parsing decompresses FlateDecode streams to
        // reveal the actual command lines, registry keys, and other artifacts
        // that ASCII scraping cannot see.
        let pdfText = null;
        try {
          const binRes = await fetch(`${WORKER_BASE}/fetch?url=${encodeURIComponent(url)}&raw=1`);
          if (binRes.ok) {
            const buf = await binRes.arrayBuffer();
            pdfText = await extractPdfText(buf);
          }
        } catch (e) { console.warn("PDF binary fetch failed:", e.message || e); }

        if (pdfText && pdfText.length > 200) {
          // Clean up: rejoin base64-fragmented tokens, normalize whitespace
          let clean = pdfText.replace(/[ \t]+/g, " ");
          clean = clean.replace(/([A-Za-z0-9+/=_-])\s*\n\s*([A-Za-z0-9+/=_-])/g, "$1$2");
          clean = clean.replace(/\s+/g, " ").trim();
          articleText = clean;
          articleBody = clean;
          // With proper PDF text (not garbage), the local engine can run safely
          const ex = extractIocs(articleText);
          engFull = ex.data;
          engDetails = ex.registryDetails;
        } else {
          // pdf.js failed — fall back to ASCII extraction for at least the AI Summary
          const printable = pRes.value.replace(/[^\x20-\x7E\n\r\t]/g, " ");
          let clean = printable.replace(/[ \t]+/g, " ");
          clean = clean.replace(/([A-Za-z0-9+/=_-])\s*\n\s*([A-Za-z0-9+/=_-])/g, "$1$2");
          clean = clean.replace(/\s+/g, " ").trim();
          articleText = clean;
          articleBody = clean;
          // Skip local engine — ASCII fallback produces garbage FILE_PATHs
        }
      } else {
        articleText = htmlToText(pRes.value);
        articleBody = extractArticleBody(pRes.value);
        if (articleBody.length < 800) articleBody = articleText;
        const ex = extractIocs(articleText);
        engFull = ex.data;
        engDetails = ex.registryDetails;
      }
    }

    if (!apiData && (!engFull || !Object.keys(filterScraped(engFull, url)).length)) {
      const why = [
        aRes.status === "rejected" ? (aRes.reason?.message || "API call failed") : "no API IOCs",
        pRes.status === "rejected" ? (pRes.reason?.message || "page fetch failed") : "no page IOCs",
      ].join("; ");
      setError(`The API call and page fetch both returned no IOCs (${why}). Try the "Paste IOCs" tab, or check the URL.`);
      setLoading(false);
      return;
    }

    let data, origin, usedDetails = [];
    if (apiData) {
      // Keep only the engine categories the API can't produce
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
      // API failed → full local extraction fallback
      data = filterScraped(engFull, url);
      origin = {};
      Object.entries(data).forEach(([c, arr]) => { origin[c] = {}; arr.forEach((v) => { origin[c][v] = "eng"; }); });
      usedDetails = engDetails;
    }

    setRegistryDetails(usedDetails);
    setIocData(applyWhitelist(data));
    setOriginData(origin);
    setMeta(apiMeta);
    setSourceUrl(url);
    if (articleText) setRawArticle(articleText);
    if (articleBody) setArticleClean(articleBody);
    setLoading(false);
  };

  // ---- On-demand AI summary: fires only when the user opens the dropdown,
  // preserving free-tier API calls. Retry is rate-limited below.
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
            executive_summary: typeof j.executive_summary === "string" ? j.executive_summary : "",
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

  // Retry limiter: first 3 retries are free; from the 3rd press onward each
  // press starts a cooldown of 20s + 5s per extra press (20, 25, 30, …).
  const retryAi = () => {
    if (cooldown > 0 || aiState === "loading") return;
    const n = retryCount + 1;
    setRetryCount(n);
    if (n >= 3) setCooldown(20 + 5 * (n - 3));
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
      setIocData(applyWhitelist(parsed)); setOriginData(origin); setRegistryDetails(details);
      setSourceUrl("(pasted JSON)");
    } catch (e) { setError(`Could not parse JSON: ${e.message}`); }
  };

  const runRaw = () => {
    resetResults();
    const ex = extractIocs(rawText);
    if (!Object.keys(ex.data).length) {
      setError("No recognizable IOCs found. Handles markdown reports, defanged & messy text — IPs, domains, URLs, emails, hashes, ssdeep, CVEs, MITRE IDs, ASNs, BTC/XMR/ETH, MACs, registry keys (with values), file names & file paths.");
      return;
    }
    const origin = {};
    Object.entries(ex.data).forEach(([c, arr]) => { origin[c] = {}; arr.forEach((v) => { origin[c][v] = "eng"; }); });
    setIocData(applyWhitelist(ex.data)); setOriginData(origin); setRegistryDetails(ex.registryDetails);
    setSourceUrl("(raw paste)");
  };


  const exportAllCSV = () => {
    const rows = [["Type", "IOC"]];
    entries.forEach(([cat, arr]) => {
      const shown = proc(arr, cat);
      arr.forEach((orig, i) => rows.push([cat, shown[i]]));
    });
    downloadBlob(new Blob([toCSV(rows)], { type: "text/csv;charset=utf-8" }), "all_iocs.csv");
  };
  const exportAllXLSX = () => {
    const all = [["Type", "IOC"]];
    entries.forEach(([cat, arr]) => {
      const shown = proc(arr, cat);
      arr.forEach((orig, i) => all.push([cat, shown[i]]));
    });
    const sheets = [{ name: "All_IOCs", rows: all }];
    entries.forEach(([cat, arr]) => {
      const shown = proc(arr, cat);
      sheets.push({ name: cat, rows: [["IOC"], ...arr.map((orig, i) => [shown[i]])] });
    });
    downloadBlob(buildWorkbook(sheets), "all_iocs.xlsx");
  };
  const exportTypeCSV = (cat, arr) => {
    const shown = proc(arr, cat);
    const rows = [["Type", "IOC"], ...arr.map((orig, i) => [cat, shown[i]])];
    downloadBlob(new Blob([toCSV(rows)], { type: "text/csv;charset=utf-8" }), `${cat.toLowerCase()}_iocs.csv`);
  };
  const exportTypeXLSX = (cat, arr) => {
    const shown = proc(arr, cat);
    const rows = [["IOC"], ...arr.map((orig, i) => [shown[i]])];
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
      <div className="mx-auto max-w-7xl px-4 py-6 sm:px-6">
        <div className="flex items-start gap-3 mb-5 flex-wrap">
          <div className="flex h-11 w-11 items-center justify-center rounded-lg shrink-0"
            style={{ backgroundColor: "rgba(0,229,255,0.08)", border: "1px solid rgba(0,229,255,0.35)", boxShadow: "0 0 22px rgba(0,229,255,0.25)" }}>
            <Shield size={22} style={{ color: "#00e5ff" }} />
          </div>
          <div className="min-w-0">
            <h1 className="text-xl sm:text-2xl font-bold tracking-tight" style={{ color: "#eafcff", textShadow: "0 0 18px rgba(0,229,255,0.35)" }}>
              Intel Extractor
            </h1>
            <p className="text-[11px]" style={{ color: "#5d7382", letterSpacing: "2px", marginTop: "2px" }}>
              EXTRACT · ENRICH · HUNT
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
                title="CrowdStrike hunting queries on GitHub"
                className="flex items-center gap-1.5 rounded-md px-2 py-1 text-xs font-semibold"
                style={{ color: "#ff4d4d", border: "1px solid rgba(255,77,77,0.4)", backgroundColor: "rgba(255,77,77,0.08)" }}>
                <Github size={13} /><Target size={13} /> CrowdStrike Queries
              </a>
              <a href="https://github.com/Aamir-Muhammad/KQL-Queries" target="_blank" rel="noreferrer noopener"
                title="Defender XDR hunting queries on GitHub"
                className="flex items-center gap-1.5 rounded-md px-2 py-1 text-xs font-semibold"
                style={{ color: "#00b7ff", border: "1px solid rgba(0,183,255,0.4)", backgroundColor: "rgba(0,183,255,0.08)" }}>
                <Github size={13} /><ShieldCheck size={13} /> Defender XDR Queries
              </a>
            </div>
          </div>
        </div>

        {total > 0 && (
        <div className="flex items-center gap-3 mb-4 py-3" style={{ borderBottom: "1px solid rgba(120,160,180,0.08)" }}>
          <span className="text-3xl font-medium tabular-nums" style={{ color: "#00ff9c", letterSpacing: "-1px" }}>{total}</span>
          <span className="text-[10px] uppercase" style={{ color: "#5d7382", letterSpacing: "1.5px" }}>indicators</span>
          <div className="shrink-0" style={{ width: "1px", height: "28px", background: "rgba(120,160,180,0.15)" }}></div>
          <span className="text-3xl font-medium tabular-nums" style={{ color: "#00e5ff", letterSpacing: "-1px" }}>{entries.length}</span>
          <span className="text-[10px] uppercase" style={{ color: "#5d7382", letterSpacing: "1.5px" }}>types</span>
          <div className="ml-auto flex items-center gap-2">
            <button onClick={() => setDefangAll((v) => !v)}
              title="Defang every IOC type at once"
              className="flex items-center gap-1.5 rounded-lg px-3 py-2 text-sm font-semibold"
              style={{
                color: defangAll ? "#04111a" : "#ffb84d",
                backgroundColor: defangAll ? "#ffb84d" : "rgba(255,184,77,0.14)",
                border: `1px solid rgba(255,184,77,${defangAll ? "1" : "0.55"})`,
              }}>
              <ShieldOff size={15} /> {defangAll ? "Defanged" : "Defang"}
            </button>
            <GButton onClick={exportAllCSV} disabled={!total} color="#00ff9c" icon={<Download size={15} />}>CSV</GButton>
            <GButton onClick={exportAllXLSX} disabled={!total} color="#00e5ff" icon={<Download size={15} />}>XLSX</GButton>
          </div>
        </div>
        )}

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
                <span className="text-xs ml-auto" style={{ color: "#5d7382" }}>
                  Handles <span style={{ color: "#8aa0ad" }}>[md](links)</span>, defang, reg add &amp; paths with spaces
                </span>
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
          <div className="flex items-start gap-3 mb-3 py-3" style={{ borderBottom: "1px solid rgba(120,160,180,0.06)" }}>
            <FileText size={16} className="shrink-0 mt-0.5" style={{ color: "#5d7382" }} />
            <div className="min-w-0 flex-1">
              {meta.title && (
                <h2 className="text-sm font-medium leading-snug" style={{ color: "#eafcff" }}>{meta.title}</h2>
              )}
              {meta.description && (
                <p className="text-xs mt-1 leading-relaxed overflow-hidden" style={{ color: "#7f95a3", display: "-webkit-box", WebkitLineClamp: 2, WebkitBoxOrient: "vertical" }}>{meta.description}</p>
              )}
              <div className="flex flex-wrap items-center gap-2 mt-1.5">
                {sourceUrl && sourceUrl !== "(pasted JSON)" && sourceUrl !== "(raw paste)" && (
                  <a href={sourceUrl} target="_blank" rel="noreferrer noopener"
                    className="inline-flex items-center gap-1 text-[11px] truncate max-w-full"
                    style={{ color: "#5d7382" }}>
                    <Globe size={10} className="shrink-0" /> <span className="truncate">{defang(stripScheme(sourceUrl))}</span>
                  </a>
                )}
                {Array.isArray(meta.tags) && meta.tags.filter(Boolean).map((t, i) => (
                  <span key={i} className="text-[10px] rounded-full px-2 py-0.5"
                    style={{ color: "#c084fc", border: "1px solid rgba(192,132,252,0.2)", backgroundColor: "rgba(192,132,252,0.04)" }}>
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
                {aiState === "idle" && (
                  <span className="text-[10px] uppercase tracking-widest rounded-full px-2 py-0.5 hidden sm:inline"
                    style={{ color: "#8aa0ad", border: "1px solid rgba(120,160,180,0.3)" }}>
                    click to generate
                  </span>
                )}
              </span>
              <ChevronDown size={18} className="shrink-0 transition-transform"
                style={{ color: "#c084fc", transform: aiOpen ? "rotate(180deg)" : "rotate(0deg)" }} />
            </button>

            {aiOpen && (
              <div className="px-4 pb-4 pt-1" style={{ borderTop: "1px solid rgba(192,132,252,0.2)" }}>
                {aiState === "loading" && (
                  <p className="text-xs sm:text-sm animate-pulse pt-2" style={{ color: "#9fb3bd" }}>
                    Analyzing article and generating summary…
                  </p>
                )}

                {aiState === "done" && aiSummary && (
                  <div className="pt-2">
                    <h2 className="text-sm sm:text-base font-extrabold leading-snug" style={{ color: "#eafcff" }}>{aiSummary.headline}</h2>
                    {aiSummary.executive_summary && (
                      <>
                        <p className="text-xs sm:text-sm uppercase tracking-widest font-bold mt-2.5 mb-1" style={{ color: "#00e5ff" }}>Executive Summary</p>
                        <p className="text-xs sm:text-sm leading-relaxed" style={{ color: "#d4e3ea" }}>{defangProse(aiSummary.executive_summary)}</p>
                      </>
                    )}
                    <p className="text-xs sm:text-sm uppercase tracking-widest font-bold mt-3 mb-1" style={{ color: "#00e5ff" }}>Technical Analysis</p>
                    <p className="text-xs sm:text-sm font-medium leading-relaxed" style={{ color: "#b8c9d1" }}>{defangProse(aiSummary.summary)}</p>
                    {aiSummary.recommendations.length > 0 && (
                      <div className="mt-2.5">
                        <p className="text-xs sm:text-sm uppercase tracking-widest font-bold mb-1" style={{ color: "#00e5ff" }}>Recommendations</p>
                        {aiSummary.recommendations.map((rec, i) => (
                          <div key={i} className="flex items-start gap-1.5 text-xs sm:text-sm py-0.5 leading-relaxed font-medium" style={{ color: "#9fb3bd" }}>
                            <span className="shrink-0" style={{ color: "#c084fc" }}>▸</span> <span>{defangProse(rec)}</span>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                )}

                {aiState === "error" && (
                  <div className="pt-2">
                    <p className="text-xs sm:text-sm leading-relaxed" style={{ color: "#ffb4b4" }}>
                      The AI engines are experiencing high traffic right now, so a summary couldn't be generated. Please give it a moment and retry.
                    </p>
                    <button onClick={retryAi} disabled={cooldown > 0}
                      className="mt-2.5 flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs font-semibold"
                      style={{
                        color: cooldown > 0 ? "#5d7382" : "#c084fc",
                        border: `1px solid ${cooldown > 0 ? "rgba(120,160,180,0.25)" : "rgba(192,132,252,0.45)"}`,
                        backgroundColor: cooldown > 0 ? "rgba(120,160,180,0.06)" : "rgba(192,132,252,0.10)",
                        cursor: cooldown > 0 ? "not-allowed" : "pointer",
                      }}>
                      <RefreshCw size={13} />
                      {cooldown > 0 ? `Retry available in ${cooldown}s` : "Retry AI Summary"}
                    </button>
                  </div>
                )}

                {aiState === "idle" && (
                  <p className="text-xs sm:text-sm pt-2 animate-pulse" style={{ color: "#9fb3bd" }}>
                    Initializing…
                  </p>
                )}
              </div>
            )}
          </div>
        )}

        {(articleClean || rawArticle) && sourceUrl && (
          <div className="rounded-xl mb-4 overflow-hidden" style={{ ...panel, borderColor: "rgba(253,224,71,0.35)" }}>
            <div className="flex items-center justify-between px-4 py-3 gap-3 flex-wrap">
              <span className="flex items-center gap-2.5 min-w-0">
                <span className="shrink-0 flex h-7 w-7 items-center justify-center rounded-lg"
                  style={{ backgroundColor: "rgba(253,224,71,0.08)", border: "1px solid rgba(253,224,71,0.35)" }}>
                  <span style={{ fontSize: 14 }}>🧠</span>
                </span>
                <span className="text-sm font-bold tracking-wide" style={{ color: "#fde047" }}>AI Scan Threat Hunting Artifacts</span>
                {aiScanState === "idle" && (
                  <span className="text-[10px] uppercase tracking-widest rounded-full px-2 py-0.5 hidden sm:inline"
                    style={{ color: "#8aa0ad", border: "1px solid rgba(120,160,180,0.3)" }}>
                    catches what regex missed
                  </span>
                )}
                {aiScanState === "done" && aiScanCounts && (
                  <span className="text-[10px] uppercase tracking-widest rounded-full px-2 py-0.5"
                    style={{ color: "#00ff9c", border: "1px solid rgba(0,255,156,0.35)", backgroundColor: "rgba(0,255,156,0.06)" }}>
                    +{aiScanCounts.scheduled_tasks + aiScanCounts.services + aiScanCounts.registry_ops + aiScanCounts.command_lines + aiScanCounts.file_paths} artifacts merged
                  </span>
                )}
              </span>
              <button onClick={runAIScan} disabled={aiScanState === "loading" || aiScanState === "done"}
                className="flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs font-semibold"
                style={{
                  color: aiScanState === "done" ? "#5d7382" : "#04111a",
                  backgroundColor: aiScanState === "done" ? "rgba(120,160,180,0.06)" : "#fde047",
                  border: `1px solid ${aiScanState === "done" ? "rgba(120,160,180,0.25)" : "rgba(253,224,71,0.6)"}`,
                  cursor: (aiScanState === "loading" || aiScanState === "done") ? "not-allowed" : "pointer",
                }}>
                {aiScanState === "loading" ? <Loader2 size={13} className="animate-spin" /> : aiScanState === "done" ? <Check size={13} /> : <span style={{ fontSize: 12 }}>🧠</span>}
                {aiScanState === "loading" ? "Scanning…" : aiScanState === "done" ? "Scan complete" : "Run AI Scan"}
              </button>
            </div>
            {aiScanState === "error" && (
              <div className="px-4 pb-3 pt-1 text-xs" style={{ color: "#ffb4b4", borderTop: "1px solid rgba(255,77,77,0.2)" }}>
                {aiScanError || "AI scan failed. Please retry."}
                <button onClick={() => { setAiScanState("idle"); setAiScanError(""); }}
                  className="ml-2 underline" style={{ color: "#fde047" }}>reset</button>
              </div>
            )}
            {aiScanState === "done" && aiScanCounts && (aiScanCounts.scheduled_tasks + aiScanCounts.services + aiScanCounts.registry_ops + aiScanCounts.command_lines + aiScanCounts.file_paths) === 0 && (
              <div className="px-4 pb-3 pt-1 text-xs" style={{ color: "#8aa0ad", borderTop: "1px solid rgba(253,224,71,0.15)" }}>
                No additional artifacts found beyond what regex already captured.
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
            const isReg = cat === "REGISTRY";
            return (
              <div key={cat} id={`cat-${cat}`} className="rounded-xl overflow-hidden flex flex-col" style={{ ...panel, borderColor: `${c}40` }}>
                <div className="flex items-center justify-between px-4 py-2.5 gap-2" style={{ borderBottom: `1px solid ${c}33`, backgroundColor: `${c}0d` }}>
                  <div className="flex items-center gap-2 min-w-0">
                    <span style={{ width: 9, height: 9, borderRadius: 99, backgroundColor: c, boxShadow: `0 0 10px ${c}` }} />
                    <span className="font-bold tracking-wide truncate" style={{ color: c, textShadow: `0 0 12px ${c}55` }}>{cat}</span>
                  </div>
                  <div className="flex items-center gap-2 shrink-0">
                    {["IPV4","IPV6","DOMAIN","URL","MD5","SHA1","SHA256","SHA512","CVE"].includes(cat) && (
                      <button onClick={() => { arr.forEach((v, i) => setTimeout(() => enrichIOC(cat, v), i * 1500)); }}
                        className="flex items-center gap-1 rounded-md px-2 py-1 text-xs"
                        style={{ color: "#2dd4bf", backgroundColor: "rgba(45,212,191,0.10)", border: "1px solid rgba(45,212,191,0.4)" }}>
                        <Search size={12} /> Enrich All
                      </button>
                    )}
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

                <div className="px-4 py-2 overflow-y-auto flex-1" style={{ maxHeight: 420 }}>
                  {shown.map((ioc, i) => {
                    const huntReady = isReg && huntReadySet.has(arr[i]);
                    const rowKey = `${cat}-i-${i}`;
                    const isCopied = copied === rowKey;
                    const eKey = `${cat}::${arr[i]}`;
                    const enr = enrichCache[eKey];
                    const enrichable = ["IPV4","IPV6","DOMAIN","URL","MD5","SHA1","SHA256","SHA512","CVE"].includes(cat);
                    return (
                      <div key={i}>
                        <div className="group flex items-start gap-1.5 py-0.5 leading-relaxed"
                          title={huntReady ? "Hunt-ready: key + value captured — enriches the hunt queries below" : undefined}>
                          <span className="text-xs shrink-0" style={{ color: `${c}aa`, userSelect: "none" }}>›</span>
                          <span className="text-xs break-all flex-1 min-w-0"
                            style={{ color: huntReady ? "#f3ddfa" : "#c8d6dd", fontWeight: huntReady ? 600 : 400 }}>
                            {ioc}
                          </span>
                          {enrichable && (
                            <button onClick={() => enrichIOC(cat, arr[i])}
                              title="Enrich via ThreatFox / URLhaus / MalwareBazaar / OTX"
                              className="shrink-0 rounded-md p-1 opacity-50 hover:opacity-100 transition-opacity"
                              style={{ color: enr?.data ? "#00ff9c" : enr?.error ? "#ff6b6b" : "#c084fc" }}>
                              {enr?.loading ? <Loader2 size={14} className="animate-spin" /> : <Search size={14} />}
                            </button>
                          )}
                          {vtLink(cat, arr[i]) && (
                            <a href={vtLink(cat, arr[i])} target="_blank" rel="noreferrer noopener"
                              title="Open in VirusTotal"
                              className="shrink-0 rounded-md p-1 opacity-50 hover:opacity-100 transition-opacity flex items-center justify-center"
                              style={{ width: 26, height: 26 }}>
                              <img src="https://www.virustotal.com/gui/images/favicon.png" alt="VT" width={14} height={14} style={{ display: "block", marginTop: "-1px" }} />
                            </a>
                          )}
                          <button onClick={() => copyText(ioc, rowKey)}
                            title="Copy this indicator"
                            className="shrink-0 rounded-md p-1 opacity-50 hover:opacity-100 transition-opacity"
                            style={{ color: isCopied ? c : "#8aa0ad" }}>
                            {isCopied ? <Check size={16} /> : <Copy size={16} />}
                          </button>
                          <button onClick={() => removeIoc(cat, arr[i])}
                            title="Discard this indicator"
                            className="shrink-0 rounded-md p-1 opacity-50 hover:opacity-100 transition-opacity"
                            style={{ color: "#ff6b6b" }}>
                            <X size={16} />
                          </button>
                        </div>
                        {enr?.data && (
                          <div className="ml-4 mb-1.5 flex flex-wrap gap-1 text-[10px]">
                            {enr.data._verdict && enr.data._verdict !== "Unknown" && (
                              <span className="rounded-full px-2 py-0.5 font-bold" style={{
                                color: enr.data._verdict === "Malicious" ? "#ff4d6d" : enr.data._verdict === "Suspicious" ? "#fbbf24" : enr.data._verdict === "Whitelisted" ? "#00ff9c" : "#8aa0ad",
                                backgroundColor: enr.data._verdict === "Malicious" ? "rgba(255,77,109,0.15)" : enr.data._verdict === "Suspicious" ? "rgba(251,191,36,0.15)" : enr.data._verdict === "Whitelisted" ? "rgba(0,255,156,0.15)" : "rgba(138,160,173,0.15)",
                                border: `1px solid ${enr.data._verdict === "Malicious" ? "rgba(255,77,109,0.4)" : enr.data._verdict === "Suspicious" ? "rgba(251,191,36,0.4)" : enr.data._verdict === "Whitelisted" ? "rgba(0,255,156,0.4)" : "rgba(138,160,173,0.3)"}`,
                              }}>
                                {enr.data._verdict === "Malicious" ? "🔴" : enr.data._verdict === "Suspicious" ? "🟡" : enr.data._verdict === "Whitelisted" ? "🟢" : "⚪"} {enr.data._verdict}
                              </span>
                            )}
                            {enr.data.threatfox && (
                              <span className="rounded-full px-2 py-0.5" style={{ color: "#ff4d6d", backgroundColor: "rgba(255,77,109,0.12)", border: "1px solid rgba(255,77,109,0.3)" }}>
                                ThreatFox · {enr.data.threatfox.malware} · {enr.data.threatfox.threat}{enr.data.threatfox.confidence ? ` · ${enr.data.threatfox.confidence}%` : ""}{enr.data.threatfox.tags ? ` · ${enr.data.threatfox.tags}` : ""}
                              </span>
                            )}
                            {enr.data.urlhaus && (
                              <span className="rounded-full px-2 py-0.5" style={{
                                color: enr.data.urlhaus.status === "online" ? "#ff4d6d" : "#fbbf24",
                                backgroundColor: enr.data.urlhaus.status === "online" ? "rgba(255,77,109,0.12)" : "rgba(251,191,36,0.12)",
                                border: `1px solid ${enr.data.urlhaus.status === "online" ? "rgba(255,77,109,0.3)" : "rgba(251,191,36,0.3)"}`,
                              }}>
                                URLhaus · {enr.data.urlhaus.status === "online" ? "🔴 Online" : "⚫ Offline"}{enr.data.urlhaus.urls_total ? ` · ${enr.data.urlhaus.urls_total} URLs` : ""}{enr.data.urlhaus.tags ? ` · ${enr.data.urlhaus.tags}` : ""}
                              </span>
                            )}
                            {enr.data.malwarebazaar && (
                              <span className="rounded-full px-2 py-0.5" style={{ color: "#00e5ff", backgroundColor: "rgba(0,229,255,0.12)", border: "1px solid rgba(0,229,255,0.3)" }}>
                                MalBazaar · {enr.data.malwarebazaar.family} · {enr.data.malwarebazaar.type}{enr.data.malwarebazaar.size ? ` · ${enr.data.malwarebazaar.size}` : ""}{enr.data.malwarebazaar.delivery ? ` · via ${enr.data.malwarebazaar.delivery}` : ""}{enr.data.malwarebazaar.tags ? ` · ${enr.data.malwarebazaar.tags}` : ""}
                              </span>
                            )}
                            {enr.data.malwarebazaar?.detections && (
                              <span className="rounded-full px-2 py-0.5" style={{ color: "#f59e0b", backgroundColor: "rgba(245,158,11,0.12)", border: "1px solid rgba(245,158,11,0.3)" }}>
                                {enr.data.malwarebazaar.detections}
                              </span>
                            )}
                            {enr.data.otx && enr.data._verdict !== "Unknown" && (
                              <span className="rounded-full px-2 py-0.5" style={{ color: "#2dd4bf", backgroundColor: "rgba(45,212,191,0.12)", border: "1px solid rgba(45,212,191,0.3)" }}>
                                OTX · {enr.data.otx.pulses} pulses{enr.data.otx.validation ? ` · ${enr.data.otx.validation}` : ""}{enr.data.otx.tags ? ` · ${enr.data.otx.tags}` : ""}{enr.data.otx.parentDomain ? ` (via ${enr.data.otx.parentDomain})` : ""}
                              </span>
                            )}
                            {enr.data.whoisASN && (
                              <span className="rounded-full px-2 py-0.5" style={{ color: "#a78bfa", backgroundColor: "rgba(167,139,250,0.12)", border: "1px solid rgba(167,139,250,0.3)" }}>
                                WHOIS/ASN{enr.data.whoisASN.country ? <>{" · "}<span style={{ color: "#eafcff", fontWeight: 700 }}>{enr.data.whoisASN.flag ? enr.data.whoisASN.flag + " " : ""}{enr.data.whoisASN.country}</span></> : ""}{enr.data.whoisASN.city ? ` (${enr.data.whoisASN.city})` : ""}{enr.data.whoisASN.asn ? ` · ${enr.data.whoisASN.asn}` : ""}
                              </span>
                            )}
                            {enr.data.whois && (
                              <span className="rounded-full px-2 py-0.5" style={{ color: "#a78bfa", backgroundColor: "rgba(167,139,250,0.12)", border: "1px solid rgba(167,139,250,0.3)" }}>
                                WHOIS{enr.data.whois.org ? ` · ${enr.data.whois.org}` : ""}{enr.data.whois.country ? ` · ${enr.data.whois.country}` : ""}{enr.data.whois.ageDays !== null ? ` · ${enr.data.whois.ageDays}d old` : ""}
                              </span>
                            )}
                            {enr.data.validin && (
                              <span className="rounded-full px-2 py-0.5" style={{
                                color: enr.data.validin.verdict === "malicious" ? "#ff4d6d" : enr.data.validin.verdict === "suspicious" ? "#fbbf24" : "#e879f9",
                                backgroundColor: enr.data.validin.verdict === "malicious" ? "rgba(255,77,109,0.12)" : enr.data.validin.verdict === "suspicious" ? "rgba(251,191,36,0.12)" : "rgba(232,121,249,0.12)",
                                border: `1px solid ${enr.data.validin.verdict === "malicious" ? "rgba(255,77,109,0.3)" : enr.data.validin.verdict === "suspicious" ? "rgba(251,191,36,0.3)" : "rgba(232,121,249,0.3)"}`,
                              }}>
                                Validin{enr.data.validin.verdict ? ` · ${enr.data.validin.verdict}` : ""}{enr.data.validin.score !== null ? ` (${enr.data.validin.score}/10)` : ""}{enr.data.validin.maliciousCount > 0 ? ` · Malicious x ${enr.data.validin.maliciousCount}` : ""}{enr.data.validin.titles?.length ? ` · ${enr.data.validin.titles.join(" · ")}` : ""}
                              </span>
                            )}
                          </div>
                        )}
                        {enr && !enr.loading && !enr.data && enr.error && (
                          <p className="ml-4 mb-1 text-[10px] font-bold" style={{ color: "#5d7382" }}>⚪ Unknown to our integrated Enrichment Engines. Please check on VirusTotal.</p>
                        )}
                        {enr?.data && enr.data._verdict === "Unknown" && (
                          <p className="ml-4 mb-1 text-[10px] font-bold" style={{ color: "#5d7382" }}>⚪ Unknown to our integrated Enrichment Engines. Please check on VirusTotal.</p>
                        )}
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

                {!isReg && HUNT_CATS.has(cat) && (
                  <div className="px-3 py-2 flex flex-wrap items-center gap-1.5" style={{ borderTop: `1px solid ${c}22`, backgroundColor: `${c}08` }}>
                    <span className="text-[10px] uppercase tracking-wider flex items-center gap-1 mr-1" style={{ color: "#8aa0ad" }}>
                      <Crosshair size={11} /> Hunt
                    </span>
                    {huntKQL(cat, arr) && <CopyBtn label="Defender KQL" copied={copied === `${cat}-hunt-kql`} onClick={() => copyText(huntKQL(cat, arr), `${cat}-hunt-kql`)} color={c} />}
                    {huntCQL(cat, arr) && <CopyBtn label="CrowdStrike CQL" copied={copied === `${cat}-hunt-cql`} onClick={() => copyText(huntCQL(cat, arr), `${cat}-hunt-cql`)} color={c} />}
                    {huntSPL(cat, arr) && <CopyBtn label="Splunk SPL" copied={copied === `${cat}-hunt-spl`} onClick={() => copyText(huntSPL(cat, arr), `${cat}-hunt-spl`)} color={c} />}
                  </div>
                )}

                <div className="px-3 py-2.5 flex flex-wrap items-center gap-1.5" style={{ borderTop: `1px solid ${c}22` }}>
                  <span className="text-[10px] uppercase tracking-wider flex items-center gap-1 mr-1" style={{ color: "#8aa0ad" }}>
                    <Copy size={11} /> Copy
                  </span>
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

        <p className="text-center mt-8" style={{ color: "#2a3a42", fontSize: "10px", letterSpacing: "1.5px" }}>
          IOC EXTRACTION · THREAT HUNTING ARTIFACTS · HUNTING QUERY GENERATION
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
