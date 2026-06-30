import { useState, useMemo, useRef } from "react";
import * as XLSX from "xlsx";
import {
  Shield, Search, Download, Copy, Check, Loader2, Globe,
  ClipboardPaste, AlertTriangle, ShieldOff, Trash2, Wand2, FileDown, Code
} from "lucide-react";

// ⚠️ SET THIS to your Cloudflare Worker URL from Part 1
const WORKER_BASE = "https://ioc-parser.aamirmuhd.workers.dev/";

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
  REGISTRY: "#e879f9", FILE: "#94a3b8",
  MITRE_ATTACK: "#f43f5e",
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

const FILE_EXT = /\.(exe|dll|sys|scr|pif|cpl|msi|msp|ps1|psm1|psd1|bat|cmd|vbs|vbe|js|jse|wsf|wsh|hta|sct|jar|py|pyc|pl|rb|elf|bin|deb|rpm|apk|dmg|lnk|inf|reg|iso|img|vhd|vmdk|ova|rar|7z|gz|tgz|bz2|xz|cab|ace|tar|txt|csv|tsv|xml|json|yaml|yml|eml|msg|pdf|rtf|docx?|docm|xlsx?|xlsm|xlsb|pptx?|pptm|odt|ods|odp|tmp|dat|log|db|sqlite|key|pem|crt|cer|p12|pfx|chm)$/i;

const isIPv4 = (t) => {
  const m = t.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  return m && m.slice(1).every((o) => +o >= 0 && +o <= 255);
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
  if (/^(HKLM|HKCU|HKCR|HKU|HKEY_[A-Z_]+)[\\/]/i.test(t)) return ["REGISTRY", t];
  if (/\\/.test(t)) return ["FILE", t];
  if (FILE_EXT.test(t)) return ["FILE", t];
  if (/^([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/i.test(t)) return ["DOMAIN", t.toLowerCase()];
  return null;
};

const ORDER = ["IPV4","IPV6","DOMAIN","URL","EMAIL","MD5","SHA1","SHA256","SHA512","SSDEEP","CVE","MITRE_ATTACK","ASN","MAC_ADDRESS","BTC","XMR","ETH","REGISTRY","FILE"];

const extractIocs = (text) => {
  const buckets = {};
  const add = (cat, val) => (buckets[cat] || (buckets[cat] = new Set())).add(val);
  let work = refangSoft(text);

  work = work.replace(/\[([^\]\n]+)\]\(([^)\n]*)\)/g, (_m, label) => {
    const t = trimTok(label.trim());
    if (t) { const r = classify(t); if (r) add(r[0], r[1]); }
    return "\n";
  });

  const segments = work.replace(/[\[\]]/g, "").split(/[\n\r;,|]+/);

  for (let seg of segments) {
    let s = seg
      .replace(/^[\s\-*•·\u2022>]+/, "")
      .replace(/^\d+[.)]\s+/, "")
      .replace(/^["'`]+|["'`]+$/g, "")
      .trim();
    if (!s) continue;

    const tokens = s.split(/[\s"'`<>]+/).map(trimTok).filter(Boolean);
    const hasOtherIoc = tokens.some((t) => { const r = classify(t); return r && r[0] !== "FILE"; });
    const extTokens = tokens.filter((t) => FILE_EXT.test(t));

    const spacedFilename =
      /\s/.test(s) && !s.includes("/") && !/:\/\//.test(s) &&
      FILE_EXT.test(s) && !hasOtherIoc && extTokens.length === 1;

    if (spacedFilename) { add("FILE", s); continue; }

    for (const t of tokens) {
      const r = classify(t);
      if (r) add(r[0], r[1]);
    }
  }

  const out = {};
  ORDER.forEach((k) => { if (buckets[k]) out[k] = Array.from(buckets[k]); });
  Object.keys(buckets).forEach((k) => { if (!out[k]) out[k] = Array.from(buckets[k]); });
  return out;
};

const parseIocs = (raw) => {
  let d = raw;
  if (raw && typeof raw === "object" && raw.data && typeof raw.data === "object") d = raw.data;
  const out = {};
  if (d && typeof d === "object") {
    Object.entries(d).forEach(([k, v]) => {
      if (Array.isArray(v)) {
        const uniq = Array.from(new Set(v.map((x) => String(x).trim()).filter(Boolean)));
        if (uniq.length) out[k] = uniq;
      }
    });
  }
  return out;
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
    .replace(/[ \t]+\n/g, "\n");

// ============================================================
//  KQL/CQL Query Extraction
// ============================================================
const extractQueries = (html) => {
  const queries = [];
  
  // Find section headers for context
  const sections = html.split(/<h[2-3][^>]*>/gi);
  
  for (const section of sections) {
    const sectionTitle = section.match(/^([^<]+)/)?.[1] || "Unknown";
    
    // Extract <pre> and <code> blocks
    const preMatches = section.matchAll(/<pre[^>]*>([\s\S]*?)<\/pre>/gi);
    for (const match of preMatches) {
      let code = match[1]
        .replace(/<code[^>]*>/gi, "")
        .replace(/<\/code>/gi, "")
        .replace(/<[^>]+>/g, "") // strip remaining HTML
        .replace(/&lt;/g, "<")
        .replace(/&gt;/g, ">")
        .replace(/&amp;/g, "&")
        .replace(/&#0?39;|&apos;/g, "'")
        .replace(/&quot;/g, '"')
        .trim();
      
      if (code.length > 20) { // filter out tiny blocks
        // Detect query type
        let type = "Code block";
        if (/let\s+\w+\s*=|union|summarize|where\s+\||project\s+\|/.test(code)) type = "KQL";
        if (/event_simpleName|ProcessRollup2|groupBy/.test(code)) type = "CQL";
        
        queries.push({
          type,
          code,
          context: sectionTitle.slice(0, 60),
        });
      }
    }
  }
  
  return queries;
};

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

const SAMPLE_URL = "https://www.microsoft.com/en-us/security/blog/2026/05/28/the-gentlemen-ransomware-dissecting-a-self-propagating-go-encryptor/";

export default function App() {
  const [mode, setMode] = useState("url");
  const [url, setUrl] = useState(SAMPLE_URL);
  const [jsonText, setJsonText] = useState("");
  const [rawText, setRawText] = useState("");
  const [iocData, setIocData] = useState(null);
  const [queries, setQueries] = useState([]);
  const [sourceUrl, setSourceUrl] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [fetchVia, setFetchVia] = useState("");
  const [rawArticle, setRawArticle] = useState("");
  const [defangMap, setDefangMap] = useState({});
  const [copied, setCopied] = useState("");
  const copyTimer = useRef(null);

  const entries = useMemo(
    () => (iocData ? Object.entries(iocData).sort((a, b) => b[1].length - a[1].length) : []),
    [iocData]
  );
  const total = useMemo(() => entries.reduce((s, [, v]) => s + v.length, 0), [entries]);

  const proc = (arr, cat) => (defangMap[cat] ? arr.map(defang) : arr);
  const toggleDefang = (cat) => setDefangMap((m) => ({ ...m, [cat]: !m[cat] }));

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

  const runFetch = async () => {
    setError(""); setLoading(true); setIocData(null); setQueries([]); setFetchVia(""); setRawArticle("");

    if (!WORKER_BASE || WORKER_BASE.includes("YOUR-WORKER")) {
      setError('ERROR: Set WORKER_BASE at the top of App.jsx to your Cloudflare Worker URL from Part 1.');
      setLoading(false);
      return;
    }

    // Hop 1: iocparser via Worker
    try {
      const res = await fetch(`${WORKER_BASE}/parse`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url }),
      });
      if (res.ok) {
        const json = await res.json();
        const parsed = parseIocs(json);
        if (Object.keys(parsed).length) {
          setIocData(parsed); setSourceUrl(url); setFetchVia("iocparser.com"); setLoading(false);
          return;
        }
      }
    } catch { /* fall through */ }

    // Hop 2: full page fetch + local parse + query extraction
    try {
      const res = await fetch(`${WORKER_BASE}/fetch?url=${encodeURIComponent(url)}`);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const html = await res.text();
      if (!html || html.length < 50) throw new Error("empty response");
      
      const text = htmlToText(html);
      const parsed = extractIocs(text);
      const foundQueries = extractQueries(html);
      
      if (!Object.keys(parsed).length && foundQueries.length === 0) throw new Error("no IOCs or queries found");
      
      setRawArticle(text);
      setIocData(parsed);
      setQueries(foundQueries);
      setSourceUrl(url);
      setFetchVia(`page fetch + local parse${foundQueries.length > 0 ? ` (${foundQueries.length} queries)` : ""}`);
      setLoading(false);
      return;
    } catch (e) {
      setError(`Fetch failed: ${e.message}. Check Worker URL is correct, or use "Paste IOCs".`);
    }
    setLoading(false);
  };

  const runPaste = () => {
    setError(""); setIocData(null);
    try {
      const parsed = parseIocs(JSON.parse(jsonText));
      if (!Object.keys(parsed).length) throw new Error("No IOC arrays found.");
      setIocData(parsed); setSourceUrl("(pasted JSON)"); setFetchVia(""); setRawArticle(""); setQueries([]);
    } catch (e) { setError(`JSON parse error: ${e.message}`); }
  };

  const runRaw = () => {
    setError(""); setIocData(null);
    const parsed = extractIocs(rawText);
    if (!Object.keys(parsed).length) {
      setError("No IOCs found. Handles: IPs, domains, URLs, emails, hashes, CVEs, MITRE IDs, ASNs, crypto, MACs, registry keys, filenames (with spaces).");
      return;
    }
    setIocData(parsed); setSourceUrl("(raw paste)"); setFetchVia(""); setRawArticle(""); setQueries([]);
  };

  const saveArticle = () =>
    downloadBlob(new Blob([rawArticle], { type: "text/plain;charset=utf-8" }), `article_${Date.now()}.txt`);

  const exportAllCSV = () => {
    const rows = [["Type", "IOC"]];
    entries.forEach(([cat, arr]) => proc(arr, cat).forEach((v) => rows.push([cat, v])));
    downloadBlob(new Blob([toCSV(rows)], { type: "text/csv;charset=utf-8" }), "all_iocs.csv");
  };
  const exportAllXLSX = () => {
    const all = [["Type", "IOC"]];
    entries.forEach(([cat, arr]) => proc(arr, cat).forEach((v) => all.push([cat, v])));
    const sheets = [{ name: "All_IOCs", rows: all }];
    entries.forEach(([cat, arr]) => sheets.push({ name: cat, rows: [["IOC"], ...proc(arr, cat).map((v) => [v])] }));
    downloadBlob(buildWorkbook(sheets), "all_iocs.xlsx");
  };
  const exportTypeCSV = (cat, arr) => {
    const rows = [["Type", "IOC"], ...proc(arr, cat).map((v) => [cat, v])];
    downloadBlob(new Blob([toCSV(rows)], { type: "text/csv;charset=utf-8" }), `${cat.toLowerCase()}_iocs.csv`);
  };
  const exportTypeXLSX = (cat, arr) => {
    const rows = [["IOC"], ...proc(arr, cat).map((v) => [v])];
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
      <div className="mx-auto max-w-6xl px-4 py-6 sm:px-6">
        <div className="flex items-center gap-3 mb-5">
          <div className="flex h-11 w-11 items-center justify-center rounded-lg"
            style={{ backgroundColor: "rgba(0,229,255,0.08)", border: "1px solid rgba(0,229,255,0.35)", boxShadow: "0 0 22px rgba(0,229,255,0.25)" }}>
            <Shield size={22} style={{ color: "#00e5ff" }} />
          </div>
          <div>
            <h1 className="text-xl sm:text-2xl font-bold tracking-tight" style={{ color: "#eafcff", textShadow: "0 0 18px rgba(0,229,255,0.35)" }}>
              IOC &amp; Detection Query Extractor
            </h1>
            <p className="text-xs sm:text-sm" style={{ color: "#7f95a3" }}>
              Extract IOCs + KQL/CQL queries · self-hosted · local parsing · zero tokens
            </p>
          </div>
        </div>

        <div className="rounded-xl p-3 mb-4 flex flex-wrap items-center gap-2" style={panel}>
          <span className="text-xs uppercase tracking-widest mr-1" style={{ color: "#7f95a3" }}>Export IOCs</span>
          <GButton onClick={exportAllCSV} disabled={!total} color="#00ff9c" icon={<Download size={15} />}>CSV</GButton>
          <GButton onClick={exportAllXLSX} disabled={!total} color="#00e5ff" icon={<Download size={15} />}>XLSX</GButton>
          {total > 0 && (
            <span className="text-xs ml-auto" style={{ color: "#7f95a3" }}>
              <span style={{ color: "#00ff9c", fontWeight: 700 }}>{total}</span> IOCs · {entries.length} types
              {queries.length > 0 && <span style={{ color: "#c084fc" }}> · {queries.length} queries</span>}
            </span>
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
                  {loading ? "Fetching…" : "Fetch"}
                </GButton>
              </div>
              <p className="text-xs" style={{ color: "#5d7382" }}>
                Extracts IOCs + KQL/CQL queries from threat intel pages (Microsoft, etc). Fetches via your Cloudflare Worker.
              </p>
            </div>
          )}

          {mode === "paste" && (
            <div className="flex flex-col gap-2">
              <textarea
                value={jsonText}
                onChange={(e) => setJsonText(e.target.value)}
                placeholder='{"IPV4":["1.2.3.4"],"DOMAIN":["evil.com"]} or {"data":{...}}'
                rows={5}
                className="w-full rounded-lg px-3 py-2.5 text-sm outline-none resize-y"
                style={{ backgroundColor: "rgba(0,0,0,0.45)", border: "1px solid rgba(120,160,180,0.22)", color: "#dff" }}
              />
              <div className="flex gap-2">
                <GButton onClick={runPaste} disabled={!jsonText.trim()} color="#00ff9c" solid icon={<ClipboardPaste size={16} />}>Parse</GButton>
                {jsonText && <GButton onClick={() => setJsonText("")} color="#94a3b8" icon={<Trash2 size={15} />}>Clear</GButton>}
              </div>
            </div>
          )}

          {mode === "raw" && (
            <div className="flex flex-col gap-2">
              <textarea
                value={rawText}
                onChange={(e) => setRawText(e.target.value)}
                placeholder={"Paste IOCs (any format): 1.2.3.4, evil[.]com, hxxps://bad.site, CVE-2025-1234, HKLM\\System, etc"}
                rows={7}
                className="w-full rounded-lg px-3 py-2.5 text-sm outline-none resize-y"
                style={{ backgroundColor: "rgba(0,0,0,0.45)", border: "1px solid rgba(120,160,180,0.22)", color: "#dff" }}
              />
              <div className="flex items-center gap-2">
                <GButton onClick={runRaw} disabled={!rawText.trim()} color="#c084fc" solid icon={<Wand2 size={16} />}>Parse</GButton>
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

        {entries.length > 0 && (
          <div className="flex flex-wrap gap-2 mb-5">
            {entries.map(([cat, arr]) => {
              const c = colorFor(cat);
              return (
                <a key={cat} href={`#cat-${cat}`} className="flex items-center gap-2 rounded-full px-3 py-1 text-xs" style={{ border: `1px solid ${c}55`, backgroundColor: `${c}14`, color: c }}>
                  <span style={{ width: 7, height: 7, borderRadius: 99, backgroundColor: c, boxShadow: `0 0 8px ${c}` }} />
                  {cat} <span style={{ opacity: 0.75 }}>· {arr.length}</span>
                </a>
              );
            })}
          </div>
        )}

        {sourceUrl && (
          <div className="flex items-center gap-3 mb-4 flex-wrap">
            <p className="text-xs truncate" style={{ color: "#5d7382" }}>
              source: <span style={{ color: "#8aa0ad" }}>{sourceUrl}</span>
              {fetchVia && <span style={{ color: "#00ff9c" }}> · {fetchVia}</span>}
            </p>
            {rawArticle && (
              <button onClick={saveArticle} className="flex items-center gap-1 text-xs rounded-md px-2 py-1"
                style={{ color: "#00e5ff", border: "1px solid rgba(0,229,255,0.4)", backgroundColor: "rgba(0,229,255,0.07)" }}>
                <FileDown size={12} /> Save article
              </button>
            )}
          </div>
        )}

        {/* IOC Cards */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 mb-6">
          {entries.map(([cat, arr]) => {
            const c = colorFor(cat);
            const isDefanged = !!defangMap[cat];
            const shown = proc(arr, cat);
            const fmt = { lines: shown.join("\n"), pipe: shown.join("|"), quoted: shown.map((v) => `"${v}"`).join(", ") };
            return (
              <div key={cat} id={`cat-${cat}`} className="rounded-xl overflow-hidden flex flex-col" style={{ ...panel, borderColor: `${c}40` }}>
                <div className="flex items-center justify-between px-4 py-2.5 gap-2" style={{ borderBottom: `1px solid ${c}33`, backgroundColor: `${c}0d` }}>
                  <div className="flex items-center gap-2 min-w-0">
                    <span style={{ width: 9, height: 9, borderRadius: 99, backgroundColor: c, boxShadow: `0 0 10px ${c}` }} />
                    <span className="font-bold tracking-wide truncate" style={{ color: c, textShadow: `0 0 12px ${c}55` }}>{cat}</span>
                  </div>
                  <div className="flex items-center gap-2 shrink-0">
                    <button onClick={() => toggleDefang(cat)} className="flex items-center gap-1 rounded-md px-2 py-1 text-xs"
                      style={{ color: isDefanged ? "#04111a" : "#ffb84d", backgroundColor: isDefanged ? "#ffb84d" : "rgba(255,184,77,0.10)", border: "1px solid rgba(255,184,77,0.5)" }}>
                      <ShieldOff size={12} /> {isDefanged ? "Defanged" : "Defang"}
                    </button>
                    <span className="text-xs rounded-full px-2 py-0.5" style={{ backgroundColor: `${c}1f`, color: c, border: `1px solid ${c}55` }}>{arr.length}</span>
                  </div>
                </div>

                <div className="px-4 py-2 overflow-y-auto" style={{ maxHeight: 240 }}>
                  {shown.map((ioc, i) => (
                    <div key={i} className="text-xs py-0.5 break-all leading-relaxed" style={{ color: "#c8d6dd" }}>
                      <span style={{ color: `${c}aa`, userSelect: "none" }}>›</span> {ioc}
                    </div>
                  ))}
                </div>

                <div className="px-3 py-2.5 flex flex-wrap gap-1.5" style={{ borderTop: `1px solid ${c}22` }}>
                  <CopyBtn label="Lines" copied={copied === `${cat}-lines`} onClick={() => copyText(fmt.lines, `${cat}-lines`)} color={c} />
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

        {/* Query Cards */}
        {queries.length > 0 && (
          <div className="mb-6">
            <h2 className="text-lg font-bold mb-3" style={{ color: "#c084fc", textShadow: "0 0 12px rgba(192,132,252,0.3)" }}>
              <Code size={18} className="inline mr-2" /> Detection Queries ({queries.length})
            </h2>
            <div className="grid grid-cols-1 gap-4">
              {queries.map((q, i) => (
                <div key={i} className="rounded-xl p-4 overflow-hidden" style={{ ...panel, borderColor: "#c084fc40" }}>
                  <div className="flex items-center justify-between mb-2" style={{ borderBottom: "1px solid rgba(192,132,252,0.2)", paddingBottom: "8px" }}>
                    <div className="flex items-center gap-2">
                      <span className="text-xs font-bold rounded px-2 py-0.5" style={{ backgroundColor: "rgba(192,132,252,0.15)", color: "#c084fc" }}>
                        {q.type}
                      </span>
                      <span className="text-xs" style={{ color: "#7f95a3" }}>{q.context}</span>
                    </div>
                    <button
                      onClick={() => copyText(q.code, `query-${i}`)}
                      className="flex items-center gap-1 text-xs rounded px-2 py-1"
                      style={{ color: copied === `query-${i}` ? "#04111a" : "#c084fc", backgroundColor: copied === `query-${i}` ? "#c084fc" : "rgba(192,132,252,0.12)", border: "1px solid rgba(192,132,252,0.44)" }}>
                      {copied === `query-${i}` ? <Check size={12} /> : <Copy size={12} />} {copied === `query-${i}` ? "Copied" : "Copy"}
                    </button>
                  </div>
                  <pre className="text-xs overflow-x-auto p-2 rounded" style={{ backgroundColor: "rgba(0,0,0,0.45)", color: "#dff", border: "1px solid rgba(192,132,252,0.2)" }}>
                    {q.code}
                  </pre>
                </div>
              ))}
            </div>
          </div>
        )}

        {!iocData && !loading && !error && (
          <div className="rounded-xl p-10 text-center" style={panel}>
            <Shield size={34} className="mx-auto mb-3" style={{ color: "#1f4754" }} />
            <p className="text-sm" style={{ color: "#5d7382" }}>
              Fetch a threat-intel article, paste JSON, or paste raw IOCs.
            </p>
          </div>
        )}

        <p className="text-center text-xs mt-8" style={{ color: "#3a4a54" }}>
          Self-hosted · Cloudflare Worker relay · local IOC engine · KQL/CQL extraction
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
