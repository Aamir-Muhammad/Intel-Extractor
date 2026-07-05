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

// Keep ALL your original helper functions here: expandHive, extractStructured, classify, extractIocs, parseIocs, mergeIocs, buildKQL, buildCQL, buildSPL, extractArticleBody, htmlToText, filterScraped, etc.
// (Paste your original code for these functions from your current file)

const ORDER = ["IPV4","IPV6","DOMAIN","URL","EMAIL","MD5","SHA1","SHA256","SHA512","SSDEEP","CVE","MITRE_ATTACK","YARA","ASN","MAC_ADDRESS","BTC","XMR","ETH","REGISTRY","FILE","FILE_PATH"];
const DISPLAY_PRIORITY = ["DOMAIN","URL","IPV4","IPV6","MD5","SHA1","SHA256","SHA512","SSDEEP","IMPHASH"];
const catRank = (cat) => {
  const p = DISPLAY_PRIORITY.indexOf(cat);
  if (p !== -1) return p;
  const o = ORDER.indexOf(cat);
  return o === -1 ? 999 : 100 + o;
};

// ... (Continue pasting all your helper functions until the end of the extraction logic)
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
    if (api && eng) return "API + Engine Parsed";
    if (api) return "API Parsed";
    if (eng) return "Engine Parsed";
    return null;
  };

  const tagFor = (cat, v) => originData?.[cat]?.[v] ? TAG_LABEL[originData[cat][v]] : "";

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
    try {
      await navigator.clipboard.writeText(text);
      flash(key);
    } catch {
      const ta = document.createElement("textarea");
      ta.value = text; ta.style.position = "fixed"; ta.style.opacity = "0";
      document.body.appendChild(ta); ta.select();
      document.execCommand("copy");
      document.body.removeChild(ta);
      flash(key);
    }
  };

  const resetResults = () => {
    setError(""); setIocData(null); setOriginData(null); setRegistryDetails([]);
    setMeta(null); setAiSummary(null); setAiState("idle"); setAiOpen(false);
    setRetryCount(0); setCooldown(0); setRawArticle(""); setArticleClean(""); setDefangAll(false);
  };

  // Improved runFetch with better article extraction
  const runFetch = async () => {
    resetResults();
    setLoading(true);

    const apiP = fetch(`${WORKER_BASE}/parse`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
    }).then((r) => { if (!r.ok) throw new Error(`API HTTP ${r.status}`); return r.json(); });

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
      if (articleBody.length < 800) articleBody = articleText; // Fallback for stubborn pages

      const ex = extractIocs(articleText);
      engFull = ex.data;
      engDetails = ex.registryDetails;
    }

    if (!apiData && (!engFull || !Object.keys(filterScraped(engFull, url)).length)) {
      setError("No IOCs found. Try another URL or Paste mode.");
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
    if (!text || text.trim().length < 300) { 
      setAiState("error"); 
      return; 
    }
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

  // Keep your original runPaste, runRaw, saveArticle, export functions as-is
    const runPaste = () => {
    resetResults();
    try {
      const parsed = parseIocs(JSON.parse(jsonText));
      if (!Object.keys(parsed).length) throw new Error("No IOC arrays found.");
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

  // ... (Keep all your export functions: exportAllCSV, exportAllXLSX, exportTypeCSV, exportTypeXLSX)

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
        {/* Header - unchanged */}
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
          {/* Author links unchanged */}
        </div>

        {/* Export bar unchanged */}
        <div className="rounded-xl p-3 mb-4 flex flex-wrap items-center gap-2" style={panel}>
          {total > 0 && (
            <div className="flex items-baseline gap-2 rounded-lg px-3 py-1.5"
              style={{ border: "1px solid rgba(0,255,156,0.5)", backgroundColor: "rgba(0,255,156,0.08)", boxShadow: "0 0 18px rgba(0,255,156,0.15)" }}>
              <span className="text-lg font-extrabold leading-none" style={{ color: "#00ff9c" }}>IOCs:</span>
              <span className="text-lg font-extrabold tabular-nums leading-none" style={{ color: "#00ff9c" }}>{total}</span>
            </div>
          )}
          {/* Export buttons unchanged */}
        </div>

        {/* Tabs & Input forms - unchanged */}
        <div className="rounded-xl p-4 mb-5" style={panel}>
          <div className="flex flex-wrap gap-1 mb-3">
            <Tab active={mode === "url"} onClick={() => setMode("url")} icon={<Globe size={14} />}>Fetch URL</Tab>
            <Tab active={mode === "paste"} onClick={() => setMode("paste")} icon={<ClipboardPaste size={14} />}>Paste JSON</Tab>
            <Tab active={mode === "raw"} onClick={() => setMode("raw")} icon={<Wand2 size={14} />}>Paste IOCs</Tab>
          </div>

          {/* Your original input forms for each mode remain the same */}
          {/* ... paste your original mode === "url", "paste", "raw" blocks here ... */}

          {error && (
            <div className="mt-3 flex items-start gap-2 rounded-lg px-3 py-2.5 text-xs" style={{ backgroundColor: "rgba(255,59,59,0.08)", border: "1px solid rgba(255,59,59,0.3)", color: "#ffb4b4" }}>
              <AlertTriangle size={15} className="mt-0.5 shrink-0" /> <span>{error}</span>
            </div>
          )}
        </div>

        {/* Meta info unchanged */}

        {/* UPDATED AI SUMMARY PANEL */}
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
                    <p className="text-xs sm:text-sm mt-1.5 leading-relaxed whitespace-pre-wrap" style={{ color: "#b8c9d1" }}>{aiSummary.summary}</p>
                    {aiSummary.recommendations?.length > 0 && (
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

        {/* Rest of your UI (IOC cards, etc.) remains unchanged */}
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
                {/* Your original IOC card JSX remains unchanged */}
                {/* ... paste your full card rendering code here ... */}
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

// Helper Components (unchanged)
function GButton({ children, onClick, disabled, color, icon, solid }) {
  return (
    <button onClick={onClick} disabled={disabled}
      className="flex items-center gap-1.5 rounded-lg px-3 py-2 text-sm font-semibold transition-opacity"
      style={{ 
        color: solid ? "#04111a" : color, 
        backgroundColor: solid ? color : `${color}14`, 
        border: `1px solid ${color}${solid ? "" : "55"}`, 
        boxShadow: solid ? `0 0 18px ${color}55` : "none", 
        opacity: disabled ? 0.4 : 1, 
        cursor: disabled ? "not-allowed" : "pointer" 
      }}>
      {icon}{children}
    </button>
  );
}

function Tab({ children, active, onClick, icon }) {
  return (
    <button onClick={onClick} className="flex items-center gap-1.5 rounded-md px-3 py-1.5 text-xs font-semibold"
      style={{ 
        color: active ? "#04111a" : "#8aa0ad", 
        backgroundColor: active ? "#00e5ff" : "transparent", 
        boxShadow: active ? "0 0 14px rgba(0,229,255,0.4)" : "none" 
      }}>
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
