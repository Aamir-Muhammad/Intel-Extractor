import { useState, useMemo, useRef, useEffect } from "react";
import * as XLSX from "xlsx";
import {
  Shield, Search, Download, Copy, Check, Loader2, Globe,
  ClipboardPaste, AlertTriangle, ShieldOff, Trash2, Wand2,
  Crosshair, FileText, Linkedin, Github, X, Target, ShieldCheck, Sparkles, ChevronDown, RefreshCw, FileUp, Pencil
} from "lucide-react";

// ============================================================
//  Backend proxy
// ============================================================
const WORKER_BASE = "https://ioc-parser.aamirmuhd.workers.dev";
const APP_VERSION = "v69";

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
const WL_DOMAINS = new Set(["github.com","www.github.com","github.io","localhost","example.com","www.example.com","kaspersky.com","www.kaspersky.com","fbi.gov","www.fbi.gov","mitre.org","attack.mitre.org","www.mitre.org","gmail.com","www.gmail.com","trendmicro.com","www.trendmicro.com"]);
// URL whitelist — github.com is intentionally NOT here: full GitHub URLs are
// often real IOCs (payload hosting, raw.githubusercontent staging) and must
// survive into the URL card. Only the bare DOMAIN entry gets filtered.
const WL_URL_HOSTS = new Set(["localhost","example.com","www.example.com","kaspersky.com","www.kaspersky.com","fbi.gov","www.fbi.gov","mitre.org","attack.mitre.org","www.mitre.org"]);
// Domain suffixes to filter (any domain ending in these gets removed)
const WL_DOMAIN_SUFFIXES = [".mitre.org"];
const WL_EMAIL_SUFFIXES = ["@kaspersky.com"];

// ============================================================
//  Reference URL detection — known security vendor, research,
//  news, sandbox, and CERT domains. URLs matching these hosts
//  are pulled from the IOC URL card into a separate References
//  box (no hunt queries, no enrichment — just citations).
// ============================================================
const REF_DOMAINS = new Set([
  // Threat intel vendors
  "securelist.com","kaspersky.com","mandiant.com","cloud.google.com",
  "unit42.paloaltonetworks.com","paloaltonetworks.com",
  "crowdstrike.com","www.crowdstrike.com",
  "microsoft.com","techcommunity.microsoft.com","learn.microsoft.com",
  "trendmicro.com","www.trendmicro.com",
  "symantec-enterprise-blogs.security.com","symantec.com","broadcom.com",
  "trellix.com","fireeye.com",
  "sentinelone.com","www.sentinelone.com","sentinelone.com",
  "sophos.com","news.sophos.com",
  "fortinet.com","fortiguard.com","www.fortinet.com",
  "checkpoint.com","research.checkpoint.com",
  "zscaler.com","www.zscaler.com",
  "proofpoint.com","www.proofpoint.com",
  "recordedfuture.com","www.recordedfuture.com",
  "elastic.co","www.elastic.co",
  "splunk.com","www.splunk.com",
  "cybereason.com","www.cybereason.com",
  "securonix.com","www.securonix.com",
  "malwarebytes.com","www.malwarebytes.com",
  "avast.com","decoded.avast.io",
  "eset.com","www.eset.com","welivesecurity.com",
  "bitdefender.com","www.bitdefender.com",
  "mcafee.com","www.mcafee.com",
  "volexity.com","www.volexity.com",
  "huntress.com","www.huntress.com",
  "deepinstinct.com","www.deepinstinct.com",
  "group-ib.com","www.group-ib.com",
  "team-cymru.com","www.team-cymru.com",
  "intezer.com","www.intezer.com",
  "blackberry.com","blogs.blackberry.com",
  "cisco.com","blog.talosintelligence.com","talosintelligence.com",
  "akamai.com","www.akamai.com",
  // Sandboxes & analysis platforms
  "virustotal.com","www.virustotal.com",
  "hybrid-analysis.com","www.hybrid-analysis.com",
  "any.run","app.any.run",
  "joesandbox.com","www.joesandbox.com",
  "tria.ge",
  "urlscan.io",
  "shodan.io","www.shodan.io",
  "censys.io","search.censys.io",
  "opentip.kaspersky.com",
  "bazaar.abuse.ch","threatfox.abuse.ch","urlhaus.abuse.ch",
  "otx.alienvault.com",
  "app.validin.com",
  // CERTs & government
  "cisa.gov","www.cisa.gov","us-cert.gov","cert.org","www.cert.org",
  "nist.gov","nvd.nist.gov","www.nist.gov",
  "ic3.gov","www.ic3.gov",
  "ncsc.gov.uk","www.ncsc.gov.uk",
  "cyber.gov.au","www.cyber.gov.au",
  "bsi.bund.de","www.bsi.bund.de",
  "cert.ssi.gouv.fr",
  // Security news & blogs
  "bleepingcomputer.com","www.bleepingcomputer.com",
  "thehackernews.com","www.thehackernews.com",
  "darkreading.com","www.darkreading.com",
  "securityweek.com","www.securityweek.com",
  "threatpost.com","www.threatpost.com",
  "therecord.media","www.therecord.media",
  "krebsonsecurity.com",
  "infosecurity-magazine.com","www.infosecurity-magazine.com",
  "csoonline.com","www.csoonline.com",
  "scmagazine.com","www.scmagazine.com",
  "sekoia.io","blog.sekoia.io",
  "duo.com","www.duo.com",
  "godaddy.com","www.godaddy.com",
  "forbes.com","www.forbes.com",
  "helpnetsecurity.com","www.helpnetsecurity.com",
  "datadoghq.com","securitylabs.datadoghq.com",
  // Research & code (NOT raw.githubusercontent.com — that's payload staging)
  // github.com intentionally NOT here — malware repos are hosted on github.com
  "medium.com","www.medium.com",
  "arxiv.org","www.arxiv.org",
  "researchgate.net","www.researchgate.net",
  "docs.google.com","drive.google.com",
  // Social media (researcher posts used as references)
  "twitter.com","x.com","www.x.com",
  "linkedin.com","www.linkedin.com",
  // Misc
  "wikipedia.org","en.wikipedia.org",
  "web.archive.org","archive.org",
]);
// Check if a URL host is a known reference domain
const isRefUrl = (urlStr) => {
  try {
    const host = new URL(urlStr.includes("://") ? urlStr : "https://" + urlStr).hostname.toLowerCase();
    if (REF_DOMAINS.has(host)) return true;
    // Also match subdomains: e.g. "blogs.blackberry.com" matches "blackberry.com"
    const parts = host.split(".");
    for (let i = 1; i < parts.length - 1; i++) {
      if (REF_DOMAINS.has(parts.slice(i).join("."))) return true;
    }
    return false;
  } catch { return false; }
};
// Split URL array into { iocs, refs }
const splitUrlRefs = (urls) => {
  const iocs = [], refs = [];
  (urls || []).forEach((u) => {
    // raw.githubusercontent.com is payload staging — always an IOC
    try {
      const host = new URL(u.includes("://") ? u : "https://" + u).hostname.toLowerCase();
      if (host === "raw.githubusercontent.com") { iocs.push(u); return; }
    } catch { /* fall through */ }
    if (isRefUrl(u)) refs.push(u);
    else iocs.push(u);
  });
  return { iocs, refs };
};
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

// Apply whitelist AND split reference URLs out of the URL category.
// Returns { data, refs } where refs is an array of reference URL strings.
const applyWhitelistAndRefs = (data) => {
  const cleaned = applyWhitelist(data);
  if (!cleaned.URL || !cleaned.URL.length) return { data: cleaned, refs: [] };
  const { iocs, refs } = splitUrlRefs(cleaned.URL);
  if (iocs.length) cleaned.URL = iocs;
  else delete cleaned.URL;
  return { data: cleaned, refs };
};

// Human-readable age: "3 Hours Ago", "28 Days Ago", "1.2 Years Ago"
const timeAgo = (dateStr) => {
  if (!dateStr) return "";
  const d = new Date(dateStr);
  if (isNaN(d)) return "";
  const now = Date.now();
  const diffMs = now - d.getTime();
  if (diffMs < 0) return "In The Future";
  const hours = Math.floor(diffMs / 3600000);
  if (hours < 1) return "< 1 Hour Ago";
  if (hours < 24) return `${hours} Hour${hours !== 1 ? "s" : ""} Ago`;
  const days = Math.floor(diffMs / 86400000);
  if (days < 365) return `${days} Day${days !== 1 ? "s" : ""} Ago`;
  const years = (diffMs / (365.25 * 86400000)).toFixed(1);
  return `${years} Year${parseFloat(years) !== 1 ? "s" : ""} Ago`;
};

// Format date as dd-mm-yyyy
const fmtDate = (dateStr) => {
  if (!dateStr) return "";
  const d = new Date(dateStr);
  if (isNaN(d)) return dateStr;
  const dd = String(d.getUTCDate()).padStart(2, "0");
  const mm = String(d.getUTCMonth() + 1).padStart(2, "0");
  const yyyy = d.getUTCFullYear();
  return `${dd}-${mm}-${yyyy}`;
};

// Combined: "28 Days Ago (20-04-2026)"
const timeAgoFmt = (dateStr) => {
  if (!dateStr) return "";
  const ago = timeAgo(dateStr);
  const dt = fmtDate(dateStr);
  return ago && dt ? `${ago} (${dt})` : ago || dt;
};

// Calculate approximate creation date from age in days
const dateFromAgeDays = (ageDays, refDateStr) => {
  if (ageDays == null || ageDays < 0) return null;
  const ref = refDateStr ? new Date(refDateStr) : new Date();
  ref.setDate(ref.getDate() - ageDays);
  return ref.toISOString().split("T")[0];
};

// Smart age: "18 Hours", "28 Days", "1.2 Years"
const smartAge = (days) => {
  if (days == null) return "";
  if (days < 1) {
    const hours = Math.max(1, Math.round(days * 24));
    return `${hours} Hour${hours !== 1 ? "s" : ""}`;
  }
  if (days < 365) return `${days} Day${days !== 1 ? "s" : ""}`;
  const years = (days / 365.25).toFixed(1);
  return `${years} Year${parseFloat(years) !== 1 ? "s" : ""}`;
};

// Dynamic favicon: sets a cyber-shield SVG as the browser tab icon
const FAVICON_SVG = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64"><defs><linearGradient id="g" x1="0" y1="0" x2="1" y2="1"><stop offset="0%" stop-color="#00e5ff"/><stop offset="100%" stop-color="#00ff9c"/></linearGradient></defs><path d="M32 4L8 16v16c0 14.4 10.3 27.8 24 31.6C45.7 59.8 56 46.4 56 32V16L32 4z" fill="none" stroke="url(#g)" stroke-width="4"/><path d="M32 14L16 22v10c0 9.6 6.9 18.5 16 21 9.1-2.5 16-11.4 16-21V22L32 14z" fill="url(#g)" opacity="0.15"/><path d="M28 32l-4-4 2.8-2.8L28 26.4l5.2-5.2L36 24l-8 8z" fill="url(#g)" transform="translate(2,2) scale(1.1)"/></svg>`;
const setFavicon = () => {
  const existing = document.querySelector('link[rel="icon"]');
  if (existing) existing.remove();
  const link = document.createElement("link");
  link.rel = "icon";
  link.type = "image/svg+xml";
  link.href = "data:image/svg+xml," + encodeURIComponent(FAVICON_SVG);
  document.head.appendChild(link);
};

// ============================================================
//  RDAP bootstrap — IANA publishes the authoritative TLD → RDAP
//  server map. Cached for the session so we only fetch it once.
//  Without this, ccTLDs like .me/.io/.xyz hit servers that don't
//  own them and return 404, which we'd wrongly read as "deleted".
// ============================================================
let rdapMapPromise = null;
const loadRdapMap = () => {
  if (rdapMapPromise) return rdapMapPromise;
  rdapMapPromise = fetch("https://data.iana.org/rdap/dns.json")
    .then((r) => (r.ok ? r.json() : null))
    .then((j) => {
      if (!j || !Array.isArray(j.services)) return null;
      const map = new Map();
      // services: [[["tld1","tld2"], ["https://rdap.example/"]], ...]
      j.services.forEach(([tlds, urls]) => {
        if (!Array.isArray(tlds) || !Array.isArray(urls) || !urls.length) return;
        tlds.forEach((t) => map.set(String(t).toLowerCase(), urls[0].replace(/\/+$/, "")));
      });
      return map;
    })
    .catch(() => { rdapMapPromise = null; return null; });
  return rdapMapPromise;
};

// Returns { url, authoritative } — authoritative means IANA confirmed
// this server owns the TLD, so a 404 from it is trustworthy.
const rdapServerFor = async (domain) => {
  const tld = String(domain).split(".").pop().toLowerCase();
  const map = await loadRdapMap();
  if (map && map.has(tld)) return { url: `${map.get(tld)}/domain/${encodeURIComponent(domain)}`, authoritative: true };
  return null;
};

// ============================================================
//  Registrable domain extraction (public suffix aware)
//  "evil.co.uk" → "evil.co.uk" (not "co.uk")
//  "sub.evil.com" → "evil.com"
//  Covers the multi-part suffixes seen in threat intel. The full
//  Public Suffix List has ~9k entries; this is the practical subset.
// ============================================================
const MULTI_PART_SUFFIXES = new Set([
  // United Kingdom
  "co.uk","org.uk","me.uk","ltd.uk","plc.uk","net.uk","sch.uk","ac.uk","gov.uk","nhs.uk","police.uk","mod.uk",
  // Australia
  "com.au","net.au","org.au","edu.au","gov.au","asn.au","id.au",
  // Brazil
  "com.br","net.br","org.br","gov.br","edu.br","art.br","blog.br",
  // Japan
  "co.jp","or.jp","ne.jp","ac.jp","ad.jp","ed.jp","go.jp","gr.jp","lg.jp",
  // China
  "com.cn","net.cn","org.cn","gov.cn","edu.cn","ac.cn",
  // India
  "co.in","net.in","org.in","gen.in","firm.in","ind.in","gov.in","ac.in","edu.in","res.in",
  // South Africa
  "co.za","net.za","org.za","gov.za","ac.za","web.za",
  // New Zealand
  "co.nz","net.nz","org.nz","govt.nz","ac.nz","school.nz","geek.nz","kiwi.nz",
  // South Korea
  "co.kr","or.kr","ne.kr","re.kr","pe.kr","go.kr","ac.kr","hs.kr","ms.kr","es.kr",
  // Mexico / LatAm
  "com.mx","net.mx","org.mx","gob.mx","edu.mx",
  "com.ar","net.ar","org.ar","gob.ar","edu.ar",
  "com.co","net.co","org.co","gov.co","edu.co",
  "com.pe","net.pe","org.pe","gob.pe","edu.pe",
  "com.ve","net.ve","org.ve","gob.ve","edu.ve",
  "com.ec","net.ec","org.ec","gob.ec","edu.ec",
  "com.uy","net.uy","org.uy","gub.uy","edu.uy",
  // Europe
  "com.es","org.es","nom.es","gob.es","edu.es",
  "com.pl","net.pl","org.pl","gov.pl","edu.pl","waw.pl","info.pl",
  "com.pt","net.pt","org.pt","gov.pt","edu.pt",
  "com.gr","net.gr","org.gr","gov.gr","edu.gr",
  "com.tr","net.tr","org.tr","gov.tr","edu.tr","bel.tr","k12.tr",
  "com.ua","net.ua","org.ua","gov.ua","edu.ua","kiev.ua",
  "com.ru","net.ru","org.ru","edu.ru","gov.ru","msk.ru","spb.ru",
  "co.rs","org.rs","edu.rs","gov.rs","in.rs",
  "com.hr","from.hr","iz.hr","name.hr",
  "com.cy","net.cy","org.cy","gov.cy","ac.cy",
  "com.mt","net.mt","org.mt","gov.mt","edu.mt",
  // Asia-Pacific
  "com.sg","net.sg","org.sg","gov.sg","edu.sg","per.sg",
  "com.my","net.my","org.my","gov.my","edu.my","mil.my","name.my",
  "com.hk","net.hk","org.hk","gov.hk","edu.hk","idv.hk",
  "com.tw","net.tw","org.tw","gov.tw","edu.tw","idv.tw","game.tw",
  "com.ph","net.ph","org.ph","gov.ph","edu.ph","ngo.ph",
  "co.th","in.th","go.th","ac.th","net.th","or.th","mi.th",
  "com.vn","net.vn","org.vn","gov.vn","edu.vn","ac.vn","biz.vn",
  "co.id","net.id","or.id","go.id","ac.id","sch.id","web.id","my.id",
  "com.pk","net.pk","org.pk","gov.pk","edu.pk","biz.pk","web.pk",
  "com.bd","net.bd","org.bd","gov.bd","edu.bd","ac.bd",
  "com.np","net.np","org.np","gov.np","edu.np",
  "com.lk","net.lk","org.lk","gov.lk","edu.lk","ac.lk",
  // Middle East
  "com.sa","net.sa","org.sa","gov.sa","edu.sa","med.sa","pub.sa",
  "co.ae","net.ae","org.ae","gov.ae","ac.ae","sch.ae","mil.ae",
  "co.il","net.il","org.il","gov.il","ac.il","k12.il","muni.il",
  "com.qa","net.qa","org.qa","gov.qa","edu.qa","mil.qa",
  "com.kw","net.kw","org.kw","gov.kw","edu.kw",
  "com.bh","net.bh","org.bh","gov.bh","edu.bh",
  "com.om","net.om","org.om","gov.om","edu.om","ac.om",
  "com.jo","net.jo","org.jo","gov.jo","edu.jo",
  "com.lb","net.lb","org.lb","gov.lb","edu.lb",
  "com.eg","net.eg","org.eg","gov.eg","edu.eg","sci.eg",
  // Africa
  "com.ng","net.ng","org.ng","gov.ng","edu.ng","sch.ng",
  "co.ke","ne.ke","or.ke","go.ke","ac.ke","sc.ke","me.ke",
  "com.gh","net.gh","org.gh","gov.gh","edu.gh",
  "co.tz","ne.tz","or.tz","go.tz","ac.tz","sc.tz",
  "co.ug","ne.ug","or.ug","go.ug","ac.ug","sc.ug",
  "com.dz","net.dz","org.dz","gov.dz","edu.dz",
  "co.ma","net.ma","org.ma","gov.ma","ac.ma",
  "com.tn","net.tn","org.tn","gov.tn","edu.tn","ens.tn",
  // Other
  "com.pa","net.pa","org.pa","gob.pa","edu.pa",
  "com.do","net.do","org.do","gob.do","edu.do",
  "com.gt","net.gt","org.gt","gob.gt","edu.gt",
  "com.sv","net.sv","org.sv","gob.sv","edu.sv",
  "com.hn","net.hn","org.hn","gob.hn","edu.hn",
  "com.ni","net.ni","org.ni","gob.ni","edu.ni",
  "com.bo","net.bo","org.bo","gob.bo","edu.bo",
  "com.py","net.py","org.py","gov.py","edu.py",
  "com.cu","net.cu","org.cu","gov.cu","edu.cu",
  "com.jm","net.jm","org.jm","gov.jm","edu.jm",
  "com.tt","net.tt","org.tt","gov.tt","edu.tt",
  "com.bz","net.bz","org.bz","gov.bz","edu.bz",
  // Hosting / dynamic-DNS suffixes commonly abused
  "s3.amazonaws.com","cloudfront.net","azurewebsites.net","blob.core.windows.net",
  "web.app","firebaseapp.com","github.io","gitlab.io","netlify.app","vercel.app",
  "herokuapp.com","pages.dev","workers.dev","r2.dev","glitch.me","repl.co",
  "duckdns.org","no-ip.org","ddns.net","hopto.org","zapto.org","serveo.net",
  "ngrok.io","ngrok-free.app","trycloudflare.com","loca.lt",
  "blogspot.com","wordpress.com","weebly.com","wixsite.com","squarespace.com",
]);

// Extract the registrable (billable) domain, honouring multi-part suffixes.
const registrableDomain = (host) => {
  const h = String(host).toLowerCase().replace(/^https?:\/\//, "").split("/")[0].split(":")[0].replace(/\.+$/, "");
  const parts = h.split(".");
  if (parts.length <= 2) return h;
  // Try the longest known suffix first (e.g. "s3.amazonaws.com" before "amazonaws.com")
  for (let take = Math.min(4, parts.length - 1); take >= 2; take--) {
    const suffix = parts.slice(-take).join(".");
    if (MULTI_PART_SUFFIXES.has(suffix)) {
      return parts.slice(-(take + 1)).join(".");
    }
  }
  return parts.slice(-2).join(".");
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
    const s = stripScheme(u).replace(/\/+$/, ""); // strip trailing slash so domain.xyz/ → domain.xyz
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
  if (/^([a-z0-9-]+\.)+[a-z]{2,}(:\d+)?\/\S+/i.test(t)) return ["URL", t];
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
  // Country TLDs that overlap with file extensions (.pl=Poland/Perl, .py=Paraguay/Python, etc.)
  // If token looks like a domain AND its extension is a known country TLD, prefer DOMAIN
  if (FILE_EXT.test(t)) {
    const ext = t.split(".").pop().toLowerCase();
    const COUNTRY_TLD = new Set(["pl","py","sh","rs","md","ba","bg","by","cz","de","dk","ee","es","fi","fr","ge","gr","hr","hu","ie","il","in","is","it","jp","kg","kr","lt","lu","lv","mk","ml","mn","ms","mt","mx","my","nl","no","nz","pe","ph","pk","pt","ro","ru","se","sg","si","sk","su","th","tr","ua","uk","us","uz","vn","za"]);
    if (COUNTRY_TLD.has(ext) && /^([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2}$/i.test(t)) {
      return ["DOMAIN", t.toLowerCase()];
    }
    return ["FILE_NAME", t];
  }
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
      return `DeviceFileEvents\n| where FileName in~ (${kqlList(arr)})\n| project-reorder Timestamp, DeviceName, FileName, FolderPath, SHA256, ActionType, InitiatingProcessFileName;\nunion DeviceProcessEvents\n| where FileName in~ (${kqlList(arr)}) or ProcessCommandLine has_any (${kqlList(arr)})\n| project-reorder Timestamp, DeviceName, FileName, ProcessCommandLine, SHA256`;
    case "FILE_PATH": {
      const pathDyn = `dynamic([${arr.map((p) => `@"${p.replace(/"/g, '\\"')}"`).join(", ")}])`;
      return `let ScopedPaths = ${pathDyn};\nlet ProcEvents =\n    DeviceProcessEvents\n    | where Timestamp > ago(30d)\n    | where FolderPath has_any (ScopedPaths) or InitiatingProcessFolderPath has_any (ScopedPaths)\n    | extend\n        Detail      = strcat(FolderPath, FileName),\n        ProcessTree = strcat(InitiatingProcessParentFileName, " > ", InitiatingProcessFileName, " > ", FileName)\n    | project Timestamp, DeviceName, AccountName, SourceTable="DeviceProcessEvents",\n        Detail, ProcessTree, CommandLine = ProcessCommandLine,\n        SHA256, InitiatingProcessSHA256;\nlet FileEvents =\n    DeviceFileEvents\n    | where Timestamp > ago(30d)\n    | where FolderPath has_any (ScopedPaths) or InitiatingProcessFolderPath has_any (ScopedPaths)\n    | extend\n        Detail      = strcat(FolderPath, FileName),\n        ProcessTree = strcat(InitiatingProcessParentFileName, " > ", InitiatingProcessFileName)\n    | project Timestamp, DeviceName, AccountName = InitiatingProcessAccountName, SourceTable="DeviceFileEvents",\n        Detail, ProcessTree, CommandLine = InitiatingProcessCommandLine,\n        SHA256, InitiatingProcessSHA256;\nlet ImageLoadEvents =\n    DeviceImageLoadEvents\n    | where Timestamp > ago(30d)\n    | where FolderPath has_any (ScopedPaths) or InitiatingProcessFolderPath has_any (ScopedPaths)\n    | extend\n        Detail      = strcat(FolderPath, FileName),\n        ProcessTree = strcat(InitiatingProcessParentFileName, " > ", InitiatingProcessFileName)\n    | project Timestamp, DeviceName, AccountName = InitiatingProcessAccountName, SourceTable="DeviceImageLoadEvents",\n        Detail, ProcessTree, CommandLine = InitiatingProcessCommandLine,\n        SHA256, InitiatingProcessSHA256;\nlet NetworkEvents =\n    DeviceNetworkEvents\n    | where Timestamp > ago(30d)\n    | where InitiatingProcessFolderPath has_any (ScopedPaths)\n    | extend\n        Detail      = strcat(RemoteIP, ":", tostring(RemotePort), " ", RemoteUrl),\n        ProcessTree = strcat(InitiatingProcessParentFileName, " > ", InitiatingProcessFileName)\n    | project Timestamp, DeviceName, AccountName = InitiatingProcessAccountName, SourceTable="DeviceNetworkEvents",\n        Detail, ProcessTree, CommandLine = InitiatingProcessCommandLine,\n        SHA256 = "", InitiatingProcessSHA256;\nlet RegistryEvents =\n    DeviceRegistryEvents\n    | where Timestamp > ago(30d)\n    | where InitiatingProcessFolderPath has_any (ScopedPaths)\n    | extend\n        Detail      = strcat(RegistryKey, " \\\\ ", RegistryValueName),\n        ProcessTree = strcat(InitiatingProcessParentFileName, " > ", InitiatingProcessFileName)\n    | project Timestamp, DeviceName, AccountName = InitiatingProcessAccountName, SourceTable="DeviceRegistryEvents",\n        Detail, ProcessTree, CommandLine = InitiatingProcessCommandLine,\n        SHA256 = "", InitiatingProcessSHA256;\nlet MiscEvents =\n    DeviceEvents\n    | where Timestamp > ago(30d)\n    | where InitiatingProcessFolderPath has_any (ScopedPaths)\n    | extend\n        Detail      = ActionType,\n        ProcessTree = strcat(InitiatingProcessParentFileName, " > ", InitiatingProcessFileName)\n    | project Timestamp, DeviceName, AccountName, SourceTable="DeviceEvents",\n        Detail, ProcessTree, CommandLine = InitiatingProcessCommandLine,\n        SHA256 = "", InitiatingProcessSHA256;\nunion ProcEvents, FileEvents, ImageLoadEvents, NetworkEvents, RegistryEvents, MiscEvents\n| summarize\n    FirstSeen    = min(Timestamp),\n    LastSeen     = max(Timestamp),\n    EventCount   = count(),\n    Accounts     = make_set(AccountName),\n    Details      = make_set(Detail),\n    CommandLines = make_set(CommandLine),\n    SHA256s      = make_set(SHA256)\n    by DeviceName, SourceTable, ProcessTree\n| sort by FirstSeen desc`;
    }
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
    case "FILE_PATH": {
      // CrowdStrike doesn't log drive letters — strip C:\ D:\ etc. from paths
      const cqlPaths = arr.map((p) => p.replace(/^[A-Za-z]:\\/, "\\\\"));
      return `#event_simpleName=ProcessRollup2 OR #event_simpleName=NewExecutableWritten\n| ImageFileName=/(${cqlPaths.map(reEsc).join("|")})/i\n| groupBy([ComputerName, ImageFileName, CommandLine, SHA256HashData], function=stats([count(as=Total), min(@timestamp, as=FirstSeen), max(@timestamp, as=LastSeen)]), limit=max)`;
    }
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

// DOCX text extraction using mammoth.js loaded from CDN at runtime
const MAMMOTH_CDN = "https://cdnjs.cloudflare.com/ajax/libs/mammoth/1.8.0/mammoth.browser.min.js";
let mammothPromise = null;
const loadMammoth = () => {
  if (typeof window !== "undefined" && window.mammoth) return Promise.resolve(window.mammoth);
  if (mammothPromise) return mammothPromise;
  mammothPromise = new Promise((resolve, reject) => {
    const s = document.createElement("script");
    s.src = MAMMOTH_CDN;
    s.onload = () => resolve(window.mammoth);
    s.onerror = () => { mammothPromise = null; reject(new Error("mammoth CDN load failed")); };
    document.head.appendChild(s);
  });
  return mammothPromise;
};

const extractDocxText = async (arrayBuffer) => {
  try {
    const mammoth = await loadMammoth();
    if (!mammoth) return null;
    const result = await mammoth.extractRawText({ arrayBuffer });
    const text = result?.value || "";
    return text.trim().length > 40 ? text : null;
  } catch (e) {
    console.warn("DOCX extraction failed:", e.message || e);
    return null;
  }
};

// PPTX text extraction using JSZip loaded from CDN at runtime
// PPTX files are ZIP archives with XML slides containing text in <a:t> tags
const JSZIP_CDN = "https://cdnjs.cloudflare.com/ajax/libs/jszip/3.10.1/jszip.min.js";
let jszipPromise = null;
const loadJSZip = () => {
  if (typeof window !== "undefined" && window.JSZip) return Promise.resolve(window.JSZip);
  if (jszipPromise) return jszipPromise;
  jszipPromise = new Promise((resolve, reject) => {
    const s = document.createElement("script");
    s.src = JSZIP_CDN;
    s.onload = () => resolve(window.JSZip);
    s.onerror = () => { jszipPromise = null; reject(new Error("JSZip CDN load failed")); };
    document.head.appendChild(s);
  });
  return jszipPromise;
};

const extractPptxText = async (arrayBuffer) => {
  try {
    const JSZip = await loadJSZip();
    if (!JSZip) return null;
    const zip = await JSZip.loadAsync(arrayBuffer);
    const parts = [];
    // Iterate slide XML files in order (slide1.xml, slide2.xml, ...)
    const slideFiles = Object.keys(zip.files)
      .filter((n) => /^ppt\/slides\/slide\d+\.xml$/i.test(n))
      .sort((a, b) => {
        const na = parseInt(a.match(/slide(\d+)/i)?.[1] || "0");
        const nb = parseInt(b.match(/slide(\d+)/i)?.[1] || "0");
        return na - nb;
      });
    for (const name of slideFiles) {
      const xml = await zip.files[name].async("text");
      // Extract text from <a:t>...</a:t> tags
      const texts = [];
      xml.replace(/<a:t[^>]*>([^<]*)<\/a:t>/gi, (_, t) => { if (t.trim()) texts.push(t.trim()); return ""; });
      if (texts.length) parts.push(texts.join(" "));
    }
    // Also check notesSlides for speaker notes (often contain IOCs)
    const noteFiles = Object.keys(zip.files).filter((n) => /^ppt\/notesSlides\/notesSlide\d+\.xml$/i.test(n));
    for (const name of noteFiles) {
      const xml = await zip.files[name].async("text");
      const texts = [];
      xml.replace(/<a:t[^>]*>([^<]*)<\/a:t>/gi, (_, t) => { if (t.trim()) texts.push(t.trim()); return ""; });
      if (texts.length) parts.push(texts.join(" "));
    }
    const out = parts.join("\n\n");
    return out.trim().length > 40 ? out : null;
  } catch (e) {
    console.warn("PPTX extraction failed:", e.message || e);
    return null;
  }
};

// XLSX text extraction using SheetJS (already bundled)
const extractXlsxText = (arrayBuffer) => {
  try {
    const wb = XLSX.read(arrayBuffer, { type: "array" });
    const parts = [];
    wb.SheetNames.forEach((name) => {
      const ws = wb.Sheets[name];
      const csv = XLSX.utils.sheet_to_csv(ws, { blankrows: false });
      if (csv.trim()) parts.push(csv);
    });
    const out = parts.join("\n\n");
    return out.trim().length > 10 ? out : null;
  } catch (e) {
    console.warn("XLSX extraction failed:", e.message || e);
    return null;
  }
};

// Supported upload formats and their MIME/extension mapping
const UPLOAD_ACCEPT = ".pdf,.txt,.csv,.md,.html,.htm,.json,.eml,.docx,.xlsx,.xls,.pptx";

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

  // Set custom favicon on mount
  useEffect(() => { setFavicon(); }, []);
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
  const [references, setReferences] = useState([]);               // URLs pulled from IOC card as references

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

  // ---- File upload: parse any supported format locally ----
  const fileInputRef = useRef(null);
  const [uploadDragging, setUploadDragging] = useState(false);

  const runUpload = async (file) => {
    if (!file) return;
    resetResults();
    setLoading(true);
    const ext = (file.name.split(".").pop() || "").toLowerCase();
    const fileName = file.name;
    let text = null;
    let isJson = false;

    try {
      if (ext === "pdf") {
        const buf = await file.arrayBuffer();
        text = await extractPdfText(buf);
        if (!text) throw new Error("Could not extract text from this PDF. It may be scanned/image-only.");
      } else if (ext === "docx") {
        const buf = await file.arrayBuffer();
        text = await extractDocxText(buf);
        if (!text) throw new Error("Could not extract text from this DOCX file.");
      } else if (ext === "pptx") {
        const buf = await file.arrayBuffer();
        text = await extractPptxText(buf);
        if (!text) throw new Error("Could not extract text from this PPTX file.");
      } else if (ext === "xlsx" || ext === "xls") {
        const buf = await file.arrayBuffer();
        text = extractXlsxText(buf);
        if (!text) throw new Error("Could not extract data from this spreadsheet.");
      } else if (ext === "json") {
        text = await file.text();
        isJson = true;
      } else if (["html", "htm"].includes(ext)) {
        const raw = await file.text();
        text = htmlToText(raw);
      } else {
        // txt, csv, md, eml — plain text
        text = await file.text();
      }

      if (!text || text.trim().length < 10) throw new Error("File appears empty or contains no extractable text.");

      // JSON files → try parseIocs first (MISP, STIX, iocparser.com exports)
      if (isJson) {
        try {
          const parsed = parseIocs(JSON.parse(text));
          if (Object.keys(parsed).length) {
            const origin = {};
            Object.entries(parsed).forEach(([c, arr]) => { origin[c] = {}; arr.forEach((v) => { origin[c][v] = "eng"; }); });
            { const { data: wd, refs: wr } = applyWhitelistAndRefs(parsed); setIocData(wd); setReferences(wr); }
            setOriginData(origin);
            setMeta({ title: fileName });
            setSourceUrl(`(uploaded: ${fileName})`);
            setRawArticle(text);
            setArticleClean(text);
            setLoading(false);
            return;
          }
        } catch { /* not structured IOC JSON — fall through to regex */ }
      }

      // Run local regex engine on extracted text
      const ex = extractIocs(text);
      const data = ex.data;
      if (!Object.keys(data).length) {
        throw new Error("No recognizable IOCs found in this file.");
      }

      const origin = {};
      Object.entries(data).forEach(([c, arr]) => { origin[c] = {}; arr.forEach((v) => { origin[c][v] = "eng"; }); });
      { const { data: wd, refs: wr } = applyWhitelistAndRefs(data); setIocData(wd); setReferences(wr); }
      setOriginData(origin);
      setRegistryDetails(ex.registryDetails);
      setMeta({ title: fileName });
      setSourceUrl(`(uploaded: ${fileName})`);
      setRawArticle(text);
      setArticleClean(text);
    } catch (e) {
      setError(e.message || "Failed to process uploaded file.");
    }
    setLoading(false);
  };

  const handleFileDrop = (e) => {
    e.preventDefault();
    setUploadDragging(false);
    const file = e.dataTransfer?.files?.[0];
    if (file) runUpload(file);
  };

  const handleFileSelect = (e) => {
    const file = e.target?.files?.[0];
    if (file) runUpload(file);
    if (e.target) e.target.value = ""; // allow re-uploading same file
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
              last: d.last_seen ? d.last_seen.split(" ")[0] : null,
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
            // Extract earliest/latest dates from URL entries
            const uhDates = j.urls.map((u) => u.dateadded).filter(Boolean).sort();
            results.urlhaus = {
              urls_total: j.urls.length, online, offline,
              status: online > 0 ? "online" : "offline",
              tags: [...new Set(j.urls.flatMap((u) => u.tags || []).filter((t) => t && !GENERIC_TAGS.has(t.toLowerCase())))].slice(0