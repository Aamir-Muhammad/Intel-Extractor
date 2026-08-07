// ============================================================
// Intel Extractor — © 2024-2026 Aamir Muhammad
// Licensed under the PolyForm Noncommercial License 1.0.0
// Commercial use, rehosting, and redistribution without
// explicit written permission from the author is prohibited.
// https://polyformproject.org/licenses/noncommercial/1.0.0/
// ============================================================
import { useState, useMemo, useRef, useEffect, Component } from "react";
import * as XLSX from "xlsx";
import {
  Shield, Search, Download, Copy, Check, Loader2, Globe,
  ClipboardPaste, AlertTriangle, ShieldOff, Trash2, Wand2,
  Crosshair, FileText, Linkedin, Github, X, Target, ShieldCheck, Sparkles, ChevronDown, RefreshCw, FileUp, Pencil, Share2, Zap, FileBarChart,
  Database, Terminal
} from "lucide-react";

// ============================================================
//  Backend proxy
// ============================================================
const WORKER_BASE = "https://ioc-parser.aamirmuhd.workers.dev";

// Anonymous per-browser session id for usage analytics. Generated once,
// persisted in localStorage. No PII — just a random string so the dashboard
// can group activity by browser. Cleared if the user clears site data.
const getSessionId = () => {
  try {
    let sid = localStorage.getItem("intel-session-id");
    if (!sid) {
      sid = "s-" + Math.random().toString(36).slice(2, 10) + Date.now().toString(36).slice(-4);
      localStorage.setItem("intel-session-id", sid);
    }
    return sid;
  } catch { return "s-nostorage"; }
};
const SESSION_ID = getSessionId();
// NOTE: analytics are logged entirely server-side (in worker.js), piggybacked
// onto the /fetch, /parse, and /enrich requests the app already makes for
// functional reasons — SESSION_ID is attached to those, but there is no
// dedicated client-initiated logging call. Invisible to browser DevTools.
const APP_VERSION = "v111";

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
const WL_DOMAINS = new Set(["github.com","www.github.com","github.io","localhost","example.com","www.example.com","kaspersky.com","www.kaspersky.com","fbi.gov","www.fbi.gov","mitre.org","attack.mitre.org","www.mitre.org","gmail.com","www.gmail.com","trendmicro.com","www.trendmicro.com","zscloud.net","admin.zscloud.net"]);
// Wildcard suffix whitelist — any subdomain of these roots is whitelisted.
const WL_SUFFIXES = [
  "microsoft.com","microsoftonline.com","office.com","office365.com",
  "azure.com","azureedge.net","azurewebsites.net","windows.net",
  "sharepoint.com","live.com","bing.com","msn.com","outlook.com",
  "skype.com","xbox.com","visualstudio.com","nuget.org",
];
// URL whitelist — github.com is intentionally NOT here: full GitHub URLs are
// often real IOCs (payload hosting, raw.githubusercontent staging) and must
// survive into the URL card. Only the bare DOMAIN entry gets filtered.
const WL_URL_HOSTS = new Set(["localhost","example.com","www.example.com","kaspersky.com","www.kaspersky.com","fbi.gov","www.fbi.gov","mitre.org","attack.mitre.org","www.mitre.org"]);
// Domain suffixes to filter (any domain ending in these gets removed)
const WL_DOMAIN_SUFFIXES = [
  ".mitre.org",
  // Microsoft owned-and-operated domains only — NOT tenant-hostable ones.
  // Excluded: .azure.com, .azureedge.net, .azurewebsites.net, .windows.net,
  // .sharepoint.com — attackers can create subdomains on those (C2, phishing,
  // malware hosting) so they must never be auto-whitelisted.
  ".microsoft.com",".microsoftonline.com",".office.com",".office365.com",
  ".live.com",".bing.com",".msn.com",".outlook.com",
  ".skype.com",".xbox.com",".visualstudio.com",".nuget.org",
];
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

// CDN / analytics / benign infrastructure hosts. A page contacting these is
// normal web behavior, not threat infrastructure — so they're filtered out of
// urlscan's contacted-IPs/domains before those become graph nodes, to avoid
// cluttering the graph with fonts.googleapis.com and similar noise.
const BENIGN_INFRA_SUFFIXES = new Set([
  "googleapis.com","gstatic.com","google.com","google-analytics.com",
  "googletagmanager.com","googlesyndication.com","googleadservices.com",
  "doubleclick.net","gomngr.com","recaptcha.net",
  "cloudflare.com","cloudflareinsights.com","cloudflare.net","cdnjs.cloudflare.com",
  "cloudfront.net","amazonaws.com","akamai.net","akamaiedge.net","akamaihd.net",
  "fastly.net","fastlylb.net","jsdelivr.net","unpkg.com","bootstrapcdn.com",
  "fontawesome.com","typekit.net","use.fontawesome.com",
  "facebook.com","facebook.net","fbcdn.net","connect.facebook.net",
  "twitter.com","x.com","t.co","twimg.com",
  "linkedin.com","licdn.com","instagram.com","cdninstagram.com",
  "youtube.com","ytimg.com","youtu.be","vimeo.com",
  "gravatar.com","wp.com","wordpress.org","w.org","gmpg.org",
  "jquery.com","code.jquery.com","polyfill.io",
  "cookiebot.com","onetrust.com","cookielaw.org","hotjar.com","hotjar.io",
  "segment.com","segment.io","mixpanel.com","amplitude.com","newrelic.com",
  "bing.com","microsoft.com","msn.com","live.com","office.com","office365.com",
  "windows.net","azureedge.net","azure.com","msftauth.net","msauth.net",
  "apple.com","icloud.com","mzstatic.com","cdn-apple.com",
  "adobe.com","typekit.com","demdex.net","omtrdc.net","2o7.net",
  "sentry.io","sentry-cdn.com","bugsnag.com","datadoghq.com","cloudflare-dns.com",
  "gtld-servers.net","root-servers.net","nstld.com",
]);
// True if a host is benign CDN/analytics infrastructure (exact or subdomain match)
const isBenignInfra = (host) => {
  if (!host) return false;
  const h = String(host).toLowerCase().replace(/\.$/, "");
  if (BENIGN_INFRA_SUFFIXES.has(h)) return true;
  const parts = h.split(".");
  for (let i = 1; i < parts.length - 1; i++) {
    if (BENIGN_INFRA_SUFFIXES.has(parts.slice(i).join("."))) return true;
  }
  return false;
};
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

// Smart age: "18 Hours", "28 Days", "5 Months", "1.2 Years"
const smartAge = (days) => {
  if (days == null) return "";
  if (days < 1) {
    const hours = Math.max(1, Math.round(days * 24));
    return `${hours} Hour${hours !== 1 ? "s" : ""}`;
  }
  if (days < 60) return `${days} Day${days !== 1 ? "s" : ""}`;
  if (days < 365) {
    const months = Math.round(days / 30.44);
    return `${months} Month${months !== 1 ? "s" : ""}`;
  }
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
  // Blast animation keyframe for hash consolidation
  if (!document.getElementById("hash-blast-style")) {
    const s = document.createElement("style");
    s.id = "hash-blast-style";
    s.textContent = `@keyframes hashBlast {
      0%   { box-shadow: 0 0 0 0 rgba(124,156,255,0.8), 0 0 0 0 rgba(124,156,255,0.4); background: rgba(124,156,255,0.18); }
      40%  { box-shadow: 0 0 0 6px rgba(124,156,255,0.4), 0 0 28px rgba(124,156,255,0.3); background: rgba(124,156,255,0.10); }
      100% { box-shadow: 0 0 0 14px rgba(124,156,255,0), 0 0 0 rgba(124,156,255,0); background: transparent; }
    }
    @keyframes hashFlash {
      0%   { opacity: 0; transform: translate(-50%,-80%) scale(0.8); }
      15%  { opacity: 1; transform: translate(-50%,-80%) scale(1.05); }
      70%  { opacity: 1; transform: translate(-50%,-80%) scale(1); }
      100% { opacity: 0; transform: translate(-50%,-90%) scale(0.95); }
    }
    @keyframes toastSlide {
      0%   { opacity: 0; transform: translateY(-20px) scale(0.9); }
      10%  { opacity: 1; transform: translateY(0) scale(1.02); }
      15%  { opacity: 1; transform: translateY(0) scale(1); }
      85%  { opacity: 1; transform: translateY(0) scale(1); }
      100% { opacity: 0; transform: translateY(-20px) scale(0.95); }
    }`;
    document.head.appendChild(s);
  }
};

// ============================================================
//  RDAP bootstrap — IANA publishes the authoritative TLD → RDAP
//  server map. Cached for the session so we only fetch it once.
//  Without this, ccTLDs like .me/.io/.xyz hit servers that don't
//  own them and return 404, which we'd wrongly read as "deleted".
// ============================================================
let rdapMapPromise = null;

// Registry-operator RDAP bases for TLDs absent from IANA's bootstrap.
// Routing by *operator* rather than per-TLD hostname covers a long tail in
// one shot (Identity Digital alone is the backend for dozens of ccTLDs).
// Always probed as NON-authoritative: a 404 here never implies deletion.
const RDAP_OPERATOR = {
  // Identity Digital (formerly Afilias / Donuts) — registry backend
  me: "https://rdap.identitydigital.services/rdap",
  io: "https://rdap.identitydigital.services/rdap",
  sh: "https://rdap.identitydigital.services/rdap",
  ac: "https://rdap.identitydigital.services/rdap",
  mn: "https://rdap.identitydigital.services/rdap",
  bz: "https://rdap.identitydigital.services/rdap",
  lc: "https://rdap.identitydigital.services/rdap",
  vc: "https://rdap.identitydigital.services/rdap",
  ag: "https://rdap.identitydigital.services/rdap",
  gi: "https://rdap.identitydigital.services/rdap",
  // CentralNic
  la: "https://rdap.centralnic.com/la",
  pw: "https://rdap.centralnic.com/pw",
  // Channel Islands
  gg: "https://rdap.channelisles.net",
  je: "https://rdap.channelisles.net",
};
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
  SSDEEP: "#f472b6", IMPHASH: "#f59e0b", AUTHENTIHASH: "#eab308",
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

const trimTok = (s) => {
  if (isIPv6(s)) return s; // don't strip the leading/trailing "::" of "::1", "fe80::", etc.
  return s.replace(/^[.,;:!?'"`(){}<>\u201c\u201d\u2018\u2019]+/, "")
   .replace(/[.,;:!?'"`(){}<>\u201c\u201d\u2018\u2019]+$/, "");
};

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

// Validates full and "::"-compressed IPv6 notation — plain group-count math
// rather than one giant regex, so every valid compression point is covered.
const isIPv6 = (t) => {
  if (!t.includes(":")) return false;
  if (t.split("::").length > 2) return false; // at most one "::"
  let groups;
  if (t.includes("::")) {
    const [left, right] = t.split("::");
    const leftGroups = left ? left.split(":") : [];
    const rightGroups = right ? right.split(":") : [];
    groups = [...leftGroups, ...rightGroups];
    if (groups.length > 7) return false; // "::" must stand in for >=1 group
  } else {
    groups = t.split(":");
    if (groups.length !== 8) return false;
  }
  return groups.every((g) => /^[0-9a-f]{1,4}$/i.test(g));
};

const ipCat = (t) => (t.includes(":") ? "IPV6" : "IPV4");

// Strip port suffix from an IP — "1.2.3.4:8080" → "1.2.3.4"
const stripPort = (t) => t.replace(/:\d{1,5}$/, "");

// Expand CIDR notation to individual IPs (max /24 = 256 hosts).
// Larger ranges are kept as-is (return null → caller keeps original token).
const expandCIDR = (cidr) => {
  const m = cidr.match(/^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\/(\d{1,2})$/);
  if (!m) return null;
  const prefix = parseInt(m[2], 10);
  if (prefix < 24) return null; // too large to expand sensibly
  const parts = m[1].split(".").map(Number);
  if (parts.some((p) => p < 0 || p > 255)) return null;
  const base = (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3];
  const count = Math.pow(2, 32 - prefix);
  const ips = [];
  for (let i = 1; i < count - 1; i++) { // skip network + broadcast
    const n = (base | i) >>> 0;
    ips.push(`${(n >>> 24) & 255}.${(n >>> 16) & 255}.${(n >>> 8) & 255}.${n & 255}`);
  }
  return ips.length ? ips : null;
};

// Expand last-octet IP ranges — "1.2.3.5-10" → ["1.2.3.5", ..., "1.2.3.10"]
// Also handles full-range "1.2.3.5-1.2.3.10"
const expandIPRange = (t) => {
  // Full range: 1.2.3.5-1.2.3.10
  const full = t.match(/^(\d{1,3}\.\d{1,3}\.\d{1,3}\.)(\d{1,3})-\d{1,3}\.\d{1,3}\.\d{1,3}\.(\d{1,3})$/);
  if (full) {
    const prefix = full[1], a = parseInt(full[2], 10), b = parseInt(full[3], 10);
    if (a > b || b > 255) return null;
    return Array.from({ length: b - a + 1 }, (_, i) => `${prefix}${a + i}`);
  }
  // Last-octet range: 1.2.3.5-10
  const last = t.match(/^(\d{1,3}\.\d{1,3}\.\d{1,3}\.)(\d{1,3})-(\d{1,3})$/);
  if (last) {
    const prefix = last[1], a = parseInt(last[2], 10), b = parseInt(last[3], 10);
    if (a > b || b > 255) return null;
    return Array.from({ length: b - a + 1 }, (_, i) => `${prefix}${a + i}`);
  }
  return null;
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
  // Strip port suffix before IPV4 check — "1.2.3.4:8080" → classify as IPV4 "1.2.3.4"
  // Port must be 1-65535; reject invalid ports like :99999
  const portMatch = t.match(/^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d{1,5})$/);
  if (portMatch && parseInt(portMatch[2], 10) <= 65535) {
    const bare = portMatch[1];
    if (isIPv4(bare)) return ["IPV4", bare];
  }
  if (isIPv4(t)) return ["IPV4", t]; // bare IP with no port
  if (/^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$/i.test(t) || /^(?:[0-9a-f]{2}-){5}[0-9a-f]{2}$/i.test(t)) return ["MAC_ADDRESS", t.toLowerCase()];
  if (isIPv6(t)) return ["IPV6", t.toLowerCase()];
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
  if (/^([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/i.test(t)) {
    const dom = t.toLowerCase().replace(/^www\./, "");
    return ["DOMAIN", dom];
  }
  return null;
};

const ORDER = ["IPV4","IPV6","DOMAIN","URL","EMAIL","MD5","SHA1","SHA256","SHA512","SSDEEP","IMPHASH","AUTHENTIHASH","CVE","MITRE_ATTACK","YARA","ASN","MAC_ADDRESS","BTC","XMR","ETH","REGISTRY","SCHEDULED_TASK","SERVICE","COMMAND_LINE","FILE_NAME","FILE_PATH"];

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

  // Label-based extraction for IMPHASH / AUTHENTIHASH — these share the 32/40-hex
  // format with MD5/SHA1, so we can only distinguish them when explicitly labeled
  // (e.g. "imphash: abc123..." or "Authentihash: def456..."). Extract and strip
  // so they don't get misclassified as MD5/SHA1 in the general pass.
  work = work.replace(/\b(imphash|imp[_\s-]?hash)\s*[:=]\s*([a-fA-F0-9]{32})\b/gi, (_m, _l, h) => {
    add("IMPHASH", h.toLowerCase());
    return " ";
  });
  work = work.replace(/\b(authentihash|authenti[_\s-]?hash)\s*[:=]\s*([a-fA-F0-9]{40,64})\b/gi, (_m, _l, h) => {
    add("AUTHENTIHASH", h.toLowerCase());
    return " ";
  });

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
      // CIDR notation — expand ranges, handle /32 single-host as bare IP
      if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2}$/.test(t)) {
        const prefix = parseInt(t.split("/")[1], 10);
        const bareIP = t.split("/")[0];
        if (prefix === 32) {
          // /32 = single host — strip the mask and add the bare IP
          if (isIPv4(bareIP)) { add("IPV4", bareIP); continue; }
        } else {
          const expanded = expandCIDR(t);
          if (expanded) { expanded.forEach((ip) => add("IPV4", ip)); continue; }
          // prefix < 24 — too large to expand, fall through to classify as-is
        }
      }
      // IP range expansion — "1.2.3.5-10" or "1.2.3.5-1.2.3.10"
      if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}-/.test(t)) {
        const expanded = expandIPRange(t);
        if (expanded) { expanded.filter(isIPv4).forEach((ip) => add("IPV4", ip)); continue; }
      }
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
const normVal = (cat, v) => {
  let n = CASE_SENSITIVE_CATS.has(cat) ? v : String(v).toLowerCase();
  // Strip www. prefix from domains — it adds no intel value and creates duplicates
  if (cat === "DOMAIN") n = n.replace(/^www\./, "");
  return n;
};

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

  // Cross-category dedup: a URL with no path component is a DOMAIN, not a URL.
  // iocparser sometimes returns bare hostnames as URLs — move them to DOMAIN.
  if (data.URL) {
    const toPromote = [];
    data.URL = data.URL.filter((v) => {
      try {
        const u = new URL(v.includes("://") ? v : "https://" + v);
        const hasPath = u.pathname && u.pathname !== "/" && u.pathname !== "";
        const hasQuery = !!u.search;
        if (!hasPath && !hasQuery) { toPromote.push(u.hostname.toLowerCase()); return false; }
      } catch { /* keep on parse failure */ }
      return true;
    });
    if (!data.URL.length) delete data.URL;
    toPromote.forEach((dom) => put("DOMAIN", dom, "dedup"));
  }

  // Master dedup: remove a value from lower-priority categories if it already
  // exists in a higher-priority one. Priority: specific hash > DOMAIN > URL.
  // Main case: kawosyetw.gu.cc parsed as both DOMAIN and URL → keep DOMAIN only.
  if (data.DOMAIN && data.URL) {
    const domainSet = new Set(data.DOMAIN.map((d) => d.toLowerCase()));
    data.URL = data.URL.filter((u) => {
      try {
        const host = new URL(u.includes("://") ? u : "https://" + u).hostname.toLowerCase();
        return !domainSet.has(host);
      } catch { return true; }
    });
    if (!data.URL.length) delete data.URL;
  }

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
// CrowdStrike epoch time formatter — appended to any query that produces
// FirstSeen/LastSeen timestamp fields so analysts see human-readable dates.
const CQL_TIME_FMT = (first = "FirstSeen", last = "LastSeen") =>
  `\n| ${first} := formatTime("%e %b %Y %r", field=${first}, locale=en_UAE, timezone="Asia/Dubai")\n| ${last}  := formatTime("%e %b %Y %r", field=${last}, locale=en_UAE, timezone="Asia/Dubai")`;

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

const AQL_BASE = `SELECT DATEFORMAT("startTime", 'dd MMM yyyy hh:mm a') AS 'Start Time', QIDNAME(qid) AS 'Event Name', logsourcename(logSourceId) AS 'Log Source', categoryname(category) AS 'Low Level Category'`;
const AQL_NET = `, "hostname" AS 'Domain', "URL" AS 'URL', "sourceIP" AS 'Source IP', "sourcePort" AS 'Source Port', "destinationIP" AS 'Destination IP', "destinationPort" AS 'Destination Port', "userName" AS 'Username', "eventCount" AS 'Event Count'`;
const AQL_TAIL = `\nORDER BY "Start Time" DESC LAST 30 DAYS`;
const aqlHashFields = (label, field) => `, "${field}" AS '${label}', "file hash" AS 'File Hash', "Command" AS 'CommandLine', "Process Path" AS 'Child Process Path', "Parent Process Path" AS 'Parent Process Path', "Parent Command" AS 'Parent CommandLine', "sourceIP" AS 'Source IP', "destinationIP" AS 'Destination IP', "userName" AS 'Username', "eventCount" AS 'Event Count'`;
const ilikeOr = (field, arr) => arr.map((v) => `"${field}" ILIKE '%${v.replace(/'/g, "''")}%'`).join("\n    OR ");

const buildAQL = (details) => {
  const clauses = uniqDetails(details).map((d) => {
    const keyEsc = stripHive(d.key).replace(/'/g, "''");
    const parts = [`"payload" ILIKE '%${keyEsc}%'`];
    if (d.valueName) parts.push(`"payload" ILIKE '%${String(d.valueName).replace(/'/g, "''")}%'`);
    if (d.data !== undefined && d.data !== null && d.data !== "") parts.push(`"payload" ILIKE '%${String(d.data).replace(/'/g, "''")}%'`);
    return parts.length > 1 ? `(${parts.join(" AND ")})` : parts[0];
  });
  return `${AQL_BASE}${AQL_NET} FROM events WHERE ${clauses.join("\n    OR ")}${AQL_TAIL}`;
};

// ---- Universal hunt query builders: per-category KQL / CQL / SPL / AQL ----
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
      return `#event_simpleName=NetworkConnectIP4\n| ${cqlIn("RemoteAddressIP4")}\n| groupBy([ComputerName, RemoteAddressIP4, RemotePort, ImageFileName], function=stats([count(as=Total), min(@timestamp, as=FirstSeen), max(@timestamp, as=LastSeen)]), limit=max)${CQL_TIME_FMT()}`;
    case "IPV6":
      return `#event_simpleName=NetworkConnectIP6\n| ${cqlIn("RemoteAddressIP6")}\n| groupBy([ComputerName, RemoteAddressIP6, RemotePort, ImageFileName], function=stats([count(as=Total), min(@timestamp, as=FirstSeen), max(@timestamp, as=LastSeen)]), limit=max)${CQL_TIME_FMT()}`;
    case "DOMAIN":
      return `#event_simpleName=DnsRequest\n| ${cqlInWild("DomainName")}\n| groupBy([ComputerName, DomainName, RespondingDnsServer, ImageFileName], function=stats([count(as=Total), min(@timestamp, as=FirstSeen), max(@timestamp, as=LastSeen)]), limit=max)${CQL_TIME_FMT()}`;
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
      return `#event_simpleName=ProcessRollup2 OR #event_simpleName=NewExecutableWritten\n| ImageFileName=/(${cqlPaths.map(reEsc).join("|")})/i\n| groupBy([ComputerName, ImageFileName, CommandLine, SHA256HashData], function=stats([count(as=Total), min(@timestamp, as=FirstSeen), max(@timestamp, as=LastSeen)]), limit=max)${CQL_TIME_FMT()}`;
    }
    case "EMAIL":
      return `#event_simpleName=UserLogon OR #event_simpleName=SSOLogin\n| ${cqlIn("UserPrincipal")}\n| groupBy([ComputerName, UserPrincipal, LogonType], function=stats([count(as=Total), min(@timestamp, as=FirstSeen), max(@timestamp, as=LastSeen)]), limit=max)${CQL_TIME_FMT()}`;
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

const huntAQL = (cat, arr) => {
  const ql = (a) => a.map((v) => `'${v.replace(/'/g, "''")}'`).join(", ");
  switch (cat) {
    case "IPV4": case "IPV6":
      return `${AQL_BASE}${AQL_NET} FROM events WHERE sourceip IN (${ql(arr)}) OR destinationip IN (${ql(arr)})${AQL_TAIL}`;
    case "DOMAIN":
      return `${AQL_BASE}${AQL_NET} FROM events WHERE (${ilikeOr("url", arr)})\n    OR (${ilikeOr("hostname", arr)})${AQL_TAIL}`;
    case "URL": {
      const hosts = [...new Set(arr.map((u) => { try { return u.replace(/^https?:\/\//i, "").split("/")[0].split(":")[0]; } catch { return u; } }))];
      const allTerms = [...new Set([...arr, ...hosts])];
      return `${AQL_BASE}${AQL_NET} FROM events WHERE (${ilikeOr("url", allTerms)})\n    OR (${ilikeOr("hostname", hosts)})${AQL_TAIL}`;
    }
    case "MD5":
      return `${AQL_BASE}${aqlHashFields("MD5", "MD5 Hash")} FROM events WHERE (${arr.map((v) => `"MD5 Hash" ILIKE '${v.replace(/'/g, "''")}'`).join("\n    OR ")})\n    OR (${arr.map((v) => `"file hash" ILIKE '${v.replace(/'/g, "''")}'`).join("\n    OR ")})${AQL_TAIL}`;
    case "SHA1":
      return `${AQL_BASE}${aqlHashFields("SHA1", "SHA1 Hash")} FROM events WHERE (${arr.map((v) => `"SHA1 Hash" ILIKE '${v.replace(/'/g, "''")}'`).join("\n    OR ")})\n    OR (${arr.map((v) => `"file hash" ILIKE '${v.replace(/'/g, "''")}'`).join("\n    OR ")})${AQL_TAIL}`;
    case "SHA256":
      return `${AQL_BASE}${aqlHashFields("SHA256", "SHA256 Hash")} FROM events WHERE (${arr.map((v) => `"SHA256 Hash" ILIKE '${v.replace(/'/g, "''")}'`).join("\n    OR ")})\n    OR (${arr.map((v) => `"file hash" ILIKE '${v.replace(/'/g, "''")}'`).join("\n    OR ")})${AQL_TAIL}`;
    case "EMAIL":
      return `${AQL_BASE}${AQL_NET} FROM events WHERE ${ilikeOr("userName", arr)}${AQL_TAIL}`;
    case "FILE_NAME": case "FILE_PATH":
      return `${AQL_BASE}${AQL_NET} FROM events WHERE ${ilikeOr("payload", arr)}${AQL_TAIL}`;
    case "CVE":
      return `${AQL_BASE}${AQL_NET} FROM events WHERE ${ilikeOr("payload", arr)}${AQL_TAIL}`;
    case "SCHEDULED_TASK": {
      const names = arr.map((v) => v.split(" → ")[0].trim());
      return `${AQL_BASE}${AQL_NET} FROM events WHERE ${ilikeOr("payload", names)}${AQL_TAIL}`;
    }
    case "SERVICE": {
      const names = arr.map((v) => v.split(" → ")[0].trim());
      return `${AQL_BASE}${AQL_NET} FROM events WHERE ${ilikeOr("payload", names)}${AQL_TAIL}`;
    }
    case "COMMAND_LINE": {
      const tokens = new Set();
      arr.forEach((cl) => {
        (String(cl).match(/"[^"]{4,80}"/g) || []).forEach((m) => tokens.add(m.slice(1, -1)));
        (String(cl).match(/[A-Za-z]:\\[^\s"']{3,150}/g) || []).forEach((m) => tokens.add(m));
      });
      const distinctive = [...tokens].filter((t) => t.length > 3).slice(0, 15);
      const patterns = distinctive.length ? distinctive : arr.slice(0, 10);
      return `${AQL_BASE}${AQL_NET} FROM events WHERE ${ilikeOr("payload", patterns)}${AQL_TAIL}`;
    }
    default: return null;
  }
};

// Sigma — generic, SIEM-agnostic detection format (SigmaHQ taxonomy).
// Only covers categories with a well-established, unambiguous Sigma logsource
// category. EMAIL and CVE are deliberately omitted: Sigma has no single
// universally-standard mail logsource category, and Sigma is a log-matching
// format (not applicable to CVE/vulnerability-database matching) — returning
// null here (same as CQL already does for CVE) beats fabricating a
// non-standard mapping.
const huntSigma = (cat, arr, sourceUrl) => {
  const yamlList = (items, indent = "        ") =>
    items.map((v) => `${indent}- '${String(v).replace(/'/g, "''")}'`).join("\n");
  const sourceLabel = (sourceUrl && sourceUrl !== "(pasted JSON)" && sourceUrl !== "(raw paste)")
    ? defang(stripScheme(sourceUrl)) : "threat intelligence enrichment";

  switch (cat) {
    case "IPV4": case "IPV6":
      return `title: Network Connection to Known-Malicious IP
status: experimental
description: Detects network connections to IP(s) sourced from ${sourceLabel}
references:
    - Intel Extractor enrichment via hxxps[://]aamir-muhammad[.]github[.]io/Intel-Extractor
author: Aamir Muhammad
logsource:
    category: network_connection
detection:
    selection:
        DestinationIp:
${yamlList(arr)}
    condition: selection
falsepositives:
    - Legitimate connections to shared/CDN/cloud infrastructure
level: high`;

    case "DOMAIN":
      return `title: DNS Query for Known-Malicious Domain
status: experimental
description: Detects DNS resolution of domain(s) sourced from ${sourceLabel}
references:
    - Intel Extractor enrichment via hxxps[://]aamir-muhammad[.]github[.]io/Intel-Extractor
author: Aamir Muhammad
logsource:
    category: dns_query
detection:
    selection:
        query|contains:
${yamlList(arr)}
    condition: selection
falsepositives:
    - Unknown
level: high`;

    case "URL": {
      const hosts = [...new Set(arr.map((u) => { try { return u.replace(/^https?:\/\//i, "").split("/")[0].split(":")[0]; } catch { return u; } }))];
      return `title: Proxy Request to Known-Malicious URL
status: experimental
description: Detects HTTP(S) requests matching URL(s) sourced from ${sourceLabel}
references:
    - Intel Extractor enrichment via hxxps[://]aamir-muhammad[.]github[.]io/Intel-Extractor
author: Aamir Muhammad
logsource:
    category: proxy
detection:
    selection_url:
        c-uri|contains:
${yamlList(arr)}
    selection_host:
        cs-host:
${yamlList(hosts)}
    condition: 1 of selection_*
falsepositives:
    - Unknown
level: high`;
    }

    case "MD5": case "SHA1": case "SHA256": {
      return `title: Process Creation Matching Known-Malicious ${cat} Hash
status: experimental
description: Detects process creation events where the file hash matches (a) known-malicious ${cat}(s) sourced from ${sourceLabel}
references:
    - Intel Extractor enrichment via hxxps[://]aamir-muhammad[.]github[.]io/Intel-Extractor
author: Aamir Muhammad
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Hashes|contains:
${yamlList(arr)}
    condition: selection
falsepositives:
    - Unknown
level: high`;
    }

    case "FILE_NAME":
      return `title: Process Creation Matching Known-Malicious File Name
status: experimental
description: Detects process creation events where the image file name matches (a) known-malicious file name(s) sourced from ${sourceLabel}
references:
    - Intel Extractor enrichment via hxxps[://]aamir-muhammad[.]github[.]io/Intel-Extractor
author: Aamir Muhammad
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith:
${yamlList(arr.map((f) => `\\${f}`))}
    condition: selection
falsepositives:
    - Legitimate file sharing the same name in a different location
level: high`;

    case "FILE_PATH":
      return `title: File Event Matching Known-Malicious File Path
status: experimental
description: Detects file creation/write events matching (a) known-malicious file path(s) sourced from ${sourceLabel}
references:
    - Intel Extractor enrichment via hxxps[://]aamir-muhammad[.]github[.]io/Intel-Extractor
author: Aamir Muhammad
logsource:
    category: file_event
    product: windows
detection:
    selection:
        TargetFilename|contains:
${yamlList(arr)}
    condition: selection
falsepositives:
    - Unknown
level: high`;

    case "SCHEDULED_TASK": {
      const names = arr.map((v) => v.split(" → ")[0].trim());
      return `title: Scheduled Task Creation/Modification Matching Known-Malicious Task Name
status: experimental
description: Detects scheduled task creation/modification via schtasks.exe/at.exe/PowerShell matching task name(s) sourced from ${sourceLabel}
references:
    - Intel Extractor enrichment via hxxps[://]aamir-muhammad[.]github[.]io/Intel-Extractor
author: Aamir Muhammad
logsource:
    category: process_creation
    product: windows
detection:
    selection_tools:
        Image|endswith:
            - '\\schtasks.exe'
            - '\\at.exe'
            - '\\powershell.exe'
            - '\\pwsh.exe'
    selection_name:
        CommandLine|contains:
${yamlList(names)}
    condition: all of selection_*
falsepositives:
    - Legitimate scheduled task administration
level: high`;
    }

    case "SERVICE": {
      const names = arr.map((v) => v.split(" → ")[0].trim());
      return `title: Service Creation/Modification Matching Known-Malicious Service Name
status: experimental
description: Detects service creation/modification via sc.exe/PowerShell matching service name(s) sourced from ${sourceLabel}
references:
    - Intel Extractor enrichment via hxxps[://]aamir-muhammad[.]github[.]io/Intel-Extractor
author: Aamir Muhammad
logsource:
    category: process_creation
    product: windows
detection:
    selection_tools:
        Image|endswith:
            - '\\sc.exe'
            - '\\powershell.exe'
            - '\\pwsh.exe'
    selection_name:
        CommandLine|contains:
${yamlList(names)}
    condition: all of selection_*
falsepositives:
    - Legitimate service administration
level: high`;
    }

    case "COMMAND_LINE": {
      const tokens = new Set();
      arr.forEach((cl) => {
        (String(cl).match(/"[^"]{4,80}"/g) || []).forEach((m) => tokens.add(m.slice(1, -1)));
        (String(cl).match(/[A-Za-z]:\\[^\s"']{3,150}/g) || []).forEach((m) => tokens.add(m));
      });
      const distinctive = [...tokens].filter((t) => t.length > 3).slice(0, 15);
      const patterns = distinctive.length ? distinctive : arr.slice(0, 10);
      return `title: Process Creation Matching Known-Malicious Command Line
status: experimental
description: Detects process creation events where the command line matches pattern(s) sourced from ${sourceLabel}
references:
    - Intel Extractor enrichment via hxxps[://]aamir-muhammad[.]github[.]io/Intel-Extractor
author: Aamir Muhammad
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains:
${yamlList(patterns)}
    condition: selection
falsepositives:
    - Unknown
level: high`;
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
    if (enrichCache[key] && !enrichCache[key].error) return;
    setEnrichCache((c) => ({ ...c, [key]: { loading: true } }));
    const results = {};
    const _t0 = Date.now();
    const _apiLog = [];

    // Push partial results to the cache immediately as each engine completes,
    // so the card renders progressively rather than waiting for all engines.
    const setPartial = () => {
      setEnrichCache((c) => ({ ...c, [key]: { loading: true, data: Object.keys(results).length > 0 ? { ...results } : null } }));
    };
    const callEnrich = async (api, otxType, otxSection, overrideValue, extra) => {
      const body = { api, value: overrideValue || value, cat, session_id: SESSION_ID }; // cat + session_id for server-side D1 logging
      if (otxType) body.otx_type = otxType;
      if (otxSection) body.otx_section = otxSection;
      if (extra && typeof extra === "object") Object.assign(body, extra);
      const _apiT0 = Date.now();
      const r = await fetch(`${WORKER_BASE}/enrich`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      _apiLog.push({ api, status: r.status, ms: Date.now() - _apiT0 });
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      const text = await r.text();
      try { return JSON.parse(text); } catch {
        throw new Error(text.slice(0, 100));
      }
    };

    // ═══════════════════════════════════════════════════════════════
    // CVE: CISA KEV (confirmed active exploitation), EPSS (predicted
    // 30-day exploitation probability), NVD (CVSS severity + description).
    // ═══════════════════════════════════════════════════════════════
    if (cat === "CVE") {
      try {
        const kevj = await callEnrich("cisa_kev");
        if (kevj && !kevj.error) {
          results.cisaKev = {
            listed: !!kevj.listed,
            dateAdded: kevj.dateAdded || null,
            dueDate: kevj.dueDate || null,
            ransomwareUse: kevj.ransomwareUse && kevj.ransomwareUse !== "Unknown" ? kevj.ransomwareUse : null,
          };
        }
      } catch (e) { console.warn("Enrich CISA KEV failed:", e.message); }
      setPartial();

      try {
        const epssj = await callEnrich("epss");
        const row = epssj?.data?.[0];
        if (row) {
          results.epss = {
            score: Math.round(parseFloat(row.epss) * 1000) / 10,       // percentage, 1 decimal
            percentile: Math.round(parseFloat(row.percentile) * 1000) / 10,
          };
        }
      } catch (e) { console.warn("Enrich EPSS failed:", e.message); }
      setPartial();

      try {
        const nvdj = await callEnrich("nvd");
        const vuln = nvdj?.vulnerabilities?.[0]?.cve;
        if (vuln) {
          const metrics = vuln.metrics || {};
          const cvssEntry = (metrics.cvssMetricV31 || metrics.cvssMetricV30 || metrics.cvssMetricV2 || [])[0];
          const cvssData = cvssEntry?.cvssData;
          const desc = (vuln.descriptions || []).find(d => d.lang === "en")?.value || null;
          results.nvd = {
            cvss: cvssData?.baseScore ?? null,
            severity: cvssData?.baseSeverity || cvssEntry?.baseSeverity || null,
            description: desc,
            published: vuln.published ? vuln.published.split("T")[0] : null,
          };
        }
      } catch (e) { console.warn("Enrich NVD failed:", e.message); }
      setPartial();
    }

    // ═══════════════════════════════════════════════════════════════
    // PRE-FLIGHT: For MD5/SHA1, run Tri.age then Kaspersky first.
    // If either resolves to a canonical SHA256 that's already in the
    // IOC list → short-circuit: skip all remaining calls, transfer
    // data to the SHA256 card, trigger collapse animation.
    // ═══════════════════════════════════════════════════════════════
    if (["MD5","SHA1"].includes(cat)) {
      try {
        // Step 1: Tri.age hash search
        const triageAlgo = { MD5: "md5", SHA1: "sha1" }[cat];
        const tj = await callEnrich("triage", triageAlgo, null);
        if (tj && !tj.error && tj.found) {
          // Cache under SHA256 immediately so SHA256 enrichment reuses it
          const tSHA256 = (tj.sha256 || tj.SHA256 || "").toLowerCase();
          if (tSHA256) {
            const sha256Key = `SHA256::${tSHA256}`;
            results._canonicalSHA256 = tSHA256;
            results.triage = {
              sampleId: tj.sampleId, score: tj.score, families: tj.families || [],
              tags: tj.tags || [], filename: tj.filename || null,
              submitted: tj.submitted ? tj.submitted.split("T")[0] : null,
              completed: tj.completed ? tj.completed.split("T")[0] : null,
              c2Urls: tj.c2Urls || [], triageUrl: tj.triageUrl,
            };
            // Pre-cache the Triage result for the SHA256 key
            setEnrichCache((c) => ({
              ...c,
              [sha256Key]: c[sha256Key] || { loading: false, data: { triage: results.triage, _preflightSource: key }, error: false },
            }));
          }
        }
      } catch (e) { console.warn("Pre-flight Tri.age failed:", e.message); }

      // Step 2: Kaspersky (only if Tri.age didn't resolve)
      if (!results._canonicalSHA256) {
        try {
          const kType = "hash";
          const kj = await callEnrich("kaspersky", null, null, undefined, { kaspersky_type: kType });
          if (kj && !kj.error && kj.Zone) {
            const generalInfo = kj.FileGeneralInfo || {};
            const kSHA256 = (generalInfo.SHA256 || generalInfo.Sha256 || kj.SHA256 || "").toLowerCase();
            if (kSHA256) results._canonicalSHA256 = kSHA256;
            // Sibling hashes for cross-type dedup
            if (generalInfo.MD5) results._siblingMD5 = String(generalInfo.MD5).toLowerCase();
            if (generalInfo.SHA1) results._siblingSHA1 = String(generalInfo.SHA1).toLowerCase();
            // Store Kaspersky result so we don't call it again in the full flow
            const zone = String(kj.Zone).toLowerCase();
            const detections = (kj.DetectionsInfo || []).map(d => d.DetectionName).filter(Boolean).slice(0,3);
            const categories = Array.isArray(kj.CategoriesWithZone)
              ? kj.CategoriesWithZone.map(c => c.Name).filter(Boolean).slice(0,3)
              : (Array.isArray(kj.Categories) ? kj.Categories.slice(0,3) : []);
            results.kaspersky = {
              zone, fileStatus: generalInfo.FileStatus || null,
              signer: generalInfo.Signer || null, productName: generalInfo.ProductName || null,
              firstSeen: generalInfo.FirstSeen ? String(generalInfo.FirstSeen).split("T")[0] : null,
              lastSeen: generalInfo.LastSeen ? String(generalInfo.LastSeen).split("T")[0] : null,
              hits: typeof generalInfo.HitsCount === "number" ? generalInfo.HitsCount : null,
              detections: detections.length ? detections.join(", ") : null,
              categories: categories.length ? categories.join(", ") : null,
              size: generalInfo.Size ? `${Math.round(Number(generalInfo.Size)/1024)}KB` : null,
            };
          }
        } catch (e) { console.warn("Pre-flight Kaspersky failed:", e.message); }
      }

      // Step 3: Hybrid Analysis /search/hash (last pre-flight — cheap SHA256 resolver)
      // Uses lightweight search/hash endpoint; overview/{sha256} is called later
      // for the SHA256 card's full behavioral data. Only resolves canonical SHA256
      // and sibling hashes here — verdict data comes from main enrichment.
      if (!results._canonicalSHA256) {
        try {
          const hj = await callEnrich("hybrid_analysis", null, null, undefined, { ha_type: "hash" });
          if (hj && !hj.error && Array.isArray(hj) && hj.length > 0) {
            const best = hj.find(r => r && r.sha256) || hj[0];
            if (best?.sha256) results._canonicalSHA256 = String(best.sha256).toLowerCase();
            if (best?.md5) results._siblingMD5 = results._siblingMD5 || String(best.md5).toLowerCase();
            if (best?.sha1) results._siblingSHA1 = results._siblingSHA1 || String(best.sha1).toLowerCase();
          }
        } catch (e) { console.warn("Pre-flight Hybrid Analysis failed:", e.message); }
      }

      // If canonical SHA256 found, check if it's in the current IOC list
      if (results._canonicalSHA256) {
        const canonical = results._canonicalSHA256;
        const currentSHA256s = (Object.keys(iocData || {}).includes("SHA256")
          ? (iocData.SHA256 || []) : []).map(v => v.toLowerCase());
        if (currentSHA256s.includes(canonical)) {
          // ✅ SHORT-CIRCUIT: SHA256 already in list — transfer enrichment and stop
          const sha256Key = `SHA256::${canonical}`;
          // Transfer our partial results to the SHA256 card with provenance
          setEnrichCache((c) => ({
            ...c,
            [key]: { loading: false, data: { ...results, _verdict: "Unknown", _transferredTo: sha256Key }, error: false },
            [sha256Key]: {
              loading: false,
              data: {
                ...(c[sha256Key]?.data || {}),
                ...results,
                _verdict: "Unknown",
                _sourcedFrom: { cat, value, label: `${cat} ${value.slice(0,12)}…` },
              },
              error: false,
            },
          }));
          // Trigger merge dedup
          setMergedHashes(m => {
            const entry = m[canonical] || { removed: [], sources: [] };
            if (entry.removed.some(r => r.cat === cat && r.value.toLowerCase() === value.toLowerCase())) return m;
            return { ...m, [canonical]: { removed: [...entry.removed, { cat, value }], sources: [...new Set([...entry.sources, cat])] } };
          });
          // Fire the guaranteed-visible toast immediately
          fireDedupToast(cat, value, canonical);
          // Trigger graph arc animation (500ms delay for nodes to render)
          // Keep source node in iocData during the arc, remove only after animation ends.
          setTimeout(() => {
            setHashCollapseAnims(a => [...a, {
              fromId: value.toLowerCase(), toId: canonical, startTime: Date.now(), id: `${value}->${canonical}`,
            }]);
            // Blast animation on the card row
            setBlastNodes(s => new Set([...s, value]));
            // Remove source from IOC list AFTER arc animation completes (1400ms + buffer)
            setTimeout(() => {
              // Identify sibling weak hash to also remove
              const otherCat = cat === "MD5" ? "SHA1" : "MD5";
              const otherHash = cat === "MD5" ? results._siblingSHA1 : results._siblingMD5;
              setIocData(prev => {
                if (!prev) return prev;
                const next = { ...prev };
                if (next[cat]) {
                  next[cat] = next[cat].filter(v => v.toLowerCase() !== value.toLowerCase());
                  if (!next[cat].length) delete next[cat];
                }
                // Also remove sibling weak hash (e.g. SHA1 when MD5 was enriched)
                if (otherHash && next[otherCat]) {
                  const siblingFound = next[otherCat].some(v => v.toLowerCase() === otherHash);
                  if (siblingFound) {
                    next[otherCat] = next[otherCat].filter(v => v.toLowerCase() !== otherHash);
                    if (!next[otherCat].length) delete next[otherCat];
                  }
                }
                if (!next.SHA256) next.SHA256 = [canonical];
                else if (!next.SHA256.map(v=>v.toLowerCase()).includes(canonical)) next.SHA256 = [...next.SHA256, canonical];
                return next;
              });
              // Toast + blast for sibling weak hash
              if (otherHash) {
                setMergedHashes(m => {
                  const entry = m[canonical] || { removed: [], sources: [] };
                  if (entry.removed.some(r => r.cat === otherCat && r.value.toLowerCase() === otherHash)) return m;
                  return { ...m, [canonical]: { removed: [...entry.removed, { cat: otherCat, value: otherHash }], sources: [...new Set([...entry.sources, otherCat])] } };
                });
                fireDedupToast(otherCat, otherHash, canonical);
                setBlastNodes(s => new Set([...s, otherHash]));
                setTimeout(() => setBlastNodes(s => { const n = new Set(s); n.delete(otherHash); return n; }), 950);
              }
              setBlastNodes(s => { const n = new Set(s); n.delete(value); return n; });
              // Clean up animation after another 600ms
              setTimeout(() => setHashCollapseAnims(a => a.filter(x => x.id !== `${value}->${canonical}`)), 600);
              // Auto-trigger SHA256 enrichment after consolidation — clear the
              // partial pre-flight snapshot first so the full cascade isn't
              // blocked by its own "already has non-error data" cache entry.
              setTimeout(() => {
                setEnrichCache((c) => { const n = { ...c }; delete n[sha256Key]; return n; });
                enrichIOC("SHA256", canonical);
              }, 500);
            }, 1600); // wait for arc to finish (1400ms) + 200ms buffer
          }, 500);
          return; // ← SHORT-CIRCUIT: skip all remaining enrichment calls
        }
      }
    }
    // End pre-flight

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
        setPartial();
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
              tags: [...new Set(j.urls.flatMap((u) => u.tags || []).filter((t) => t && !GENERIC_TAGS.has(t.toLowerCase())))].slice(0, 4).join(", ") || null,
              first: uhDates.length ? uhDates[0].split(" ")[0] : null,
              last: uhDates.length > 1 ? uhDates[uhDates.length - 1].split(" ")[0] : null,
            };
          }
        } catch (e) { console.warn("Enrich URLhaus failed:", e.message); }
        setPartial();
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
              first: j.date_added ? j.date_added.split(" ")[0] : null,
              last: j.last_online ? j.last_online.split(" ")[0] : null,
            };
          }
        } catch (e) { console.warn("Enrich URLhaus URL failed:", e.message); }
        setPartial();
      }
      // MalwareBazaar — hashes (includes vendor_intel for detection names)
      if (["MD5","SHA1","SHA256","SHA512"].includes(cat)) {
        try {
          const j = await callEnrich("malwarebazaar");
          if (j.query_status === "ok" && Array.isArray(j.data) && j.data.length > 0) {
            const d = j.data[0];
            // Extract detection names from vendor_intel (e.g. Trojan.Win32.Agentb.tpwa)
            // Skip untrusted vendors entirely; filter "clean" detections when any
            // suspicious/malicious detection exists (so infostealers don't show "Legit File")
            // Individual vendor verdicts are IGNORED for verdict derivation —
            // MalwareBazaar only indexes confirmed malware, so existence = Malicious.
            const SKIP_VENDORS = new Set(["YOROI_YOMI"]);
            const CLEAN_LABELS = new Set(["legit file","clean","safe","benign","legitimate","no threat","no_threat","not malicious","whitelisted","trusted","harmless","undetected"]);
            let detections = [];
            if (d.vendor_intel && typeof d.vendor_intel === "object") {
              Object.entries(d.vendor_intel).forEach(([vendor, info]) => {
                if (SKIP_VENDORS.has(vendor)) return;
                if (!info || typeof info !== "object") return;
                // Handle array-format vendors (ANY.RUN, Spamhaus_HBL, UnpacMe)
                if (Array.isArray(info)) {
                  info.forEach((entry) => {
                    if (entry?.malware_family) detections.push(entry.malware_family);
                    if (entry?.verdict && !["suspicious","malicious activity"].includes(entry.verdict.toLowerCase())) detections.push(entry.verdict);
                    if (Array.isArray(entry?.detections)) detections.push(...entry.detections);
                  });
                  return;
                }
                // Standard detection/detections fields
                if (Array.isArray(info.detections)) detections.push(...info.detections);
                else if (typeof info.detection === "string" && info.detection) detections.push(info.detection);
                // ReversingLabs: threat_name field
                if (typeof info.threat_name === "string" && info.threat_name) detections.push(info.threat_name);
                // Triage: malware_family field
                if (typeof info.malware_family === "string" && info.malware_family) detections.push(info.malware_family);
              });
            }
            detections = [...new Set(detections.filter(Boolean))];
            // If ANY detection is suspicious/malicious, drop all clean/benign labels
            const hasMalicious = detections.some((det) => !CLEAN_LABELS.has(det.toLowerCase()));
            if (hasMalicious) detections = detections.filter((det) => !CLEAN_LABELS.has(det.toLowerCase()));
            detections = detections.slice(0, 3);
            // Code signing extraction — signed malware is a real thing
            // (stolen certs, LOLBIN wrappers). Publisher CN is the useful field.
            let codeSign = null;
            if (Array.isArray(d.code_sign) && d.code_sign.length) {
              const cs = d.code_sign[0];
              if (cs && (cs.subject_cn || cs.issuer_cn)) {
                codeSign = {
                  subject: cs.subject_cn || null,
                  issuer: cs.issuer_cn || null,
                  algorithm: cs.algorithm || null,
                  serial: cs.serial_number || null,
                };
              }
            }
            results.malwarebazaar = {
              family: d.signature || "unknown",
              type: d.file_type || "—",
              size: d.file_size ? `${Math.round(d.file_size / 1024)}KB` : null,
              first: d.first_seen ? d.first_seen.split(" ")[0] : null,
              last: d.last_seen ? d.last_seen.split(" ")[0] : null,
              delivery: d.delivery_method || null,
              tags: Array.isArray(d.tags) ? d.tags.filter((t) => t && !GENERIC_TAGS.has(t.toLowerCase())).slice(0, 4).join(", ") : null,
              detections: detections.length ? detections.join(" | ") : null,
              fileName: d.file_name || null,
              codeSign,
            };
            // Canonical SHA256 from MalwareBazaar — case-insensitive
            const mbSHA256 = d.sha256_hash || d.SHA256 || null;
            if (mbSHA256 && ["MD5","SHA1"].includes(cat)) {
              results._canonicalSHA256 = mbSHA256.toLowerCase();
            }
            // Sibling hashes for cross-type dedup (MD5↔SHA1↔SHA256)
            if (d.md5_hash) results._siblingMD5 = results._siblingMD5 || String(d.md5_hash).toLowerCase();
            if (d.sha1_hash) results._siblingSHA1 = results._siblingSHA1 || String(d.sha1_hash).toLowerCase();
            if (d.sha256_hash) results._siblingSHA256 = results._siblingSHA256 || String(d.sha256_hash).toLowerCase();
          }
        } catch (e) { console.warn("Enrich MalwareBazaar failed:", e.message); }
        setPartial();

        // CIRCL hashlookup — proxied through Worker (CIRCL tightened CORS in 2026,
        // direct browser fetch now blocked). No API key, Worker just relays.
        // Whitelist-oriented: NSRL + community databases of known-legit files.
        try {
          const algo = { MD5: "md5", SHA1: "sha1", SHA256: "sha256" }[cat];
          if (algo) {
            const cj = await callEnrich("circl", algo, null);
            // 404s come back as null/error from callEnrich; real hits have FileName/MD5.
            if (cj && !cj.message && !cj.error && (cj.FileName || cj.SHA1 || cj["SHA-1"] || cj.MD5)) {
              const trust = typeof cj["hashlookup:trust"] === "number" ? cj["hashlookup:trust"] : null;
              const pc = cj.ProductCode || {};
              // Find the most informative parent — prefer one with PackageMaintainer/PackageName
              const parents = Array.isArray(cj.parents) ? cj.parents : [];
              const bestParent = parents.find(p => p.PackageMaintainer || p.PackageName)
                || parents.find(p => p["snap-name"])
                || parents[0] || null;
              results.circl = {
                fileName: cj.FileName || null,
                fileSize: cj.FileSize ? `${Math.round(Number(cj.FileSize) / 1024)}KB` : null,
                trust,
                legit: trust != null && trust > 50,
                // Package info from CIRCL response
                productName: pc.ProductName || bestParent?.PackageName || null,
                packageVersion: bestParent?.PackageVersion || null,
                // PackageMaintainer / maintainer org — strong legitimacy signal
                maintainer: bestParent?.PackageMaintainer
                  ? bestParent.PackageMaintainer.replace(/<[^>]+>/g, "").trim() // strip email angle brackets
                  : (bestParent?.["snap-name"] ? `Canonical Snap: ${bestParent["snap-name"]}` : null),
                productType: pc.ApplicationType || null,
                os: cj.OpSystemCode?.OpSystemName || null,
                mimetype: cj.mimetype || null,
                // How many parent packages contain this file — high count = widely distributed = legit
                parentTotal: typeof cj["hashlookup:parent-total"] === "number" ? cj["hashlookup:parent-total"] : null,
                // Package description (first line only)
                description: bestParent?.PackageDescription
                  ? bestParent.PackageDescription.split("\n")[0].trim()
                  : null,
                source: cj.source ? String(cj.source).split(":")[0] : null, // "snap", "debian" etc.
              };
              // Canonical SHA256 from CIRCL — enables MD5/SHA1 → SHA256 dedup
              const cSHA256 = cj["SHA-256"] || cj["SHA256"] || null;
              if (cSHA256 && ["MD5","SHA1"].includes(cat)) {
                results._canonicalSHA256 = cSHA256.toLowerCase();
              }
              // Sibling hashes for cross-type dedup
              if (cj.MD5) results._siblingMD5 = results._siblingMD5 || String(cj.MD5).toLowerCase();
              if (cj["SHA-1"]) results._siblingSHA1 = results._siblingSHA1 || String(cj["SHA-1"]).toLowerCase();
              if (cSHA256) results._siblingSHA256 = results._siblingSHA256 || cSHA256.toLowerCase();
            } // end if (cj && ...)
          } // end if (algo)
          // 404 = hash unknown to CIRCL (not an error, just quiet)
        } catch (e) { console.warn("Enrich CIRCL failed:", e.message); }
        setPartial();

        // Tri.age (Recorded Future Sandbox) — hash lookup + C2 extraction.
        // Two-step: search → overview+summary. Only proceeds if the hash exists
        // in Triage's public corpus. Extracts: family, behavioral score, tags, C2 URLs.
        // Skip if pre-flight already ran Tri.age for this IOC (MD5/SHA1 that didn't short-circuit).
        try {
          const triageAlgo = { MD5: "md5", SHA1: "sha1", SHA256: "sha256" }[cat];
          const preflightRanTriage = ["MD5","SHA1"].includes(cat) && !!results.triage;
          if (triageAlgo && !preflightRanTriage) {
            const tj = await callEnrich("triage", triageAlgo, null);
            if (tj && !tj.error && tj.found) {
              results.triage = {
                sampleId: tj.sampleId,
                score: tj.score, // 0-10 (10 = max malicious)
                families: tj.families || [],
                tags: tj.tags || [],
                filename: tj.filename || null,
                submitted: tj.submitted ? tj.submitted.split("T")[0] : null,
                completed: tj.completed ? tj.completed.split("T")[0] : null,
                c2Urls: tj.c2Urls || [],
                triageUrl: tj.triageUrl,
              };
              // Canonical SHA256 from Tri.age — case-insensitive
              const tSHA256 = tj.sha256 || tj.SHA256 || null;
              if (tSHA256 && ["MD5","SHA1"].includes(cat)) {
                results._canonicalSHA256 = tSHA256.toLowerCase();
              }
            }
          }
        } catch (e) { console.warn("Enrich Tri.age failed:", e.message); }
        setPartial();
      }
      // Hybrid Analysis (Falcon Sandbox) — hash lookup with behavioral analysis.
      // SHA256: uses /overview/{sha256} for full behavioral data (verdict, threat_score,
      //         MITRE, family, contacted infra, siblings).
      // MD5/SHA1/SHA512: uses /search/hash for sibling extraction — pre-flight already
      //                  ran /search/hash for MD5/SHA1, so we skip duplicate call.
      // Rate limit: 200/min, 2000/hr — generous, no throttling needed.
      if (cat === "SHA256") {
        try {
          const hj = await callEnrich("hybrid_analysis", null, null, undefined, { ha_type: "overview" });
          if (hj && !hj.error && hj.sha256) {
            const best = hj;
            const haVerdict = best.verdict || null;
            const threatScore = typeof best.threat_score === "number" ? best.threat_score : null;
            const avDetect = best.av_detect != null ? String(best.av_detect) : null;
            const family = best.vx_family || null;
            const tags = Array.isArray(best.tags) ? best.tags.filter(Boolean).slice(0, 8) : [];
            const classifTags = Array.isArray(best.classification_tags) ? best.classification_tags.filter(Boolean).slice(0, 5) : [];
            const mitreAttacks = Array.isArray(best.mitre_attcks) ? best.mitre_attcks.map(m => m.technique || m.tactic || m).filter(Boolean).slice(0, 6) : [];
            const domains = Array.isArray(best.domains) ? best.domains.filter(Boolean).slice(0, 10) : [];
            const hosts = Array.isArray(best.hosts) ? best.hosts.filter(Boolean).slice(0, 10) : [];
            const compromised = Array.isArray(best.compromised_hosts) ? best.compromised_hosts.filter(Boolean).slice(0, 5) : [];
            const fileName = best.submit_name || null;
            const fileType = best.type || null;
            const typeShort = Array.isArray(best.type_short) ? best.type_short.filter(Boolean) : [];
            const fileSize = best.size ? `${Math.round(best.size / 1024)}KB` : null;
            const envDesc = best.environment_description || null;
            const analysisTime = best.analysis_start_time ? best.analysis_start_time.split(" ")[0] : null;
            const netConns = best.total_network_connections || 0;
            const totalProcs = best.total_processes || 0;
            const totalSigs = best.total_signatures || 0;
            const impHash = best.imphash || null;
            const ssdeepHash = best.ssdeep || null;
            const authentiHash = best.authentihash || null;
            // submit_context — URLs the sample was originally downloaded from.
            // Filter for real URL/domain strings; drop empty/non-URL entries.
            const submitContext = Array.isArray(best.submit_context)
              ? best.submit_context.filter(s => typeof s === "string" && s.trim() && /[.:\/]/.test(s)).slice(0, 8)
              : [];

            results.hybridAnalysis = {
              verdict: haVerdict, threatScore, avDetect, family,
              tags: tags.length ? tags.join(", ") : null,
              classifTags: classifTags.length ? classifTags.join(", ") : null,
              mitreAttacks: mitreAttacks.length ? mitreAttacks : null,
              domains: domains.length ? domains : null,
              hosts: hosts.length ? hosts : null,
              compromised: compromised.length ? compromised : null,
              submitContext: submitContext.length ? submitContext : null,
              fileName,
              fileType: typeShort.length ? typeShort.join("/") : fileType,
              fileSize, envDesc, analysisTime,
              netConns, totalProcs, totalSigs,
              impHash, ssdeepHash, authentiHash,
              reportUrl: best.sha256 ? `https://www.hybrid-analysis.com/sample/${best.sha256}` : null,
            };

            // Sibling hashes
            if (best.md5) results._siblingMD5 = results._siblingMD5 || String(best.md5).toLowerCase();
            if (best.sha1) results._siblingSHA1 = results._siblingSHA1 || String(best.sha1).toLowerCase();
            if (best.sha256) results._siblingSHA256 = results._siblingSHA256 || String(best.sha256).toLowerCase();
          }
        } catch (e) { console.warn("Enrich Hybrid Analysis (overview) failed:", e.message); }
        setPartial();
      }
      // MD5/SHA1: /search/hash was already called in pre-flight — reuse if not
      // present via a lightweight second call for behavioral data (verdict, family).
      // SHA512: full search/hash call (no pre-flight coverage).
      else if (["MD5","SHA1","SHA512"].includes(cat)) {
        try {
          const hj = await callEnrich("hybrid_analysis", null, null, undefined, { ha_type: "hash" });
          if (hj && !hj.error && Array.isArray(hj) && hj.length > 0) {
            const best = hj.filter(r => r && typeof r === "object").sort((a, b) => (b.threat_score || 0) - (a.threat_score || 0))[0];
            if (best) {
              const haVerdict = best.verdict || null;
              const threatScore = typeof best.threat_score === "number" ? best.threat_score : null;
              const avDetect = best.av_detect != null ? String(best.av_detect) : null;
              const family = best.vx_family || null;
              const tags = Array.isArray(best.tags) ? best.tags.filter(Boolean).slice(0, 8) : [];
              const classifTags = Array.isArray(best.classification_tags) ? best.classification_tags.filter(Boolean).slice(0, 5) : [];
              const mitreAttacks = Array.isArray(best.mitre_attcks) ? best.mitre_attcks.map(m => m.technique || m.tactic || m).filter(Boolean).slice(0, 6) : [];
              const domains = Array.isArray(best.domains) ? best.domains.filter(Boolean).slice(0, 10) : [];
              const hosts = Array.isArray(best.hosts) ? best.hosts.filter(Boolean).slice(0, 10) : [];
              const compromised = Array.isArray(best.compromised_hosts) ? best.compromised_hosts.filter(Boolean).slice(0, 5) : [];
              const submitContext = Array.isArray(best.submit_context)
                ? best.submit_context.filter(s => typeof s === "string" && s.trim() && /[.:\/]/.test(s)).slice(0, 8)
                : [];
              const fileName = best.submit_name || null;
              const fileType = best.type || null;
              const typeShort = Array.isArray(best.type_short) ? best.type_short.filter(Boolean) : [];
              const fileSize = best.size ? `${Math.round(best.size / 1024)}KB` : null;

              results.hybridAnalysis = {
                verdict: haVerdict, threatScore, avDetect, family,
                tags: tags.length ? tags.join(", ") : null,
                classifTags: classifTags.length ? classifTags.join(", ") : null,
                mitreAttacks: mitreAttacks.length ? mitreAttacks : null,
                domains: domains.length ? domains : null,
                hosts: hosts.length ? hosts : null,
                compromised: compromised.length ? compromised : null,
                submitContext: submitContext.length ? submitContext : null,
                fileName,
                fileType: typeShort.length ? typeShort.join("/") : fileType,
                fileSize,
                envDesc: best.environment_description || null,
                netConns: best.total_network_connections || 0,
                totalProcs: best.total_processes || 0,
                totalSigs: best.total_signatures || 0,
                impHash: best.imphash || null,
                ssdeepHash: best.ssdeep || null,
                authentiHash: best.authentihash || null,
                reportUrl: best.sha256 ? `https://www.hybrid-analysis.com/sample/${best.sha256}` : null,
              };
              if (best.md5) results._siblingMD5 = results._siblingMD5 || String(best.md5).toLowerCase();
              if (best.sha1) results._siblingSHA1 = results._siblingSHA1 || String(best.sha1).toLowerCase();
              if (best.sha256) {
                results._siblingSHA256 = results._siblingSHA256 || String(best.sha256).toLowerCase();
                if (["MD5","SHA1"].includes(cat)) {
                  results._canonicalSHA256 = results._canonicalSHA256 || String(best.sha256).toLowerCase();
                }
              }
            }
          }
        } catch (e) { console.warn("Enrich Hybrid Analysis (search/hash) failed:", e.message); }
        setPartial();
      }
      // IMPHASH / SSDEEP / AUTHENTIHASH — hunt for related samples via search/terms
      if (["IMPHASH","SSDEEP","AUTHENTIHASH"].includes(cat)) {
        try {
          const termField = cat === "IMPHASH" ? "imp_hash" : cat === "SSDEEP" ? "ssdeep" : "authentihash";
          const hj = await callEnrich("hybrid_analysis", null, null, undefined, { ha_type: "terms", ha_term_field: termField });
          const haArr = Array.isArray(hj) ? hj : (hj && Array.isArray(hj.result) ? hj.result : []);
          if (haArr.length > 0) {
            const valid = haArr.filter(r => r && typeof r === "object");
            const malCount = valid.filter(r => r.verdict === "malicious").length;
            const suspCount = valid.filter(r => r.verdict === "suspicious").length;
            const families = [...new Set(valid.map(r => r.vx_family).filter(Boolean))].slice(0, 4);
            const bestScore = valid.reduce((m, r) => Math.max(m, r.threat_score || 0), 0);
            const avgScore = valid.length ? Math.round(valid.reduce((s, r) => s + (r.threat_score || 0), 0) / valid.length) : 0;
            const relatedSHA256s = [...new Set(valid.map(r => r.sha256).filter(Boolean))].slice(0, 6);
            // Verdict: real reading of the aggregate, not defaulting to "no specific threat"
            let hv = null;
            if (malCount > 0 || bestScore >= 70) hv = "malicious";
            else if (suspCount > 0 || bestScore >= 30) hv = "suspicious";
            else if (valid.length > 0) hv = "seen but no verdict";
            results.hybridAnalysis = {
              submissions: valid.length, malicious: malCount, suspicious: suspCount,
              threatScore: bestScore > 0 ? bestScore : null, avgScore: avgScore || null,
              families: families.length ? families.join(", ") : null,
              relatedSHA256s: relatedSHA256s.length ? relatedSHA256s : null,
              verdict: hv,
            };
          }
        } catch (e) { console.warn("Enrich Hybrid Analysis (terms/hash-code) failed:", e.message); }
        setPartial();
      }
      // Hybrid Analysis — domain/IP/URL: samples that contacted this infra.
      // Fixed verdict logic — reads real threat data, not always "no specific threat".
      if (["IPV4","IPV6","DOMAIN","URL"].includes(cat)) {
        try {
          const haType = ["IPV4","IPV6"].includes(cat) ? "host"
            : cat === "URL" ? "url" : "domain";
          const hj = await callEnrich("hybrid_analysis", null, null, undefined, { ha_type: "terms", ha_term_field: haType });
          const haArr = Array.isArray(hj) ? hj : (hj && Array.isArray(hj.result) ? hj.result : []);
          if (haArr.length > 0) {
            const valid = haArr.filter(r => r && typeof r === "object");
            const malCount = valid.filter(r => r.verdict === "malicious").length;
            const suspCount = valid.filter(r => r.verdict === "suspicious").length;
            const families = [...new Set(valid.map(r => r.vx_family).filter(Boolean))].slice(0, 4);
            const bestScore = valid.reduce((m, r) => Math.max(m, r.threat_score || 0), 0);
            const avgScore = valid.length ? Math.round(valid.reduce((s, r) => s + (r.threat_score || 0), 0) / valid.length) : 0;
            const relatedSHA256s = [...new Set(valid.map(r => r.sha256).filter(Boolean))].slice(0, 6);
            // Real verdict aggregation
            let hv = null;
            if (malCount > 0 || bestScore >= 70) hv = "malicious";
            else if (suspCount > 0 || bestScore >= 30) hv = "suspicious";
            else if (valid.length > 0) hv = "seen but no verdict";
            results.hybridAnalysis = {
              submissions: valid.length, malicious: malCount, suspicious: suspCount,
              threatScore: bestScore > 0 ? bestScore : null, avgScore: avgScore || null,
              families: families.length ? families.join(", ") : null,
              relatedSHA256s: relatedSHA256s.length ? relatedSHA256s : null,
              verdict: hv,
            };
          }
        } catch (e) { console.warn("Enrich Hybrid Analysis (domain/IP) failed:", e.message); }
        setPartial();
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
            const parentDomain = registrableDomain(value);
            if (parentDomain && parentDomain !== value.toLowerCase()) {
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
        setPartial();

        // OTX Passive DNS — historical resolution records for infrastructure pivoting.
        // Domain query returns every IP the domain resolved to (with dates).
        // IP query returns every hostname that pointed to the IP.
        // Free-tier friendly — uses the existing OTX key.
        if (["IPV4","IPV6","DOMAIN"].includes(cat)) {
          try {
            const otxTypeMap = { IPV4: "IPv4", IPV6: "IPv6", DOMAIN: "domain" };
            const pd = await callEnrich("otx", otxTypeMap[cat], "passive_dns");
            if (pd && !pd.error && Array.isArray(pd.passive_dns) && pd.passive_dns.length) {
              const rawTotal = pd.count || pd.passive_dns.length;
              // For DOMAIN queries the useful pivot is the IP it resolved to (A/AAAA).
              // NS/SOA/CNAME/MX/TXT point at DNS infrastructure (often shared, e.g.
              // Cloudflare nameservers) — noise for hunting, so we drop them.
              // NXDOMAIN entries are failed lookups with no usable target.
              const KEEP_TYPES = new Set(["A", "AAAA", null, ""]); // null = IP-query results (hostnames)
              const cleaned = pd.passive_dns.filter((r) => {
                const rt = (r.record_type || "").toUpperCase();
                if (rt === "NXDOMAIN") return false;
                // For domain queries keep only A/AAAA. For IP queries record_type is
                // usually absent and the field of interest is hostname.
                if (cat === "DOMAIN") return rt === "A" || rt === "AAAA";
                return !!r.hostname;
              });
              // Group by the pivot target (address for domain-queries, hostname for IP-queries),
              // merging multiple observation windows into one first→last span.
              const groups = new Map();
              cleaned.forEach((r) => {
                const target = cat === "DOMAIN" ? r.address : r.hostname;
                if (!target) return;
                const key = String(target).toLowerCase();
                const first = r.first ? String(r.first).split("T")[0] : null;
                const last = r.last ? String(r.last).split("T")[0] : null;
                const g = groups.get(key) || {
                  hostname: cat === "DOMAIN" ? null : target,
                  address: cat === "DOMAIN" ? target : null,
                  recordType: (r.record_type || (cat === "DOMAIN" ? "A" : null)),
                  first, last, obs: 0, asn: null, country: null,
                  _latestLast: null, // track which record contributed ASN/country
                  windows: [],
                };
                if (first && (!g.first || first < g.first)) g.first = first;
                if (last && (!g.last || last > g.last)) g.last = last;
                // Use ASN/country from the MOST RECENT observation (latest 'last' date).
                // An IP can change ASN over time (reassigned ranges); the current
                // observation's ASN is what matters — not whatever record happened
                // to be iterated first.
                const isMoreRecent = last && (!g._latestLast || last > g._latestLast);
                if (isMoreRecent && (r.asn || r.flag_title)) {
                  g.asn = r.asn || g.asn;
                  g.country = r.flag_title || g.country;
                  g._latestLast = last;
                } else {
                  if (!g.asn && r.asn) g.asn = r.asn;
                  if (!g.country && r.flag_title) g.country = r.flag_title;
                }
                g.obs += 1;
                if ((first || last) && !g.windows.some((w) => w.first === first && w.last === last)) {
                  g.windows.push({ first, last });
                }
                groups.set(key, g);
              });
              const grouped = Array.from(groups.values())
                .map((g) => {
                  // Current = last observation within ~30 days of today; else Historical.
                  let current = false;
                  if (g.last) {
                    const lastMs = new Date(g.last).getTime();
                    if (!isNaN(lastMs)) current = (Date.now() - lastMs) <= 30 * 86400000;
                  }
                  return { ...g, current, windows: g.windows.sort((a, b) => String(b.last || "").localeCompare(String(a.last || ""))) };
                })
                // Current first, then by most-recent last-seen
                .sort((a, b) => (b.current - a.current) || String(b.last || "").localeCompare(String(a.last || "")))
                .slice(0, 40);
              if (grouped.length) {
                const currentCount = grouped.filter((g) => g.current).length;
                results.otxPDNS = { total: rawTotal, unique: grouped.length, currentCount, records: grouped };
              }
            }
          } catch (e) { console.warn("Enrich OTX Passive DNS failed:", e.message); }
        }
      }
      // Dedicated WHOIS/ASN + Geo lookup for IP addresses via IPLocate.io
      // Returns country (full name), city, ASN, company, and threat flags (VPN/proxy/hosting)
      if (["IPV4","IPV6"].includes(cat)) {
        try {
          const g = await callEnrich("iplocate");
          if (g && !g.error && g.country_code) {
            const cc = g.country_code || null;
            const privacyFlags = [];
            if (g.privacy?.is_vpn) privacyFlags.push("VPN");
            if (g.privacy?.is_proxy) privacyFlags.push("Proxy");
            if (g.privacy?.is_tor) privacyFlags.push("Tor");
            if (g.privacy?.is_hosting) privacyFlags.push("Hosting");
            results.whoisASN = {
              asn: g.asn?.asn || null,
              asnOrg: g.asn?.name || g.asn?.org || g.company?.name || null,
              country: g.country || cc || null,
              countryCode: cc,
              flag: countryFlag(cc),
              city: g.city || null,
              region: g.region || null,
              privacy: privacyFlags.length ? privacyFlags.join(", ") : null,
            };
          }
        } catch (e) { console.warn("Enrich IPLocate failed:", e.message); }

        // Shodan InternetDB — no key, permissive CORS, free non-commercial.
        // Adds open ports, tags, CPEs (services running), and known CVEs.
        // Weekly refresh cadence, so it's exposure snapshot, not real-time.
        try {
          const r = await fetch(`https://internetdb.shodan.io/${encodeURIComponent(value)}`, {
            headers: { "Accept": "application/json" },
          });
          if (r.ok) {
            const sj = await r.json();
            const ports = Array.isArray(sj.ports) ? sj.ports : [];
            const vulns = Array.isArray(sj.vulns) ? sj.vulns : [];
            const tags = Array.isArray(sj.tags) ? sj.tags : [];
            const cpes = Array.isArray(sj.cpes) ? sj.cpes : [];
            const hostnames = Array.isArray(sj.hostnames) ? sj.hostnames : [];
            if (ports.length || vulns.length || tags.length || cpes.length || hostnames.length) {
              results.shodan = {
                ports: ports.slice(0, 20),
                vulns: vulns.slice(0, 20),
                tags: tags.slice(0, 10),
                // Trim cpe:/a:vendor:product:version → vendor:product for readability
                cpes: cpes.slice(0, 10).map((c) => {
                  const parts = String(c).replace(/^cpe:[\/2].?:/, "").split(":");
                  return parts.slice(0, 3).filter(Boolean).join(":");
                }).filter(Boolean),
                hostnames: hostnames.slice(0, 5),
              };
            }
          }
          // 404 = no data on this IP (not an error, just quiet)
        } catch (e) { console.warn("Enrich Shodan InternetDB failed:", e.message); }
        setPartial();

        // SANS ISC / DShield — crowd-sourced firewall log submissions.
        // "attacks" = distinct targets that reported this IP, not a normalized
        // score, so it's treated as a soft signal (Suspicious ceiling only,
        // same restraint as AbuseIPDB's own Suspicious tier).
        try {
          const sj = await callEnrich("sans_isc");
          const ipInfo = sj?.ip;
          if (ipInfo && (ipInfo.count || ipInfo.attacks)) {
            results.sansIsc = {
              attacks: parseInt(ipInfo.attacks, 10) || 0,
              count: parseInt(ipInfo.count, 10) || 0,
              minDate: ipInfo.mindate || null,
              maxDate: ipInfo.maxdate || null,
              threatFeeds: ipInfo.threatfeeds ? Object.keys(ipInfo.threatfeeds) : [],
            };
          }
        } catch (e) { console.warn("Enrich SANS ISC failed:", e.message); }
        setPartial();
      }

      // Kaspersky OpenTIP — hash / IP / domain / URL enrichment.
      // Free tier 500/day. Zone (Red/Yellow/Green) is the headline signal.
      // Returns 401 when token expired, 429 when rate-limited — both silent.
      // Skip for MD5/SHA1 if pre-flight already ran Kaspersky (avoids double-billing).
      const kMap = { MD5: "hash", SHA1: "hash", SHA256: "hash", IPV4: "ip", IPV6: "ip", DOMAIN: "domain", URL: "url" };
      const kType = kMap[cat];
      const preflightRanKaspersky = ["MD5","SHA1"].includes(cat) && !!results.kaspersky;
      if (kType && !preflightRanKaspersky) {
        try {
          const kj = await callEnrich("kaspersky", null, null, undefined, { kaspersky_type: kType });
          if (kj && !kj.error && kj.Zone) {
            // Extract shape-varying fields per IOC type into a normalised chip.
            const zone = String(kj.Zone).toLowerCase(); // "red" | "yellow" | "green" | "grey"
            const generalInfo = kj.FileGeneralInfo || kj.IpGeneralInfo || kj.DomainGeneralInfo || kj.UrlGeneralInfo || {};
            const detections = kj.DetectionsInfo || [];
            const detectionNames = Array.isArray(detections)
              ? detections.map((d) => d.DetectionName).filter(Boolean).slice(0, 3)
              : [];
            const categories = Array.isArray(kj.CategoriesWithZone)
              ? kj.CategoriesWithZone.map((c) => c.Name).filter(Boolean).slice(0, 3)
              : (Array.isArray(kj.Categories) ? kj.Categories.slice(0, 3) : []);
            results.kaspersky = {
              zone, // red/yellow/green/grey
              fileStatus: generalInfo.FileStatus || null,     // hash only
              signer: generalInfo.Signer || null,             // hash only
              productName: generalInfo.ProductName || null,   // hash only
              firstSeen: generalInfo.FirstSeen ? String(generalInfo.FirstSeen).split("T")[0] : null,
              lastSeen: generalInfo.LastSeen ? String(generalInfo.LastSeen).split("T")[0] : null,
              hits: typeof generalInfo.HitsCount === "number" ? generalInfo.HitsCount : null,
              country: generalInfo.CountryCode || generalInfo.Country || null, // ip/domain
              detections: detectionNames.length ? detectionNames.join(", ") : null,
              categories: categories.length ? categories.join(", ") : null,
              size: generalInfo.Size ? `${Math.round(Number(generalInfo.Size) / 1024)}KB` : null,
            };
            // Canonical SHA256 from Kaspersky (case-insensitive — API may return any case)
            const kSHA256 = generalInfo.SHA256 || generalInfo.Sha256 || kj.SHA256 || kj.Sha256 || null;
            if (kSHA256 && ["MD5","SHA1"].includes(cat)) results._canonicalSHA256 = kSHA256.toLowerCase();
            // Sibling hashes for cross-type dedup
            if (generalInfo.MD5) results._siblingMD5 = results._siblingMD5 || String(generalInfo.MD5).toLowerCase();
            if (generalInfo.SHA1) results._siblingSHA1 = results._siblingSHA1 || String(generalInfo.SHA1).toLowerCase();
            if (kSHA256) results._siblingSHA256 = results._siblingSHA256 || kSHA256.toLowerCase();
          }
          // 401/403 = expired/invalid key; 404 = not in DB; 429 = rate limited — all silent
        } catch (e) { console.warn("Enrich Kaspersky failed:", e.message); }
        setPartial();
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

      // AbuseIPDB — community abuse reports for IP addresses
      if (["IPV4","IPV6"].includes(cat)) {
        try {
          const aj = await callEnrich("abuseipdb");
          if (aj && aj.data && !aj.errors) {
            const d = aj.data;
            const categories = Array.isArray(d.reports)
              ? [...new Set(d.reports.flatMap((r) => r.categories || []).map((c) => {
                  const CAT_MAP = {1:"DNS Compromise",2:"DNS Poisoning",3:"Fraud Orders",4:"DDoS Attack",5:"FTP Brute-Force",
                    6:"Ping of Death",7:"Phishing",8:"Fraud VoIP",9:"Open Proxy",10:"Web Spam",11:"Email Spam",
                    12:"Blog Spam",13:"VPN IP",14:"Port Scan",15:"Hacking",16:"SQL Injection",17:"Spoofing",
                    18:"Brute-Force",19:"Bad Web Bot",20:"Exploited Host",21:"Web App Attack",22:"SSH",23:"IoT Targeted"};
                  return CAT_MAP[c] || null;
                }).filter(Boolean))].slice(0, 4)
              : [];
            if (d.abuseConfidenceScore != null || d.totalReports > 0) {
              results.abuseipdb = {
                score: d.abuseConfidenceScore,
                reports: d.totalReports || 0,
                lastReported: d.lastReportedAt ? d.lastReportedAt.split("T")[0] : null,
                isp: d.isp || null,
                usageType: d.usageType || null,
                categories: categories.length ? categories.join(", ") : null,
              };
            }
          }
        } catch (e) { console.warn("Enrich AbuseIPDB failed:", e.message); }
        setPartial();
      }

      // ---- urlscan.io — community scan results for domains, URLs, IPs ----
      if (["IPV4","IPV6","DOMAIN","URL"].includes(cat)) {
        try {
          const searchField = cat === "DOMAIN" ? "domain" : cat === "URL" ? "page.url" : "ip";
          const searchValue = cat === "URL" ? (value.includes("://") ? value : "https://" + value) : value;
          const uj = await callEnrich("urlscan", searchField, searchValue);
          if (uj && !uj.error && Array.isArray(uj.results) && uj.results.length > 0) {
            const totalScans = uj.total || uj.results.length;
            // The IOC host we're actually enriching.
            const iocHostExact = (() => {
              if (cat === "IPV4" || cat === "IPV6") return String(value).toLowerCase();
              try { return new URL(value.includes("://") ? value : "https://" + value).hostname.toLowerCase(); }
              catch { return String(value).toLowerCase().replace(/^https?:\/\//, "").split("/")[0]; }
            })();
            // urlscan's domain: search returns EVERY scan that merely *contacted*
            // the host — including scans of a DIFFERENT submitted URL where our host
            // was only a redirect hop or resource server (e.g. a bitbucket.org
            // download that redirects through an Atlassian S3 bucket). Those scans
            // are "about" the other target: their page.domain / page.title / age all
            // describe bitbucket.org, not our host. So a scan counts as being ABOUT
            // our host ONLY when its PRIMARY page (page.domain, i.e. where the scan
            // ended up) equals our host. task.domain (what was submitted) matching
            // is a strong signal too. Everything else is incidental contact.
            const finalHostOf = (r) => {
              const h = r.page?.domain || (() => { try { return new URL(r.page?.url || "").hostname; } catch { return null; } })();
              return h ? String(h).toLowerCase() : null;
            };
            const submittedHostOf = (r) => {
              const h = r.task?.domain || (() => { try { return new URL(r.task?.url || "").hostname; } catch { return null; } })();
              return h ? String(h).toLowerCase() : null;
            };
            // Scans genuinely about our host: primary page IS our host.
            const primaryScans = uj.results.filter((r) => finalHostOf(r) === iocHostExact);
            // Among those, prefer ones that were also SUBMITTED as our host (cleanest).
            const submittedPrimary = primaryScans.filter((r) => submittedHostOf(r) === iocHostExact);
            const chosenPool = submittedPrimary.length ? submittedPrimary : primaryScans;
            const isPrimaryTarget = chosenPool.length > 0;
            // Pick newest from the chosen pool; if none, we have only incidental
            // contact scans — we DON'T show their host-specific data as ours.
            const latest = isPrimaryTarget ? chosenPool[0] : uj.results[0];
            // malicious count only over scans actually about our host (avoids
            // counting a malicious bitbucket scan as our host being malicious).
            const scoringPool = isPrimaryTarget ? chosenPool : [];
            const malCount = scoringPool.filter((r) => r.verdicts?.overall?.malicious || r.verdicts?.urlscan?.malicious).length;
            const oldest = uj.results[uj.results.length - 1];
            // Host-specific fields ONLY when we have a primary-target scan.
            const pageTitle = isPrimaryTarget ? (latest.page?.title || null) : null;
            const pageServer = isPrimaryTarget ? (latest.page?.server || null) : null;
            const pageCountry = isPrimaryTarget ? (latest.page?.country || null) : null;
            const scanDate = latest.task?.time ? latest.task.time.split("T")[0] : null;
            const resultUrl = latest.result || null;

            // First Seen / Last Seen — only from scans about our host.
            const datePool = isPrimaryTarget ? chosenPool : [];
            const allScanDates = datePool.map((r) => r.task?.time).filter(Boolean).sort();
            const usFirstSeen = allScanDates.length ? allScanDates[0].split("T")[0] : null;
            const usLastSeen = allScanDates.length > 1 ? allScanDates[allScanDates.length - 1].split("T")[0] : null;

            // Observation-based ages — ONLY read from a primary-target scan, else
            // they'd describe the wrong host (e.g. bitbucket.org's 13yr age).
            const domainAgeDays = isPrimaryTarget ? (latest.page?.domainAgeDays ?? null) : null;
            const subdomainCreated = domainAgeDays != null ? dateFromAgeDays(domainAgeDays, latest.task?.time) : null;
            const apexAgeDays = isPrimaryTarget ? (latest.page?.apexDomainAgeDays ?? null) : null;
            const apexFirstSeen = apexAgeDays != null ? dateFromAgeDays(apexAgeDays, latest.task?.time) : null;

            results.urlscan = {
              scans: totalScans,
              primaryScans: chosenPool.length, // scans actually ABOUT this host
              isPrimaryTarget,                  // false = host only appears as contacted/redirect hop
              malicious: malCount,
              verdict: malCount > 0 ? "malicious" : (isPrimaryTarget && chosenPool.length > 3) ? "seen" : "low data",
              title: pageTitle,
              server: pageServer,
              country: pageCountry,
              flag: countryFlag(pageCountry),
              scanDate,
              // Link ONLY to a scan that's about our host. If our host only appears
              // as an incidental contact in scans of other URLs, we don't link to
              // one of those (it'd open bitbucket.org etc.) — we point to the host's
              // own urlscan search page instead.
              link: (isPrimaryTarget && resultUrl) ? `https://urlscan.io/result/${latest._id}/` : null,
              hostSearchLink: `https://urlscan.io/search/#page.domain%3A%22${encodeURIComponent(iocHostExact)}%22`,
              screenshot: isPrimaryTarget ? (latest.screenshot || null) : null,
              firstSeen: usFirstSeen,
              lastSeen: usLastSeen,
              subdomainAgeDays: domainAgeDays,
              apexAgeDays,
              apexFirstSeen,
              subdomainCreated,
              // Pivot points: serving IP (only from a primary-target scan)
              servingIP: isPrimaryTarget ? (latest.page?.ip || null) : null,
              servingASN: isPrimaryTarget ? (latest.page?.asn || null) : null,
              servingASNName: isPrimaryTarget ? (latest.page?.asnname || null) : null,
              // Scanned URLs from all results (for showing as additional info)
              scannedUrls: (() => {
                const seen = new Set();
                const out = [];
                uj.results.forEach((r) => {
                  const u = r.page?.url || r.task?.url;
                  if (!u) return;
                  const k = u.toLowerCase().replace(/\/+$/, "");
                  if (seen.has(k)) return;
                  seen.add(k);
                  out.push({ url: u, screenshot: r.screenshot || null });
                });
                return out.slice(0, 10);
              })(),
              // Files observed in scans (filename, hash, URL)
              files: (() => {
                const seen = new Set();
                const out = [];
                uj.results.forEach((r) => {
                  if (r.files && Array.isArray(r.files)) {
                    r.files.forEach((f) => {
                      const key = f.sha256 || f.filename || f.url;
                      if (key && !seen.has(key)) {
                        seen.add(key);
                        out.push({ filename: f.filename || null, sha256: f.sha256 || null, url: f.url || null, size: f.size || null });
                      }
                    });
                  }
                });
                return out.length ? out.slice(0, 8) : null;
              })(),
            };

            // ---- Deep result fetch: contacted infra, brand impersonation, loaded resources ----
            // The search API omits these; fetch the latest scan's full document.
            // Only when the latest scan is actually ABOUT our host — otherwise we'd
            // pull bitbucket.org's contacted infra / brands, not our host's.
            if (isPrimaryTarget) {
            try {
              const detail = await callEnrich("urlscan_result", null, latest._id);
              if (detail && !detail.error) {
                const self = String(value).toLowerCase().replace(/^https?:\/\//, "").replace(/\/.*$/, "");
                const selfHost = (() => { try { return new URL(value.includes("://") ? value : "https://" + value).hostname.toLowerCase(); } catch { return self; } })();

                // Brand impersonation — urlscan flags which brands a page mimics.
                const brands = Array.isArray(detail.verdicts?.overall?.brands)
                  ? detail.verdicts.overall.brands.map((b) => (typeof b === "string" ? b : b?.name)).filter(Boolean)
                  : (Array.isArray(detail.brands) ? detail.brands.map((b) => b?.name || b).filter(Boolean) : []);
                const overallMalicious = !!detail.verdicts?.overall?.malicious;
                const overallScore = typeof detail.verdicts?.overall?.score === "number" ? detail.verdicts.overall.score : null;

                // TLS cert info (fresh cert on a brand domain = phishing signal)
                const tlsIssuer = detail.page?.tlsIssuer || detail.lists?.certificates?.[0]?.issuer || null;
                const tlsValidFrom = detail.page?.tlsValidFrom || detail.lists?.certificates?.[0]?.validFrom || null;
                const tlsAgeDays = detail.page?.tlsAgeDays ?? null;

                // Contacted IPs — only surface ones urlscan itself flags, or that
                // are clearly not benign CDN/analytics. IPs have no "benign" list,
                // so we keep all contacted IPs but drop the serving IP (already a node).
                // Static asset extensions that are never threat infrastructure —
                // CSS, fonts, icons, images, common JS frameworks loaded from CDNs.
                const STATIC_EXTS = /\.(css|woff2?|ttf|eot|otf|ico|png|jpg|jpeg|gif|svg|webp|map|txt|xml|json)(\?.*)?$/i;
                const isStaticAsset = (url) => STATIC_EXTS.test(String(url || "").split("?")[0]);

                const contactedIPs = Array.isArray(detail.lists?.ips)
                  ? Array.from(new Set(detail.lists.ips))
                      .filter((ip) => ip && ip !== results.urlscan.servingIP)
                      .slice(0, 15)
                  : [];

                // Contacted domains — filter out benign CDN/analytics infra, self,
                // and domains that only serve static assets.
                const contactedDomains = Array.isArray(detail.lists?.domains)
                  ? Array.from(new Set(detail.lists.domains.map((d) => String(d).toLowerCase())))
                      .filter((dom) => dom && dom !== selfHost && !isBenignInfra(dom))
                      .slice(0, 15)
                  : [];

                // Loaded-resource hashes — filter to only executable/document types.
                // Skip CSS, images, fonts, and other static assets by extension AND MIME type.
                const BENIGN_MIME = /^(text\/css|image\/|font\/|text\/plain|application\/font|application\/x-font)/i;
                const STATIC_EXTS_HASH = /\.(css|woff2?|ttf|eot|otf|ico|png|jpg|jpeg|gif|svg|webp|map)(\?.*)?$/i;
                const resourceHashes = Array.isArray(detail.lists?.hashes)
                  ? Array.from(new Set(detail.lists.hashes))
                      .filter((h) => {
                        const req = (detail.data?.requests || []).find((r) =>
                          r?.response?.hash === h
                        );
                        if (!req) return true;
                        const url = req?.request?.url || "";
                        const mime = req?.response?.mimeType || req?.response?.type || "";
                        if (STATIC_EXTS_HASH.test(url.split("?")[0])) return false;
                        if (BENIGN_MIME.test(mime)) return false;
                        return true;
                      })
                      .slice(0, 10)
                  : [];

                results.urlscan.brands = brands.length ? brands : null;
                results.urlscan.overallMalicious = overallMalicious;
                results.urlscan.overallScore = overallScore;
                results.urlscan.tlsIssuer = tlsIssuer;
                results.urlscan.tlsValidFrom = tlsValidFrom ? String(tlsValidFrom).split("T")[0] : null;
                results.urlscan.tlsAgeDays = tlsAgeDays;
                results.urlscan.contactedIPs = contactedIPs.length ? contactedIPs : null;
                results.urlscan.contactedDomains = contactedDomains.length ? contactedDomains : null;
                results.urlscan.resourceHashes = resourceHashes.length ? resourceHashes : null;
              }
            } catch (e) { console.warn("urlscan result detail failed:", e.message); }
            } // end if (isPrimaryTarget)
          }
        } catch (e) { console.warn("Enrich urlscan.io failed:", e.message); }
      }

      // ---- RDAP — domain registration date (TLD age) ----
      // Called directly from browser (RDAP servers support CORS per RFC 7480).
      // Skip for IP-based URLs (e.g. 95.182.97.58/path) — not a proper domain.
      if (["DOMAIN","URL"].includes(cat)) {
        // Check if the value is an IP address rather than a domain name
        const rdapTarget = cat === "URL"
          ? (() => { try { return new URL(value.includes("://") ? value : "https://" + value).hostname; } catch { return value; } })()
          : value;
        const isIP = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(rdapTarget) || rdapTarget.includes(":");
        if (!isIP) {
        try {
          const baseDomain = registrableDomain(rdapTarget);
          // Build endpoint list: IANA-authoritative server first, then generic
          // fallbacks. Only a 404 from an authoritative server proves the domain
          // is gone — a 404 from a server that doesn't own the TLD proves nothing.
          // ONLY a server IANA explicitly maps to this TLD counts as authoritative.
          // rdap.org and ARIN's bootstrap both proxy the same IANA file, so their
          // 404s mean "unknown TLD", not "domain doesn't exist" — never trust them.
          const authoritative = await rdapServerFor(baseDomain);
          const rdapEndpoints = [];
          if (authoritative) rdapEndpoints.push({ url: authoritative.url, auth: true });
          // Registries missing from IANA's bootstrap (.me, .io, .co, ...). Probed
          // for data but marked non-authoritative so a 404 can never mark deleted.
          const extra = RDAP_OPERATOR[String(baseDomain).split(".").pop().toLowerCase()];
          if (extra && !authoritative) rdapEndpoints.push({ url: `${extra}/domain/${encodeURIComponent(baseDomain)}`, auth: false });
          rdapEndpoints.push({ url: `https://rdap.org/domain/${encodeURIComponent(baseDomain)}`, auth: false });
          rdapEndpoints.push({ url: `https://rdap-bootstrap.arin.net/bootstrap/domain/${encodeURIComponent(baseDomain)}`, auth: false });
          let rj = null;
          let rdapStatus = null;
          let got404FromAuthoritative = false;
          for (const ep of rdapEndpoints) {
            try {
              const r = await fetch(ep.url, { headers: { "Accept": "application/rdap+json, application/json" } });
              rdapStatus = r.status;
              if (r.ok) { rj = await r.json(); break; }
              if (r.status === 404 && ep.auth) got404FromAuthoritative = true;
            } catch { /* try next */ }
          }
          if (rj && Array.isArray(rj.events)) {
            const regEvent = rj.events.find((e) => e.eventAction === "registration");
            const regDate = regEvent?.eventDate || null;
            // Extract EPP status codes (serverHold, clientTransferProhibited, etc.)
            const eppStatus = Array.isArray(rj.status) ? rj.status.filter((s) => typeof s === "string").slice(0, 4) : [];
            if (regDate) {
              const regD = new Date(regDate);
              const ageDays = !isNaN(regD) ? Math.floor((Date.now() - regD.getTime()) / 86400000) : null;
              results.domainReg = {
                date: regDate.split("T")[0],
                ageDays,
                status: eppStatus.length ? eppStatus.join(", ") : null,
                state: "active",
              };
            }
          } else if (got404FromAuthoritative) {
            // Only an authoritative registry 404 proves the domain isn't registered.
            // Distinguish deleted (other engines have history) vs never existed.
            const hasHistoricalData = results.threatfox || results.urlhaus || results.malwarebazaar
              || (results.otx && ((results.otx.pulses || 0) > 0 || results.otx.validation))
              || (results.urlscan && results.urlscan.scans > 0);
            results.domainReg = {
              date: null,
              ageDays: null,
              status: null,
              state: hasHistoricalData ? "deleted" : "unregistered",
            };
          }
        } catch (e) { console.warn("Enrich RDAP failed:", e.message); }
        } // end if (!isIP)

        // ---- Layer 3: WhoisJSON fallback ----
        // Only fires when Layer 1 (RDAP) produced no registration date AND
        // authoritative RDAP hasn't confirmed the domain is gone. Skipped for
        // IP-as-domain values. Fails silently if the key isn't configured.
        if (!isIP && (!results.domainReg || results.domainReg.state === "unregistered" || (results.domainReg.state === "active" && results.domainReg.ageDays == null))) {
          try {
            const baseDomain = registrableDomain(rdapTarget);
            const wj = await callEnrich("whoisjson", null, null, baseDomain);
            // WhoisJSON returns flat fields at root: created, status, registered
            const created = wj?.created || null;
            const statusArr = Array.isArray(wj?.status) ? wj.status : null;
            if (created) {
              const cd = new Date(created);
              if (!isNaN(cd)) {
                const ageDays = Math.floor((Date.now() - cd.getTime()) / 86400000);
                const eppStatus = statusArr && statusArr.length
                  ? statusArr.filter((s) => typeof s === "string" && /^[a-zA-Z]/.test(s)).slice(0, 4).join(", ")
                  : null;
                results.domainReg = {
                  date: created.split("T")[0],
                  ageDays,
                  status: eppStatus || null,
                  state: "active",
                  source: "whoisjson",
                };
              }
            }
          } catch (e) { console.warn("Enrich WhoisJSON failed:", e.message); }
        }
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

      // ---- Consolidated First Seen / Last Seen across all engines ----
      const allFirsts = [
        results.threatfox?.first, results.urlhaus?.first,
        results.malwarebazaar?.first, results.urlscan?.firstSeen,
      ].filter(Boolean).sort();
      const allLasts = [
        results.threatfox?.last, results.urlhaus?.last,
        results.malwarebazaar?.last, results.urlscan?.lastSeen,
        // AbuseIPDB lastReported = last time this IP was reported malicious —
        // include as Last Seen if it's more recent than other sources.
        results.abuseipdb?.lastReported,
      ].filter(Boolean).sort();
      if (allFirsts.length || allLasts.length) {
        const firstDate = allFirsts.length ? allFirsts[0] : null;
        const lastDate = allLasts.length ? allLasts[allLasts.length - 1] : null;
        results._timeline = {
          firstSeen: firstDate,
          firstFmt: timeAgoFmt(firstDate),
          lastSeen: lastDate,
          lastFmt: timeAgoFmt(lastDate),
        };
      }

      // ---- Derive combined verdict ----
      // MalwareBazaar only indexes confirmed malware — existence = Malicious.
      // Individual vendor verdicts (NO_THREAT, LIKELY_MALICIOUS) are ignored.
      let verdict = "Unknown";
      const _isHashCat = ["MD5", "SHA1", "SHA256", "SHA512"].includes(cat);
      // CVE verdict: CISA KEV listing = confirmed active exploitation in the
      // wild, treated the same as any other confirmed-malicious signal. High
      // EPSS (≥50%) without a KEV listing is a prediction, not a confirmation
      // — Suspicious, not Malicious. CVSS severity alone (no KEV, no high
      // EPSS) doesn't drive verdict at all — it's shown as context only,
      // same principle as Kaspersky green not being auto-trusted for non-hashes.
      if (cat === "CVE" && results.cisaKev?.listed) verdict = "Malicious";
      else if (cat === "CVE" && (results.epss?.score || 0) >= 50) verdict = "Suspicious";
      // Kaspersky Zone=Red is a strong signal from a first-party AV vendor —
      // check it first alongside the explicit threat feeds.
      else if (results.kaspersky?.zone === "red") verdict = "Malicious";
      else if (results.threatfox) verdict = "Malicious";
      else if (results.urlhaus?.status === "online") verdict = "Malicious";
      else if (results.malwarebazaar) verdict = "Malicious";
      // Tri.age score 10 = confirmed malicious; 5-9 = suspicious
      else if (results.triage?.score === 10) verdict = "Malicious";
      else if ((results.triage?.score || 0) >= 5) verdict = "Suspicious";
      // Hybrid Analysis verdict — sandbox behavioral analysis with AV consensus
      else if (results.hybridAnalysis?.verdict === "malicious" || (results.hybridAnalysis?.threatScore || 0) >= 70) verdict = "Malicious";
      else if (results.hybridAnalysis?.verdict === "suspicious" || (results.hybridAnalysis?.threatScore || 0) >= 30) verdict = "Suspicious";
      // urlscan's own engine flagged the latest scan malicious.
      else if (results.urlscan?.overallMalicious) verdict = "Malicious";
      else if (results.urlhaus?.status === "offline") verdict = "Suspicious";
      // Brand impersonation detected by urlscan (page mimics Microsoft/PayPal/etc).
      // Strong phishing signal — would have caught onedrive.cv-style impersonation.
      else if (results.urlscan?.brands && results.urlscan.brands.length) verdict = "Suspicious";
      else if (results.otx?.whitelisted === true) verdict = "Whitelisted";
      // Kaspersky green: for a HASH it means the file is in Kaspersky's known-clean
      // DB (reliable — file hashes are immutable). For a DOMAIN/URL/IP, green only
      // means "no current malicious classification" — NOT trusted. A fresh
      // impersonation domain (onedrive.cv, seha.hospital) defaults to green before
      // classification, which would wrongly whitelist it. So green whitelists hashes only.
      else if (results.kaspersky?.zone === "green" && _isHashCat) verdict = "Whitelisted";
      // CIRCL known-legitimate: NSRL/community-attested legit file, trust > 50.
      // (CIRCL is hash-only, so no domain risk here.)
      else if (results.circl?.legit) verdict = "Whitelisted";
      else if (results.otx?.validation) verdict = "Suspicious"; // OTX flagged (DGA, blocklist, etc.)
      else if ((results.otx?.pulses || 0) >= 9) verdict = "Malicious";
      else if ((results.abuseipdb?.score || 0) >= 80) verdict = "Malicious";
      else if ((results.abuseipdb?.score || 0) >= 25) verdict = "Suspicious";
      // SANS ISC "attacks" is a raw count of distinct reporters, not a
      // normalized score — kept to a Suspicious ceiling, same restraint as
      // AbuseIPDB's own mid-range tier.
      else if ((results.sansIsc?.attacks || 0) >= 5) verdict = "Suspicious";
      else if (results.kaspersky?.zone === "yellow") verdict = "Suspicious";
      // EPP hold / withheld status = registry/registrar intervention → suspicious.
      // Catches withheld impersonation domains that engines haven't classified yet.
      else if (results.domainReg?.status && /hold|withheld|pendingdelete|redemption/i.test(results.domainReg.status)) verdict = "Suspicious";
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
      const hasNonOtx = results.threatfox || results.urlhaus || results.malwarebazaar || results.whois || results.validin || results.abuseipdb || results.urlscan || results.circl || results.kaspersky || results.triage || results.hybridAnalysis;
      if (!hasNonOtx && results.otx && results.otx.pulses === 0 && !results.otx.validation) verdict = "Unknown";

      // Final verdict normalization — catch any non-standard strings
      const vUp = verdict.toUpperCase();
      if (vUp.includes("MALICIOUS") && verdict !== "Malicious") verdict = "Malicious";
      else if (vUp.includes("SUSPICIOUS") && verdict !== "Suspicious") verdict = "Suspicious";

      const hasData = Object.keys(results).length > 0;
      if (hasData) results._verdict = verdict;
      setEnrichCache((c) => ({ ...c, [key]: { loading: false, data: hasData ? results : null, error: !hasData } }));

      // ---- Hash dedup: MD5/SHA1 → SHA256 consolidation ----
      // GATED: consolidation only fires when the canonical SHA256 is ALREADY
      // present in the IOC list. If not, the MD5/SHA1 stays as-is with its
      // enrichment — the user can manually convert via the header button.
      // Sibling weak hash removal ALSO fires only if canonical is in list.
      if (results._canonicalSHA256 && ["MD5","SHA1"].includes(cat)) {
        const canonical = results._canonicalSHA256;
        const otherCat = cat === "MD5" ? "SHA1" : "MD5";
        const otherHash = cat === "MD5" ? results._siblingSHA1 : results._siblingMD5;
        // Only proceed if SHA256 already exists in the IOC list
        const currentSHA256s = ((iocData || {}).SHA256 || []).map(v => v.toLowerCase());
        const canonicalInList = currentSHA256s.includes(canonical);
        if (canonicalInList) {
          setIocData((prev) => {
            if (!prev) return prev;
            const next = { ...prev };
            // Remove the enriched hash (SHA256 already in list — no need to add)
            if (next[cat]) {
              const removed = next[cat].filter(v => v.toLowerCase() === value.toLowerCase());
              next[cat] = next[cat].filter(v => v.toLowerCase() !== value.toLowerCase());
              if (!next[cat].length) delete next[cat];
              if (removed.length) {
                setMergedHashes(m => {
                  const entry = m[canonical] || { removed: [], sources: [] };
                  if (entry.removed.some(r => r.cat === cat && r.value.toLowerCase() === value.toLowerCase())) return m;
                  return { ...m, [canonical]: { removed: [...entry.removed, { cat, value, manual: false }], sources: [...new Set([...entry.sources, cat])] } };
                });
                setBlastNodes(s => new Set([...s, value]));
                setTimeout(() => setBlastNodes(s => { const n = new Set(s); n.delete(value); return n; }), 950);
                fireDedupToast(cat, value, canonical);
              }
            }
            // Also remove sibling weak hash if it's in the list
            if (otherHash && next[otherCat]) {
              const siblingFound = next[otherCat].some(v => v.toLowerCase() === otherHash);
              if (siblingFound) {
                next[otherCat] = next[otherCat].filter(v => v.toLowerCase() !== otherHash);
                if (!next[otherCat].length) delete next[otherCat];
                setMergedHashes(m => {
                  const entry = m[canonical] || { removed: [], sources: [] };
                  if (entry.removed.some(r => r.cat === otherCat && r.value.toLowerCase() === otherHash)) return m;
                  return { ...m, [canonical]: { removed: [...entry.removed, { cat: otherCat, value: otherHash, manual: false }], sources: [...new Set([...entry.sources, otherCat])] } };
                });
                setBlastNodes(s => new Set([...s, otherHash]));
                setTimeout(() => setBlastNodes(s => { const n = new Set(s); n.delete(otherHash); return n; }), 950);
                fireDedupToast(otherCat, otherHash, canonical);
              }
            }
            return next;
          });
          // Auto-trigger SHA256 enrichment after consolidation
          setTimeout(() => {
            setEnrichCache((c) => { const n = { ...c }; delete n[`SHA256::${canonical}`]; return n; });
            enrichIOC("SHA256", canonical);
          }, 2000);
        }
        // else: canonical SHA256 not in list — leave MD5/SHA1 as-is.
        // User can click "Consolidate as SHA256 IOC" on card header to manually convert.
      }

      // ---- SHA256 enrichment: remove any MD5/SHA1 siblings still in the IOC list ----
      // When SHA256 is enriched directly, enrichment engines return the file's
      // MD5 and SHA1 — check if those exist as IOCs and consolidate them.
      if (cat === "SHA256" && (results._siblingMD5 || results._siblingSHA1)) {
        setIocData((prev) => {
          if (!prev) return prev;
          const next = { ...prev };
          [["MD5", results._siblingMD5], ["SHA1", results._siblingSHA1]].forEach(([weakCat, weakHash]) => {
            if (!weakHash || !next[weakCat]) return;
            const found = next[weakCat].find(v => v.toLowerCase() === weakHash);
            if (!found) return;
            next[weakCat] = next[weakCat].filter(v => v.toLowerCase() !== weakHash);
            if (!next[weakCat].length) delete next[weakCat];
            setMergedHashes(m => {
              const sha = value.toLowerCase();
              const entry = m[sha] || { removed: [], sources: [] };
              if (entry.removed.some(r => r.cat === weakCat && r.value.toLowerCase() === weakHash)) return m;
              return { ...m, [sha]: { removed: [...entry.removed, { cat: weakCat, value: found }], sources: [...new Set([...entry.sources, weakCat])] } };
            });
            setBlastNodes(s => new Set([...s, found]));
            setTimeout(() => setBlastNodes(s => { const n = new Set(s); n.delete(found); return n; }), 950);
            fireDedupToast(weakCat, found, value);
          });
          return next;
        });
      }
      // Logging is now handled server-side in the Worker's /enrich route —
      // no client-side log call needed, nothing suspicious in DevTools.
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
  const [prependHttps, setPrependHttps] = useState(false); // URL card only: prepend https:// for View/Copy
  const [copied, setCopied] = useState("");
  const [editingKey, setEditingKey] = useState(null);
  const [editValue, setEditValue] = useState("");
  const [movingKey, setMovingKey] = useState(null); // "cat::value" being moved
  const [addedPivots, setAddedPivots] = useState(new Set());       // "targetCat::targetValue" → added
  const [dismissedPivots, setDismissedPivots] = useState(new Set()); // dismissed pivot suggestions
  const [enrichAllDone, setEnrichAllDone] = useState({});
  // Hash dedup: { sha256: { removed: [{cat, value}], sources: Set } }
  const [mergedHashes, setMergedHashes] = useState({});
  const [showMerged, setShowMerged] = useState(false);
  // Graph arc animation: { fromId, toId, startTime } triggers the collapse arc
  const [blastNodes, setBlastNodes] = useState(new Set()); // IOC values with active blast animation
  const [hashCollapseAnims, setHashCollapseAnims] = useState([]);
  // Simple, always-visible toast for hash consolidation events.
  // { id, fromCat, fromValue, toValue } — displayed as centered floating card for 3s
  const [dedupToasts, setDedupToasts] = useState([]);
  const fireDedupToast = (fromCat, fromValue, toValue) => {
    const id = `${fromValue}-${Date.now()}`;
    setDedupToasts(t => [...t, { id, fromCat, fromValue, toValue }]);
    setTimeout(() => setDedupToasts(t => t.filter(x => x.id !== id)), 3000);
  };
  // Manual consolidation: user clicked "Consolidate as SHA256 IOC" on MD5/SHA1 card.
  // For each resolvable weak hash, add the canonical SHA256 to the IOC list,
  // remove the weak hash, log to mergedHashes with manual:true flag so the
  // consolidation summary can distinguish auto-dedup vs manual conversion.
  const manualConsolidateToSHA256 = (cat, values) => {
    setIocData(prev => {
      if (!prev) return prev;
      const next = { ...prev };
      values.forEach((value, idx) => {
        const k = `${cat}::${String(value).toLowerCase()}`;
        const canonical = enrichCache[k]?.data?._canonicalSHA256;
        if (!canonical) return;
        // Add SHA256 if not already there
        const sha256List = (next.SHA256 || []).map(v => v.toLowerCase());
        if (!sha256List.includes(canonical)) {
          next.SHA256 = [...(next.SHA256 || []), canonical];
        }
        // Remove the weak hash
        if (next[cat]) {
          next[cat] = next[cat].filter(v => v.toLowerCase() !== value.toLowerCase());
          if (!next[cat].length) delete next[cat];
        }
        // Track with manual flag
        setMergedHashes(m => {
          const entry = m[canonical] || { removed: [], sources: [] };
          if (entry.removed.some(r => r.cat === cat && r.value.toLowerCase() === value.toLowerCase())) return m;
          return { ...m, [canonical]: { removed: [...entry.removed, { cat, value, manual: true }], sources: [...new Set([...entry.sources, cat])] } };
        });
        setBlastNodes(s => new Set([...s, value]));
        setTimeout(() => setBlastNodes(s => { const n = new Set(s); n.delete(value); return n; }), 950);
        fireDedupToast(cat, value, canonical);
        // Auto-trigger enrichment of the new SHA256 — staggered so a multi-hash
        // consolidation doesn't fire a burst of simultaneous enrichments. Clear
        // any stray cache entry first so it can't block the fresh enrichment.
        setTimeout(() => {
          setEnrichCache((c) => { const n = { ...c }; delete n[`SHA256::${canonical}`]; return n; });
          enrichIOC("SHA256", canonical);
        }, 1500 + idx * 1500);
      });
      return next;
    });
  };
  const [customAddCat, setCustomAddCat] = useState(null);           // category currently showing add input
  const [customAddValue, setCustomAddValue] = useState("");
  const [condensed, setCondensed] = useState(false);
  const [graphView, setGraphView] = useState(true);
  const [hoveredActionRow, setHoveredActionRow] = useState(null);
  const [parseFlash, setParseFlash] = useState(null); // "paste"|"raw" — brief glow on click // eKey whose action button is hovered
  const [pdnsExpanded, setPdnsExpanded] = useState({});   // { "cat::ioc": bool } show all raw obs
  const [pdnsRowOpen, setPdnsRowOpen] = useState({});     // { "cat::ioc::target": bool } per-IP expand
  const [expiringTokens, setExpiringTokens] = useState([]);
  const [tokenBannerDismissed, setTokenBannerDismissed] = useState(false);
  const [cardCondensed, setCardCondensed] = useState({});        // { cat: true } per-card collapse
  // ---- Card removal confirmation state ----
  const [confirmRemoveCat, setConfirmRemoveCat] = useState(null); // cat name showing inline confirm
  // ---- Report Builder state ----
  const [reportOpen, setReportOpen] = useState(false);
  const [reportTemplate, setReportTemplate] = useState("full"); // exec | technical | mitre | hunting | full
  const [reportAnalyst, setReportAnalyst] = useState(() => localStorage.getItem("ie_analyst") || "");
  const [reportOrg, setReportOrg] = useState(() => localStorage.getItem("ie_org") || "");
  const [reportTLP, setReportTLP] = useState("AMBER"); // WHITE|GREEN|AMBER|RED
  const [reportWatermark, setReportWatermark] = useState("");
  const [reportRefNum, setReportRefNum] = useState("");
  const [reportVariant, setReportVariant] = useState("dark"); // dark | light
  // Section ordering + toggles — reorderable via arrows
  const [reportSections, setReportSections] = useState([
    { id: "cover",       name: "Cover Page",           enabled: true },
    { id: "exec",        name: "Executive Summary",    enabled: true },
    { id: "technical",   name: "Technical IOC Report", enabled: true },
    { id: "graph",       name: "Shared-Pivot Graph",   enabled: true },
    { id: "mitre",       name: "MITRE ATT&CK Mapping", enabled: true },
    { id: "hunting",     name: "Hunting Playbook",     enabled: true },
    { id: "consolidation", name: "Hash Consolidation", enabled: true },
    { id: "glossary",    name: "Glossary",             enabled: true },
  ]);
  // IOC types to include (global filter)
  const [reportIocTypes, setReportIocTypes] = useState({}); // { CAT: true }
  // Query languages to include in Hunting Playbook
  const [reportQueryLangs, setReportQueryLangs] = useState({ kql: true, spl: true, aql: true, cql: true, sigma: true });
  // Right-panel tab: metadata | sections | content
  const [reportTab, setReportTab] = useState("metadata");
  const reportPreviewRef = useRef(null);
  // Holds a section id the user asked to jump to while the preview iframe is
  // mid-reload (srcDoc reassignment reloads the iframe asynchronously) —
  // consumed by handleReportPreviewLoad once the new document is ready.
  const reportScrollPendingRef = useRef(null);
  // Scroll the live preview iframe to a given report section. Tries immediately
  // (covers the common case where the preview content hasn't changed) and also
  // arms the pending ref so a reload in flight (e.g. from a template switch)
  // re-applies the scroll once the fresh document finishes loading.
  const scrollToReportSection = (id) => {
    reportScrollPendingRef.current = id;
    try {
      const doc = reportPreviewRef.current?.contentWindow?.document;
      const el = doc?.getElementById(`section-${id}`);
      if (el) el.scrollIntoView({ behavior: "smooth", block: "start" });
    } catch { /* cross-doc access can throw during a mid-reload */ }
  };
  const handleReportPreviewLoad = () => {
    const id = reportScrollPendingRef.current;
    if (!id) return;
    reportScrollPendingRef.current = null;
    try {
      const doc = reportPreviewRef.current?.contentWindow?.document;
      const el = doc?.getElementById(`section-${id}`);
      if (el) el.scrollIntoView({ behavior: "auto", block: "start" });
    } catch { /* ignore */ }
  };
  // First section each preset should scroll the preview to, so picking a
  // template also jumps you to the section it's built around.
  const TEMPLATE_FOCUS_SECTION = { full: "cover", exec: "exec", technical: "technical", mitre: "mitre", hunting: "hunting" };
  // Auto-initialize IOC-type filter — moved below entries definition to avoid TDZ error
  // Apply template preset: reset section toggles per template selection
  const applyTemplate = (t) => {
    setReportTemplate(t);
    setReportSections(prev => prev.map(s => {
      if (t === "full") return { ...s, enabled: true };
      if (t === "exec") return { ...s, enabled: ["cover", "exec", "glossary"].includes(s.id) };
      if (t === "technical") return { ...s, enabled: ["cover", "technical", "consolidation", "glossary"].includes(s.id) };
      if (t === "mitre") return { ...s, enabled: ["cover", "mitre", "glossary"].includes(s.id) };
      if (t === "hunting") return { ...s, enabled: ["cover", "hunting", "glossary"].includes(s.id) };
      return s;
    }));
    scrollToReportSection(TEMPLATE_FOCUS_SECTION[t] || "cover");
  };
  const moveSection = (idx, dir) => {
    setReportSections(prev => {
      const next = [...prev];
      const swap = idx + dir;
      if (swap < 0 || swap >= next.length) return prev;
      [next[idx], next[swap]] = [next[swap], next[idx]];
      return next;
    });
  };
  const toggleSection = (id) => {
    setReportSections(prev => prev.map(s => s.id === id ? { ...s, enabled: !s.enabled } : s));
  };
  const toggleReportIocType = (cat) => {
    setReportIocTypes(prev => ({ ...prev, [cat]: !prev[cat] }));
  };
  const toggleReportQueryLang = (lang) => {
    setReportQueryLangs(prev => ({ ...prev, [lang]: !prev[lang] }));
  };
  const [rowOverride, setRowOverride] = useState({});            // { "cat::value": bool } per-IOC override
  const [dragging, setDragging] = useState(null);               // { cat, value }
  const [dragOverCat, setDragOverCat] = useState(null);
  const copyTimer = useRef(null);

  // Edit an IOC value inline — replaces the old value in iocData
  const editIoc = (cat, oldValue, newValue) => {
    const trimmed = newValue.trim();
    if (!trimmed || trimmed === oldValue) { setEditingKey(null); return; }
    setIocData((prev) => {
      if (!prev?.[cat]) return prev;
      const next = { ...prev, [cat]: prev[cat].map((v) => v === oldValue ? trimmed : v) };
      return next;
    });
    // Update originData key if it exists
    setOriginData((prev) => {
      if (!prev?.[cat]?.[oldValue]) return prev;
      const next = { ...prev, [cat]: { ...prev[cat] } };
      next[cat][trimmed] = next[cat][oldValue];
      delete next[cat][oldValue];
      return next;
    });
    setEditingKey(null);
  };


  const displayData = iocData;

  const entries = useMemo(
    () => (displayData ? Object.entries(displayData).sort((a, b) => catRank(a[0]) - catRank(b[0])) : []),
    [displayData]
  );
  const total = useMemo(() => entries.reduce((s, [, v]) => s + v.length, 0), [entries]);

  // Auto-initialize report IOC-type filter when entries change (default: all enabled)
  useEffect(() => {
    setReportIocTypes(prev => {
      const next = { ...prev };
      entries.forEach(([cat]) => { if (next[cat] === undefined) next[cat] = true; });
      return next;
    });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [entries.length]);

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

  const proc = (arr, cat) => {
    let out = arr;
    // prependHttps applied first (before defang) so defang correctly converts hxxps://
    if (prependHttps && cat === "URL") out = out.map((v) => /^https?:\/\//i.test(v) ? v : `https://${v}`);
    if (defangAll || defangMap[cat]) out = out.map(defang);
    return out;
  };
  const toggleDefang = (cat) => setDefangMap((m) => ({ ...m, [cat]: !m[cat] }));

  // Drag-and-drop IOC between categories
  const handleDragStart = (cat, value) => {
    setDragging({ cat, value });
  };
  const handleDragEnd = () => {
    setDragging(null);
    setDragOverCat(null);
  };
  const handleDropOnCat = (targetCat) => {
    if (!dragging || dragging.cat === targetCat) { handleDragEnd(); return; }
    // Remove from source
    removeIoc(dragging.cat, dragging.value);
    // Add to target
    addPivotIOC(targetCat, dragging.value, `Moved from ${dragging.cat}`);
    handleDragEnd();
  };

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

  // Move an IOC from one category to another (e.g. misclassified domain → FILE_NAME)
  const moveIoc = (fromCat, value, toCat) => {
    if (fromCat === toCat) return;
    setIocData((prev) => {
      const next = { ...prev };
      // Remove from source
      if (next[fromCat]) {
        const arr = next[fromCat].filter((v) => v !== value);
        if (arr.length) next[fromCat] = arr; else delete next[fromCat];
      }
      // Add to target (create category if needed)
      next[toCat] = [...new Set([...(next[toCat] || []), value])];
      return next;
    });
    setMovingKey(null);
  };

  // All valid IOC categories for the move-to dropdown
  const ALL_IOC_CATS = ["IPV4","IPV6","DOMAIN","URL","MD5","SHA1","SHA256","SHA512","EMAIL","CVE","MITRE_ATTACK","FILE_NAME","FILE_PATH","REGISTRY","SCHEDULED_TASK","SERVICE","COMMAND_LINE","MAC_ADDRESS","BTC","ETH","XMR","YARA"];

  // Add a pivot IOC from enrichment (urlscan serving IP, file hashes, etc.)
  // The IOC gets a [pivot] tag in originData for display differentiation.
  const addPivotIOC = (cat, value, source) => {
    let normValue = String(value).trim().replace(/\/+$/, "");
    if (cat === "URL" || cat === "DOMAIN") {
      normValue = normValue.replace(/^https?:\/\//i, "").replace(/\/+$/, "");
    }
    if (!normValue) return;
    const pivotKey = `${cat}::${normValue}`;
    setIocData((prev) => {
      const existing = prev?.[cat] || [];
      const existingNorm = existing.map((v) => {
        let n = String(v).trim().replace(/\/+$/, "");
        if (cat === "URL" || cat === "DOMAIN") n = n.replace(/^https?:\/\//i, "").replace(/\/+$/, "");
        return n.toLowerCase();
      });
      if (existingNorm.includes(normValue.toLowerCase())) return prev;
      const next = { ...prev, [cat]: [...existing, normValue] };
      const ordered = {};
      ORDER.forEach((k) => { if (next[k]?.length) ordered[k] = next[k]; });
      Object.keys(next).forEach((k) => { if (!ordered[k] && next[k]?.length) ordered[k] = next[k]; });
      return ordered;
    });
    setOriginData((prev) => {
      const next = { ...prev };
      if (!next[cat]) next[cat] = {};
      next[cat][normValue] = `pivot:${source}`;
      return next;
    });
    setAddedPivots((prev) => new Set([...prev, pivotKey]));
    setEnrichAllDone((prev) => { const n = { ...prev }; delete n[cat]; return n; });
  };

  const removePivotIOC = (cat, value) => {
    let normValue = String(value).trim().replace(/\/+$/, "");
    if (cat === "URL" || cat === "DOMAIN") normValue = normValue.replace(/^https?:\/\//i, "").replace(/\/+$/, "");
    const pivotKey = `${cat}::${normValue}`;
    removeIoc(cat, normValue);
    setAddedPivots((prev) => { const n = new Set(prev); n.delete(pivotKey); return n; });
  };

  const dismissPivot = (key) => {
    setDismissedPivots((prev) => new Set([...prev, key]));
  };

  const isPivotAdded = (cat, value) => {
    let n = String(value).trim().replace(/\/+$/, "");
    if (cat === "URL" || cat === "DOMAIN") n = n.replace(/^https?:\/\//i, "").replace(/\/+$/, "");
    return addedPivots.has(`${cat}::${n}`);
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
    setReferences([]); setMergedHashes({}); setShowMerged(false);
  };

  const goHome = () => {
    resetResults();
    setMode("url");
    setUrl("");
    setJsonText("");
    setRawText("");
    setReportOpen(false);
    window.scrollTo({ top: 0, behavior: "smooth" });
  };

  // ---- URL mode: API call AND page fetch in parallel ----
  // API is authoritative for its supported categories; the local engine only
  // contributes the types the API can't return (registry+values, file paths,
  // sha512, ssdeep, asn, mac, btc/xmr/eth). If the API fails, the engine runs in
  // full as a fallback.
  // overrideUrl lets callers (e.g. the Threat Wire) trigger a fetch with an
  // explicit URL instead of relying on `url` state, which would otherwise be
  // stale if read in the same tick as a just-fired setUrl(). Guarded with a
  // strict string check so this can never accidentally receive a DOM event
  // object from a bare `onClick={runFetch}` handler.
  const runFetch = async (overrideUrl) => {
    resetResults();
    setLoading(true);
    // Auto-prepend https:// if scheme missing
    let fetchUrl = (typeof overrideUrl === "string" ? overrideUrl : url).trim();
    if (fetchUrl && !/^https?:\/\//i.test(fetchUrl)) {
      fetchUrl = "https://" + fetchUrl;
      setUrl(fetchUrl);
    }

    const apiP = fetch(`${WORKER_BASE}/parse`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: fetchUrl, session_id: SESSION_ID }),
    })
      .then((r) => { if (!r.ok) throw new Error(`API HTTP ${r.status}`); return r.json(); });

    const pageP = fetch(`${WORKER_BASE}/fetch?url=${encodeURIComponent(fetchUrl)}&session_id=${encodeURIComponent(SESSION_ID)}`)
      .then((r) => { if (!r.ok) throw new Error(`page HTTP ${r.status}`); return r.text(); });

    const [aRes, pRes] = await Promise.allSettled([apiP, pageP]);

    const apiJson = aRes.status === "fulfilled" ? aRes.value : null;
    const apiData = apiJson ? (() => { const d = parseIocs(apiJson); return Object.keys(d).length ? d : null; })() : null;
    const apiMeta = apiJson && apiJson.meta && typeof apiJson.meta === "object" ? apiJson.meta : null;

    // Local engine over the fetched page text
    let engFull = null, engDetails = [], articleText = "", articleBody = "";
    if (pRes.status === "fulfilled" && pRes.value && pRes.value.length >= 50) {
      // Detect PDF binary content
      const isPDF = pRes.value.trimStart().startsWith("%PDF") || /\.pdf(\?|#|$)/i.test(fetchUrl);
      if (isPDF) {
        // Refetch as binary (raw=1 = untouched bytes from the Worker) and extract
        // text via pdf.js — proper PDF parsing decompresses FlateDecode streams to
        // reveal the actual command lines, registry keys, and other artifacts
        // that ASCII scraping cannot see.
        let pdfText = null;
        try {
          const binRes = await fetch(`${WORKER_BASE}/fetch?url=${encodeURIComponent(fetchUrl)}&raw=1&session_id=${encodeURIComponent(SESSION_ID)}`);
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

    if (!apiData && (!engFull || !Object.keys(filterScraped(engFull, fetchUrl)).length)) {
      // ---- Retry cascade: re-fetch with anti-scraping bypass headers ----
      // Some sites (gov, enterprise WAFs) block the initial fetch. Retry with
      // realistic browser headers + Referer. Auto-detect PDF vs HTML and parse.
      try {
        const retryRes = await fetch(`${WORKER_BASE}/fetch?url=${encodeURIComponent(fetchUrl)}&retry=1&session_id=${encodeURIComponent(SESSION_ID)}`);
        if (retryRes.ok) {
          const ct = (retryRes.headers.get("Content-Type") || "").toLowerCase();
          const isPdfRetry = ct.includes("pdf") || /\.pdf(\?|#|$)/i.test(fetchUrl);

          if (isPdfRetry) {
            // Retry as binary for PDF
            const binRetry = await fetch(`${WORKER_BASE}/fetch?url=${encodeURIComponent(fetchUrl)}&raw=1&retry=1&session_id=${encodeURIComponent(SESSION_ID)}`);
            if (binRetry.ok) {
              const buf = await binRetry.arrayBuffer();
              const pdfText = await extractPdfText(buf);
              if (pdfText && pdfText.length > 200) {
                let clean = pdfText.replace(/[ \t]+/g, " ");
                clean = clean.replace(/([A-Za-z0-9+/=_-])\s*\n\s*([A-Za-z0-9+/=_-])/g, "$1$2");
                clean = clean.replace(/\s+/g, " ").trim();
                articleText = clean;
                articleBody = clean;
                const ex = extractIocs(articleText);
                engFull = ex.data;
                engDetails = ex.registryDetails;
              }
            }
          } else {
            const retryHtml = await retryRes.text();
            if (retryHtml && retryHtml.length >= 50) {
              articleText = htmlToText(retryHtml);
              articleBody = extractArticleBody(retryHtml);
              if (articleBody.length < 800) articleBody = articleText;
              const ex = extractIocs(articleText);
              engFull = ex.data;
              engDetails = ex.registryDetails;
            }
          }
        }
      } catch (e) { console.warn("Retry fetch failed:", e.message || e); }

      // If retry also failed, show error with Upload File tab guidance
      if (!apiData && (!engFull || !Object.keys(filterScraped(engFull, url)).length)) {
        const why = [
          aRes.status === "rejected" ? (aRes.reason?.message || "API call failed") : "no API IOCs",
          pRes.status === "rejected" ? (pRes.reason?.message || "page fetch failed") : "no page IOCs",
        ].join("; ");
        setError(`Could not fetch this URL (${why}). The site may use anti-scraping protection or require JavaScript. Download the page manually (Save As → PDF/HTML) and use the Upload File tab.`);
        setMode("upload");
        setLoading(false);
        return;
      }
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
    { const { data: wd, refs: wr } = applyWhitelistAndRefs(data); setIocData(wd); setReferences(wr); }
    setOriginData(origin);
    setMeta(apiMeta);
    setSourceUrl(fetchUrl);
    if (articleText) setRawArticle(articleText);
    if (articleBody) setArticleClean(articleBody);
    setLoading(false);
    const _iocCount = Object.values(data || {}).reduce((s, arr) => s + (Array.isArray(arr) ? arr.length : 0), 0);
  };

  // Triggered by the Threat Wire — jumps to the Fetch URL tab, mirrors the
  // clicked article's link into the input box for visibility, and runs the
  // fetch with that link passed explicitly (see runFetch's overrideUrl).
  const huntArticle = (link) => {
    if (typeof link !== "string" || !link) return;
    setMode("url");
    setUrl(link);
    runFetch(link);
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

  // Report Builder shouldn't look incomplete just because the analyst never
  // expanded the AI Summary panel — generate one silently the first time the
  // report is opened, same on-demand cost model, just a different trigger.
  useEffect(() => {
    if (reportOpen && aiState === "idle" && (articleClean || rawArticle)) summarizeNow();
  }, [reportOpen]);

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

  // Token expiry check — runs once on mount. Populates the top banner
  // when any tracked API key is within 30 days of expiring.
  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const r = await fetch(`${WORKER_BASE}/token-status`);
        if (!r.ok) return;
        const j = await r.json();
        if (cancelled || !Array.isArray(j?.tokens)) return;
        const expiring = j.tokens.filter((t) => typeof t.daysLeft === "number" && t.daysLeft <= 30);
        setExpiringTokens(expiring);
      } catch { /* endpoint not deployed yet — silent */ }
    })();
    return () => { cancelled = true; };
  }, []);

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
      { const { data: wd, refs: wr } = applyWhitelistAndRefs(parsed); setIocData(wd); setReferences(wr); } setOriginData(origin); setRegistryDetails(details);
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
    { const { data: wd, refs: wr } = applyWhitelistAndRefs(ex.data); setIocData(wd); setReferences(wr); } setOriginData(origin); setRegistryDetails(ex.registryDetails);
    setSourceUrl("(raw paste)");
  };


  // Enrichment row builder — extracts structured data from enrichCache for export
  const enrichRow = (cat, value) => {
    const e = enrichCache[`${cat}::${value}`]?.data;
    if (!e) return {};
    const cs = e.malwarebazaar?.codeSign;
    const isHash = ["MD5","SHA1","SHA256","SHA512"].includes(cat);
    return {
      verdict:           e._verdict || "",
      // ThreatFox
      tf_malware:        e.threatfox?.malware || "",
      tf_threat:         e.threatfox?.threat || "",
      tf_confidence:     e.threatfox?.confidence != null ? `${e.threatfox.confidence}%` : "",
      tf_tags:           e.threatfox?.tags || "",
      // URLhaus
      urlhaus:           e.urlhaus ? `${e.urlhaus.status || ""}${e.urlhaus.threat ? ` · ${e.urlhaus.threat}` : ""}` : "",
      // MalwareBazaar
      mb_family:         e.malwarebazaar?.family || "",
      mb_detections:     e.malwarebazaar?.detections || "",
      mb_fileName:       e.malwarebazaar?.fileName || "",
      mb_fileType:       e.malwarebazaar?.fileType || "",
      mb_signer:         cs ? [cs.subject && `Subject: ${cs.subject}`, cs.issuer && `Issuer: ${cs.issuer}`, cs.algorithm].filter(Boolean).join(" | ") : "",
      // OTX
      otx_pulses:        e.otx?.pulses ?? "",
      otx_tags:          e.otx?.tags || "",
      otx_validation:    e.otx?.validation || "",
      // AbuseIPDB
      abuse_score:       e.abuseipdb?.score != null ? `${e.abuseipdb.score}%` : "",
      abuse_reports:     e.abuseipdb?.reports ?? "",
      abuse_categories:  e.abuseipdb?.categories || "",
      abuse_last:        e.abuseipdb?.lastReported || "",
      // GEO / ASN
      country:           e.whoisASN?.country || e.otx?.country || "",
      city:              e.whoisASN?.city || "",
      asn:               e.whoisASN?.asn ? `${e.whoisASN.asn}${e.whoisASN.asnOrg ? ` ${e.whoisASN.asnOrg}` : ""}` : "",
      // URLScan
      urlscan_scans:     e.urlscan?.scans ?? "",
      urlscan_malicious: e.urlscan?.malicious ?? "",
      urlscan_title:     e.urlscan?.title || "",
      urlscan_server:    e.urlscan?.server || "",
      urlscan_tls:       e.urlscan?.tlsIssuer ? `${e.urlscan.tlsIssuer}${e.urlscan.tlsAgeDays != null ? ` (${smartAge(e.urlscan.tlsAgeDays)} old)` : ""}` : "",
      urlscan_brands:    e.urlscan?.brands?.join(", ") || "",
      // Shodan
      shodan_ports:      e.shodan?.ports?.join(", ") || "",
      shodan_cves:       e.shodan?.vulns?.join(", ") || "",
      shodan_tags:       e.shodan?.tags?.join(", ") || "",
      shodan_cpes:       e.shodan?.cpes?.join(", ") || "",
      // Kaspersky
      kaspersky:         e.kaspersky ? [
        `${e.kaspersky.zone?.charAt(0).toUpperCase() + e.kaspersky.zone?.slice(1)} Zone`,
        e.kaspersky.country || null,
        e.kaspersky.fileStatus || null,
        e.kaspersky.detections || null,
        e.kaspersky.categories || null,
        e.kaspersky.hits != null ? `${e.kaspersky.hits} hits` : null,
      ].filter(Boolean).join(" · ") : "",
      // CIRCL
      circl:             e.circl ? [
        e.circl.legit ? "Known Legitimate" : "CIRCL Known",
        e.circl.trust != null ? `Trust ${e.circl.trust}/100` : null,
        e.circl.parentTotal != null ? `Found in ${e.circl.parentTotal} packages` : null,
        e.circl.fileName || null,
        e.circl.productName || null,
        e.circl.packageVersion || null,
        e.circl.maintainer || null,
        e.circl.os || null,
        e.circl.mimetype || null,
        e.circl.source || null,
      ].filter(Boolean).join(" · ") : "",
      // Tri.age
      triage_score:      e.triage?.score ?? "",
      triage_family:     e.triage?.families?.join(", ") || "",
      triage_tags:       e.triage?.tags?.join(", ") || "",
      triage_c2:         e.triage?.c2Urls?.join(", ") || "",
      triage_url:        e.triage?.triageUrl || "",
      // Hybrid Analysis
      ha_verdict:        e.hybridAnalysis?.verdict || "",
      ha_score:          e.hybridAnalysis?.threatScore != null ? `${e.hybridAnalysis.threatScore}/100` : "",
      ha_family:         e.hybridAnalysis?.family || e.hybridAnalysis?.families || "",
      ha_av:             e.hybridAnalysis?.avDetect ? `${e.hybridAnalysis.avDetect}%` : "",
      ha_tags:           e.hybridAnalysis?.tags || "",
      ha_mitre:          e.hybridAnalysis?.mitreAttacks?.join(", ") || "",
      ha_url:            e.hybridAnalysis?.reportUrl || "",
      ha_downloaded:     e.hybridAnalysis?.submitContext?.join(" | ") || "",
      // Domain registration
      domain_age:        e.domainReg?.ageDays != null ? smartAge(e.domainReg.ageDays) : "",
      domain_registered: e.domainReg?.registered || "",
      domain_status:     e.domainReg?.status || "",
      // SANS ISC / DShield
      sansisc_attacks:   e.sansIsc?.attacks ?? "",
      sansisc_feeds:     e.sansIsc?.threatFeeds?.join(", ") || "",
      // CVE — CISA KEV / EPSS / NVD
      cisa_kev:          e.cisaKev ? (e.cisaKev.listed ? `Actively Exploited${e.cisaKev.dateAdded ? ` (added ${e.cisaKev.dateAdded})` : ""}` : "Not listed") : "",
      epss_score:        e.epss?.score != null ? `${e.epss.score}%` : "",
      nvd_cvss:          e.nvd?.cvss != null ? `${e.nvd.cvss}${e.nvd.severity ? ` (${e.nvd.severity})` : ""}` : "",
      nvd_description:   e.nvd?.description || "",
      // Timeline
      first_seen:        e._timeline?.firstSeen || "",
      last_seen:         e._timeline?.lastSeen || "",
    };
  };

  const ENRICH_HEADERS = [
    "Verdict",
    // ThreatFox
    "ThreatFox Malware","ThreatFox Threat","ThreatFox Confidence","ThreatFox Tags",
    // URLhaus
    "URLhaus",
    // MalwareBazaar
    "MB Family","MB Detections","MB FileName","MB FileType","MB Signer",
    // OTX
    "OTX Pulses","OTX Tags","OTX Validation",
    // AbuseIPDB
    "AbuseIPDB Score","AbuseIPDB Reports","AbuseIPDB Categories","AbuseIPDB Last Reported",
    // GEO / ASN
    "Country","City","ASN",
    // URLScan
    "URLScan Scans","URLScan Malicious","URLScan Title","URLScan Server","URLScan TLS","URLScan Brands",
    // Shodan
    "Shodan Ports","Shodan CVEs","Shodan Tags","Shodan CPEs",
    // Kaspersky
    "Kaspersky",
    // CIRCL
    "CIRCL",
    // Tri.age
    "Triage Score","Triage Family","Triage Tags","Triage C2","Triage URL",
    // Hybrid Analysis
    "HA Verdict","HA Score","HA Family","HA AV","HA Tags","HA MITRE","HA URL","HA Downloaded From",
    // Domain
    "Domain Age","Domain Registered","Domain Status",
    // SANS ISC / DShield
    "SANS ISC Attacks","SANS ISC Threat Feeds",
    // CVE — CISA KEV / EPSS / NVD
    "CISA KEV","EPSS Score","NVD CVSS","NVD Description",
    // Timeline
    "First Seen","Last Seen",
  ];

  const enrichVals = (r) => ENRICH_HEADERS.map((h) => {
    const keyMap = {
      "Verdict": r.verdict,
      "ThreatFox Malware": r.tf_malware, "ThreatFox Threat": r.tf_threat,
      "ThreatFox Confidence": r.tf_confidence, "ThreatFox Tags": r.tf_tags,
      "URLhaus": r.urlhaus,
      "MB Family": r.mb_family, "MB Detections": r.mb_detections,
      "MB FileName": r.mb_fileName, "MB FileType": r.mb_fileType, "MB Signer": r.mb_signer,
      "OTX Pulses": r.otx_pulses, "OTX Tags": r.otx_tags, "OTX Validation": r.otx_validation,
      "AbuseIPDB Score": r.abuse_score, "AbuseIPDB Reports": r.abuse_reports,
      "AbuseIPDB Categories": r.abuse_categories, "AbuseIPDB Last Reported": r.abuse_last,
      "Country": r.country, "City": r.city, "ASN": r.asn,
      "URLScan Scans": r.urlscan_scans, "URLScan Malicious": r.urlscan_malicious,
      "URLScan Title": r.urlscan_title, "URLScan Server": r.urlscan_server,
      "URLScan TLS": r.urlscan_tls, "URLScan Brands": r.urlscan_brands,
      "Shodan Ports": r.shodan_ports, "Shodan CVEs": r.shodan_cves,
      "Shodan Tags": r.shodan_tags, "Shodan CPEs": r.shodan_cpes,
      "Kaspersky": r.kaspersky, "CIRCL": r.circl,
      "Triage Score": r.triage_score, "Triage Family": r.triage_family,
      "Triage Tags": r.triage_tags, "Triage C2": r.triage_c2, "Triage URL": r.triage_url,
      "HA Verdict": r.ha_verdict, "HA Score": r.ha_score, "HA Family": r.ha_family,
      "HA AV": r.ha_av, "HA Tags": r.ha_tags, "HA MITRE": r.ha_mitre, "HA URL": r.ha_url, "HA Downloaded From": r.ha_downloaded,
      "Domain Age": r.domain_age, "Domain Registered": r.domain_registered,
      "Domain Status": r.domain_status,
      "SANS ISC Attacks": r.sansisc_attacks, "SANS ISC Threat Feeds": r.sansisc_feeds,
      "CISA KEV": r.cisa_kev, "EPSS Score": r.epss_score,
      "NVD CVSS": r.nvd_cvss, "NVD Description": r.nvd_description,
      "First Seen": r.first_seen, "Last Seen": r.last_seen,
    };
    return keyMap[h] ?? "";
  });

  const exportAllCSV = () => {
    const rows = [["Type", "IOC", ...ENRICH_HEADERS]];
    entries.forEach(([cat, arr]) => {
      const shown = proc(arr, cat);
      arr.forEach((orig, i) => rows.push([cat, shown[i], ...enrichVals(enrichRow(cat, orig))]));
    });
    downloadBlob(new Blob([toCSV(rows)], { type: "text/csv;charset=utf-8" }), "all_iocs.csv");
  };
  const exportAllXLSX = () => {
    const all = [["Type", "IOC", ...ENRICH_HEADERS]];
    entries.forEach(([cat, arr]) => {
      const shown = proc(arr, cat);
      arr.forEach((orig, i) => all.push([cat, shown[i], ...enrichVals(enrichRow(cat, orig))]));
    });
    const sheets = [{ name: "All_IOCs", rows: all }];
    entries.forEach(([cat, arr]) => {
      const shown = proc(arr, cat);
      sheets.push({ name: cat, rows: [["IOC", ...ENRICH_HEADERS], ...arr.map((orig, i) => [shown[i], ...enrichVals(enrichRow(cat, orig))])] });
    });
    downloadBlob(buildWorkbook(sheets), "all_iocs.xlsx");
  };
  // ============================================================
  // Report Builder — HTML / Markdown / Print-to-PDF
  // Presets: Full, Executive, Technical IOC, MITRE ATT&CK, Hunting Playbook
  // v98: section reordering, IOC/query filters, CQL, glossary, graph SVG,
  //      dark/light variant, expanded enrichment labels
  // v99: click-to-scroll section navigation, print respects dark/light variant
  // v100: Sigma hunt-query format; CVE enrichment (CISA KEV/EPSS/NVD); SANS ISC/DShield for IPV4/IPV6
  // v101: analytics moved fully server-side (session_id piggybacked on existing /fetch,/parse,/enrich
  //       requests; removed the one client-initiated /log call) — see worker.js for the dashboard side
  // ============================================================
  const genReportId = () => {
    const d = new Date();
    const yy = String(d.getFullYear()).slice(-2);
    const mm = String(d.getMonth() + 1).padStart(2, "0");
    const dd = String(d.getDate()).padStart(2, "0");
    const rand = Math.floor(Math.random() * 9000 + 1000);
    return `IE-${yy}${mm}${dd}-${rand}`;
  };
  const [reportId] = useState(() => genReportId());
  const [reportGeneratedAt] = useState(() => new Date());

  // Aggregate report data from current on-screen state (respects IOC-type filter)
  const buildReportData = () => {
    const rid = reportRefNum || reportId;
    const generatedAt = reportGeneratedAt;
    const verdictCounts = { Malicious: 0, Suspicious: 0, Whitelisted: 0, Unknown: 0 };
    const typeCounts = {};
    const allTechniques = new Set();
    const allFamilies = new Set();
    const c2Nodes = new Set();
    const contactedHosts = new Set();
    // Respect IOC-type filter for what enters the report
    const filteredEntries = entries.filter(([cat]) => reportIocTypes[cat] !== false);

    filteredEntries.forEach(([cat, arr]) => {
      typeCounts[cat] = arr.length;
      arr.forEach((v) => {
        const d = enrichCache[`${cat}::${v}`]?.data;
        if (!d) { verdictCounts.Unknown++; return; }
        const vd = d._verdict || "Unknown";
        if (verdictCounts[vd] != null) verdictCounts[vd]++;
        else verdictCounts.Unknown++;
        (d.hybridAnalysis?.mitreAttacks || []).forEach(t => allTechniques.add(t));
        (d.triage?.tags || []).forEach(t => { if (t.startsWith("attack.")) allTechniques.add(t.replace("attack.", "").toUpperCase()); });
        if (d.hybridAnalysis?.family) allFamilies.add(d.hybridAnalysis.family);
        if (d.triage?.families) d.triage.families.forEach(f => allFamilies.add(f));
        if (d.malwarebazaar?.signature) allFamilies.add(d.malwarebazaar.signature);
        (d.hybridAnalysis?.compromised || []).forEach(h => c2Nodes.add(h));
        (d.triage?.c2Urls || []).forEach(c => c2Nodes.add(c));
        (d.hybridAnalysis?.hosts || []).forEach(h => contactedHosts.add(h));
        (d.hybridAnalysis?.domains || []).forEach(h => contactedHosts.add(h));
      });
    });
    return {
      reportId: rid,
      generatedAt,
      analyst: reportAnalyst || "—",
      org: reportOrg || "—",
      tlp: reportTLP,
      watermark: reportWatermark,
      sourceUrl: sourceUrl || null,
      articleHeadline: aiSummary?.headline || null,
      execSummary: aiSummary?.executive_summary || null,
      techSummary: aiSummary?.summary || null,
      recommendations: aiSummary?.recommendations || [],
      aiSummaryPending: aiState === "loading" && !aiSummary,
      totalIOCs: filteredEntries.reduce((s, [, arr]) => s + arr.length, 0),
      typeCounts,
      verdictCounts,
      techniques: [...allTechniques].sort(),
      families: [...allFamilies].sort(),
      c2Nodes: [...c2Nodes],
      contactedHosts: [...contactedHosts],
      entries: filteredEntries,
      enrichCache,
      mergedHashes,
    };
  };

  // MITRE ATT&CK tactic → technique mapping (subset — most common)
  const MITRE_TACTICS = [
    { id: "TA0001", name: "Initial Access", techniques: ["T1078","T1133","T1189","T1190","T1195","T1199","T1200","T1566"] },
    { id: "TA0002", name: "Execution", techniques: ["T1053","T1059","T1072","T1106","T1129","T1203","T1204","T1559","T1569","T1610"] },
    { id: "TA0003", name: "Persistence", techniques: ["T1053","T1078","T1098","T1136","T1176","T1197","T1505","T1543","T1546","T1547"] },
    { id: "TA0004", name: "Privilege Escalation", techniques: ["T1053","T1055","T1068","T1078","T1134","T1484","T1543","T1546","T1547","T1548"] },
    { id: "TA0005", name: "Defense Evasion", techniques: ["T1027","T1036","T1055","T1070","T1078","T1112","T1140","T1197","T1218","T1553","T1562"] },
    { id: "TA0006", name: "Credential Access", techniques: ["T1003","T1040","T1056","T1110","T1187","T1212","T1552","T1555","T1556","T1558"] },
    { id: "TA0007", name: "Discovery", techniques: ["T1007","T1010","T1012","T1016","T1018","T1033","T1046","T1049","T1057","T1082","T1083","T1087"] },
    { id: "TA0008", name: "Lateral Movement", techniques: ["T1021","T1091","T1210","T1534","T1550","T1563","T1570"] },
    { id: "TA0009", name: "Collection", techniques: ["T1005","T1039","T1056","T1074","T1113","T1114","T1115","T1119","T1213","T1560"] },
    { id: "TA0011", name: "Command and Control", techniques: ["T1071","T1090","T1092","T1095","T1102","T1104","T1105","T1132","T1568","T1571","T1572","T1573"] },
    { id: "TA0010", name: "Exfiltration", techniques: ["T1011","T1020","T1029","T1030","T1041","T1048","T1052","T1567"] },
    { id: "TA0040", name: "Impact", techniques: ["T1485","T1486","T1489","T1490","T1491","T1495","T1496","T1498","T1499","T1529","T1561"] },
  ];

  const inlineLogoSVG = `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M12 2 L3 5 L3 11 C3 16.5 6.5 20.7 12 22 C17.5 20.7 21 16.5 21 11 L21 5 Z" stroke="#00e5ff" stroke-width="1.5" fill="rgba(0,229,255,0.08)"/><path d="M9 12 L11 14 L15 10" stroke="#00ff9c" stroke-width="1.5" fill="none" stroke-linecap="round" stroke-linejoin="round"/></svg>`;

  const escapeHtml = (s) => String(s == null ? "" : s).replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

  // Expanded enrichment labels — human-readable instead of compressed
  const kaspZoneLabel = (z) => {
    const zl = String(z || "").toLowerCase();
    if (zl === "red") return "Kaspersky: Red (Malicious)";
    if (zl === "yellow") return "Kaspersky: Yellow (Suspicious)";
    if (zl === "green") return "Kaspersky: Green (Clean)";
    if (zl === "grey" || zl === "gray") return "Kaspersky: Grey (Unknown)";
    return `Kaspersky: ${zl}`;
  };
  const buildSourcesLabel = (d) => {
    const parts = [];
    if (d?.cisaKev?.listed) parts.push(`CISA KEV: Actively Exploited${d.cisaKev.dateAdded ? ` (added ${d.cisaKev.dateAdded})` : ""}`);
    if (d?.epss?.score != null) parts.push(`EPSS: ${d.epss.score}% (30-day exploitation probability)`);
    if (d?.nvd?.cvss != null) parts.push(`NVD: CVSS ${d.nvd.cvss}${d.nvd.severity ? ` ${d.nvd.severity}` : ""}`);
    if (d?.virustotal?.malicious != null) parts.push(`VirusTotal: ${d.virustotal.malicious}/${d.virustotal.total || "—"} detections`);
    if (d?.kaspersky?.zone) parts.push(kaspZoneLabel(d.kaspersky.zone));
    if (d?.abuseipdb?.abuseScore != null) parts.push(`AbuseIPDB: ${d.abuseipdb.abuseScore}% abuse score`);
    if (d?.sansIsc?.attacks) parts.push(`SANS ISC: ${d.sansIsc.attacks} attack${d.sansIsc.attacks !== 1 ? "s" : ""} reported`);
    if (d?.threatfox?.malwareName) parts.push(`ThreatFox: ${d.threatfox.malwareName}`);
    if (d?.urlhaus?.threat) parts.push(`URLhaus: ${d.urlhaus.threat}`);
    if (d?.malwarebazaar?.signature) parts.push(`MalwareBazaar: ${d.malwarebazaar.signature}`);
    if (d?.otx?.pulseCount) parts.push(`OTX: ${d.otx.pulseCount} pulse${d.otx.pulseCount !== 1 ? "s" : ""}`);
    if (d?.hybridAnalysis?.verdict) {
      const parts2 = [`Hybrid Analysis: ${d.hybridAnalysis.verdict}`];
      if (d.hybridAnalysis.threatScore != null) parts2.push(`score ${d.hybridAnalysis.threatScore}/100`);
      if (d.hybridAnalysis.family) parts2.push(`family: ${d.hybridAnalysis.family}`);
      parts.push(parts2.join(", "));
    }
    if (d?.triage?.families?.[0]) parts.push(`Tri.age: ${d.triage.families[0]}${d.triage.score != null ? ` (score ${d.triage.score}/10)` : ""}`);
    if (d?.urlscan?.overallMalicious) parts.push(`urlscan: malicious verdict`);
    return parts.slice(0, 4).join(" · ") || "—";
  };

  // Radial SVG rendering of shared-pivot (bridge) nodes.
  // Only shows nodes where 2+ primary IOCs connect through them.
  const buildSharedPivotSVG = (data) => {
    // Reconstruct primary IOCs and derived-node connections
    const primaries = new Map(); // norm(id) → { cat, val, id }
    data.entries.forEach(([cat, arr]) => {
      arr.forEach(v => primaries.set(String(v).toLowerCase(), { cat, val: v, id: v }));
    });
    // Bridge candidates: derived nodes reached by ≥2 primaries
    const bridgeCount = new Map(); // pivotVal → Set(primaryIds)
    const pivotCat = new Map();    // pivotVal → cat
    data.entries.forEach(([cat, arr]) => {
      arr.forEach(v => {
        const d = data.enrichCache[`${cat}::${v}`]?.data;
        if (!d) return;
        const trackPivot = (pv, pc) => {
          if (!pv || primaries.has(String(pv).toLowerCase())) {
            // If pv is itself a primary, this is a bridge between two primaries too
            const key = String(pv).toLowerCase();
            if (!bridgeCount.has(key)) bridgeCount.set(key, new Set());
            bridgeCount.get(key).add(String(v).toLowerCase());
            if (!pivotCat.has(key)) pivotCat.set(key, pc);
            return;
          }
          const key = String(pv).toLowerCase();
          if (!bridgeCount.has(key)) bridgeCount.set(key, new Set());
          bridgeCount.get(key).add(String(v).toLowerCase());
          if (!pivotCat.has(key)) pivotCat.set(key, pc);
        };
        if (d.urlscan?.servingIP) trackPivot(d.urlscan.servingIP, ipCat(d.urlscan.servingIP));
        (d.urlscan?.contactedIPs || []).forEach(ip => trackPivot(ip, ipCat(ip)));
        (d.urlscan?.contactedDomains || []).forEach(dm => trackPivot(dm, "DOMAIN"));
        (d.urlscan?.files || []).forEach(f => { if (f.sha256) trackPivot(f.sha256, "SHA256"); });
        (d.hybridAnalysis?.hosts || []).forEach(h => trackPivot(h, ipCat(h)));
        (d.hybridAnalysis?.domains || []).forEach(dm => trackPivot(dm, "DOMAIN"));
        (d.hybridAnalysis?.compromised || []).forEach(h => {
          const isIP = isIPv4(h) || h.includes(":");
          trackPivot(h, isIP ? ipCat(h) : "DOMAIN");
        });
        (d.hybridAnalysis?.submitContext || []).forEach(sc => trackPivot(sc, "URL"));
        (d.hybridAnalysis?.relatedSHA256s || []).forEach(sh => trackPivot(sh, "SHA256"));
        (d.triage?.c2Urls || []).forEach(c2 => {
          if (typeof c2 !== "string") return;
          if (c2.startsWith("domain:")) trackPivot(c2.slice(7), "DOMAIN");
          else if (c2.startsWith("ip:")) trackPivot(c2.slice(3), ipCat(c2.slice(3)));
          else trackPivot(c2, "URL");
        });
      });
    });
    // Keep only true bridges: reached by ≥2 distinct primaries
    const bridges = [...bridgeCount.entries()]
      .filter(([, srcSet]) => srcSet.size >= 2)
      .map(([pivotVal, srcSet]) => ({
        pivotVal,
        cat: pivotCat.get(pivotVal),
        sources: [...srcSet].map(id => primaries.get(id)).filter(Boolean),
      }));

    if (bridges.length === 0) return null;

    // Radial layout
    const W = 800, H = 600, cx = W / 2, cy = H / 2;
    const nBridges = bridges.length;
    const bridgeRingR = Math.min(120, 40 + nBridges * 12);
    // Collect all unique primaries touching any bridge
    const primarySet = new Set();
    bridges.forEach(b => b.sources.forEach(s => primarySet.add(String(s.val).toLowerCase())));
    const primariesArr = [...primarySet].map(id => primaries.get(id)).filter(Boolean);
    const nPrimaries = primariesArr.length;
    const primaryRingR = Math.max(230, bridgeRingR + 180);

    // Position bridges in inner ring, primaries in outer ring
    const bridgePos = new Map();
    bridges.forEach((b, i) => {
      const angle = (i / nBridges) * 2 * Math.PI - Math.PI / 2;
      bridgePos.set(b.pivotVal, { x: cx + Math.cos(angle) * bridgeRingR, y: cy + Math.sin(angle) * bridgeRingR, angle });
    });
    const primaryPos = new Map();
    primariesArr.forEach((p, i) => {
      const angle = (i / nPrimaries) * 2 * Math.PI - Math.PI / 2;
      primaryPos.set(String(p.val).toLowerCase(), { x: cx + Math.cos(angle) * primaryRingR, y: cy + Math.sin(angle) * primaryRingR, angle, cat: p.cat, val: p.val });
    });

    // Edges
    let edges = "";
    bridges.forEach(b => {
      const bp = bridgePos.get(b.pivotVal);
      b.sources.forEach(s => {
        const pp = primaryPos.get(String(s.val).toLowerCase());
        if (!pp) return;
        edges += `<line x1="${bp.x}" y1="${bp.y}" x2="${pp.x}" y2="${pp.y}" stroke="#ffb84d" stroke-width="1.5" stroke-opacity="0.5" />`;
      });
    });

    // Label placement — outside the node, oriented away from center
    const labelOffset = 12;
    const nodeR = 8;
    const bridgeNodeR = 10;
    // Truncate long values with ellipsis for readability
    const truncLabel = (v, max = 46) => v.length > max ? v.slice(0, max - 1) + "…" : v;

    // Bridge nodes (gold, larger)
    let bridgeNodes = "";
    bridges.forEach(b => {
      const bp = bridgePos.get(b.pivotVal);
      const labelX = bp.x + Math.cos(bp.angle) * (bridgeNodeR + labelOffset);
      const labelY = bp.y + Math.sin(bp.angle) * (bridgeNodeR + labelOffset);
      const anchor = Math.cos(bp.angle) > 0.1 ? "start" : Math.cos(bp.angle) < -0.1 ? "end" : "middle";
      bridgeNodes += `
        <circle cx="${bp.x}" cy="${bp.y}" r="${bridgeNodeR + 3}" fill="none" stroke="#ffb84d" stroke-opacity="0.35" stroke-width="1.5"/>
        <circle cx="${bp.x}" cy="${bp.y}" r="${bridgeNodeR}" fill="#ffb84d" stroke="#04111a" stroke-width="1.5"/>
        <text x="${labelX}" y="${labelY}" fill="#ffcf70" font-size="10" font-family="monospace" font-weight="600" text-anchor="${anchor}" dominant-baseline="middle">${escapeHtml(truncLabel(b.pivotVal))}</text>
        <text x="${labelX}" y="${labelY + 12}" fill="#7f95a3" font-size="8" font-family="monospace" text-anchor="${anchor}" dominant-baseline="middle">${b.cat} · ${b.sources.length} shared</text>
      `;
    });

    // Primary nodes (colored by cat)
    let primaryNodes = "";
    primariesArr.forEach(p => {
      const pp = primaryPos.get(String(p.val).toLowerCase());
      const cc = colorFor(p.cat);
      const labelX = pp.x + Math.cos(pp.angle) * (nodeR + labelOffset);
      const labelY = pp.y + Math.sin(pp.angle) * (nodeR + labelOffset);
      const anchor = Math.cos(pp.angle) > 0.1 ? "start" : Math.cos(pp.angle) < -0.1 ? "end" : "middle";
      primaryNodes += `
        <circle cx="${pp.x}" cy="${pp.y}" r="${nodeR}" fill="${cc}" stroke="#04111a" stroke-width="1.5"/>
        <text x="${labelX}" y="${labelY}" fill="${cc}" font-size="10" font-family="monospace" font-weight="600" text-anchor="${anchor}" dominant-baseline="middle">${escapeHtml(truncLabel(String(p.val)))}</text>
        <text x="${labelX}" y="${labelY + 12}" fill="#7f95a3" font-size="8" font-family="monospace" text-anchor="${anchor}" dominant-baseline="middle">${p.cat}</text>
      `;
    });

    return `
      <svg viewBox="0 0 ${W} ${H}" xmlns="http://www.w3.org/2000/svg" style="width:100%;max-width:820px;height:auto;background:rgba(10,14,20,0.5);border:1px solid rgba(120,160,180,0.15);border-radius:10px;">
        ${edges}
        ${primaryNodes}
        ${bridgeNodes}
      </svg>
    `;
  };

  // Generate the full HTML report (styled, printable). variant: "dark" | "light"
  const generateReportHTML = (variant = "dark") => {
    const data = buildReportData();
    const enabledSections = reportSections.filter(s => s.enabled).map(s => s.id);
    const tlpColors = { WHITE: "#ffffff", GREEN: "#00ff9c", AMBER: "#ffb84d", RED: "#ff4d6d" };
    const tlpBgs = { WHITE: "rgba(255,255,255,0.1)", GREEN: "rgba(0,255,156,0.1)", AMBER: "rgba(255,184,77,0.1)", RED: "rgba(255,77,109,0.12)" };
    const tlpColor = tlpColors[data.tlp] || "#ffb84d";
    const tlpBg = tlpBgs[data.tlp] || "rgba(255,184,77,0.1)";
    const dateStr = data.generatedAt.toLocaleString("en-US", { year: "numeric", month: "short", day: "2-digit", hour: "2-digit", minute: "2-digit" });

    // Section generators
    const sec = {};

    sec.cover = `
      <section class="page cover">
        <div class="tlp-ribbon" style="background:${tlpBg};border-color:${tlpColor};color:${tlpColor};">TLP:${data.tlp}</div>
        <div class="cover-content">
          <div class="cover-badge">
            <span class="cover-badge-icon">${inlineLogoSVG}</span>
            <span class="cover-badge-label">INTEL EXTRACTOR</span>
          </div>
          <h1 class="cover-title">Threat Intelligence<br/>Report</h1>
          <div class="cover-subtitle">${escapeHtml(data.articleHeadline || "Enrichment Analysis")}</div>
          <div class="cover-stats">
            <div class="cover-stat"><div class="stat-num" style="color:#00ff9c;">${data.totalIOCs}</div><div class="stat-label">INDICATORS</div></div>
            <div class="cover-stat"><div class="stat-num" style="color:#00e5ff;">${data.entries.length}</div><div class="stat-label">TYPES</div></div>
            <div class="cover-stat"><div class="stat-num" style="color:#ff4d6d;">${data.verdictCounts.Malicious}</div><div class="stat-label">MALICIOUS</div></div>
            <div class="cover-stat"><div class="stat-num" style="color:#fbbf24;">${data.verdictCounts.Suspicious}</div><div class="stat-label">SUSPICIOUS</div></div>
          </div>
          <div class="cover-meta">
            <div class="meta-row"><span class="meta-label">Report ID</span><span class="meta-val">${escapeHtml(data.reportId)}</span></div>
            <div class="meta-row"><span class="meta-label">Prepared By</span><span class="meta-val">${escapeHtml(data.analyst)}</span></div>
            <div class="meta-row"><span class="meta-label">Organization</span><span class="meta-val">${escapeHtml(data.org)}</span></div>
            <div class="meta-row"><span class="meta-label">Generated</span><span class="meta-val">${dateStr}</span></div>
            ${data.sourceUrl ? `<div class="meta-row"><span class="meta-label">Source</span><span class="meta-val meta-source">${escapeHtml(data.sourceUrl)}</span></div>` : ""}
          </div>
        </div>
        <div class="cover-footer">
          <span>Generated with Intel Extractor · ${APP_VERSION}</span>
          <span>aamir-muhammad.github.io/Intel-Extractor</span>
        </div>
      </section>
    `;

    sec.exec = `
      <section class="page">
        <div class="section-header">
          <div class="section-title">Executive Summary</div>
          <div class="section-badge">FOR LEADERSHIP</div>
        </div>
        ${data.articleHeadline ? `<div class="callout callout-primary"><div class="callout-label">THREAT HEADLINE</div><div class="callout-body">${escapeHtml(data.articleHeadline)}</div></div>` : ""}
        ${data.execSummary ? `<div class="prose"><h3>Business Impact</h3><p>${escapeHtml(data.execSummary)}</p></div>` : ""}
        ${data.aiSummaryPending ? `<div class="prose"><p><em>Generating AI summary…</em></p></div>` : ""}
        <div class="verdict-grid">
          <div class="verdict-card verdict-mal">
            <div class="verdict-num">${data.verdictCounts.Malicious}</div>
            <div class="verdict-label">MALICIOUS</div>
            <div class="verdict-desc">Confirmed threats requiring immediate blocking</div>
          </div>
          <div class="verdict-card verdict-susp">
            <div class="verdict-num">${data.verdictCounts.Suspicious}</div>
            <div class="verdict-label">SUSPICIOUS</div>
            <div class="verdict-desc">Requires investigation and monitoring</div>
          </div>
          <div class="verdict-card verdict-clean">
            <div class="verdict-num">${data.verdictCounts.Whitelisted}</div>
            <div class="verdict-label">CLEAN</div>
            <div class="verdict-desc">Verified benign, false positive candidates</div>
          </div>
          <div class="verdict-card verdict-unk">
            <div class="verdict-num">${data.verdictCounts.Unknown}</div>
            <div class="verdict-label">UNKNOWN</div>
            <div class="verdict-desc">Insufficient telemetry, additional research advised</div>
          </div>
        </div>
        ${data.families.length ? `<div class="prose"><h3>Malware Families Identified</h3><div class="chip-row">${data.families.slice(0, 12).map(f => `<span class="chip chip-mal">${escapeHtml(f)}</span>`).join("")}</div></div>` : ""}
        ${data.recommendations.length ? `<div class="prose"><h3>Priority Actions</h3><ol class="action-list">${data.recommendations.slice(0, 3).map(r => `<li>${escapeHtml(r)}</li>`).join("")}</ol></div>` : ""}
        <div class="prose"><h3>Bottom Line</h3><p>${data.verdictCounts.Malicious > 0 ? `<strong>Action required.</strong> This analysis identified ${data.verdictCounts.Malicious} confirmed malicious indicator${data.verdictCounts.Malicious !== 1 ? "s" : ""}. Recommend immediate deployment to blocklists, review of endpoint telemetry for the past 30 days, and threat hunting using the queries in the Hunting Playbook.` : data.verdictCounts.Suspicious > 0 ? `<strong>Investigation recommended.</strong> ${data.verdictCounts.Suspicious} suspicious indicator${data.verdictCounts.Suspicious !== 1 ? "s were" : " was"} identified. Deploy to watchlists and correlate with endpoint activity.` : `No confirmed threats identified in this dataset. Standard hygiene applies.`}</p></div>
      </section>
    `;

    // Technical IOC Report
    const iocTables = data.entries.map(([cat, arr]) => {
      const rows = arr.map(v => {
        const d = data.enrichCache[`${cat}::${v}`]?.data;
        const verdict = d?._verdict || "Unknown";
        const vClass = verdict === "Malicious" ? "vmal" : verdict === "Suspicious" ? "vsusp" : verdict === "Whitelisted" ? "vclean" : "vunk";
        const source = buildSourcesLabel(d);
        return `<tr>
          <td class="ioc-val">${escapeHtml(v)}</td>
          <td><span class="verdict-pill ${vClass}">${verdict}</span></td>
          <td class="sources">${escapeHtml(source)}</td>
        </tr>`;
      }).join("");
      return `
        <div class="ioc-block">
          <div class="ioc-block-header">
            <span class="type-chip" style="color:${colorFor(cat)};background:${colorFor(cat)}18;border-color:${colorFor(cat)}55;">${cat}</span>
            <span class="type-count">${arr.length}</span>
          </div>
          <table class="ioc-table">
            <thead><tr><th>Indicator</th><th>Verdict</th><th>Enrichment Sources</th></tr></thead>
            <tbody>${rows}</tbody>
          </table>
        </div>
      `;
    }).join("");

    sec.technical = `
      <section class="page">
        <div class="section-header">
          <div class="section-title">Technical IOC Report</div>
          <div class="section-badge">FOR SOC</div>
        </div>
        ${data.techSummary ? `<div class="prose"><h3>Technical Summary</h3><p>${escapeHtml(data.techSummary)}</p></div>` : ""}
        <div class="prose"><h3>Indicators of Compromise (${data.totalIOCs})</h3></div>
        ${iocTables || `<div class="empty-state">No IOCs match current filter.</div>`}
      </section>
    `;

    // MITRE
    const observed = new Set(data.techniques.map(t => t.split(".")[0]));
    const mitreGrid = MITRE_TACTICS.map(tac => {
      const cells = tac.techniques.map(tid => {
        const obs = observed.has(tid);
        return `<div class="mitre-cell ${obs ? "mitre-obs" : ""}" title="${tid}${obs ? " — observed" : ""}">${tid}</div>`;
      }).join("");
      return `
        <div class="mitre-col">
          <div class="mitre-col-header">${tac.name}<br/><span class="mitre-tid">${tac.id}</span></div>
          ${cells}
        </div>
      `;
    }).join("");

    const observedList = data.techniques.length ? data.techniques.map(t => `
      <div class="tech-row">
        <span class="tech-id">${escapeHtml(t)}</span>
        <span class="tech-tactic">${MITRE_TACTICS.find(tc => tc.techniques.includes(t.split(".")[0]))?.name || "—"}</span>
      </div>
    `).join("") : `<div class="empty-state">No MITRE ATT&CK techniques identified from enrichment data.</div>`;

    sec.mitre = `
      <section class="page">
        <div class="section-header">
          <div class="section-title">MITRE ATT&amp;CK Mapping</div>
          <div class="section-badge">FOR THREAT ANALYSTS</div>
        </div>
        <div class="prose"><p>Techniques observed across all enriched indicators. Highlighted cells indicate techniques attributed to this campaign by enrichment sources (Hybrid Analysis, Tri.age behavioral analysis).</p></div>
        <div class="mitre-heatmap">${mitreGrid}</div>
        <div class="mitre-legend">
          <span class="legend-item"><span class="legend-swatch legend-obs"></span> Observed technique</span>
          <span class="legend-item"><span class="legend-swatch legend-none"></span> Not observed in this dataset</span>
        </div>
        <div class="prose"><h3>Observed Techniques (${data.techniques.length})</h3></div>
        <div class="tech-list">${observedList}</div>
      </section>
    `;

    // Hunting Playbook — respects query language filter
    const huntBlocks = data.entries.filter(([cat]) => ["IPV4","IPV6","DOMAIN","URL","MD5","SHA1","SHA256","FILE_NAME","FILE_PATH","EMAIL","CVE"].includes(cat)).map(([cat, arr]) => {
      const kql = reportQueryLangs.kql ? huntKQL(cat, arr) : null;
      const spl = reportQueryLangs.spl ? huntSPL(cat, arr) : null;
      const aql = reportQueryLangs.aql ? huntAQL(cat, arr) : null;
      const cql = reportQueryLangs.cql ? huntCQL(cat, arr) : null;
      const sigma = reportQueryLangs.sigma ? huntSigma(cat, arr, data.sourceUrl) : null;
      if (!kql && !spl && !aql && !cql && !sigma) return "";
      return `
        <div class="hunt-block">
          <div class="hunt-block-header">
            <span class="type-chip" style="color:${colorFor(cat)};background:${colorFor(cat)}18;border-color:${colorFor(cat)}55;">${cat}</span>
            <span class="hunt-count">${arr.length} IOC${arr.length !== 1 ? "s" : ""}</span>
          </div>
          ${kql ? `<div class="hunt-query"><div class="hunt-lang">Microsoft Sentinel · Defender XDR (KQL)</div><pre>${escapeHtml(kql)}</pre></div>` : ""}
          ${spl ? `<div class="hunt-query"><div class="hunt-lang">Splunk (SPL)</div><pre>${escapeHtml(spl)}</pre></div>` : ""}
          ${aql ? `<div class="hunt-query"><div class="hunt-lang">IBM QRadar (AQL)</div><pre>${escapeHtml(aql)}</pre></div>` : ""}
          ${cql ? `<div class="hunt-query"><div class="hunt-lang">CrowdStrike Falcon (CQL)</div><pre>${escapeHtml(cql)}</pre></div>` : ""}
          ${sigma ? `<div class="hunt-query"><div class="hunt-lang">Sigma (Generic / SIEM-agnostic)</div><pre>${escapeHtml(sigma)}</pre></div>` : ""}
        </div>
      `;
    }).filter(Boolean).join("");

    const anyLang = reportQueryLangs.kql || reportQueryLangs.spl || reportQueryLangs.aql || reportQueryLangs.cql || reportQueryLangs.sigma;
    sec.hunting = `
      <section class="page">
        <div class="section-header">
          <div class="section-title">Hunting Playbook</div>
          <div class="section-badge">FOR THREAT HUNTERS</div>
        </div>
        <div class="prose"><p>Copy-paste hunt queries for the leading SIEM and EDR platforms. Recommended lookback: 30 days for infrastructure IOCs, 7 days for host-based artifacts.</p></div>
        ${!anyLang ? `<div class="empty-state">No query languages selected. Enable KQL / SPL / AQL / CQL / Sigma in the Content tab.</div>` : (huntBlocks || `<div class="empty-state">No huntable IOCs in this dataset.</div>`)}
        ${data.c2Nodes.length ? `
          <div class="prose"><h3>Command &amp; Control Infrastructure</h3><p>Confirmed C2 endpoints identified by behavioral analysis. Prioritize network blocking and hunt for outbound connections to these hosts.</p></div>
          <div class="chip-row">${data.c2Nodes.slice(0, 20).map(c => `<span class="chip chip-mal">${escapeHtml(c)}</span>`).join("")}</div>
        ` : ""}
      </section>
    `;

    // Shared-Pivot Graph
    const graphSVG = buildSharedPivotSVG(data);
    sec.graph = graphSVG ? `
      <section class="page">
        <div class="section-header">
          <div class="section-title">Shared-Pivot Infrastructure Graph</div>
          <div class="section-badge">INFRASTRUCTURE</div>
        </div>
        <div class="prose"><p>Nodes shown are <strong>shared pivots</strong> — infrastructure elements that connect two or more primary IOCs. Gold nodes at the center are bridge points; colored nodes at the outer ring are the primary IOCs from this analysis. This view isolates the relationships that likely indicate a coordinated campaign.</p></div>
        <div style="text-align:center;margin:20px 0;">${graphSVG}</div>
        <div class="mitre-legend">
          <span class="legend-item"><span class="legend-swatch" style="background:#ffb84d;border-color:#ffb84d;"></span> Shared-pivot bridge (2+ IOCs)</span>
          <span class="legend-item"><span class="legend-swatch" style="background:#00e5ff;border-color:#00e5ff;"></span> Primary IOC</span>
        </div>
      </section>
    ` : `
      <section class="page">
        <div class="section-header">
          <div class="section-title">Shared-Pivot Infrastructure Graph</div>
          <div class="section-badge">INFRASTRUCTURE</div>
        </div>
        <div class="empty-state">No shared-pivot infrastructure detected. Bridge nodes require 2+ primary IOCs to connect through the same derived infrastructure element.</div>
      </section>
    `;

    // Consolidation
    sec.consolidation = Object.keys(data.mergedHashes).length ? `
      <section class="page">
        <div class="section-header">
          <div class="section-title">Hash Consolidation</div>
          <div class="section-badge">APPENDIX</div>
        </div>
        <div class="prose"><p>${Object.values(data.mergedHashes).reduce((s, m) => s + m.removed.length, 0)} weak hashes (MD5/SHA1) were consolidated into their canonical SHA256 identifiers during analysis.</p></div>
        ${Object.entries(data.mergedHashes).map(([sha256, m]) => `
          <div class="consol-block">
            <div class="consol-target"><span class="consol-label">SHA256</span><span class="consol-val">${escapeHtml(sha256)}</span></div>
            ${m.removed.map(r => `<div class="consol-source"><span class="consol-label">${r.cat}</span><span class="consol-val">${escapeHtml(r.value)}</span><span class="consol-tag ${r.manual ? "consol-manual" : "consol-auto"}">${r.manual ? "Manually converted" : "Auto-deduplicated"}</span></div>`).join("")}
          </div>
        `).join("")}
      </section>
    ` : "";

    // Glossary — explains every enrichment source and shorthand
    sec.glossary = `
      <section class="page">
        <div class="section-header">
          <div class="section-title">Glossary &amp; Source Reference</div>
          <div class="section-badge">REFERENCE</div>
        </div>
        <div class="prose"><p>This report aggregates verdicts and metadata from multiple threat-intelligence sources. Below is an explanation of each source and its verdict scheme.</p></div>
        <div class="glossary-grid">
          <div class="glossary-item">
            <div class="glossary-name">Kaspersky Security Network (KSN)</div>
            <div class="glossary-body">Kaspersky's cloud reputation database. Verdict zones: <strong style="color:#ff4d6d">Red</strong> = confirmed malicious, <strong style="color:#fbbf24">Yellow</strong> = suspicious / adware / PUA, <strong style="color:#00ff9c">Green</strong> = clean / whitelisted, <strong style="color:#8aa0ad">Grey</strong> = unknown.</div>
          </div>
          <div class="glossary-item">
            <div class="glossary-name">VirusTotal</div>
            <div class="glossary-body">Aggregated AV scanning. Displayed as X/Y where X is engines flagging the file/URL as malicious and Y is total engines. 10+ detections typically indicates confirmed malware.</div>
          </div>
          <div class="glossary-item">
            <div class="glossary-name">AbuseIPDB</div>
            <div class="glossary-body">Community-reported IP abuse. Confidence score 0–100%. ≥75% = confirmed abuse; 25–74% = suspicious; &lt;25% = low signal.</div>
          </div>
          <div class="glossary-item">
            <div class="glossary-name">Hybrid Analysis (Falcon Sandbox)</div>
            <div class="glossary-body">CrowdStrike-owned behavioral sandbox. Verdicts: <strong>Malicious</strong>, <strong>Suspicious</strong>, <strong>Whitelisted</strong>, <strong>No specific threat</strong>. Threat score 0–100 (higher = more malicious). Includes MITRE ATT&amp;CK mappings.</div>
          </div>
          <div class="glossary-item">
            <div class="glossary-name">Tri.age (Recorded Future Sandbox)</div>
            <div class="glossary-body">Behavioral sandbox with family attribution. Score 0–10 (10 = confirmed malicious, 5–9 = suspicious). Extracts C2 URLs from runtime analysis.</div>
          </div>
          <div class="glossary-item">
            <div class="glossary-name">abuse.ch ThreatFox / URLhaus / MalwareBazaar</div>
            <div class="glossary-body">Community-driven threat feeds. ThreatFox = IOC database, URLhaus = malicious URLs (payload delivery), MalwareBazaar = malware sample repository with family signatures.</div>
          </div>
          <div class="glossary-item">
            <div class="glossary-name">AlienVault OTX</div>
            <div class="glossary-body">Open Threat Exchange. Pulse count indicates how many threat-intel reports reference this IOC — higher = more widely observed.</div>
          </div>
          <div class="glossary-item">
            <div class="glossary-name">urlscan.io</div>
            <div class="glossary-body">Website scanner. Provides serving IP, contacted infrastructure, screenshots, and brand-impersonation detection for URLs and domains.</div>
          </div>
          <div class="glossary-item">
            <div class="glossary-name">CISA KEV (Known Exploited Vulnerabilities)</div>
            <div class="glossary-body">U.S. government catalog of CVEs with <strong>confirmed</strong> active exploitation in the wild. A KEV listing is treated as a Malicious verdict — this is the strongest exploitation signal available for a CVE.</div>
          </div>
          <div class="glossary-item">
            <div class="glossary-name">EPSS (Exploit Prediction Scoring System)</div>
            <div class="glossary-body">FIRST.org's probability (0–100%) that a CVE will be exploited in the next 30 days. A prediction, not a confirmation — scores ≥50% are treated as Suspicious.</div>
          </div>
          <div class="glossary-item">
            <div class="glossary-name">NVD (National Vulnerability Database)</div>
            <div class="glossary-body">NIST's CVSS severity score and vulnerability description. Shown as context only — severity alone (without a KEV listing or high EPSS score) does not drive the verdict, since a severe CVE with no exploitation signal isn't yet a confirmed or predicted threat.</div>
          </div>
          <div class="glossary-item">
            <div class="glossary-name">SANS ISC / DShield</div>
            <div class="glossary-body">Crowd-sourced firewall/IDS log submissions aggregated by the SANS Internet Storm Center. "Attacks" is a raw count of distinct reporters, not a normalized score — kept to a Suspicious ceiling in verdicts, same restraint as AbuseIPDB's mid-range tier.</div>
          </div>
          <div class="glossary-item">
            <div class="glossary-name">TLP (Traffic Light Protocol)</div>
            <div class="glossary-body"><strong style="color:#ffffff">WHITE</strong> = unrestricted, <strong style="color:#00ff9c">GREEN</strong> = community, <strong style="color:#ffb84d">AMBER</strong> = need-to-know within organization, <strong style="color:#ff4d6d">RED</strong> = named recipients only.</div>
          </div>
          <div class="glossary-item">
            <div class="glossary-name">Verdict Classifications</div>
            <div class="glossary-body"><strong style="color:#ff4d6d">Malicious</strong> = confirmed threat, block/hunt immediately. <strong style="color:#fbbf24">Suspicious</strong> = warrants investigation. <strong style="color:#00ff9c">Whitelisted</strong> = confirmed benign. <strong style="color:#8aa0ad">Unknown</strong> = insufficient telemetry.</div>
          </div>
        </div>
      </section>
    `;

    // Build in section order per reportSections — wrapped with an id anchor
    // so the builder UI can scroll the live preview to a specific section.
    const orderedSections = reportSections
      .filter(s => s.enabled && sec[s.id])
      .map(s => `<div id="section-${s.id}">${sec[s.id]}</div>`)
      .join("");

    // Styles — variant-aware. Light variant flips core color vars.
    const isLight = variant === "light";
    const rootVars = isLight ? `
      --bg: #ffffff;
      --bg-page: #ffffff;
      --panel: #ffffff;
      --line: #d0d7de;
      --txt: #1a1f26;
      --txt-strong: #05070a;
      --txt-muted: #57636f;
      --txt-dim: #7a8794;
      --cyan: #0088a8;
      --green: #008040;
      --purple: #7c3aed;
      --mal: #d63348;
      --susp: #b78015;
      --clean: #008040;
      --unk: #6b7580;
    ` : `
      --bg: #05070a;
      --bg-page: #080b12;
      --panel: rgba(10,14,20,0.72);
      --line: rgba(120,160,180,0.16);
      --txt: #e6f0f3;
      --txt-strong: #eafcff;
      --txt-muted: #7f95a3;
      --txt-dim: #5d7382;
      --cyan: #00e5ff;
      --green: #00ff9c;
      --purple: #c084fc;
      --mal: #ff4d6d;
      --susp: #fbbf24;
      --clean: #00ff9c;
      --unk: #8aa0ad;
    `;

    return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Intel Extractor Report · ${escapeHtml(data.reportId)}</title>
<style>
  :root { ${rootVars} }
  * { box-sizing: border-box; }
  html, body { margin: 0; padding: 0; background: var(--bg); color: var(--txt); font-family: ui-monospace, "SF Mono", Menlo, Consolas, monospace; font-size: 12px; line-height: 1.55; }
  body { max-width: 900px; margin: 0 auto; padding: 24px; }
  .page {
    background: var(--bg-page);
    border: 1px solid var(--line);
    border-radius: 14px;
    padding: 40px 44px;
    margin-bottom: 22px;
    position: relative;
    overflow: hidden;
  }
  ${!isLight ? `.page::before {
    content: "";
    position: absolute; inset: 0;
    background:
      radial-gradient(600px 300px at 90% -5%, rgba(0,229,255,0.08), transparent 60%),
      linear-gradient(rgba(255,255,255,0.015) 1px, transparent 1px),
      linear-gradient(90deg, rgba(255,255,255,0.015) 1px, transparent 1px);
    background-size: auto, 36px 36px, 36px 36px;
    pointer-events: none;
  }` : ""}
  .page > * { position: relative; z-index: 1; }
  ${data.watermark ? `.page::after { content: "${escapeHtml(data.watermark)}"; position: absolute; inset: 0; display: flex; align-items: center; justify-content: center; font-size: 90px; font-weight: 900; color: rgba(255,77,109,0.06); letter-spacing: 8px; pointer-events: none; z-index: 0; transform: rotate(-30deg); white-space: nowrap; }` : ""}

  .tlp-ribbon {
    position: absolute; top: 0; right: 0;
    padding: 6px 16px;
    font-size: 10px; font-weight: 900; letter-spacing: 3px;
    border-left: 1px solid; border-bottom: 1px solid;
    border-bottom-left-radius: 10px;
    z-index: 2;
  }

  .cover { min-height: 800px; display: flex; flex-direction: column; }
  .cover-content { flex: 1; display: flex; flex-direction: column; justify-content: center; }
  .cover-badge {
    display: inline-flex; align-items: center; gap: 10px;
    padding: 8px 14px;
    background: ${isLight ? "#f6faff" : "rgba(0,229,255,0.08)"}; border: 1px solid ${isLight ? "#c0dcea" : "rgba(0,229,255,0.35)"};
    border-radius: 10px;
    font-size: 11px; font-weight: 700; letter-spacing: 3px;
    color: var(--cyan);
    width: fit-content;
    margin-bottom: 32px;
    ${!isLight ? "box-shadow: 0 0 22px rgba(0,229,255,0.15);" : ""}
  }
  .cover-badge-icon { display: inline-flex; }
  .cover-title {
    font-size: 56px; font-weight: 800; letter-spacing: -1.5px; line-height: 1.05;
    color: var(--txt-strong);
    ${!isLight ? "text-shadow: 0 0 40px rgba(0,229,255,0.25);" : ""}
    margin: 0 0 20px;
  }
  .cover-subtitle {
    font-size: 15px; font-weight: 500; color: var(--txt-muted);
    border-left: 3px solid var(--cyan);
    padding-left: 14px;
    margin-bottom: 40px;
    line-height: 1.5;
  }
  .cover-stats { display: grid; grid-template-columns: repeat(4, 1fr); gap: 14px; margin-bottom: 40px; }
  .cover-stat {
    background: ${isLight ? "#f6f8fa" : "rgba(10,14,20,0.5)"};
    border: 1px solid var(--line);
    border-radius: 12px;
    padding: 20px 16px;
    text-align: center;
  }
  .stat-num { font-size: 40px; font-weight: 800; letter-spacing: -1px; line-height: 1; }
  .stat-label { font-size: 9px; font-weight: 700; letter-spacing: 2px; color: var(--txt-dim); margin-top: 8px; }
  .cover-meta {
    background: ${isLight ? "#f6f8fa" : "rgba(10,14,20,0.4)"};
    border: 1px solid var(--line);
    border-radius: 12px;
    padding: 18px 20px;
  }
  .meta-row { display: flex; padding: 6px 0; border-bottom: 1px dashed ${isLight ? "#d0d7de" : "rgba(120,160,180,0.1)"}; font-size: 11px; }
  .meta-row:last-child { border-bottom: none; }
  .meta-label { width: 130px; color: var(--txt-dim); font-size: 10px; text-transform: uppercase; letter-spacing: 1.5px; font-weight: 700; }
  .meta-val { color: var(--txt); flex: 1; word-break: break-all; }
  .meta-source { color: var(--cyan); }
  .cover-footer {
    display: flex; justify-content: space-between; align-items: center;
    padding-top: 24px; margin-top: 30px;
    border-top: 1px solid var(--line);
    font-size: 10px; color: var(--txt-dim); letter-spacing: 1px;
  }

  .section-header {
    display: flex; align-items: center; justify-content: space-between;
    padding-bottom: 14px; margin-bottom: 24px;
    border-bottom: 2px solid ${isLight ? "#0088a833" : "rgba(0,229,255,0.2)"};
    position: relative;
  }
  .section-header::before {
    content: ""; position: absolute; bottom: -2px; left: 0; width: 60px; height: 2px;
    background: linear-gradient(90deg, var(--cyan), transparent);
    ${!isLight ? "box-shadow: 0 0 12px var(--cyan);" : ""}
  }
  .section-title { font-size: 22px; font-weight: 800; color: var(--txt-strong); letter-spacing: -0.5px; }
  .section-badge {
    padding: 5px 12px;
    background: ${isLight ? "#f4efff" : "rgba(192,132,252,0.1)"}; border: 1px solid ${isLight ? "#d8c5f7" : "rgba(192,132,252,0.35)"};
    border-radius: 20px;
    font-size: 9px; font-weight: 800; letter-spacing: 2px;
    color: var(--purple);
  }

  .prose { margin-bottom: 20px; }
  .prose h3 {
    font-size: 13px; text-transform: uppercase; letter-spacing: 2px;
    color: var(--cyan); font-weight: 800;
    margin: 22px 0 12px;
    padding-left: 10px; border-left: 3px solid var(--cyan);
  }
  .prose p { font-size: 12px; line-height: 1.65; color: var(--txt); margin: 0 0 12px; }
  .prose strong { color: var(--txt-strong); font-weight: 700; }

  .callout {
    padding: 16px 20px; margin-bottom: 20px;
    border-radius: 10px;
    background: ${isLight ? "#f0faff" : "rgba(0,229,255,0.05)"};
    border: 1px solid ${isLight ? "#b5dfec" : "rgba(0,229,255,0.25)"};
    border-left: 4px solid var(--cyan);
  }
  .callout-label { font-size: 9px; font-weight: 800; letter-spacing: 2px; color: var(--cyan); margin-bottom: 6px; }
  .callout-body { font-size: 15px; font-weight: 700; color: var(--txt-strong); line-height: 1.4; }

  .verdict-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin: 20px 0; }
  .verdict-card {
    padding: 18px 14px;
    background: ${isLight ? "#f6f8fa" : "rgba(10,14,20,0.5)"};
    border: 1px solid var(--line);
    border-radius: 10px;
  }
  .verdict-num { font-size: 32px; font-weight: 800; letter-spacing: -1px; line-height: 1; }
  .verdict-label { font-size: 9px; font-weight: 800; letter-spacing: 2px; margin-top: 6px; }
  .verdict-desc { font-size: 10px; color: var(--txt-dim); margin-top: 8px; line-height: 1.4; }
  .verdict-mal { border-color: ${isLight ? "#f0b5be" : "rgba(255,77,109,0.4)"}; }
  .verdict-mal .verdict-num, .verdict-mal .verdict-label { color: var(--mal); }
  .verdict-susp { border-color: ${isLight ? "#e5cf82" : "rgba(251,191,36,0.4)"}; }
  .verdict-susp .verdict-num, .verdict-susp .verdict-label { color: var(--susp); }
  .verdict-clean { border-color: ${isLight ? "#a3d9b5" : "rgba(0,255,156,0.4)"}; }
  .verdict-clean .verdict-num, .verdict-clean .verdict-label { color: var(--clean); }
  .verdict-unk { border-color: var(--line); }
  .verdict-unk .verdict-num, .verdict-unk .verdict-label { color: var(--unk); }

  .chip-row { display: flex; flex-wrap: wrap; gap: 6px; margin-top: 8px; }
  .chip { padding: 4px 10px; border-radius: 20px; font-size: 10px; font-weight: 600; border: 1px solid; }
  .chip-mal { color: var(--mal); background: ${isLight ? "#fff0f2" : "rgba(255,77,109,0.08)"}; border-color: ${isLight ? "#f0b5be" : "rgba(255,77,109,0.3)"}; }

  .action-list { padding-left: 18px; margin: 0; }
  .action-list li { font-size: 12px; line-height: 1.65; color: var(--txt); margin-bottom: 8px; }
  .action-list li::marker { color: var(--cyan); font-weight: 800; }

  .ioc-block { margin-bottom: 24px; }
  .ioc-block-header { display: flex; align-items: center; gap: 10px; margin-bottom: 8px; }
  .type-chip { padding: 4px 10px; border-radius: 6px; font-size: 10px; font-weight: 800; letter-spacing: 1.5px; border: 1px solid; }
  .type-count {
    font-size: 11px; font-weight: 700; color: var(--txt-muted);
    padding: 3px 10px;
    background: ${isLight ? "#f6f8fa" : "rgba(255,255,255,0.04)"};
    border-radius: 20px;
  }
  .ioc-table { width: 100%; border-collapse: collapse; margin-top: 4px; }
  .ioc-table th {
    text-align: left; padding: 8px 10px;
    font-size: 9px; font-weight: 800; letter-spacing: 1.5px; color: var(--txt-dim);
    border-bottom: 1px solid var(--line); text-transform: uppercase;
  }
  .ioc-table td {
    padding: 7px 10px; font-size: 11px;
    border-bottom: 1px solid ${isLight ? "#e6ebf0" : "rgba(120,160,180,0.06)"};
    vertical-align: middle;
  }
  .ioc-val { color: var(--cyan); word-break: break-all; font-weight: 500; }
  .sources { color: var(--txt-muted); font-size: 10px; }
  .verdict-pill { padding: 2px 8px; border-radius: 12px; font-size: 9px; font-weight: 800; letter-spacing: 1px; border: 1px solid; white-space: nowrap; }
  .vmal { color: var(--mal); background: ${isLight ? "#fff0f2" : "rgba(255,77,109,0.1)"}; border-color: ${isLight ? "#f0b5be" : "rgba(255,77,109,0.35)"}; }
  .vsusp { color: var(--susp); background: ${isLight ? "#fff8e5" : "rgba(251,191,36,0.1)"}; border-color: ${isLight ? "#e5cf82" : "rgba(251,191,36,0.35)"}; }
  .vclean { color: var(--clean); background: ${isLight ? "#eaf7ee" : "rgba(0,255,156,0.1)"}; border-color: ${isLight ? "#a3d9b5" : "rgba(0,255,156,0.35)"}; }
  .vunk { color: var(--unk); background: ${isLight ? "#f6f8fa" : "rgba(120,160,180,0.08)"}; border-color: var(--line); }

  .mitre-heatmap { display: grid; grid-template-columns: repeat(6, 1fr); gap: 10px; margin: 20px 0; }
  .mitre-col {
    background: ${isLight ? "#f6f8fa" : "rgba(10,14,20,0.4)"};
    border: 1px solid var(--line);
    border-radius: 8px;
    padding: 10px 6px;
    display: flex; flex-direction: column; gap: 4px;
  }
  .mitre-col-header {
    font-size: 9px; font-weight: 800; letter-spacing: 1px;
    color: var(--txt-strong);
    padding-bottom: 8px; margin-bottom: 4px;
    border-bottom: 1px solid var(--line);
    text-align: center; line-height: 1.3;
  }
  .mitre-tid { font-size: 8px; color: var(--txt-dim); font-weight: 500; letter-spacing: 0.5px; }
  .mitre-cell {
    padding: 5px 4px; border-radius: 4px;
    font-size: 8.5px; text-align: center;
    background: ${isLight ? "#ffffff" : "rgba(10,14,20,0.4)"};
    color: var(--txt-dim);
    border: 1px solid ${isLight ? "#d0d7de" : "rgba(120,160,180,0.1)"};
    font-weight: 600;
  }
  .mitre-obs {
    background: ${isLight ? "#cff5fb" : "rgba(0,229,255,0.15)"};
    color: ${isLight ? "#005566" : "var(--cyan)"};
    border-color: var(--cyan);
    ${!isLight ? "box-shadow: 0 0 8px rgba(0,229,255,0.3);" : ""}
    font-weight: 800;
  }
  .mitre-legend { display: flex; gap: 20px; margin: 12px 0 24px; font-size: 10px; color: var(--txt-muted); }
  .legend-item { display: flex; align-items: center; gap: 8px; }
  .legend-swatch { width: 16px; height: 16px; border-radius: 3px; border: 1px solid; }
  .legend-obs { background: ${isLight ? "#cff5fb" : "rgba(0,229,255,0.15)"}; border-color: var(--cyan); ${!isLight ? "box-shadow: 0 0 6px rgba(0,229,255,0.3);" : ""} }
  .legend-none { background: ${isLight ? "#ffffff" : "rgba(10,14,20,0.4)"}; border-color: ${isLight ? "#d0d7de" : "rgba(120,160,180,0.1)"}; }

  .tech-list { display: flex; flex-direction: column; gap: 6px; margin-top: 12px; }
  .tech-row {
    display: flex; align-items: center; gap: 14px;
    padding: 8px 12px;
    background: ${isLight ? "#f6f8fa" : "rgba(10,14,20,0.4)"};
    border: 1px solid var(--line);
    border-radius: 6px;
  }
  .tech-id { font-family: ui-monospace, Menlo, monospace; font-size: 11px; color: var(--cyan); font-weight: 700; min-width: 100px; }
  .tech-tactic { font-size: 10px; color: var(--txt-muted); text-transform: uppercase; letter-spacing: 1px; }

  .hunt-block {
    margin-bottom: 22px; padding: 14px;
    background: ${isLight ? "#f6f8fa" : "rgba(10,14,20,0.4)"};
    border: 1px solid var(--line);
    border-radius: 10px;
  }
  .hunt-block-header { display: flex; align-items: center; gap: 10px; margin-bottom: 10px; }
  .hunt-count { font-size: 10px; color: var(--txt-muted); }
  .hunt-query { margin-top: 10px; }
  .hunt-lang {
    font-size: 9px; font-weight: 800; letter-spacing: 2px; color: var(--purple);
    margin-bottom: 4px; text-transform: uppercase;
  }
  .hunt-query pre {
    background: ${isLight ? "#eef4f8" : "rgba(0,0,0,0.55)"};
    border: 1px solid ${isLight ? "#c8d5df" : "rgba(0,229,255,0.15)"};
    border-left: 3px solid var(--cyan);
    border-radius: 6px;
    padding: 10px 12px; margin: 0;
    font-size: 10.5px; line-height: 1.55;
    color: ${isLight ? "#0e2f3f" : "#b8e5ee"};
    white-space: pre-wrap; word-break: break-word;
    overflow-x: auto;
  }

  .consol-block {
    padding: 12px 14px; margin-bottom: 10px;
    background: ${isLight ? "#f2f4ff" : "rgba(124,156,255,0.05)"};
    border: 1px solid ${isLight ? "#c5d0ff" : "rgba(124,156,255,0.2)"};
    border-radius: 8px;
  }
  .consol-target { display: flex; align-items: center; gap: 10px; margin-bottom: 6px; }
  .consol-source { display: flex; align-items: center; gap: 10px; margin-left: 20px; padding: 3px 0; }
  .consol-label { font-size: 9px; font-weight: 800; letter-spacing: 1.5px; color: var(--txt-dim); min-width: 60px; }
  .consol-val { font-family: ui-monospace, Menlo, monospace; font-size: 10px; color: ${isLight ? "#7c3aed" : "#c084fc"}; flex: 1; word-break: break-all; }
  .consol-target .consol-val { color: ${isLight ? "#3b5cb8" : "#7c9cff"}; font-weight: 600; }
  .consol-tag { font-size: 8.5px; font-weight: 700; padding: 2px 8px; border-radius: 10px; border: 1px solid; }
  .consol-auto { color: ${isLight ? "#3b5cb8" : "#7c9cff"}; background: ${isLight ? "#f0f3ff" : "rgba(124,156,255,0.1)"}; border-color: ${isLight ? "#c5d0ff" : "rgba(124,156,255,0.25)"}; }
  .consol-manual { color: var(--mal); background: ${isLight ? "#fff0f2" : "rgba(255,77,109,0.1)"}; border-color: ${isLight ? "#f0b5be" : "rgba(255,77,109,0.3)"}; }

  .glossary-grid { display: grid; grid-template-columns: repeat(2, 1fr); gap: 14px; margin-top: 16px; }
  .glossary-item {
    padding: 14px 16px;
    background: ${isLight ? "#f6f8fa" : "rgba(10,14,20,0.4)"};
    border: 1px solid var(--line);
    border-radius: 8px;
    border-left: 3px solid var(--purple);
  }
  .glossary-name { font-size: 12px; font-weight: 800; color: var(--txt-strong); margin-bottom: 6px; letter-spacing: -0.2px; }
  .glossary-body { font-size: 11px; color: var(--txt-muted); line-height: 1.55; }

  .empty-state {
    padding: 24px;
    background: ${isLight ? "#f6f8fa" : "rgba(10,14,20,0.3)"};
    border: 1px dashed var(--line);
    border-radius: 8px;
    text-align: center;
    color: var(--txt-dim);
    font-size: 11px;
  }

  @media print {
    /* Force the browser to actually print background colors — otherwise
       both variants (and especially dark) print with backgrounds stripped. */
    * { -webkit-print-color-adjust: exact !important; print-color-adjust: exact !important; color-adjust: exact !important; }
    ${isLight ? `
    :root {
      --bg: #ffffff; --bg-page: #ffffff; --panel: #ffffff;
      --line: #d0d7de;
      --txt: #1a1f26; --txt-strong: #05070a;
      --txt-muted: #57636f; --txt-dim: #7a8794;
      --cyan: #0088a8; --green: #008040; --purple: #7c3aed;
    }` : ""}
    html, body { background: var(--bg); color: var(--txt); }
    body { padding: 0; max-width: none; }
    .page {
      background: var(--bg-page);
      border: ${isLight ? "none" : "1px solid var(--line)"};
      border-radius: 0;
      padding: 24px 32px; margin-bottom: 0;
      page-break-after: always;
    }
    .page:last-child { page-break-after: auto; }
    ${isLight ? `.page::before { display: none; }` : ""}
    .cover { min-height: auto; }
    .cover-title { ${isLight ? "color: #05070a; text-shadow: none;" : ""} font-size: 42px; }
    ${isLight ? `
    .cover-stat, .cover-meta { background: #f6f8fa; }
    .hunt-query pre { background: #f6f8fa; color: #1a1f26; border-color: #d0d7de; border-left-color: #0088a8; }
    .mitre-col, .verdict-card, .tech-row, .consol-block, .callout, .glossary-item { background: #f6f8fa; }
    .mitre-cell { background: #ffffff; color: #57636f; border-color: #d0d7de; }
    .mitre-obs { background: #cff5fb; color: #005566; border-color: #0088a8; box-shadow: none; }
    ` : ""}
    .section-header::before { box-shadow: none; }
    @page {
      margin: 20mm 15mm 25mm 15mm;
      @bottom-center {
        content: "Intel Extractor Report · ${escapeHtml(data.reportId)} · Page " counter(page) " of " counter(pages);
        font-family: monospace; font-size: 9px; color: #7a8794;
      }
    }
  }
</style>
</head>
<body>
  ${orderedSections}
</body>
</html>`;
  };

  // Markdown export — respects section toggles and query filters
  const generateReportMarkdown = () => {
    const data = buildReportData();
    const enabledSections = new Set(reportSections.filter(s => s.enabled).map(s => s.id));
    const dateStr = data.generatedAt.toISOString().split("T")[0];
    let md = "";

    if (enabledSections.has("cover")) {
      md += `# Threat Intelligence Report\n\n`;
      md += `**TLP:${data.tlp}** · **Report ID:** ${data.reportId} · **Generated:** ${dateStr}\n\n`;
      md += `**Analyst:** ${data.analyst} · **Organization:** ${data.org}\n\n`;
      if (data.sourceUrl) md += `**Source:** ${data.sourceUrl}\n\n`;
      md += `---\n\n`;
    }

    if (enabledSections.has("exec")) {
      md += `## Executive Summary\n\n`;
      if (data.articleHeadline) md += `> **${data.articleHeadline}**\n\n`;
      if (data.execSummary) md += `${data.execSummary}\n\n`;
      if (data.aiSummaryPending) md += `*Generating AI summary…*\n\n`;
      md += `### Verdict Breakdown\n\n`;
      md += `| Verdict | Count |\n|---|---|\n`;
      md += `| Malicious | ${data.verdictCounts.Malicious} |\n`;
      md += `| Suspicious | ${data.verdictCounts.Suspicious} |\n`;
      md += `| Whitelisted | ${data.verdictCounts.Whitelisted} |\n`;
      md += `| Unknown | ${data.verdictCounts.Unknown} |\n\n`;
      if (data.families.length) md += `### Malware Families\n\n${data.families.map(f => `- ${f}`).join("\n")}\n\n`;
      if (data.recommendations.length) {
        md += `### Priority Actions\n\n`;
        data.recommendations.forEach((r, i) => { md += `${i + 1}. ${r}\n`; });
        md += `\n`;
      }
    }

    if (enabledSections.has("technical")) {
      md += `## Technical IOC Report\n\n`;
      if (data.techSummary) md += `${data.techSummary}\n\n`;
      data.entries.forEach(([cat, arr]) => {
        md += `### ${cat} (${arr.length})\n\n`;
        md += `| Indicator | Verdict | Enrichment |\n|---|---|---|\n`;
        arr.forEach(v => {
          const d = enrichCache[`${cat}::${v}`]?.data;
          md += `| \`${v}\` | ${d?._verdict || "Unknown"} | ${buildSourcesLabel(d)} |\n`;
        });
        md += `\n`;
      });
    }

    if (enabledSections.has("mitre") && data.techniques.length) {
      md += `## MITRE ATT&CK Techniques\n\n`;
      data.techniques.forEach(t => { md += `- **${t}** — ${MITRE_TACTICS.find(tc => tc.techniques.includes(t.split(".")[0]))?.name || "—"}\n`; });
      md += `\n`;
    }

    if (enabledSections.has("hunting")) {
      md += `## Hunting Playbook\n\n`;
      data.entries.filter(([cat]) => ["IPV4","IPV6","DOMAIN","URL","MD5","SHA1","SHA256","FILE_NAME","FILE_PATH","EMAIL","CVE"].includes(cat)).forEach(([cat, arr]) => {
        const kql = reportQueryLangs.kql ? huntKQL(cat, arr) : null;
        const spl = reportQueryLangs.spl ? huntSPL(cat, arr) : null;
        const aql = reportQueryLangs.aql ? huntAQL(cat, arr) : null;
        const cql = reportQueryLangs.cql ? huntCQL(cat, arr) : null;
        const sigma = reportQueryLangs.sigma ? huntSigma(cat, arr, data.sourceUrl) : null;
        if (!kql && !spl && !aql && !cql && !sigma) return;
        md += `### ${cat}\n\n`;
        if (kql) md += `**Sentinel / Defender XDR (KQL)**\n\n\`\`\`kql\n${kql}\n\`\`\`\n\n`;
        if (spl) md += `**Splunk (SPL)**\n\n\`\`\`spl\n${spl}\n\`\`\`\n\n`;
        if (aql) md += `**QRadar (AQL)**\n\n\`\`\`sql\n${aql}\n\`\`\`\n\n`;
        if (cql) md += `**CrowdStrike Falcon (CQL)**\n\n\`\`\`\n${cql}\n\`\`\`\n\n`;
        if (sigma) md += `**Sigma (Generic / SIEM-agnostic)**\n\n\`\`\`yaml\n${sigma}\n\`\`\`\n\n`;
      });
    }

    if (enabledSections.has("consolidation") && Object.keys(data.mergedHashes).length) {
      md += `## Hash Consolidation\n\n`;
      Object.entries(data.mergedHashes).forEach(([sha256, m]) => {
        md += `**SHA256:** \`${sha256}\`\n\n`;
        m.removed.forEach(r => {
          md += `- **${r.cat}:** \`${r.value}\` — ${r.manual ? "Manually converted" : "Auto-deduplicated"}\n`;
        });
        md += `\n`;
      });
    }

    if (enabledSections.has("glossary")) {
      md += `## Glossary & Source Reference\n\n`;
      md += `- **Kaspersky KSN:** Red = malicious, Yellow = suspicious, Green = clean, Grey = unknown\n`;
      md += `- **VirusTotal:** X/Y detections (engines flagging / total engines)\n`;
      md += `- **AbuseIPDB:** 0–100% confidence score\n`;
      md += `- **Hybrid Analysis:** Falcon Sandbox verdict + threat score 0–100\n`;
      md += `- **Tri.age:** Behavioral score 0–10\n`;
      md += `- **abuse.ch:** ThreatFox / URLhaus / MalwareBazaar community feeds\n`;
      md += `- **OTX:** Pulse count from AlienVault Open Threat Exchange\n`;
      md += `- **CISA KEV:** Confirmed active exploitation in the wild — treated as Malicious\n`;
      md += `- **EPSS:** 0–100% predicted probability of exploitation in the next 30 days\n`;
      md += `- **NVD:** CVSS severity score + description — context only, doesn't drive verdict\n`;
      md += `- **SANS ISC / DShield:** Crowd-sourced attack report count — capped at Suspicious\n`;
      md += `- **TLP:** WHITE = unrestricted, GREEN = community, AMBER = internal, RED = named recipients\n\n`;
    }

    md += `---\n\n_Generated with Intel Extractor ${APP_VERSION} · https://aamir-muhammad.github.io/Intel-Extractor_\n`;
    return md;
  };

  const downloadReport = (fmt) => {
    localStorage.setItem("ie_analyst", reportAnalyst);
    localStorage.setItem("ie_org", reportOrg);
    if (fmt === "html") {
      const html = generateReportHTML(reportVariant);
      const suffix = reportVariant === "light" ? "_light" : "";
      downloadBlob(new Blob([html], { type: "text/html;charset=utf-8" }), `intel-extractor-report_${reportId}${suffix}.html`);
    } else if (fmt === "md") {
      const md = generateReportMarkdown();
      downloadBlob(new Blob([md], { type: "text/markdown;charset=utf-8" }), `intel-extractor-report_${reportId}.md`);
    } else if (fmt === "copy-md") {
      const md = generateReportMarkdown();
      copyText(md, "report-md");
    } else if (fmt === "print") {
      // Print respects the selected variant (dark/light) like the other exports
      const html = generateReportHTML(reportVariant);
      const w = window.open("", "_blank");
      w.document.write(html);
      w.document.close();
      setTimeout(() => w.print(), 500);
    }
  };


  const exportTypeCSV = (cat, arr) => {
    const shown = proc(arr, cat);
    const rows = [["Type", "IOC", ...ENRICH_HEADERS], ...arr.map((orig, i) => [cat, shown[i], ...enrichVals(enrichRow(cat, orig))])];
    downloadBlob(new Blob([toCSV(rows)], { type: "text/csv;charset=utf-8" }), `${cat.toLowerCase()}_iocs.csv`);
  };
  const exportTypeXLSX = (cat, arr) => {
    const shown = proc(arr, cat);
    const rows = [["IOC", ...ENRICH_HEADERS], ...arr.map((orig, i) => [shown[i], ...enrichVals(enrichRow(cat, orig))])];
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
      {/* Report Builder Modal */}
      {reportOpen && (
        <div style={{
          position: "fixed", inset: 0, zIndex: 10000,
          background: "rgba(0,0,0,0.75)", backdropFilter: "blur(8px)",
          display: "flex", alignItems: "center", justifyContent: "center",
          padding: "20px",
        }} onClick={(e) => { if (e.target === e.currentTarget) setReportOpen(false); }}>
          <div style={{
            background: "#080b12", border: "1px solid rgba(0,229,255,0.3)", borderRadius: 16,
            width: "100%", maxWidth: 1280, maxHeight: "92vh",
            display: "flex", flexDirection: "column",
            boxShadow: "0 0 60px rgba(0,229,255,0.15)",
            overflow: "hidden",
          }}>
            {/* Modal Header */}
            <div style={{
              display: "flex", alignItems: "center", justifyContent: "space-between",
              padding: "18px 24px", borderBottom: "1px solid rgba(120,160,180,0.15)",
              background: "linear-gradient(90deg, rgba(192,132,252,0.06), transparent)",
            }}>
              <div className="flex items-center gap-3">
                <div style={{
                  width: 36, height: 36, borderRadius: 10,
                  display: "flex", alignItems: "center", justifyContent: "center",
                  background: "rgba(192,132,252,0.1)", border: "1px solid rgba(192,132,252,0.35)",
                }}>
                  <FileBarChart size={18} style={{ color: "#c084fc" }} />
                </div>
                <div>
                  <h2 style={{ margin: 0, fontSize: 16, fontWeight: 700, color: "#eafcff", letterSpacing: "-0.3px" }}>Threat Intelligence Report Builder</h2>
                  <p style={{ margin: 0, fontSize: 10, color: "#5d7382", letterSpacing: 1.5, marginTop: 2 }}>
                    {total} INDICATORS · {entries.length} TYPES · REPORT ID {reportRefNum || reportId}
                  </p>
                </div>
              </div>
              <button onClick={() => setReportOpen(false)}
                style={{
                  padding: 8, background: "rgba(120,160,180,0.06)", border: "1px solid rgba(120,160,180,0.2)",
                  borderRadius: 8, color: "#8aa0ad", cursor: "pointer",
                }}>
                <X size={16} />
              </button>
            </div>

            {/* Variant Toggle — prominent, at top so analysts see it */}
            <div style={{
              padding: "14px 24px", borderBottom: "1px solid rgba(120,160,180,0.15)",
              display: "flex", alignItems: "center", gap: 14, flexWrap: "wrap",
              background: "rgba(10,14,20,0.5)",
            }}>
              <span style={{ fontSize: 10, fontWeight: 800, letterSpacing: 2, color: "#7f95a3" }}>REPORT VARIANT</span>
              <div style={{ display: "flex", gap: 6, background: "rgba(0,0,0,0.4)", padding: 4, borderRadius: 10, border: "1px solid rgba(120,160,180,0.15)" }}>
                <button onClick={() => setReportVariant("dark")}
                  style={{
                    display: "flex", alignItems: "center", gap: 8, padding: "8px 16px",
                    background: reportVariant === "dark" ? "linear-gradient(135deg, #00e5ff, #0088a8)" : "transparent",
                    color: reportVariant === "dark" ? "#04111a" : "#8aa0ad",
                    border: "none", borderRadius: 6,
                    fontSize: 12, fontWeight: 700, cursor: "pointer",
                    boxShadow: reportVariant === "dark" ? "0 0 14px rgba(0,229,255,0.3)" : "none",
                  }}>
                  🌙 DARK <span style={{ opacity: 0.7, fontSize: 10, marginLeft: 4 }}>for sharing</span>
                </button>
                <button onClick={() => setReportVariant("light")}
                  style={{
                    display: "flex", alignItems: "center", gap: 8, padding: "8px 16px",
                    background: reportVariant === "light" ? "linear-gradient(135deg, #ffb84d, #f59e0b)" : "transparent",
                    color: reportVariant === "light" ? "#04111a" : "#8aa0ad",
                    border: "none", borderRadius: 6,
                    fontSize: 12, fontWeight: 700, cursor: "pointer",
                    boxShadow: reportVariant === "light" ? "0 0 14px rgba(255,184,77,0.3)" : "none",
                  }}>
                  ☀️ LIGHT <span style={{ opacity: 0.7, fontSize: 10, marginLeft: 4 }}>for printing</span>
                </button>
              </div>
              <span style={{ fontSize: 10, color: "#5d7382", flex: 1, textAlign: "right" }}>
                {reportVariant === "dark" ? "Dark theme — cyber aesthetic, best for viewing on screen or Slack" : "Light theme — clean white background, best for printing or attachment to formal reports"}
              </span>
            </div>

            {/* Modal Body */}
            <div style={{ display: "grid", gridTemplateColumns: "240px 1fr 320px", flex: 1, overflow: "hidden" }}>

              {/* Left: Template Presets */}
              <div style={{ padding: 18, borderRight: "1px solid rgba(120,160,180,0.15)", overflowY: "auto" }}>
                <div style={{ fontSize: 10, fontWeight: 800, letterSpacing: 2, color: "#5d7382", marginBottom: 12 }}>PRESETS</div>
                {[
                  { id: "full", name: "Full Investigation", desc: "Everything included", audience: "COMPREHENSIVE", icon: "📊" },
                  { id: "exec", name: "Executive Summary", desc: "Cover + Executive + Glossary", audience: "LEADERSHIP", icon: "📋" },
                  { id: "technical", name: "Technical IOC", desc: "IOC tables + Consolidation", audience: "SOC", icon: "🔍" },
                  { id: "mitre", name: "MITRE ATT&CK", desc: "Techniques heatmap", audience: "ANALYSTS", icon: "🎯" },
                  { id: "hunting", name: "Hunting Playbook", desc: "SIEM/EDR queries", audience: "HUNTERS", icon: "🎣" },
                ].map(t => (
                  <button key={t.id} onClick={() => applyTemplate(t.id)}
                    style={{
                      display: "block", width: "100%", textAlign: "left",
                      padding: "10px 12px", marginBottom: 6,
                      background: reportTemplate === t.id ? "rgba(192,132,252,0.1)" : "rgba(10,14,20,0.4)",
                      border: `1px solid ${reportTemplate === t.id ? "rgba(192,132,252,0.5)" : "rgba(120,160,180,0.15)"}`,
                      borderRadius: 8,
                      cursor: "pointer",
                      boxShadow: reportTemplate === t.id ? "0 0 12px rgba(192,132,252,0.2)" : "none",
                    }}>
                    <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 3 }}>
                      <span style={{ fontSize: 14 }}>{t.icon}</span>
                      <span style={{ fontSize: 8, fontWeight: 800, letterSpacing: 1.2, color: reportTemplate === t.id ? "#c084fc" : "#5d7382" }}>{t.audience}</span>
                    </div>
                    <div style={{ fontSize: 11, fontWeight: 700, color: reportTemplate === t.id ? "#eafcff" : "#c8d6dd", marginBottom: 2 }}>{t.name}</div>
                    <div style={{ fontSize: 9, color: "#7f95a3", lineHeight: 1.4 }}>{t.desc}</div>
                  </button>
                ))}
                <div style={{
                  marginTop: 14, padding: "10px 12px",
                  background: "rgba(10,14,20,0.5)", border: "1px dashed rgba(120,160,180,0.2)",
                  borderRadius: 6, fontSize: 9, color: "#7f95a3", lineHeight: 1.5,
                }}>
                  💡 Presets pre-configure sections. Fine-tune in <strong style={{ color: "#c8d6dd" }}>Sections</strong> &amp; <strong style={{ color: "#c8d6dd" }}>Content</strong> tabs.
                </div>
              </div>

              {/* Center: Preview */}
              <div style={{ padding: 0, overflow: "hidden", display: "flex", flexDirection: "column", background: reportVariant === "light" ? "#ffffff" : "#05070a" }}>
                <div style={{
                  padding: "10px 16px", borderBottom: "1px solid rgba(120,160,180,0.15)",
                  fontSize: 10, fontWeight: 800, letterSpacing: 2, color: "#7f95a3",
                  display: "flex", justifyContent: "space-between", alignItems: "center",
                  background: "rgba(10,14,20,0.4)",
                }}>
                  <span>LIVE PREVIEW</span>
                  <span style={{ color: reportVariant === "dark" ? "#00e5ff" : "#f59e0b" }}>
                    {reportVariant === "dark" ? "🌙 DARK VARIANT" : "☀️ LIGHT VARIANT"}
                  </span>
                </div>
                <iframe
                  ref={reportPreviewRef}
                  srcDoc={generateReportHTML(reportVariant)}
                  onLoad={handleReportPreviewLoad}
                  style={{ flex: 1, border: "none", background: reportVariant === "light" ? "#ffffff" : "#05070a" }}
                  title="Report Preview"
                />
              </div>

              {/* Right: Tabbed configuration */}
              <div style={{ borderLeft: "1px solid rgba(120,160,180,0.15)", display: "flex", flexDirection: "column", overflow: "hidden" }}>
                {/* Tab bar */}
                <div style={{ display: "flex", borderBottom: "1px solid rgba(120,160,180,0.15)" }}>
                  {[
                    { id: "metadata", label: "Metadata" },
                    { id: "sections", label: "Sections" },
                    { id: "content", label: "Content" },
                  ].map(t => (
                    <button key={t.id} onClick={() => setReportTab(t.id)}
                      style={{
                        flex: 1, padding: "10px 8px",
                        background: reportTab === t.id ? "rgba(0,229,255,0.08)" : "transparent",
                        color: reportTab === t.id ? "#00e5ff" : "#7f95a3",
                        border: "none",
                        borderBottom: `2px solid ${reportTab === t.id ? "#00e5ff" : "transparent"}`,
                        fontSize: 10, fontWeight: 800, letterSpacing: 1.5,
                        cursor: "pointer",
                      }}>
                      {t.label.toUpperCase()}
                    </button>
                  ))}
                </div>

                <div style={{ flex: 1, overflowY: "auto", padding: 16 }}>

                  {reportTab === "metadata" && (
                    <>
                      <div style={{ marginBottom: 14 }}>
                        <label style={{ fontSize: 10, color: "#8aa0ad", display: "block", marginBottom: 4, letterSpacing: 1 }}>ANALYST NAME</label>
                        <input value={reportAnalyst} onChange={(e) => setReportAnalyst(e.target.value)} placeholder="Your name"
                          style={{
                            width: "100%", padding: "8px 10px", fontSize: 12,
                            background: "rgba(0,0,0,0.4)", border: "1px solid rgba(120,160,180,0.25)",
                            borderRadius: 6, color: "#e6f0f3", fontFamily: "inherit",
                          }} />
                      </div>

                      <div style={{ marginBottom: 14 }}>
                        <label style={{ fontSize: 10, color: "#8aa0ad", display: "block", marginBottom: 4, letterSpacing: 1 }}>ORGANIZATION</label>
                        <input value={reportOrg} onChange={(e) => setReportOrg(e.target.value)} placeholder="Company or team"
                          style={{
                            width: "100%", padding: "8px 10px", fontSize: 12,
                            background: "rgba(0,0,0,0.4)", border: "1px solid rgba(120,160,180,0.25)",
                            borderRadius: 6, color: "#e6f0f3", fontFamily: "inherit",
                          }} />
                      </div>

                      <div style={{ marginBottom: 14 }}>
                        <label style={{ fontSize: 10, color: "#8aa0ad", display: "block", marginBottom: 4, letterSpacing: 1 }}>REFERENCE NUMBER (OPTIONAL)</label>
                        <input value={reportRefNum} onChange={(e) => setReportRefNum(e.target.value)} placeholder={`Auto: ${reportId}`}
                          style={{
                            width: "100%", padding: "8px 10px", fontSize: 12,
                            background: "rgba(0,0,0,0.4)", border: "1px solid rgba(120,160,180,0.25)",
                            borderRadius: 6, color: "#e6f0f3", fontFamily: "inherit",
                          }} />
                      </div>

                      <div style={{ marginBottom: 14 }}>
                        <label style={{ fontSize: 10, color: "#8aa0ad", display: "block", marginBottom: 6, letterSpacing: 1 }}>TLP MARKING</label>
                        <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 4 }}>
                          {[
                            { v: "WHITE", c: "#ffffff", bg: "rgba(255,255,255,0.08)" },
                            { v: "GREEN", c: "#00ff9c", bg: "rgba(0,255,156,0.1)" },
                            { v: "AMBER", c: "#ffb84d", bg: "rgba(255,184,77,0.1)" },
                            { v: "RED", c: "#ff4d6d", bg: "rgba(255,77,109,0.12)" },
                          ].map(t => (
                            <button key={t.v} onClick={() => setReportTLP(t.v)}
                              style={{
                                padding: "6px 4px", fontSize: 9, fontWeight: 800, letterSpacing: 1,
                                background: reportTLP === t.v ? t.bg : "rgba(10,14,20,0.4)",
                                border: `1px solid ${reportTLP === t.v ? t.c : "rgba(120,160,180,0.2)"}`,
                                borderRadius: 5,
                                color: reportTLP === t.v ? t.c : "#7f95a3",
                                cursor: "pointer",
                              }}>{t.v}</button>
                          ))}
                        </div>
                      </div>

                      <div style={{ marginBottom: 14 }}>
                        <label style={{ fontSize: 10, color: "#8aa0ad", display: "block", marginBottom: 4, letterSpacing: 1 }}>WATERMARK (OPTIONAL)</label>
                        <input value={reportWatermark} onChange={(e) => setReportWatermark(e.target.value)} placeholder="e.g. DRAFT, INTERNAL"
                          style={{
                            width: "100%", padding: "8px 10px", fontSize: 12,
                            background: "rgba(0,0,0,0.4)", border: "1px solid rgba(120,160,180,0.25)",
                            borderRadius: 6, color: "#e6f0f3", fontFamily: "inherit",
                          }} />
                      </div>
                    </>
                  )}

                  {reportTab === "sections" && (
                    <>
                      <div style={{ fontSize: 10, fontWeight: 800, letterSpacing: 2, color: "#5d7382", marginBottom: 8 }}>REPORT SECTIONS</div>
                      <div style={{ fontSize: 9, color: "#7f95a3", marginBottom: 14, lineHeight: 1.5 }}>
                        Toggle sections on/off. Use arrows to reorder. Click a section name to jump the preview to it.
                      </div>
                      {reportSections.map((s, idx) => (
                        <div key={s.id}
                          onClick={() => scrollToReportSection(s.id)}
                          title="Jump to this section in the preview"
                          style={{
                          display: "flex", alignItems: "center", gap: 6,
                          padding: "8px 10px", marginBottom: 6,
                          background: s.enabled ? "rgba(0,229,255,0.05)" : "rgba(10,14,20,0.3)",
                          border: `1px solid ${s.enabled ? "rgba(0,229,255,0.2)" : "rgba(120,160,180,0.1)"}`,
                          borderRadius: 6, cursor: "pointer",
                        }}>
                          <label style={{ display: "flex", alignItems: "center", gap: 8, flex: 1, cursor: "pointer" }}
                            onClick={(e) => e.stopPropagation()}>
                            <span role="checkbox" aria-checked={s.enabled} onClick={() => toggleSection(s.id)}
                              style={{
                                width: 14, height: 14, borderRadius: 3, flexShrink: 0, cursor: "pointer",
                                display: "flex", alignItems: "center", justifyContent: "center",
                                background: s.enabled ? "#00e5ff" : "transparent",
                                border: `1px solid ${s.enabled ? "#00e5ff" : "rgba(120,160,180,0.5)"}`,
                              }}>
                              {s.enabled && <Check size={10} strokeWidth={3} style={{ color: "#04111a" }} />}
                            </span>
                            <span style={{ fontSize: 11, color: s.enabled ? "#e6f0f3" : "#7f95a3", fontWeight: 600 }}>{s.name}</span>
                          </label>
                          <button onClick={(e) => { e.stopPropagation(); moveSection(idx, -1); }} disabled={idx === 0}
                            title="Move up"
                            style={{
                              padding: 3, background: "rgba(120,160,180,0.08)", border: "1px solid rgba(120,160,180,0.2)",
                              borderRadius: 4, color: idx === 0 ? "#3a4a54" : "#8aa0ad",
                              cursor: idx === 0 ? "not-allowed" : "pointer", fontSize: 10,
                            }}>▲</button>
                          <button onClick={(e) => { e.stopPropagation(); moveSection(idx, 1); }} disabled={idx === reportSections.length - 1}
                            title="Move down"
                            style={{
                              padding: 3, background: "rgba(120,160,180,0.08)", border: "1px solid rgba(120,160,180,0.2)",
                              borderRadius: 4, color: idx === reportSections.length - 1 ? "#3a4a54" : "#8aa0ad",
                              cursor: idx === reportSections.length - 1 ? "not-allowed" : "pointer", fontSize: 10,
                            }}>▼</button>
                        </div>
                      ))}
                    </>
                  )}

                  {reportTab === "content" && (
                    <>
                      <div style={{ fontSize: 10, fontWeight: 800, letterSpacing: 2, color: "#5d7382", marginBottom: 8 }}>IOC TYPES TO INCLUDE</div>
                      <div style={{ fontSize: 9, color: "#7f95a3", marginBottom: 12, lineHeight: 1.5 }}>
                        Applies globally — filters IOCs in Technical Report and Hunting Playbook.
                      </div>
                      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 4, marginBottom: 20 }}>
                        {entries.map(([cat, arr]) => {
                          const on = reportIocTypes[cat] !== false;
                          const cc = colorFor(cat);
                          return (
                            <label key={cat} style={{
                              display: "flex", alignItems: "center", gap: 6,
                              padding: "5px 8px",
                              background: on ? `${cc}18` : "rgba(10,14,20,0.4)",
                              border: `1px solid ${on ? `${cc}55` : "rgba(120,160,180,0.15)"}`,
                              borderRadius: 5, cursor: "pointer",
                            }}>
                              <input type="checkbox" checked={on} onChange={() => toggleReportIocType(cat)}
                                style={{ accentColor: cc, cursor: "pointer" }} />
                              <span style={{ fontSize: 10, color: on ? cc : "#7f95a3", fontWeight: 700, letterSpacing: 0.5 }}>{cat}</span>
                              <span style={{ fontSize: 9, color: "#5d7382", marginLeft: "auto" }}>{arr.length}</span>
                            </label>
                          );
                        })}
                      </div>

                      <div style={{ fontSize: 10, fontWeight: 800, letterSpacing: 2, color: "#5d7382", marginBottom: 8 }}>HUNTING QUERY LANGUAGES</div>
                      <div style={{ fontSize: 9, color: "#7f95a3", marginBottom: 12, lineHeight: 1.5 }}>
                        Which SIEM/EDR queries appear in the Hunting Playbook.
                      </div>
                      <div style={{ display: "flex", flexDirection: "column", gap: 5, marginBottom: 20 }}>
                        {[
                          { k: "kql", name: "Sentinel / Defender XDR (KQL)" },
                          { k: "spl", name: "Splunk (SPL)" },
                          { k: "aql", name: "IBM QRadar (AQL)" },
                          { k: "cql", name: "CrowdStrike Falcon (CQL)" },
                          { k: "sigma", name: "Sigma (Generic / SIEM-agnostic)" },
                        ].map(q => (
                          <label key={q.k} style={{
                            display: "flex", alignItems: "center", gap: 8,
                            padding: "7px 10px",
                            background: reportQueryLangs[q.k] ? "rgba(192,132,252,0.08)" : "rgba(10,14,20,0.4)",
                            border: `1px solid ${reportQueryLangs[q.k] ? "rgba(192,132,252,0.35)" : "rgba(120,160,180,0.15)"}`,
                            borderRadius: 6, cursor: "pointer",
                          }}>
                            <input type="checkbox" checked={reportQueryLangs[q.k]} onChange={() => toggleReportQueryLang(q.k)}
                              style={{ accentColor: "#c084fc", cursor: "pointer" }} />
                            <span style={{ fontSize: 11, color: reportQueryLangs[q.k] ? "#e6f0f3" : "#7f95a3", fontWeight: 600 }}>{q.name}</span>
                          </label>
                        ))}
                      </div>
                    </>
                  )}
                </div>

                {/* Export buttons — always visible at bottom */}
                <div style={{ padding: 14, borderTop: "1px solid rgba(120,160,180,0.15)", background: "rgba(10,14,20,0.5)" }}>
                  <div style={{ fontSize: 10, fontWeight: 800, letterSpacing: 2, color: "#5d7382", marginBottom: 8 }}>EXPORT</div>

                  <button onClick={() => downloadReport("print")}
                    style={{
                      display: "flex", alignItems: "center", justifyContent: "center", gap: 8,
                      width: "100%", padding: "10px 14px", marginBottom: 6,
                      background: "#00e5ff", border: "none", borderRadius: 8,
                      color: "#04111a", fontWeight: 700, fontSize: 12,
                      cursor: "pointer", boxShadow: "0 0 18px rgba(0,229,255,0.35)",
                    }}>
                    <FileText size={14} /> Print / Save as PDF
                  </button>

                  <button onClick={() => downloadReport("html")}
                    style={{
                      display: "flex", alignItems: "center", justifyContent: "center", gap: 8,
                      width: "100%", padding: "9px 14px", marginBottom: 6,
                      background: "rgba(192,132,252,0.1)", border: "1px solid rgba(192,132,252,0.4)",
                      borderRadius: 8, color: "#c084fc", fontWeight: 700, fontSize: 11,
                      cursor: "pointer",
                    }}>
                    <Download size={13} /> Download HTML ({reportVariant})
                  </button>

                  <button onClick={() => downloadReport("md")}
                    style={{
                      display: "flex", alignItems: "center", justifyContent: "center", gap: 8,
                      width: "100%", padding: "9px 14px", marginBottom: 6,
                      background: "rgba(0,255,156,0.08)", border: "1px solid rgba(0,255,156,0.4)",
                      borderRadius: 8, color: "#00ff9c", fontWeight: 700, fontSize: 11,
                      cursor: "pointer",
                    }}>
                    <Download size={13} /> Download Markdown
                  </button>

                  <button onClick={() => downloadReport("copy-md")}
                    style={{
                      display: "flex", alignItems: "center", justifyContent: "center", gap: 8,
                      width: "100%", padding: "8px 14px",
                      background: "rgba(120,160,180,0.06)", border: "1px solid rgba(120,160,180,0.25)",
                      borderRadius: 8, color: "#8aa0ad", fontWeight: 600, fontSize: 10,
                      cursor: "pointer",
                    }}>
                    <Copy size={11} /> {copied === "report-md" ? "Copied!" : "Copy Markdown"}
                  </button>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Hash dedup toasts — fixed position, cannot be missed */}
      {dedupToasts.length > 0 && (
        <div style={{
          position: "fixed", top: 24, left: "50%", transform: "translateX(-50%)",
          zIndex: 9999, display: "flex", flexDirection: "column", gap: 8,
          pointerEvents: "none",
        }}>
          {dedupToasts.map(t => (
            <div key={t.id} style={{
              background: "rgba(10,14,20,0.95)",
              border: "1px solid rgba(0,229,255,0.6)",
              borderRadius: 12,
              padding: "12px 18px",
              boxShadow: "0 0 32px rgba(0,229,255,0.35), 0 8px 24px rgba(0,0,0,0.6)",
              backdropFilter: "blur(8px)",
              animation: "toastSlide 3s ease-out forwards",
              minWidth: 340,
            }}>
              <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                <span style={{
                  fontSize: 20, lineHeight: 1,
                  filter: "drop-shadow(0 0 8px rgba(0,229,255,0.8))",
                }}>🔗</span>
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ color: "#00e5ff", fontSize: 11, fontWeight: 700, letterSpacing: "0.06em", textTransform: "uppercase", marginBottom: 2 }}>
                    Hash consolidated → SHA256
                  </div>
                  <div style={{ color: "#8aa0ad", fontSize: 10, fontFamily: "monospace" }}>
                    <span style={{ color: "#c084fc", fontWeight: 700 }}>{t.fromCat}</span> {t.fromValue.slice(0, 20)}…
                  </div>
                  <div style={{ color: "#8aa0ad", fontSize: 10, fontFamily: "monospace" }}>
                    → <span style={{ color: "#00ff9c" }}>SHA256</span> {t.toValue.slice(0, 20)}…
                  </div>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
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
        .sitroom-sonar { position: absolute; inset: 0; pointer-events: none; }
        .sitroom-sonar i {
          position: absolute; inset: 0; border-radius: 50%; border: 1.4px solid #d99a4e;
          opacity: 0; animation: sitroomPing 4.2s cubic-bezier(.2,.6,.4,1) infinite;
        }
        .sitroom-sonar i:nth-child(2) { animation-delay: 1.4s; }
        .sitroom-sonar i:nth-child(3) { animation-delay: 2.8s; }
        @keyframes sitroomPing { 0% { transform: scale(1); opacity: .55; } 100% { transform: scale(6.5); opacity: 0; } }
        @media (prefers-reduced-motion: reduce) { .sitroom-sonar i { animation: none; opacity: 0; } }
      `}</style>
      <div className="mx-auto max-w-7xl px-4 py-6 sm:px-6">
        {!tokenBannerDismissed && expiringTokens.length > 0 && (() => {
          const mostUrgent = expiringTokens.reduce((a, b) => (a.daysLeft <= b.daysLeft ? a : b));
          const isCritical = mostUrgent.daysLeft <= 7;
          const isExpired = mostUrgent.daysLeft < 0;
          const color = isExpired || isCritical ? "#ff4d6d" : "#fbbf24";
          const bg = isExpired || isCritical ? "rgba(255,77,109,0.10)" : "rgba(251,191,36,0.10)";
          const border = isExpired || isCritical ? "rgba(255,77,109,0.4)" : "rgba(251,191,36,0.4)";
          return (
            <div className="mb-4 rounded-xl px-4 py-3 flex items-start gap-3 flex-wrap"
              style={{ backgroundColor: bg, border: `1px solid ${border}`, color }}>
              <span className="text-lg leading-none">{isExpired || isCritical ? "🔴" : "⚠️"}</span>
              <div className="flex-1 min-w-0">
                <div className="text-sm font-semibold mb-1">
                  {expiringTokens.length === 1
                    ? isExpired
                      ? `${mostUrgent.label} token has expired (${Math.abs(mostUrgent.daysLeft)} days ago)`
                      : `${mostUrgent.label} token expires in ${mostUrgent.daysLeft} day${mostUrgent.daysLeft !== 1 ? "s" : ""}`
                    : `${expiringTokens.length} API tokens are near expiry`}
                </div>
                <div className="text-xs opacity-90 flex flex-wrap gap-x-3 gap-y-1">
                  {expiringTokens.map((t) => (
                    <span key={t.label}>
                      <span className="font-semibold">{t.label}</span>: {t.daysLeft < 0 ? `expired ${Math.abs(t.daysLeft)}d ago` : `${t.daysLeft}d left`} · <a href={t.portal} target="_blank" rel="noreferrer noopener" style={{ textDecoration: "underline" }}>renew</a>
                    </span>
                  ))}
                </div>
                <div className="text-[10px] opacity-70 mt-1">
                  After renewing, update <code style={{ fontFamily: "monospace" }}>*_TOKEN_ISSUED</code> in the Cloudflare Worker variables.
                </div>
              </div>
              <button onClick={() => setTokenBannerDismissed(true)}
                className="rounded-md p-1 opacity-60 hover:opacity-100 shrink-0"
                title="Hide until next reload">
                <X size={14} />
              </button>
            </div>
          );
        })()}
        <div style={{ position: "relative", zIndex: 0 }}>
          <div aria-hidden="true" style={{
            position: "absolute", top: 0, right: 0, width: "100%", height: "100%", zIndex: -1,
            backgroundImage: "radial-gradient(rgba(217,154,78,0.13) 1px, transparent 1px)",
            backgroundSize: "26px 26px",
            WebkitMaskImage: "radial-gradient(circle at 92% 0%, #000 0%, transparent 45%)",
            maskImage: "radial-gradient(circle at 92% 0%, #000 0%, transparent 45%)",
            pointerEvents: "none",
          }} />
        <div className="relative flex items-start gap-3 mb-5 flex-wrap">
          <button onClick={goHome} title="Back to home" aria-label="Back to home"
            className="relative flex h-11 w-11 items-center justify-center rounded-lg shrink-0"
            style={{ backgroundColor: "rgba(217,154,78,0.10)", border: "1px solid rgba(217,154,78,0.4)", boxShadow: "0 0 22px rgba(217,154,78,0.2)", cursor: "pointer" }}>
            <span className="sitroom-sonar"><i></i><i></i><i></i></span>
            <Shield size={22} style={{ color: "#d99a4e", position: "relative" }} />
          </button>
          <div className="min-w-0">
            <h1 className="text-xl sm:text-2xl font-bold tracking-tight" style={{ color: "#eafcff", textShadow: "0 0 16px rgba(217,154,78,0.3)", fontFamily: 'ui-monospace, "Cascadia Code", Consolas, monospace' }}>
              <button onClick={goHome} title="Back to home" style={{ color: "inherit", background: "none", border: "none", padding: 0, font: "inherit", cursor: "pointer", textShadow: "inherit" }}>
                Intel Extractor
              </button>
            </h1>
            <p className="text-[11px]" style={{ color: "#5d7382", letterSpacing: "2px", marginTop: "2px" }}>
              EXTRACT · ENRICH · HUNT <span style={{ color: "#3a4a54", marginLeft: "8px" }}>{APP_VERSION}</span>
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
        <div className="flex items-center gap-3 mb-4 py-3 flex-wrap" style={{ borderBottom: "1px solid rgba(120,160,180,0.08)" }}>
          <span className="text-3xl font-medium tabular-nums" style={{ color: "#00ff9c", letterSpacing: "-1px" }}>{total}</span>
          <span className="text-[10px] uppercase" style={{ color: "#5d7382", letterSpacing: "1.5px" }}>indicators</span>
          <div className="shrink-0" style={{ width: "1px", height: "28px", background: "rgba(120,160,180,0.15)" }}></div>
          <span className="text-3xl font-medium tabular-nums" style={{ color: "#00e5ff", letterSpacing: "-1px" }}>{entries.length}</span>
          <span className="text-[10px] uppercase" style={{ color: "#5d7382", letterSpacing: "1.5px" }}>types</span>
          <div className="flex items-center gap-2 flex-wrap w-full sm:w-auto sm:ml-auto">
            <button onClick={() => { setCondensed((v) => !v); setRowOverride({}); setCardCondensed({}); }}
              title={condensed ? "Expand all enrichment sections" : "Collapse to verdicts only"}
              className="flex items-center gap-1.5 rounded-lg px-3 py-2 text-sm font-semibold"
              style={{
                color: condensed ? "#04111a" : "#c084fc",
                backgroundColor: condensed ? "#c084fc" : "rgba(192,132,252,0.14)",
                border: `1px solid rgba(192,132,252,${condensed ? "1" : "0.55"})`,
              }}>
              {condensed ? "Expand" : "Compact"}
            </button>
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
            <button onClick={() => setReportOpen(true)} disabled={!total}
              title="Generate professional threat intelligence report (HTML / Markdown / PDF)"
              className="flex items-center gap-1.5 rounded-lg px-3 py-2 text-sm font-semibold transition-opacity"
              style={{
                color: "#04111a",
                backgroundColor: !total ? "rgba(192,132,252,0.14)" : "#c084fc",
                border: `1px solid rgba(192,132,252,${!total ? "0.55" : "1"})`,
                boxShadow: !total ? "none" : "0 0 18px rgba(192,132,252,0.4)",
                opacity: !total ? 0.4 : 1,
                cursor: !total ? "not-allowed" : "pointer",
              }}>
              <FileBarChart size={15} /> Report
            </button>
          </div>
        </div>
        )}

        <div className="rounded-xl p-4 mb-5" style={panel}>
          <div className="flex flex-wrap gap-1 mb-3">
            <Tab active={mode === "url"} onClick={() => setMode("url")} icon={<Globe size={14} />}>Fetch URL</Tab>
            <Tab active={mode === "upload"} onClick={() => setMode("upload")} icon={<FileUp size={14} />}>Upload File</Tab>
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
                <GButton onClick={() => runFetch()} disabled={!url || loading} color="#d99a4e" solid icon={loading ? <Loader2 size={16} className="animate-spin" /> : <Search size={16} />}>
                  {loading ? "Fetching…" : "Fetch & Extract"}
                </GButton>
              </div>
            </div>
          )}

          {mode === "upload" && (
            <div className="flex flex-col gap-2">
              <div
                onDragOver={(e) => { e.preventDefault(); setUploadDragging(true); }}
                onDragLeave={() => setUploadDragging(false)}
                onDrop={handleFileDrop}
                onClick={() => fileInputRef.current?.click()}
                className="rounded-lg px-6 py-8 text-center cursor-pointer transition-colors"
                style={{
                  backgroundColor: uploadDragging ? "rgba(217,154,78,0.08)" : "rgba(0,0,0,0.35)",
                  border: `2px dashed ${uploadDragging ? "rgba(217,154,78,0.5)" : "rgba(120,160,180,0.25)"}`,
                }}>
                <FileUp size={28} className="mx-auto mb-2" style={{ color: uploadDragging ? "#d99a4e" : "#5d7382" }} />
                {loading ? (
                  <p className="text-sm animate-pulse" style={{ color: "#9fb3bd" }}>Processing file…</p>
                ) : (
                  <>
                    <p className="text-sm" style={{ color: "#9fb3bd" }}>
                      <span style={{ color: "#d99a4e", fontWeight: 600 }}>Click to browse</span> or drag & drop a file
                    </p>
                    <p className="text-[11px] mt-1.5" style={{ color: "#5d7382" }}>
                      PDF · DOCX · PPTX · XLSX · HTML · TXT · CSV · JSON · MD · EML
                    </p>
                  </>
                )}
              </div>
              <input ref={fileInputRef} type="file" accept={UPLOAD_ACCEPT} onChange={handleFileSelect}
                className="hidden" />
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
                <GButton onClick={() => { setParseFlash("paste"); setTimeout(() => setParseFlash(null), 600); runPaste(); }} disabled={!jsonText.trim()} color="#00ff9c" solid icon={<ClipboardPaste size={16} />}
                  flash={parseFlash === "paste"}>Parse JSON</GButton>
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
                <GButton onClick={() => { setParseFlash("raw"); setTimeout(() => setParseFlash(null), 600); runRaw(); }} disabled={!rawText.trim()} color="#c084fc" solid icon={<Wand2 size={16} />}
                  flash={parseFlash === "raw"}>Refang &amp; Parse</GButton>
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

        {!total && <ThreatWire onHunt={huntArticle} />}

        {!total && (
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3 mb-5">
            {[
              { icon: <Search size={19} />, title: "IOC Extraction", desc: "Pull IPs, hashes, domains, and URLs from pasted text, JSON, or a live article URL." },
              { icon: <Database size={19} />, title: "Multi-Engine Enrichment", desc: "Cross-reference every indicator against 10+ engines — OTX, Kaspersky, Hybrid Analysis, and more." },
              { icon: <Share2 size={19} />, title: "Threat Graph", desc: "Pivot across shared infrastructure and visualize the blast radius as a live node graph." },
              { icon: <Crosshair size={19} />, title: "Hunting Artifacts", desc: "Auto-generate Sigma and YARA rules plus EDR-ready artifacts from what was found." },
              { icon: <Terminal size={19} />, title: "Query Generation", desc: "Ship straight to KQL, SPL, AQL, or CQL — no manual translation between platforms." },
              { icon: <FileBarChart size={19} />, title: "Report Builder", desc: "Export a TLP-marked, analyst-ready report as HTML, Markdown, or PDF." },
            ].map((f, i) => (
              <div key={i} className="rounded-xl p-4"
                style={{ backgroundColor: "rgba(10,14,20,0.5)", border: "1px solid rgba(217,154,78,0.16)", borderTop: "2px solid rgba(217,154,78,0.5)" }}>
                <div style={{ color: "#d99a4e", marginBottom: 10 }}>{f.icon}</div>
                <div className="text-sm font-bold mb-1" style={{ color: "#eafcff" }}>{f.title}</div>
                <div className="text-xs leading-relaxed" style={{ color: "#8aa0ad" }}>{f.desc}</div>
              </div>
            ))}
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
          <div className="rounded-xl mb-4 overflow-hidden" style={{ ...panel, borderColor: "rgba(253,224,71,0.35)" }}>
            <div className="flex items-center justify-between px-4 py-3 gap-3 flex-wrap">
              <span className="flex items-center gap-2.5 min-w-0">
                <span className="shrink-0 flex h-7 w-7 items-center justify-center rounded-lg"
                  style={{ backgroundColor: "rgba(253,224,71,0.08)", border: "1px solid rgba(253,224,71,0.35)" }}>
                  <span style={{ fontSize: 14 }}>🧠</span>
                </span>
                <span className="text-sm font-bold tracking-wide" style={{ color: "#fde047" }}>AI Scan Threat Hunting Artifacts</span>
                {aiScanState === "loading" && (
                  <span className="text-[10px] uppercase tracking-widest flex items-center gap-1" style={{ color: "#8aa0ad" }}>
                    <Loader2 size={11} className="animate-spin" /> scanning
                  </span>
                )}
                {aiScanState === "done" && aiScanCounts && (
                  <span className="text-[10px] uppercase tracking-widest rounded-full px-2 py-0.5"
                    style={{ color: "#00ff9c", border: "1px solid rgba(0,255,156,0.35)", backgroundColor: "rgba(0,255,156,0.06)" }}>
                    +{aiScanCounts.scheduled_tasks + aiScanCounts.services + aiScanCounts.registry_ops + aiScanCounts.command_lines + aiScanCounts.file_paths} artifacts merged
                  </span>
                )}
              </span>
              {aiScanState === "done" ? (
                <button onClick={() => { setAiScanState("idle"); setAiScanCounts(null); }}
                  className="text-[11px] underline shrink-0" style={{ color: "#8aa0ad", cursor: "pointer", background: "none", border: "none" }}>
                  re-scan
                </button>
              ) : (
                <button onClick={runAIScan}
                  disabled={aiScanState === "loading"}
                  title="Deep artifact extraction — scheduled tasks, services, registry ops, command lines, file paths"
                  className="flex items-center gap-1 rounded-lg px-2.5 py-1 text-[11px] font-semibold shrink-0"
                  style={{
                    color: "#04111a",
                    backgroundColor: "#fde047",
                    border: "1px solid rgba(253,224,71,0.6)",
                    cursor: aiScanState === "loading" ? "not-allowed" : "pointer",
                  }}>
                  {aiScanState === "loading" ? <Loader2 size={12} className="animate-spin" /> : <span style={{ fontSize: 11 }}>🧠</span>}
                  {aiScanState === "loading" ? "Scanning…" : "AI Scan Artifacts"}
                </button>
              )}
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

        {entries.length > 0 && (
          <div className="flex flex-wrap gap-2 mb-5 items-center">
            {entries.map(([cat, arr]) => {
              const c = colorFor(cat);
              return (
                <a key={cat} href={`#cat-${cat}`} className="flex items-center gap-2 rounded-full px-3 py-1 text-xs" style={{ border: `1px solid ${c}55`, backgroundColor: `${c}14`, color: c }}>
                  <span style={{ width: 7, height: 7, borderRadius: 99, backgroundColor: c, boxShadow: `0 0 8px ${c}` }} />
                  {cat} <span className="font-bold" style={{ opacity: 0.85 }}>· {arr.length}</span>
                </a>
              );
            })}
            {/* Add new IOC category — for when an article lacks a type you want to add manually */}
            {/* Always-visible "Add Category / IOC" dropdown — single interaction */}
            <div className="relative">
              <select
                value={customAddCat && customAddCat !== "__NEW__" ? customAddCat : ""}
                onChange={(e) => { if (e.target.value) { setCustomAddCat(e.target.value); setCustomAddValue(""); } }}
                className="rounded-full px-3 py-1 text-xs font-semibold outline-none cursor-pointer appearance-none pr-7"
                style={{ background: "rgba(0,229,255,0.06)", border: "1px solid rgba(0,229,255,0.35)", color: "#00e5ff" }}>
                <option value="" style={{ background: "#0a0e14", color: "#5d7382" }}>+ Add Category / IOC</option>
                {ALL_IOC_CATS.map((c) => (
                  <option key={c} value={c} style={{ background: "#0a0e14", color: colorFor(c) }}>{c}</option>
                ))}
              </select>
              <span className="absolute right-2.5 top-1/2 -translate-y-1/2 pointer-events-none text-[10px]" style={{ color: "#00e5ff" }}>▾</span>
            </div>
          </div>
        )}
        {/* Floating input for adding to a new category that has no card yet */}
        {customAddCat && customAddCat !== "__NEW__" && !iocData?.[customAddCat] && (
          <div className="flex items-center gap-2 mb-3 rounded-lg px-3 py-2" style={{ border: `1px solid ${colorFor(customAddCat)}55`, backgroundColor: `${colorFor(customAddCat)}0a` }}>
            <span className="text-xs font-bold shrink-0" style={{ color: colorFor(customAddCat) }}>{customAddCat}</span>
            <input autoFocus value={customAddValue} onChange={(e) => setCustomAddValue(e.target.value)}
              placeholder={`Enter ${customAddCat} value…`}
              onKeyDown={(e) => {
                if (e.key === "Enter" && customAddValue.trim()) { addPivotIOC(customAddCat, customAddValue.trim(), "Manual"); setCustomAddValue(""); setCustomAddCat(null); }
                if (e.key === "Escape") { setCustomAddCat(null); setCustomAddValue(""); }
              }}
              className="flex-1 rounded-md px-2 py-1 text-xs outline-none"
              style={{ background: "rgba(0,0,0,0.3)", border: "1px solid rgba(120,160,180,0.3)", color: "#dff" }} />
            <button onClick={() => { if (customAddValue.trim()) { addPivotIOC(customAddCat, customAddValue.trim(), "Manual"); setCustomAddValue(""); setCustomAddCat(null); } }}
              className="text-xs rounded-md px-2 py-1 shrink-0"
              style={{ color: "#04111a", background: colorFor(customAddCat), cursor: "pointer", border: "none" }}>Add</button>
            <button onClick={() => { setCustomAddCat(null); setCustomAddValue(""); }} style={{ color: "#5d7382", background: "none", border: "none", cursor: "pointer" }}><X size={13} /></button>
          </div>
        )}


        {dragging && (
          <div className="fixed inset-0 z-[9998] pointer-events-none">
            <div className="fixed bottom-6 left-1/2 -translate-x-1/2 pointer-events-auto rounded-2xl px-5 py-3"
              style={{ backgroundColor: "rgba(10,14,20,0.95)", border: "2px solid rgba(0,229,255,0.4)", backdropFilter: "blur(12px)", boxShadow: "0 0 40px rgba(0,229,255,0.15)" }}>
              <p className="text-[10px] uppercase tracking-widest text-center mb-2" style={{ color: "#5d7382" }}>
                Drop <span style={{ color: "#00e5ff", fontWeight: 700 }}>{dragging.value.length > 30 ? dragging.value.slice(0, 30) + "…" : dragging.value}</span> into:
              </p>
              <div className="flex flex-wrap gap-1.5 justify-center">
                {ORDER.filter((k) => k !== dragging.cat).slice(0, 16).map((targetCat) => {
                  const tc = colorFor(targetCat);
                  const isOver = dragOverCat === targetCat;
                  return (
                    <button key={targetCat}
                      onDragOver={(e) => { e.preventDefault(); setDragOverCat(targetCat); }}
                      onDragLeave={() => setDragOverCat(null)}
                      onDrop={(e) => { e.preventDefault(); handleDropOnCat(targetCat); }}
                      className="rounded-lg px-3 py-1.5 text-xs font-bold transition-all"
                      style={{
                        color: isOver ? "#04111a" : tc,
                        backgroundColor: isOver ? tc : `${tc}18`,
                        border: `1px solid ${tc}${isOver ? "" : "55"}`,
                        transform: isOver ? "scale(1.1)" : "scale(1)",
                        boxShadow: isOver ? `0 0 16px ${tc}55` : "none",
                      }}>
                      {targetCat}
                    </button>
                  );
                })}
              </div>
            </div>
          </div>
        )}

        {entries.length > 0 && (
          <div className="mb-4" style={{ position: "relative" }}>
            <div className="px-4 py-2 flex items-center gap-3" style={{ borderBottom: "1px solid rgba(120,160,180,0.12)" }}>
              <span className="text-xs uppercase tracking-widest font-bold" style={{ color: "#5d7382" }}>Threat Graph</span>
              <span className="text-[10px]" style={{ color: "#3a4a54" }}>· {entries.length} indicator types · click nodes to investigate</span>
            </div>
            {/* Hash collapse flash overlay — visible confirmation of arc animation */}
            {hashCollapseAnims.length > 0 && (
              <div className="absolute inset-0 pointer-events-none z-20 flex items-center justify-center" style={{ top: "32px" }}>
                <div style={{
                  position: "absolute", inset: 0,
                  background: "radial-gradient(ellipse at center, rgba(0,229,255,0.08) 0%, transparent 70%)",
                  animation: "hashBlast 1.4s ease-out forwards",
                }} />
                {hashCollapseAnims.map(anim => (
                  <div key={anim.id} className="absolute flex items-center gap-1.5 rounded-full px-3 py-1.5"
                    style={{
                      top: "50%", left: "50%", transform: "translate(-50%,-80%)",
                      background: "rgba(0,229,255,0.15)", border: "1px solid rgba(0,229,255,0.5)",
                      backdropFilter: "blur(4px)", animation: "hashFlash 1.4s ease-out forwards",
                    }}>
                    <span className="text-[11px] font-bold" style={{ color: "#00e5ff" }}>
                      🔗 {anim.fromId.slice(0,10)}… → SHA256
                    </span>
                  </div>
                ))}
              </div>
            )}
            <div style={{ width: "100vw", marginLeft: "calc(50% - 50vw)", marginRight: "calc(50% - 50vw)" }}>
              <GraphErrorBoundary>
                <ThreatGraph iocData={iocData} enrichCache={enrichCache} colorFor={colorFor}
                  enrichIOC={enrichIOC} copyText={copyText}
                  addPivotIOC={addPivotIOC} isPivotAdded={isPivotAdded}
                  removeIoc={removeIoc}
                  anyEnriched={iocData ? Object.entries(iocData).some(([cat, arr]) =>
                    Array.isArray(arr) && arr.some(v => enrichCache[`${cat}::${v}`]?.data)
                  ) : false}
                  hashCollapseAnims={hashCollapseAnims} />
              </GraphErrorBoundary>
            </div>
          </div>
        )}

        {/* Hash dedup banner */}
        {Object.keys(mergedHashes).length > 0 && (() => {
          const totalMerged = Object.values(mergedHashes).reduce((s, m) => s + m.removed.length, 0);
          return (
            <div className="rounded-xl mb-4 overflow-hidden"
              style={{ border: "1px solid rgba(124,156,255,0.25)", background: "rgba(124,156,255,0.05)" }}>
              {/* Header row */}
              <div className="flex items-center justify-between px-4 py-2.5"
                style={{ borderBottom: showMerged ? "1px solid rgba(124,156,255,0.15)" : "none" }}>
                <div className="flex items-center gap-2">
                  <span className="text-xs font-semibold" style={{ color: "#7c9cff" }}>
                    {totalMerged} {totalMerged === 1 ? "hash" : "hashes"} consolidated into SHA256
                  </span>
                  <span className="text-xs" style={{ color: "#5d7382" }}>
                    · duplicate identifiers removed
                  </span>
                </div>
                <button onClick={() => setShowMerged(v => !v)}
                  className="text-[11px] rounded-md px-2.5 py-1"
                  style={{ color: "#7c9cff", background: "rgba(124,156,255,0.1)", border: "1px solid rgba(124,156,255,0.3)", cursor: "pointer" }}>
                  {showMerged ? "Hide" : "Show details"}
                </button>
              </div>
              {/* Expanded detail — full hashes in clean table */}
              {showMerged && (
                <div className="px-4 py-3 flex flex-col gap-3">
                  {Object.entries(mergedHashes).map(([sha256, m]) => (
                    <div key={sha256}>
                      {/* Target SHA256 */}
                      <div className="flex items-center gap-2 mb-1.5">
                        <span className="text-[9px] uppercase tracking-widest font-bold w-12 shrink-0" style={{ color: "#5d7382" }}>SHA256</span>
                        <span className="font-mono text-[11px] break-all" style={{ color: "#7c9cff" }}>{sha256}</span>
                      </div>
                      {/* Merged sources */}
                      {m.removed.map(r => (
                        <div key={r.cat + r.value} className="flex items-center gap-2 ml-14 mb-1">
                          <span className="text-[9px] uppercase tracking-widest font-bold w-12 shrink-0" style={{ color: "#5d7382" }}>{r.cat}</span>
                          <span className="font-mono text-[11px] break-all" style={{ color: "#c084fc" }}>{r.value}</span>
                          <span className="text-[9px] shrink-0 rounded-full px-1.5 py-0.5" style={{
                            color: r.manual ? "#ff4d6d" : "#7c9cff",
                            backgroundColor: r.manual ? "rgba(255,77,109,0.10)" : "rgba(124,156,255,0.10)",
                            border: `1px solid ${r.manual ? "rgba(255,77,109,0.3)" : "rgba(124,156,255,0.25)"}`
                          }}>
                            {r.manual ? "⚡ Manually converted" : "→ Auto-deduplicated"}
                          </span>
                        </div>
                      ))}
                    </div>
                  ))}
                </div>
              )}
            </div>
          );
        })()}

        <div className="grid grid-cols-1 gap-4">
          {entries.map(([cat, arr]) => {
            const c = colorFor(cat);
            // Card-level effective collapse: explicit card state wins over global.
            const cardCollapseState = cardCondensed[cat];
            const inheritedCollapse = cardCollapseState !== undefined ? cardCollapseState : condensed;
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
                    {["IPV4","IPV6","DOMAIN","URL","MD5","SHA1","SHA256","SHA512","CVE","FILE_NAME","FILE_PATH","REGISTRY","SCHEDULED_TASK","SERVICE","COMMAND_LINE","EMAIL","MAC_ADDRESS"].includes(cat) && (
                      <button onClick={() => { setCustomAddCat(customAddCat === cat ? null : cat); setCustomAddValue(""); }}
                        title="Add custom IOC"
                        className="rounded-md px-1.5 py-1 text-xs font-bold"
                        style={{ color: customAddCat === cat ? "#04111a" : c, backgroundColor: customAddCat === cat ? c : `${c}14`, border: `1px solid ${c}55`, cursor: "pointer" }}>
                        +
                      </button>
                    )}
                    {["IPV4","IPV6","DOMAIN","URL","MD5","SHA1","SHA256","SHA512","EMAIL","CVE"].includes(cat) && (
                      <button onClick={() => { const pending = arr.filter((v) => { const e = enrichCache[`${cat}::${v}`]; return !e || e.error; }); pending.forEach((v, i) => setTimeout(() => enrichIOC(cat, v), i * 1500)); setEnrichAllDone((p) => ({ ...p, [cat]: true })); setTimeout(() => setEnrichAllDone((p) => { const n = { ...p }; delete n[cat]; return n; }), 5000); }}
                        disabled={!!enrichAllDone[cat]}
                        className="flex items-center gap-1 rounded-md px-2 py-1 text-xs"
                        style={{ color: enrichAllDone[cat] ? "#5d7382" : "#2dd4bf", backgroundColor: enrichAllDone[cat] ? "rgba(120,160,180,0.06)" : "rgba(45,212,191,0.10)", border: `1px solid ${enrichAllDone[cat] ? "rgba(120,160,180,0.2)" : "rgba(45,212,191,0.4)"}`, cursor: enrichAllDone[cat] ? "not-allowed" : "pointer" }}>
                        <Search size={12} /> {enrichAllDone[cat] ? "Enriched" : "Enrich All"}
                      </button>
                    )}
                    <button onClick={() => { setCardCondensed((p) => ({ ...p, [cat]: !inheritedCollapse })); setRowOverride((p) => { const n = { ...p }; arr.forEach((v) => delete n[`${cat}::${v}`]); return n; }); }}
                      title={inheritedCollapse ? "Expand enrichment details" : "Collapse to verdicts only"}
                      className="flex items-center gap-1 rounded-md px-2 py-1 text-xs font-semibold"
                      style={{ color: inheritedCollapse ? "#04111a" : "#c084fc", backgroundColor: inheritedCollapse ? "#c084fc" : "rgba(192,132,252,0.12)", border: "1px solid rgba(192,132,252,0.4)", cursor: "pointer" }}>
                      <ChevronDown size={11} style={{ transform: inheritedCollapse ? "rotate(-90deg)" : "rotate(0deg)", transition: "transform 0.2s" }} />
                      {inheritedCollapse ? "Expand" : "Collapse"}
                    </button>
                    <button onClick={() => toggleDefang(cat)} className="flex items-center gap-1 rounded-md px-2 py-1 text-xs"
                      title="Defang this type for safe sharing (display, copy & export)"
                      style={{ color: isDefanged ? "#04111a" : "#ffb84d", backgroundColor: isDefanged ? "#ffb84d" : "rgba(255,184,77,0.10)", border: "1px solid rgba(255,184,77,0.5)" }}>
                      <ShieldOff size={12} /> {isDefanged ? "Defanged" : "Defang"}
                    </button>
                    {/* https:// prepend toggle — URL card only, View/Copy only, queries unaffected */}
                    {cat === "URL" && (
                      <button onClick={() => setPrependHttps((v) => !v)}
                        title="Toggle https:// prefix for View and Copy only — does not affect hunt queries"
                        className="flex items-center gap-1 rounded-md px-2 py-1 text-xs font-bold"
                        style={{
                          color: prependHttps ? "#04111a" : "#2dd4bf",
                          backgroundColor: prependHttps ? "#2dd4bf" : "rgba(45,212,191,0.10)",
                          border: "1px solid rgba(45,212,191,0.5)",
                          cursor: "pointer",
                        }}>
                        https://
                      </button>
                    )}
                    {/* Manual "Consolidate as SHA256 IOC" — MD5/SHA1 cards only.
                        Shows resolved canonical SHA256 count for any IOC in this card.
                        Click promotes all resolvable weak hashes to SHA256 in one go. */}
                    {["MD5","SHA1"].includes(cat) && (() => {
                      const resolvable = arr.filter(v => {
                        const k = `${cat}::${String(v).toLowerCase()}`;
                        const canonical = enrichCache[k]?.data?._canonicalSHA256;
                        if (!canonical) return false;
                        const alreadyIn = ((iocData || {}).SHA256 || []).some(s => s.toLowerCase() === canonical);
                        return !alreadyIn;
                      });
                      if (!resolvable.length) return null;
                      return (
                        <button
                          onClick={() => manualConsolidateToSHA256(cat, resolvable)}
                          title={`Manually promote ${resolvable.length} ${cat}${resolvable.length !== 1 ? "es" : ""} to SHA256 IOCs (using canonical SHA256 resolved from enrichment)`}
                          className="flex items-center gap-1 rounded-md px-2 py-1 text-xs font-bold"
                          style={{
                            color: "#04111a",
                            backgroundColor: "#ff4d6d",
                            border: "1px solid rgba(255,77,109,0.7)",
                            boxShadow: "0 0 12px rgba(255,77,109,0.4)",
                            cursor: "pointer",
                          }}>
                          <Zap size={11} /> Consolidate as SHA256 ({resolvable.length})
                        </button>
                      );
                    })()}
                    <span className="flex items-center justify-center text-base font-extrabold tabular-nums rounded-lg px-2.5 py-0.5 min-w-[2.2rem]"
                      style={{ backgroundColor: `${c}22`, color: c, border: `1px solid ${c}66`, textShadow: `0 0 10px ${c}66` }}>
                      {arr.length}
                    </span>
                    {/* Inline remove-card confirmation: click X → shows Confirm/Cancel */}
                    {confirmRemoveCat === cat ? (
                      <div className="flex items-center gap-1 rounded-md px-1.5 py-1"
                        style={{ background: "rgba(255,77,109,0.08)", border: "1px solid rgba(255,77,109,0.4)" }}>
                        <span className="text-[10px] font-semibold" style={{ color: "#ff8a9b" }}>Remove {arr.length}?</span>
                        <button onClick={(e) => {
                            e.stopPropagation();
                            // Wipe entire cat + its enrichCache entries + associated pivots
                            setIocData(prev => {
                              if (!prev) return prev;
                              const next = { ...prev };
                              delete next[cat];
                              return next;
                            });
                            setEnrichCache(prev => {
                              const next = { ...prev };
                              arr.forEach(v => { delete next[`${cat}::${v}`]; });
                              return next;
                            });
                            setConfirmRemoveCat(null);
                          }}
                          title="Confirm removal"
                          className="flex items-center gap-0.5 rounded px-1.5 py-0.5 text-[10px] font-bold"
                          style={{ color: "#04111a", background: "#ff4d6d", border: "none", cursor: "pointer" }}>
                          <Check size={10} /> Yes
                        </button>
                        <button onClick={(e) => { e.stopPropagation(); setConfirmRemoveCat(null); }}
                          title="Cancel"
                          className="rounded px-1.5 py-0.5 text-[10px] font-bold"
                          style={{ color: "#8aa0ad", background: "rgba(120,160,180,0.1)", border: "1px solid rgba(120,160,180,0.25)", cursor: "pointer" }}>
                          No
                        </button>
                      </div>
                    ) : (
                      <button onClick={(e) => { e.stopPropagation(); setConfirmRemoveCat(cat); }}
                        title={`Remove all ${arr.length} ${cat} IOC${arr.length !== 1 ? "s" : ""} and delete this card`}
                        className="rounded-md p-1"
                        style={{ color: "#8aa0ad", background: "transparent", border: "1px solid rgba(120,160,180,0.2)", cursor: "pointer" }}>
                        <X size={12} />
                      </button>
                    )}
                  </div>
                </div>

                <div className="px-4 py-2 overflow-y-auto flex-1" style={{ maxHeight: 420 }}>
                  {customAddCat === cat && (
                    <div className="flex gap-1.5 mb-2 pb-2" style={{ borderBottom: `1px solid ${c}22` }}>
                      <input
                        autoFocus
                        value={customAddValue}
                        onChange={(e) => setCustomAddValue(e.target.value)}
                        onKeyDown={(e) => {
                          if (e.key === "Enter" && customAddValue.trim()) {
                            addPivotIOC(cat, customAddValue.trim(), "Manual");
                            setCustomAddValue("");
                          }
                          if (e.key === "Escape") setCustomAddCat(null);
                        }}
                        placeholder={`Add ${cat} indicator...`}
                        className="flex-1 rounded px-2 py-1 text-xs outline-none"
                        style={{ backgroundColor: "rgba(0,0,0,0.4)", border: `1px solid ${c}44`, color: "#dff" }}
                      />
                      <button onClick={() => { if (customAddValue.trim()) { addPivotIOC(cat, customAddValue.trim(), "Manual"); setCustomAddValue(""); } }}
                        className="rounded px-2 py-1 text-xs font-bold"
                        style={{ color: "#04111a", backgroundColor: c, cursor: "pointer", border: "none" }}>
                        Add</button>
                    </div>
                  )}
                  {shown.map((ioc, i) => {
                    const huntReady = isReg && huntReadySet.has(arr[i]);
                    const rowKey = `${cat}-i-${i}`;
                    const isCopied = copied === rowKey;
                    const isEditing = editingKey === rowKey;
                    const eKey = `${cat}::${arr[i]}`;
                    const enr = enrichCache[eKey];
                    const enrichable = ["IPV4","IPV6","DOMAIN","URL","MD5","SHA1","SHA256","SHA512","SSDEEP","IMPHASH","AUTHENTIHASH","CVE"].includes(cat);
                    // Precedence: row override > card/global effective (inheritedCollapse from card scope).
                    const isRowCollapsed = rowOverride[eKey] !== undefined ? rowOverride[eKey] : inheritedCollapse;
                    const isBlasting = blastNodes.has(arr[i]) || blastNodes.has(arr[i].toLowerCase());
                    return (
                      <div key={i} style={
                        isBlasting ? {
                          borderRadius: "6px",
                          animation: "hashBlast 0.95s ease-out forwards",
                        } : hoveredActionRow === eKey ? {
                          background: `${c}14`, borderRadius: "6px",
                          boxShadow: `inset 0 0 0 1px ${c}44`,
                          transition: "background 0.15s, box-shadow 0.15s",
                        } : {
                          transition: "background 0.15s, box-shadow 0.15s",
                        }
                      }>
                        <div className="group flex items-start gap-1.5 py-0.5 leading-relaxed"
                          draggable
                          onDragStart={(e) => { e.dataTransfer.setData("text/plain", arr[i]); handleDragStart(cat, arr[i]); }}
                          onDragEnd={handleDragEnd}
                          title={huntReady ? "Hunt-ready: key + value captured — enriches the hunt queries below" : undefined}
                          style={{ cursor: "grab" }}>
                          <span className="text-xs shrink-0" style={{ color: `${c}aa`, userSelect: "none" }}>›</span>
                          {isEditing ? (
                            <input
                              autoFocus
                              value={editValue}
                              onChange={(e) => setEditValue(e.target.value)}
                              onKeyDown={(e) => {
                                if (e.key === "Enter") editIoc(cat, arr[i], editValue);
                                if (e.key === "Escape") setEditingKey(null);
                              }}
                              onBlur={() => editIoc(cat, arr[i], editValue)}
                              className="text-xs flex-1 min-w-0 rounded px-1 py-0.5 outline-none"
                              style={{ backgroundColor: "rgba(0,229,255,0.08)", border: "1px solid rgba(0,229,255,0.4)", color: "#dff" }}
                            />
                          ) : (
                          <span className="text-xs break-all flex-1 min-w-0"
                            style={{ color: huntReady ? "#f3ddfa" : "#c8d6dd", fontWeight: huntReady ? 600 : 400 }}>
                            {ioc}
                            {originData?.[cat]?.[arr[i]]?.startsWith?.("pivot:") && (
                              <span className="ml-1.5 text-[9px] rounded px-1 py-0.5 align-middle"
                                style={{ color: "#22d3ee", backgroundColor: "rgba(34,211,238,0.12)", border: "1px solid rgba(34,211,238,0.3)" }}>
                                Pivot: {originData[cat][arr[i]].slice(6)}
                              </span>
                            )}
                            {enr?.data?.domainReg?.state === "deleted" && (
                              <span className="ml-1.5 text-[9px] rounded px-1 py-0.5 align-middle font-bold"
                                style={{ color: "#ff4d6d", backgroundColor: "rgba(255,77,109,0.15)", border: "1px solid rgba(255,77,109,0.3)" }}>
                                🔴 Domain Deleted / Taken Down
                              </span>
                            )}
                            {enr?.data?.domainReg?.state === "active" && enr.data.domainReg.ageDays != null && enr.data.domainReg.ageDays < 30 && (
                              <span className="ml-1.5 text-[9px] rounded px-1 py-0.5 align-middle font-bold"
                                style={{ color: "#ff4d6d", backgroundColor: "rgba(255,77,109,0.15)", border: "1px solid rgba(255,77,109,0.3)" }}>
                                🔴 Newly Created Domain
                              </span>
                            )}
                            {/* In-flight indicator: partial data exists but more engines still running */}
                            {enr?.loading && enr?.data && (
                              <span className="ml-1 inline-flex items-center" title="Enrichment still in progress — more data arriving">
                                <Loader2 size={10} className="animate-spin" style={{ color: "#5d7382" }} />
                              </span>
                            )}
                            {isRowCollapsed && enr?.data?._verdict && (
                              <span className="ml-1.5 text-[9px] rounded px-1.5 py-0.5 align-middle font-bold" style={{
                                color: enr.data._verdict === "Malicious" ? "#ff4d6d" : enr.data._verdict === "Suspicious" ? "#fbbf24" : enr.data._verdict === "Whitelisted" ? "#00ff9c" : "#8aa0ad",
                                backgroundColor: enr.data._verdict === "Malicious" ? "rgba(255,77,109,0.15)" : enr.data._verdict === "Suspicious" ? "rgba(251,191,36,0.15)" : enr.data._verdict === "Whitelisted" ? "rgba(0,255,156,0.15)" : "rgba(138,160,173,0.15)",
                                border: `1px solid ${enr.data._verdict === "Malicious" ? "rgba(255,77,109,0.4)" : enr.data._verdict === "Suspicious" ? "rgba(251,191,36,0.4)" : enr.data._verdict === "Whitelisted" ? "rgba(0,255,156,0.4)" : "rgba(138,160,173,0.3)"}`,
                              }}>
                                {enr.data._verdict === "Malicious" ? "🔴" : enr.data._verdict === "Suspicious" ? "🟡" : enr.data._verdict === "Whitelisted" ? "🟢" : "⚪"} {enr.data._verdict === "Unknown" ? "Unknown - Check VirusTotal" : enr.data._verdict}
                              </span>
                            )}
                            {enr?.data?.domainReg?.state === "active" && enr?.data?.domainReg?.status && /client.?hold|server.?hold/i.test(enr.data.domainReg.status) && (
                              <span className="ml-1.5 text-[9px] rounded px-1 py-0.5 align-middle font-bold"
                                style={{ color: "#f59e0b", backgroundColor: "rgba(245,158,11,0.15)", border: "1px solid rgba(245,158,11,0.3)" }}>
                                🟠 Domain Suspended / Registrar Hold
                              </span>
                            )}
                            {enr?.data?.domainReg?.state === "active" && enr?.data?.domainReg?.status && /redemption.?period|pending.?delete/i.test(enr.data.domainReg.status) && (
                              <span className="ml-1.5 text-[9px] rounded px-1 py-0.5 align-middle font-bold"
                                style={{ color: "#ff4d6d", backgroundColor: "rgba(255,77,109,0.15)", border: "1px solid rgba(255,77,109,0.3)" }}>
                                🔴 Domain Pending Deletion
                              </span>
                            )}
                          </span>
                          )}
                          {enr?.data && (
                            <button onClick={() => setRowOverride((p) => ({ ...p, [eKey]: !isRowCollapsed }))}
                              title={isRowCollapsed ? "Expand this indicator" : "Collapse this indicator"}
                              className="shrink-0 rounded-md p-1 opacity-60 hover:opacity-100 transition-opacity"
                              style={{ color: c }}>
                              <ChevronDown size={14} style={{ transform: isRowCollapsed ? "rotate(-90deg)" : "rotate(0deg)", transition: "transform 0.2s ease" }} />
                            </button>
                          )}
                          {enrichable && (
                            <button onClick={() => enrichIOC(cat, arr[i])}
                              onMouseEnter={() => setHoveredActionRow(eKey)} onMouseLeave={() => setHoveredActionRow(null)}
                              title="Enrich via ThreatFox / URLhaus / MalwareBazaar / OTX"
                              className="shrink-0 rounded-md p-1 opacity-50 hover:opacity-100 transition-opacity"
                              style={{ color: enr?.data ? "#00ff9c" : enr?.error ? "#ff6b6b" : "#c084fc" }}>
                              {enr?.loading ? <Loader2 size={14} className="animate-spin" /> : <Search size={14} />}
                            </button>
                          )}
                          {vtLink(cat, arr[i]) && (
                            <a href={vtLink(cat, arr[i])} target="_blank" rel="noreferrer noopener"
                              onMouseEnter={() => setHoveredActionRow(eKey)} onMouseLeave={() => setHoveredActionRow(null)}
                              title="Open in VirusTotal"
                              className="shrink-0 rounded-md p-1 opacity-50 hover:opacity-100 transition-opacity flex items-center justify-center"
                              style={{ width: 26, height: 26 }}>
                              <img src="https://www.virustotal.com/gui/images/favicon.png" alt="VT" width={14} height={14} style={{ display: "block", marginTop: "-1px" }} />
                            </a>
                          )}
                          <button onClick={() => copyText(ioc, rowKey)}
                            onMouseEnter={() => setHoveredActionRow(eKey)} onMouseLeave={() => setHoveredActionRow(null)}
                            title="Copy this indicator"
                            className="shrink-0 rounded-md p-1 opacity-50 hover:opacity-100 transition-opacity"
                            style={{ color: isCopied ? c : "#8aa0ad" }}>
                            {isCopied ? <Check size={16} /> : <Copy size={16} />}
                          </button>
                          <button onClick={() => { setEditingKey(rowKey); setEditValue(arr[i]); }}
                            onMouseEnter={() => setHoveredActionRow(eKey)} onMouseLeave={() => setHoveredActionRow(null)}
                            title="Edit this indicator"
                            className="shrink-0 rounded-md p-1 opacity-50 hover:opacity-100 transition-opacity"
                            style={{ color: "#8aa0ad" }}>
                            <Pencil size={14} />
                          </button>
                          {/* Move to category — inline dropdown when active */}
                          {movingKey === eKey ? (
                            <div className="relative shrink-0">
                              <select
                                autoFocus
                                defaultValue=""
                                onChange={(e) => { if (e.target.value) moveIoc(cat, arr[i], e.target.value); }}
                                onBlur={() => setMovingKey(null)}
                                className="rounded-md text-[10px] px-1.5 py-0.5 outline-none"
                                style={{ background: "rgba(10,14,20,0.97)", border: "1px solid rgba(0,229,255,0.5)", color: "#00e5ff", cursor: "pointer" }}>
                                <option value="" disabled>Move to…</option>
                                {ALL_IOC_CATS.filter((c) => c !== cat).map((c) => (
                                  <option key={c} value={c}>{c}</option>
                                ))}
                              </select>
                            </div>
                          ) : (
                            <button onClick={() => setMovingKey(eKey)}
                              onMouseEnter={() => setHoveredActionRow(eKey)} onMouseLeave={() => setHoveredActionRow(null)}
                              title="Move to another category"
                              className="shrink-0 rounded-md p-1 opacity-50 hover:opacity-100 transition-opacity"
                              style={{ color: "#8aa0ad" }}>
                              <Share2 size={13} />
                            </button>
                          )}
                          <button onClick={() => removeIoc(cat, arr[i])}
                            onMouseEnter={() => setHoveredActionRow(eKey)} onMouseLeave={() => setHoveredActionRow(null)}
                            title="Discard this indicator"
                            className="shrink-0 rounded-md p-1 opacity-50 hover:opacity-100 transition-opacity"
                            style={{ color: "#ff6b6b" }}>
                            <X size={16} />
                          </button>
                        </div>
                        {enr?.data && (() => {
                          const d = enr.data;
                          const isHash = ["MD5","SHA1","SHA256","SHA512"].includes(cat);
                          const isIP = ["IPV4","IPV6"].includes(cat);
                          const isDomUrl = ["DOMAIN","URL"].includes(cat);
                          const isIpAsDomain = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(arr[i]);
                          const hasVerdict = d._verdict && d._verdict !== "Unknown";
                          const hasThreatfox = !!d.threatfox;
                          const hasMalBaz = !!d.malwarebazaar;
                          const hasUrlhaus = !!d.urlhaus;
                          const hasOtx = !!d.otx;
                          const hasAbuse = !!d.abuseipdb;
                          const hasValidin = !!d.validin;
                          const hasGeo = !!d.whoisASN;
                          const hasUrlscan = !!d.urlscan;
                          const hasTimeline = !!d._timeline;
                          const hasDomainReg = isDomUrl && !isIpAsDomain && !!d.domainReg;
                          // Layer 1 = RDAP registration date (authoritative).
                          // Layer 2 = urlscan apex first-sighting (observational),
                          // used only when Layer 1 produced no registration date.
                          const layer1Ok = hasDomainReg && d.domainReg.state === "active" && d.domainReg.ageDays != null;
                          const hasApexObs = isDomUrl && !isIpAsDomain && !layer1Ok
                            && d.domainReg?.state !== "deleted" && d.urlscan?.apexAgeDays != null;
                          const hasWhois = !!d.whois;
                          const hasShodan = !!d.shodan;
                          const hasSansIsc = !!d.sansIsc;
                          const hasCisaKev = !!d.cisaKev;
                          const hasEpss = !!d.epss;
                          const hasNvd = !!d.nvd;
                          const hasCircl = !!d.circl;
                          const hasKaspersky = !!d.kaspersky;
                          const hasPivotIP = hasUrlscan && d.urlscan.servingIP && d.urlscan.servingIP !== arr[i];
                          const isCondensed = isRowCollapsed;
                          // Compact row: bold label on the left, chips flowing right
                          const secRow = (label, children) => (
                            <div className="flex items-start gap-2 py-0.5">
                              <span className="text-[9px] uppercase tracking-widest font-black shrink-0 pt-0.5" style={{ color: "#8aa0ad", width: "104px", letterSpacing: "1.5px" }}>{label}</span>
                              <div className="flex flex-wrap gap-1 flex-1 min-w-0">{children}</div>
                            </div>
                          );
                          return (
                          <div className="ml-4 mb-1.5 text-[10px]">
                            {/* Provenance badge — shown when this SHA256 card received data via hash dedup */}
                            {d._sourcedFrom && (
                              <div className="flex items-center gap-2 mb-2 rounded-lg px-2.5 py-1.5"
                                style={{ background: "rgba(124,156,255,0.08)", border: "1px solid rgba(124,156,255,0.3)" }}>
                                <span style={{ color: "#7c9cff" }}>🔗 Enrichment data sourced from {d._sourcedFrom.cat} <span style={{ fontFamily: "monospace" }}>{d._sourcedFrom.value.slice(0,16)}…</span> — partial results until re-enriched as SHA256</span>
                                <button onClick={() => { const newKey = `SHA256::${arr[i]}`; setEnrichCache(c=>({...c,[newKey]:undefined})); enrichIOC("SHA256", arr[i]); }}
                                  className="shrink-0 rounded-md px-2 py-0.5 text-[10px] font-bold"
                                  style={{ color: "#04111a", background: "#7c9cff", border: "none", cursor: "pointer" }}>
                                  Re-enrich as SHA256
                                </button>
                              </div>
                            )}
                            {/* ── VERDICT & IDENTITY ── */}
                            {!isCondensed && cat === "CVE" && (hasCisaKev || hasEpss || hasNvd) && secRow("Vulnerability Intel", (
                              <>
                                  {hasCisaKev && d.cisaKev.listed && (
                                    <span className="rounded-full px-2 py-0.5 font-bold" style={{ color: "#ff4d6d", backgroundColor: "rgba(255,77,109,0.15)", border: "1px solid rgba(255,77,109,0.4)" }}
                                      title="CISA Known Exploited Vulnerabilities catalog — confirmed active exploitation in the wild">
                                      🔴 CISA KEV · Actively Exploited{d.cisaKev.dateAdded ? ` · Added ${d.cisaKev.dateAdded}` : ""}{d.cisaKev.dueDate ? ` · Remediate by ${d.cisaKev.dueDate}` : ""}{d.cisaKev.ransomwareUse ? ` · 🔒 Ransomware use: ${d.cisaKev.ransomwareUse}` : ""}
                                    </span>
                                  )}
                                  {hasCisaKev && !d.cisaKev.listed && (
                                    <span className="rounded-full px-2 py-0.5" style={{ color: "#8aa0ad", backgroundColor: "rgba(138,160,173,0.08)", border: "1px solid rgba(138,160,173,0.25)" }}>
                                      ⚪ CISA KEV · Not listed
                                    </span>
                                  )}
                                  {hasEpss && (
                                    <span className="rounded-full px-2 py-0.5" style={{
                                      color: d.epss.score >= 50 ? "#fbbf24" : "#8aa0ad",
                                      backgroundColor: d.epss.score >= 50 ? "rgba(251,191,36,0.10)" : "rgba(138,160,173,0.08)",
                                      border: `1px solid ${d.epss.score >= 50 ? "rgba(251,191,36,0.35)" : "rgba(138,160,173,0.25)"}`,
                                    }} title="EPSS — Exploit Prediction Scoring System (first.org): probability of exploitation in the next 30 days">
                                      {d.epss.score >= 50 ? "🟡" : "⚪"} EPSS · {d.epss.score}% (30-day exploitation probability, {d.epss.percentile}th percentile)
                                    </span>
                                  )}
                                  {hasNvd && (
                                    <span className="flex flex-col gap-0.5">
                                      <span className="rounded-full px-2 py-0.5" style={{
                                        color: (d.nvd.cvss || 0) >= 9 ? "#ff4d6d" : (d.nvd.cvss || 0) >= 7 ? "#fbbf24" : "#4ade80",
                                        backgroundColor: (d.nvd.cvss || 0) >= 9 ? "rgba(255,77,109,0.10)" : (d.nvd.cvss || 0) >= 7 ? "rgba(251,191,36,0.10)" : "rgba(74,222,128,0.08)",
                                        border: `1px solid ${(d.nvd.cvss || 0) >= 9 ? "rgba(255,77,109,0.3)" : (d.nvd.cvss || 0) >= 7 ? "rgba(251,191,36,0.3)" : "rgba(74,222,128,0.3)"}`,
                                      }} title="NVD (National Vulnerability Database) — severity is shown as context only and does not by itself drive the verdict">
                                        NVD · CVSS {d.nvd.cvss ?? "—"}{d.nvd.severity ? ` (${d.nvd.severity})` : ""}{d.nvd.published ? ` · Published ${d.nvd.published}` : ""}
                                      </span>
                                      {d.nvd.description && (
                                        <span className="rounded-full px-2 py-0.5 text-[10px]" style={{ color: "#7f95a3", backgroundColor: "rgba(148,163,184,0.04)", border: "1px solid rgba(148,163,184,0.15)" }}>
                                          {d.nvd.description.length > 220 ? d.nvd.description.slice(0, 220) + "…" : d.nvd.description}
                                        </span>
                                      )}
                                    </span>
                                  )}
                              </>
                            ))}
                            {!isCondensed && (hasVerdict || hasThreatfox || hasMalBaz || hasUrlhaus || hasCircl || (hasKaspersky && isHash)) && secRow("Verdict & Identity", (
                              <>
                                  {hasVerdict && (
                                    <span className="rounded-full px-2 py-0.5 font-bold" style={{
                                      color: d._verdict === "Malicious" ? "#ff4d6d" : d._verdict === "Suspicious" ? "#fbbf24" : d._verdict === "Whitelisted" ? "#00ff9c" : "#8aa0ad",
                                      backgroundColor: d._verdict === "Malicious" ? "rgba(255,77,109,0.15)" : d._verdict === "Suspicious" ? "rgba(251,191,36,0.15)" : d._verdict === "Whitelisted" ? "rgba(0,255,156,0.15)" : "rgba(138,160,173,0.15)",
                                      border: `1px solid ${d._verdict === "Malicious" ? "rgba(255,77,109,0.4)" : d._verdict === "Suspicious" ? "rgba(251,191,36,0.4)" : d._verdict === "Whitelisted" ? "rgba(0,255,156,0.4)" : "rgba(138,160,173,0.3)"}`,
                                    }}>
                                      {d._verdict === "Malicious" ? "🔴" : d._verdict === "Suspicious" ? "🟡" : d._verdict === "Whitelisted" ? "🟢" : "⚪"} {d._verdict}
                                    </span>
                                  )}
                                  {hasThreatfox && (
                                    <span className="rounded-full px-2 py-0.5" style={{ color: "#ff4d6d", backgroundColor: "rgba(255,77,109,0.12)", border: "1px solid rgba(255,77,109,0.3)" }}>
                                      ThreatFox · {d.threatfox.malware} · {d.threatfox.threat}{d.threatfox.confidence ? ` · ${d.threatfox.confidence}%` : ""}{d.threatfox.tags ? ` · ${d.threatfox.tags}` : ""}
                                    </span>
                                  )}
                                  {hasUrlhaus && (
                                    <span className="rounded-full px-2 py-0.5" style={{
                                      color: d.urlhaus.status === "online" ? "#ff4d6d" : "#fbbf24",
                                      backgroundColor: d.urlhaus.status === "online" ? "rgba(255,77,109,0.12)" : "rgba(251,191,36,0.12)",
                                      border: `1px solid ${d.urlhaus.status === "online" ? "rgba(255,77,109,0.3)" : "rgba(251,191,36,0.3)"}`,
                                    }}>
                                      URLhaus · {d.urlhaus.status === "online" ? "🔴 Online" : "⚫ Offline"}{d.urlhaus.urls_total ? ` · ${d.urlhaus.urls_total} URLs` : ""}{d.urlhaus.tags ? ` · ${d.urlhaus.tags}` : ""}
                                    </span>
                                  )}
                                  {hasMalBaz && (
                                    <span className="rounded-full px-2 py-0.5" style={{ color: "#00e5ff", backgroundColor: "rgba(0,229,255,0.12)", border: "1px solid rgba(0,229,255,0.3)" }}>
                                      MalBazaar · {d.malwarebazaar.family} · {d.malwarebazaar.type}{d.malwarebazaar.size ? ` · ${d.malwarebazaar.size}` : ""}{d.malwarebazaar.delivery ? ` · via ${d.malwarebazaar.delivery}` : ""}{d.malwarebazaar.tags ? ` · ${d.malwarebazaar.tags}` : ""}
                                    </span>
                                  )}
                                  {(d.malwarebazaar?.detections || d.malwarebazaar?.fileName) && (
                                    <span className="rounded-full px-2 py-0.5" style={{ color: "#ff4d6d", backgroundColor: "rgba(245,158,11,0.12)", border: "1px solid rgba(245,158,11,0.3)" }}>
                                      🔴 {d.malwarebazaar.fileName ? d.malwarebazaar.fileName + (d.malwarebazaar.detections ? " | " : "") : ""}{d.malwarebazaar.detections || ""}
                                    </span>
                                  )}
                                  {d.malwarebazaar?.codeSign && (
                                    <span className="rounded-full px-2 py-0.5" style={{ color: "#fbbf24", backgroundColor: "rgba(251,191,36,0.10)", border: "1px solid rgba(251,191,36,0.35)" }}
                                      title="Code-signed malware — stolen or abused certificate">
                                      ✍️ Signed{d.malwarebazaar.codeSign.subject ? ` · Subject: ${d.malwarebazaar.codeSign.subject}` : ""}{d.malwarebazaar.codeSign.issuer ? ` · Issuer: ${d.malwarebazaar.codeSign.issuer}` : ""}{d.malwarebazaar.codeSign.algorithm ? ` · ${d.malwarebazaar.codeSign.algorithm}` : ""}
                                    </span>
                                  )}
                                  {d.circl && (
                                    <span className="flex flex-col gap-0.5">
                                      <span className="rounded-full px-2 py-0.5" style={{
                                        color: d.circl.legit ? "#4ade80" : "#94a3b8",
                                        backgroundColor: d.circl.legit ? "rgba(74,222,128,0.10)" : "rgba(148,163,184,0.08)",
                                        border: `1px solid ${d.circl.legit ? "rgba(74,222,128,0.35)" : "rgba(148,163,184,0.25)"}`,
                                      }} title="CIRCL hashlookup — NSRL and community-attested known files">
                                        {d.circl.legit ? "🟢 Known Legitimate" : "🔵 CIRCL Known"}
                                        {d.circl.trust != null ? ` · Trust ${d.circl.trust}/100` : ""}
                                        {d.circl.parentTotal != null ? ` · Found in ${d.circl.parentTotal} packages` : ""}
                                        {d.circl.fileName ? ` · ${d.circl.fileName}` : ""}
                                        {d.circl.fileSize ? ` (${d.circl.fileSize})` : ""}
                                        {d.circl.mimetype ? ` · ${d.circl.mimetype}` : ""}
                                        {d.circl.source ? ` · Source: ${d.circl.source}` : ""}
                                      </span>
                                      {(d.circl.productName || d.circl.packageVersion || d.circl.maintainer) && (
                                        <span className="rounded-full px-2 py-0.5 text-[10px]" style={{ color: "#8aa0ad", backgroundColor: "rgba(148,163,184,0.06)", border: "1px solid rgba(148,163,184,0.2)" }}>
                                          📦 {[
                                            d.circl.productName,
                                            d.circl.packageVersion,
                                            d.circl.os,
                                          ].filter(Boolean).join(" ")}
                                          {d.circl.maintainer ? ` · 👤 ${d.circl.maintainer}` : ""}
                                        </span>
                                      )}
                                      {d.circl.description && (
                                        <span className="rounded-full px-2 py-0.5 text-[10px]" style={{ color: "#7f95a3", backgroundColor: "rgba(148,163,184,0.04)", border: "1px solid rgba(148,163,184,0.15)" }}>
                                          {d.circl.description}
                                        </span>
                                      )}
                                    </span>
                                  )}
                                  {d.triage && (() => {
                                    const score = d.triage.score || 0;
                                    const col = score >= 8 ? "#ff4d6d" : score >= 5 ? "#fbbf24" : "#00ff9c";
                                    const bg = score >= 8 ? "rgba(255,77,109,0.12)" : score >= 5 ? "rgba(251,191,36,0.10)" : "rgba(0,255,156,0.08)";
                                    const bd = score >= 8 ? "rgba(255,77,109,0.35)" : score >= 5 ? "rgba(251,191,36,0.35)" : "rgba(0,255,156,0.3)";
                                    const icon = score >= 8 ? "🔴" : score >= 5 ? "🟡" : "🟢";
                                    return (
                                      <span className="flex flex-col gap-0.5">
                                        <span className="rounded-full px-2 py-0.5" style={{ color: col, backgroundColor: bg, border: `1px solid ${bd}` }}
                                          title="Tri.age (Recorded Future Sandbox) behavioral analysis">
                                          {icon} Tri.age · Score {score}/10
                                          {d.triage.families?.length ? ` · ${d.triage.families.join(", ")}` : ""}
                                          {d.triage.filename ? ` · ${d.triage.filename}` : ""}
                                          {d.triage.submitted ? ` · Submitted ${fmtDate(d.triage.submitted)}` : ""}
                                          {" · "}<a href={d.triage.triageUrl} target="_blank" rel="noreferrer noopener" style={{ textDecoration: "underline", color: "inherit" }}>View</a>
                                        </span>
                                        {d.triage.tags?.length > 0 && (
                                          <span className="rounded-full px-2 py-0.5 text-[9px]" style={{ color: "#8aa0ad", backgroundColor: "rgba(148,163,184,0.06)", border: "1px solid rgba(148,163,184,0.2)" }}>
                                            🏷️ {d.triage.tags.join(", ")}
                                          </span>
                                        )}
                                        {d.triage.c2Urls?.length > 0 && (
                                          <span className="rounded-full px-2 py-0.5 text-[9px]" style={{ color: "#ff8a9b", backgroundColor: "rgba(255,77,109,0.08)", border: "1px solid rgba(255,77,109,0.3)" }}>
                                            📡 C2: {d.triage.c2Urls.slice(0, 3).join(", ")}{d.triage.c2Urls.length > 3 ? ` +${d.triage.c2Urls.length - 3} more` : ""}
                                          </span>
                                        )}
                                      </span>
                                    );
                                  })()}
                                  {d.hybridAnalysis && (() => {
                                    const ha = d.hybridAnalysis;
                                    const isHashHA = ["MD5","SHA1","SHA256","SHA512"].includes(cat);
                                    const score = ha.threatScore || 0;
                                    const col = ha.verdict === "malicious" || score >= 70 ? "#ff4d6d" : ha.verdict === "suspicious" || score >= 30 ? "#fbbf24" : "#4ade80";
                                    const bg = ha.verdict === "malicious" || score >= 70 ? "rgba(255,77,109,0.12)" : ha.verdict === "suspicious" || score >= 30 ? "rgba(251,191,36,0.10)" : "rgba(74,222,128,0.08)";
                                    const bd = ha.verdict === "malicious" || score >= 70 ? "rgba(255,77,109,0.35)" : ha.verdict === "suspicious" || score >= 30 ? "rgba(251,191,36,0.35)" : "rgba(74,222,128,0.3)";
                                    const icon = ha.verdict === "malicious" || score >= 70 ? "🔴" : ha.verdict === "suspicious" || score >= 30 ? "🟡" : "🟢";
                                    return (
                                      <span className="flex flex-col gap-0.5">
                                        <span className="rounded-full px-2 py-0.5" style={{ color: col, backgroundColor: bg, border: `1px solid ${bd}` }}
                                          title="Hybrid Analysis (Falcon Sandbox) — CrowdStrike behavioral sandbox">
                                          {icon} Hybrid Analysis{isHashHA && score > 0 ? ` · Score ${score}/100` : ""}
                                          {isHashHA ? ` · ${(ha.verdict || "unknown").charAt(0).toUpperCase() + (ha.verdict || "unknown").slice(1)}` : ` · ${ha.submissions} submission${ha.submissions !== 1 ? "s" : ""}`}
                                          {ha.family ? ` · ${ha.family}` : (ha.families ? ` · ${ha.families}` : "")}
                                          {ha.avDetect ? ` · AV ${ha.avDetect}%` : ""}
                                          {ha.fileName ? ` · ${ha.fileName}` : ""}
                                          {ha.fileType ? ` · ${ha.fileType}` : ""}
                                          {ha.fileSize ? ` (${ha.fileSize})` : ""}
                                          {isHashHA && ha.envDesc ? ` · ${ha.envDesc}` : ""}
                                          {!isHashHA && ha.malicious > 0 ? ` · 🔴 ${ha.malicious} malicious` : ""}
                                          {!isHashHA && ha.suspicious > 0 ? ` · 🟡 ${ha.suspicious} suspicious` : ""}
                                          {ha.reportUrl ? <>{" · "}<a href={ha.reportUrl} target="_blank" rel="noreferrer noopener" style={{ textDecoration: "underline", color: "inherit" }}>View</a></> : ""}
                                        </span>
                                        {ha.classifTags && (
                                          <span className="rounded-full px-2 py-0.5 text-[9px]" style={{ color: "#8aa0ad", backgroundColor: "rgba(148,163,184,0.06)", border: "1px solid rgba(148,163,184,0.2)" }}>
                                            🏷️ {ha.classifTags}
                                          </span>
                                        )}
                                        {ha.tags && (
                                          <span className="rounded-full px-2 py-0.5 text-[9px]" style={{ color: "#8aa0ad", backgroundColor: "rgba(148,163,184,0.06)", border: "1px solid rgba(148,163,184,0.2)" }}>
                                            🔬 {ha.tags}
                                          </span>
                                        )}
                                        {ha.mitreAttacks && ha.mitreAttacks.length > 0 && (
                                          <span className="rounded-full px-2 py-0.5 text-[9px]" style={{ color: "#f43f5e", backgroundColor: "rgba(244,63,94,0.08)", border: "1px solid rgba(244,63,94,0.25)" }}>
                                            🎯 MITRE: {ha.mitreAttacks.join(", ")}
                                          </span>
                                        )}
                                        {ha.compromised && ha.compromised.length > 0 && (
                                          <span className="rounded-full px-2 py-0.5 text-[9px]" style={{ color: "#ff8a9b", backgroundColor: "rgba(255,77,109,0.08)", border: "1px solid rgba(255,77,109,0.3)" }}>
                                            📡 C2: {ha.compromised.join(", ")}
                                          </span>
                                        )}
                                        {ha.submitContext && ha.submitContext.length > 0 && (
                                          <span className="rounded-full px-2 py-0.5 text-[9px]" style={{ color: "#ffb84d", backgroundColor: "rgba(255,184,77,0.08)", border: "1px solid rgba(255,184,77,0.3)" }}>
                                            ⬇️ Downloaded from: {ha.submitContext.join(", ")}
                                          </span>
                                        )}
                                        {isHashHA && (ha.netConns > 0 || ha.totalProcs > 0 || ha.totalSigs > 0) && (
                                          <span className="rounded-full px-2 py-0.5 text-[9px]" style={{ color: "#8aa0ad", backgroundColor: "rgba(148,163,184,0.04)", border: "1px solid rgba(148,163,184,0.15)" }}>
                                            📊 {ha.totalProcs} processes · {ha.netConns} network · {ha.totalSigs} signatures
                                          </span>
                                        )}
                                      </span>
                                    );
                                  })()}
                                  {isHash && d.kaspersky && (() => {
                                    const z = d.kaspersky.zone;
                                    const c = z === "red" ? "#ff4d6d" : z === "yellow" ? "#fbbf24" : z === "green" ? "#4ade80" : "#94a3b8";
                                    const bg = z === "red" ? "rgba(255,77,109,0.12)" : z === "yellow" ? "rgba(251,191,36,0.10)" : z === "green" ? "rgba(74,222,128,0.10)" : "rgba(148,163,184,0.08)";
                                    const bd = z === "red" ? "rgba(255,77,109,0.35)" : z === "yellow" ? "rgba(251,191,36,0.35)" : z === "green" ? "rgba(74,222,128,0.35)" : "rgba(148,163,184,0.25)";
                                    const icon = z === "red" ? "🔴" : z === "yellow" ? "🟡" : z === "green" ? "🟢" : "⚪";
                                    return (
                                      <span className="rounded-full px-2 py-0.5" style={{ color: c, backgroundColor: bg, border: `1px solid ${bd}` }}
                                        title="Kaspersky OpenTIP — vendor threat intelligence">
                                        {icon} Kaspersky · {z.charAt(0).toUpperCase() + z.slice(1)} Zone
                                        {d.kaspersky.fileStatus ? ` · ${d.kaspersky.fileStatus}` : ""}
                                        {d.kaspersky.detections ? ` · ${d.kaspersky.detections}` : ""}
                                        {d.kaspersky.productName ? ` · ${d.kaspersky.productName}` : ""}
                                        {d.kaspersky.size ? ` · ${d.kaspersky.size}` : ""}
                                        {d.kaspersky.signer ? ` · Signer: ${d.kaspersky.signer}` : ""}
                                      </span>
                                    );
                                  })()}
                              </>
                            ))}

                            {/* ── REPUTATION ── */}
                            {!isCondensed && (hasOtx || hasAbuse || hasValidin || (hasKaspersky && !isHash) || d._verdict === "Unknown") && secRow("Reputation", (
                              <>
                                  {d._verdict === "Unknown" && d.domainReg?.state !== "deleted" && (
                                    <span className="rounded-full px-2 py-0.5 font-bold" style={{ color: "#5d7382", backgroundColor: "rgba(148,163,184,0.08)", border: "1px solid rgba(148,163,184,0.2)" }}>
                                      ⚪ Unknown - Check VirusTotal
                                    </span>
                                  )}
                                  {hasOtx && d._verdict !== "Unknown" && (
                                    <span className="rounded-full px-2 py-0.5" style={{ color: "#2dd4bf", backgroundColor: "rgba(45,212,191,0.12)", border: "1px solid rgba(45,212,191,0.3)" }}>
                                      OTX · {d.otx.pulses} pulses{d.otx.validation ? ` · ${d.otx.validation}` : ""}{d.otx.tags ? ` · ${d.otx.tags}` : ""}{d.otx.parentDomain ? ` (via ${d.otx.parentDomain})` : ""}
                                    </span>
                                  )}
                                  {hasAbuse && (
                                    <span className="rounded-full px-2 py-0.5" style={{
                                      color: (d.abuseipdb.score || 0) >= 80 ? "#ff4d6d" : (d.abuseipdb.score || 0) >= 25 ? "#fbbf24" : "#2dd4bf",
                                      backgroundColor: (d.abuseipdb.score || 0) >= 80 ? "rgba(255,77,109,0.12)" : (d.abuseipdb.score || 0) >= 25 ? "rgba(251,191,36,0.12)" : "rgba(45,212,191,0.08)",
                                      border: `1px solid ${(d.abuseipdb.score || 0) >= 80 ? "rgba(255,77,109,0.3)" : (d.abuseipdb.score || 0) >= 25 ? "rgba(251,191,36,0.3)" : "rgba(45,212,191,0.25)"}`,
                                    }}>
                                      AbuseIPDB · {d.abuseipdb.score}% Confidence · {d.abuseipdb.reports} Report{d.abuseipdb.reports !== 1 ? "s" : ""}{d.abuseipdb.categories ? ` · ${d.abuseipdb.categories}` : ""}{d.abuseipdb.lastReported ? ` · Last: ${d.abuseipdb.lastReported}` : ""}
                                    </span>
                                  )}
                                  {hasValidin && (
                                    <span className="rounded-full px-2 py-0.5" style={{
                                      color: d.validin.verdict === "malicious" ? "#ff4d6d" : d.validin.verdict === "suspicious" ? "#fbbf24" : "#e879f9",
                                      backgroundColor: d.validin.verdict === "malicious" ? "rgba(255,77,109,0.12)" : d.validin.verdict === "suspicious" ? "rgba(251,191,36,0.12)" : "rgba(232,121,249,0.12)",
                                      border: `1px solid ${d.validin.verdict === "malicious" ? "rgba(255,77,109,0.3)" : d.validin.verdict === "suspicious" ? "rgba(251,191,36,0.3)" : "rgba(232,121,249,0.3)"}`,
                                    }}>
                                      Validin{d.validin.verdict ? ` · ${d.validin.verdict}` : ""}{d.validin.score !== null ? ` (${d.validin.score}/10)` : ""}{d.validin.maliciousCount > 0 ? ` · Malicious x ${d.validin.maliciousCount}` : ""}{d.validin.titles?.length ? ` · ${d.validin.titles.join(" · ")}` : ""}
                                    </span>
                                  )}
                                  {!isHash && d.kaspersky && (() => {
                                    const z = d.kaspersky.zone;
                                    // For domain/URL/IP, green means "unclassified", not trusted → show as Unknown.
                                    const greenIsUnknown = z === "green";
                                    const c = z === "red" ? "#ff4d6d" : z === "yellow" ? "#fbbf24" : "#8aa0ad";
                                    const bg = z === "red" ? "rgba(255,77,109,0.12)" : z === "yellow" ? "rgba(251,191,36,0.10)" : "rgba(148,163,184,0.08)";
                                    const bd = z === "red" ? "rgba(255,77,109,0.35)" : z === "yellow" ? "rgba(251,191,36,0.35)" : "rgba(148,163,184,0.25)";
                                    const icon = z === "red" ? "🔴" : z === "yellow" ? "🟡" : "⚪";
                                    const label = greenIsUnknown ? "Unknown" : (z.charAt(0).toUpperCase() + z.slice(1) + " Zone");
                                    return (
                                      <span className="rounded-full px-2 py-0.5" style={{ color: c, backgroundColor: bg, border: `1px solid ${bd}` }}
                                        title="Kaspersky OpenTIP — for domains/IPs, green means unclassified, not trusted">
                                        {icon} Kaspersky · {label}
                                        {!greenIsUnknown && d.kaspersky.categories ? ` · ${d.kaspersky.categories}` : ""}
                                        {!greenIsUnknown && d.kaspersky.hits != null ? ` · ${d.kaspersky.hits} hits` : ""}
                                        {d.kaspersky.country ? ` · ${d.kaspersky.country}` : ""}
                                      </span>
                                    );
                                  })()}
                              </>
                            ))}

                            {/* ── INFRASTRUCTURE (skip for hashes) ── */}
                            {!isCondensed && !isHash && (hasGeo || hasUrlscan || hasWhois || hasShodan || hasSansIsc) && secRow("Infrastructure", (
                              <>
                                  {hasGeo && (
                                    <span className="rounded-full px-2 py-0.5" style={{ color: "#a78bfa", backgroundColor: "rgba(167,139,250,0.12)", border: "1px solid rgba(167,139,250,0.3)" }}>
                                      GEO/ASN{d.whoisASN.country ? <>{" · "}<span style={{ color: "#eafcff", fontWeight: 700 }}>{d.whoisASN.flag ? d.whoisASN.flag + " " : ""}{d.whoisASN.country}</span></> : ""}{d.whoisASN.city ? ` (${d.whoisASN.city}${d.whoisASN.region ? `, ${d.whoisASN.region}` : ""})` : ""}{d.whoisASN.asn ? ` · ${d.whoisASN.asn}` : ""}{d.whoisASN.asnOrg ? ` · ${d.whoisASN.asnOrg}` : ""}{d.whoisASN.privacy ? <>{" · "}<span style={{ color: "#fbbf24", fontWeight: 700 }}>{d.whoisASN.privacy}</span></> : ""}
                                    </span>
                                  )}
                                  {hasUrlscan && (
                                    <span className="rounded-full px-2 py-0.5" style={{
                                      color: d.urlscan.malicious > 0 ? "#ff4d6d" : "#38bdf8",
                                      backgroundColor: d.urlscan.malicious > 0 ? "rgba(255,77,109,0.12)" : "rgba(56,189,248,0.10)",
                                      border: `1px solid ${d.urlscan.malicious > 0 ? "rgba(255,77,109,0.3)" : "rgba(56,189,248,0.3)"}`,
                                    }}>
                                      Urlscan.io · {d.urlscan.isPrimaryTarget ? `${d.urlscan.primaryScans} Scan${d.urlscan.primaryScans !== 1 ? "s" : ""}` : `${d.urlscan.scans} apex scan${d.urlscan.scans !== 1 ? "s" : ""}`}{d.urlscan.isPrimaryTarget && d.urlscan.malicious > 0 ? ` · 🔴 ${d.urlscan.malicious} Malicious` : ""}{d.urlscan.isPrimaryTarget && d.urlscan.title ? ` · "${d.urlscan.title}"` : ""}{d.urlscan.isPrimaryTarget && d.urlscan.server ? ` · ${d.urlscan.server}` : ""}{d.urlscan.isPrimaryTarget && d.urlscan.country && d.urlscan.flag ? ` · ${d.urlscan.flag}` : ""}
                                      {!d.urlscan.isPrimaryTarget && (
                                        <span className="text-[9px] ml-1" style={{ color: "#fbbf24" }} title="No urlscan scan targets this exact host. It only appears as a contacted domain / redirect hop inside scans of other URLs, so no host-specific verdict, title, or screenshot is shown.">⚠ host only seen as contacted domain — no direct scan</span>
                                      )}
                                      {d.urlscan.link && <>{" · "}<a href={d.urlscan.link} target="_blank" rel="noreferrer noopener" style={{ textDecoration: "underline", color: "inherit" }}>View</a></>}
                                      {" · "}<a href={d.urlscan.hostSearchLink || (isIP ? `https://urlscan.io/ip/${encodeURIComponent(arr[i])}` : `https://urlscan.io/domain/${encodeURIComponent(arr[i].replace(/^https?:\/\//i, "").split("/")[0])}`)} target="_blank" rel="noreferrer noopener" style={{ textDecoration: "underline", color: "#fbbf24" }}>History</a>
                                      {d.urlscan.isPrimaryTarget && d.urlscan.screenshot && (
                                        <span className="relative inline-block ml-1" style={{ cursor: "pointer" }}>
                                          <a href={d.urlscan.screenshot} target="_blank" rel="noreferrer noopener"
                                            className="peer text-[10px] px-1 py-0.5 rounded inline-block"
                                            style={{ color: "#c084fc", border: "1px solid rgba(192,132,252,0.3)", backgroundColor: "rgba(192,132,252,0.08)", textDecoration: "none" }}>
                                            🖥️ Screen
                                          </a>
                                          <span className="hidden peer-hover:block fixed z-[9999] rounded-lg shadow-2xl pointer-events-none"
                                            style={{ border: "2px solid rgba(192,132,252,0.5)", backgroundColor: "#0a0e14", padding: "4px", width: "400px", maxWidth: "90vw", left: "50%", top: "50%", transform: "translate(-50%, -50%)" }}>
                                            <img src={d.urlscan.screenshot} alt="Screenshot" loading="lazy"
                                              style={{ width: "100%", borderRadius: "6px", display: "block" }}
                                              onError={(e) => { e.target.parentElement.style.display = "none"; }} />
                                            <p className="text-[9px] text-center mt-1" style={{ color: "#5d7382" }}>{arr[i]}</p>
                                          </span>
                                        </span>
                                      )}
                                    </span>
                                  )}
                                  {hasUrlscan && d.urlscan.brands && d.urlscan.brands.length > 0 && (
                                    <span className="rounded-full px-2 py-0.5 font-bold" style={{ color: "#ff4d6d", backgroundColor: "rgba(255,77,109,0.12)", border: "1px solid rgba(255,77,109,0.4)" }}
                                      title="urlscan detected this page impersonating a known brand — strong phishing signal">
                                      🎭 Impersonates: {d.urlscan.brands.slice(0, 3).join(", ")}
                                    </span>
                                  )}
                                  {hasUrlscan && d.urlscan.tlsIssuer && (
                                    <span className="rounded-full px-2 py-0.5" style={{ color: "#8aa0ad", backgroundColor: "rgba(148,163,184,0.08)", border: "1px solid rgba(148,163,184,0.25)" }}
                                      title="TLS certificate — a very fresh cert on a brand-like domain is a phishing indicator">
                                      🔒 {d.urlscan.tlsIssuer}{d.urlscan.tlsAgeDays != null ? ` · cert ${smartAge(d.urlscan.tlsAgeDays)} old` : ""}
                                    </span>
                                  )}
                                  {hasWhois && (
                                    <span className="rounded-full px-2 py-0.5" style={{ color: "#a78bfa", backgroundColor: "rgba(167,139,250,0.12)", border: "1px solid rgba(167,139,250,0.3)" }}>
                                      WHOIS{d.whois.org ? ` · ${d.whois.org}` : ""}{d.whois.country ? ` · ${d.whois.country}` : ""}{d.whois.ageDays !== null ? ` · ${d.whois.ageDays}d old` : ""}
                                    </span>
                                  )}
                                  {hasShodan && (() => {
                                    const s = d.shodan;
                                    const vulnCount = s.vulns.length;
                                    // Bare-minimum snapshot always fits: N ports · CPEs · tags · CVEs.
                                    // Vulnerabilities carry the strongest signal → gate the colour on them.
                                    const hasCritical = vulnCount > 0;
                                    return (
                                      <span className="rounded-full px-2 py-0.5" style={{
                                        color: hasCritical ? "#fbbf24" : "#4ade80",
                                        backgroundColor: hasCritical ? "rgba(251,191,36,0.10)" : "rgba(74,222,128,0.08)",
                                        border: `1px solid ${hasCritical ? "rgba(251,191,36,0.35)" : "rgba(74,222,128,0.3)"}`,
                                      }} title="Shodan InternetDB — weekly refresh, exposure snapshot">
                                        🛰️ Shodan
                                        {s.ports.length ? ` · ${s.ports.length} port${s.ports.length !== 1 ? "s" : ""}: ${s.ports.slice(0, 8).join(", ")}${s.ports.length > 8 ? "…" : ""}` : ""}
                                        {s.tags.length ? ` · ${s.tags.join(", ")}` : ""}
                                        {s.cpes.length ? ` · ${s.cpes.slice(0, 3).join(", ")}${s.cpes.length > 3 ? "…" : ""}` : ""}
                                        {vulnCount ? (
                                          <> · <span style={{ color: "#ff4d6d", fontWeight: 700 }}>🔴 {vulnCount} CVE{vulnCount !== 1 ? "s" : ""}: {s.vulns.slice(0, 3).join(", ")}{vulnCount > 3 ? "…" : ""}</span></>
                                        ) : null}
                                      </span>
                                    );
                                  })()}
                                  {hasSansIsc && (
                                    <span className="rounded-full px-2 py-0.5" style={{
                                      color: d.sansIsc.attacks >= 5 ? "#fbbf24" : "#8aa0ad",
                                      backgroundColor: d.sansIsc.attacks >= 5 ? "rgba(251,191,36,0.10)" : "rgba(138,160,173,0.08)",
                                      border: `1px solid ${d.sansIsc.attacks >= 5 ? "rgba(251,191,36,0.35)" : "rgba(138,160,173,0.25)"}`,
                                    }} title="SANS ISC / DShield — crowd-sourced firewall log submissions">
                                      🛡️ SANS ISC · {d.sansIsc.attacks} attack{d.sansIsc.attacks !== 1 ? "s" : ""} reported{d.sansIsc.count ? ` (${d.sansIsc.count} total reports)` : ""}{d.sansIsc.threatFeeds.length ? ` · Listed: ${d.sansIsc.threatFeeds.slice(0, 3).join(", ")}` : ""}
                                    </span>
                                  )}
                                {hasPivotIP && !dismissedPivots.has(`ip::${d.urlscan.servingIP}::${arr[i]}`) && (
                                    <span className="rounded-full px-2 py-0.5 flex items-center gap-1.5 flex-wrap" style={{ color: "#22d3ee", backgroundColor: "rgba(34,211,238,0.08)", border: "1px solid rgba(34,211,238,0.25)" }}>
                                      <span>Serving IP: {d.urlscan.servingIP}{d.urlscan.servingASN ? ` · ${d.urlscan.servingASN}` : ""}{d.urlscan.servingASNName ? ` · ${d.urlscan.servingASNName}` : ""}</span>
                                      {isPivotAdded(ipCat(d.urlscan.servingIP), d.urlscan.servingIP) ? (
                                        <>
                                          <span className="rounded px-1.5 py-0.5 font-bold" style={{ color: "#04111a", backgroundColor: "#00ff9c", fontSize: "9px", lineHeight: 1 }}>Added to {ipCat(d.urlscan.servingIP)}</span>
                                          <button onClick={() => removePivotIOC(ipCat(d.urlscan.servingIP), d.urlscan.servingIP)} className="rounded px-1.5 py-0.5 font-bold" style={{ color: "#ff6b6b", backgroundColor: "rgba(255,107,107,0.15)", fontSize: "9px", lineHeight: 1, cursor: "pointer", border: "1px solid rgba(255,107,107,0.3)" }}>Remove</button>
                                        </>
                                      ) : (
                                        <button onClick={() => addPivotIOC(ipCat(d.urlscan.servingIP), d.urlscan.servingIP, `Serving IP of ${arr[i]}`)} className="rounded px-1.5 py-0.5 font-bold" style={{ color: "#04111a", backgroundColor: "#22d3ee", fontSize: "9px", lineHeight: 1, cursor: "pointer", border: "none" }}>+ Add as IOC</button>
                                      )}
                                      <button onClick={() => dismissPivot(`ip::${d.urlscan.servingIP}::${arr[i]}`)} className="rounded p-0.5" style={{ color: "#5d7382", cursor: "pointer", border: "none", background: "none" }}><X size={10} /></button>
                                    </span>
                                )}
                              </>
                            ))}

                            {/* ── TIMELINE ── */}
                            {!isCondensed && (hasTimeline || hasApexObs || (hasDomainReg && d.domainReg.state !== "deleted")) && secRow("Timeline", (
                              <>
                                  {hasTimeline && (
                                    <span className="rounded-full px-2 py-0.5" style={{ color: "#94a3b8", backgroundColor: "rgba(148,163,184,0.08)", border: "1px solid rgba(148,163,184,0.25)" }}>
                                      🕐{d._timeline.firstFmt ? ` First Seen: ${d._timeline.firstFmt}` : ""}{d._timeline.lastFmt ? ` · Last Seen: ${d._timeline.lastFmt}` : ""}
                                    </span>
                                  )}
                                  {hasDomainReg && d.domainReg.state !== "deleted" && (() => {
                                    const dr = d.domainReg;
                                    const sd = d.urlscan;
                                    const isUnregistered = dr?.state === "unregistered";
                                    const iocHost = arr[i].replace(/^https?:\/\//i, "").split("/")[0];
                                    const isActualSubdomain = registrableDomain(iocHost) !== iocHost.toLowerCase();
                                    const isNewDomain = dr?.state === "active" && dr?.ageDays != null && dr.ageDays < 30;
                                    const isNewSubdomain = isActualSubdomain && sd?.subdomainAgeDays != null && sd.subdomainAgeDays < 30 && dr?.ageDays > 120;
                                    // A subdomain cannot be older than its registrable domain's
                                    // registration. urlscan's observational age is unreliable for
                                    // cloud/wildcard hosts (AWS, Atlassian PaaS) and sometimes
                                    // exceeds the domain age — suppress it when that happens.
                                    const subExceedsDomain = sd?.subdomainAgeDays != null && dr?.ageDays != null && sd.subdomainAgeDays > dr.ageDays;
                                    const showSubdomainLine = sd?.subdomainAgeDays != null && isActualSubdomain && !subExceedsDomain;
                                    const isAlert = isNewDomain || isNewSubdomain;
                                    return (
                                      <span className="rounded-full px-2 py-0.5" style={{
                                        color: isAlert ? "#ff4d6d" : isUnregistered ? "#8aa0ad" : "#94a3b8",
                                        backgroundColor: isAlert ? "rgba(255,77,109,0.10)" : "rgba(148,163,184,0.08)",
                                        border: `1px solid ${isAlert ? "rgba(255,77,109,0.3)" : "rgba(148,163,184,0.25)"}`,
                                      }}>
                                        📋{dr?.state === "active" && dr.ageDays != null ? ` Domain: ${smartAge(dr.ageDays)} old (Reg. ${fmtDate(dr.date)})` : ""}{isUnregistered ? " ⚪ Domain Not Registered" : ""}{showSubdomainLine ? ` · Subdomain: ${smartAge(sd.subdomainAgeDays)} old (Active Since ${fmtDate(sd.subdomainCreated)})` : ""}{dr?.status ? ` · Status: ${dr.status}` : ""}
                                        {isNewSubdomain && <span style={{ color: "#ff4d6d", fontWeight: 700 }}>{" · "}🔴 Newly Created Subdomain</span>}
                                      </span>
                                    );
                                  })()}
                                  {hasApexObs && (() => {
                                    const sd = d.urlscan;
                                    const iocHost = arr[i].replace(/^https?:\/\//i, "").split("/")[0];
                                    const isActualSubdomain = registrableDomain(iocHost) !== iocHost.toLowerCase();
                                    const showSub = sd?.subdomainAgeDays != null && isActualSubdomain && (sd.apexAgeDays == null || sd.subdomainAgeDays <= sd.apexAgeDays);
                                    const isNewApex = sd.apexAgeDays < 30;
                                    return (
                                      <span className="rounded-full px-2 py-0.5" style={{
                                        color: isNewApex ? "#ff4d6d" : "#8aa0ad",
                                        backgroundColor: isNewApex ? "rgba(255,77,109,0.10)" : "rgba(148,163,184,0.05)",
                                        border: `1px dashed ${isNewApex ? "rgba(255,77,109,0.35)" : "rgba(148,163,184,0.3)"}`,
                                      }} title="Observational — urlscan first-sighting, not registry data">
                                        👁️ Domain: ~{smartAge(sd.apexAgeDays)} old (First Observed {fmtDate(sd.apexFirstSeen)}){showSub ? ` · Subdomain: ${smartAge(sd.subdomainAgeDays)} old (Active Since ${fmtDate(sd.subdomainCreated)})` : ""}
                                        {isNewApex && <span style={{ color: "#ff4d6d", fontWeight: 700 }}>{" · "}🔴 Recently Observed Domain</span>}
                                      </span>
                                    );
                                  })()}
                              </>
                            ))}

                            {/* ── PIVOTS (skip for hashes) ── */}
                            {!isCondensed && !isHash && (hasUrlscan || !!d.otxPDNS) && (() => {
                              const existingUrls = new Set((displayData?.URL || []).map((u) => u.toLowerCase().replace(/\/+$/, "")));
                              const fileUrls = new Set((d.urlscan?.files || []).map((f) => f.url?.toLowerCase().replace(/\/+$/, "")).filter(Boolean));
                              const iocNorm = arr[i].toLowerCase().replace(/\/+$/, "").replace(/^https?:\/\//i, "");
                              const seenNorm = new Set();
                              const existingDomains = new Set((displayData?.DOMAIN || []).map((x) => x.toLowerCase()));
                              const existingIPs = new Set([...(displayData?.IPV4 || []), ...(displayData?.IPV6 || [])].map((x) => x.toLowerCase()));
                              const newUrls = (d.urlscan?.scannedUrls || []).filter((su) => {
                                const u = typeof su === "string" ? su : su.url;
                                const stripped = u.replace(/^https?:\/\//i, "").replace(/\/+$/, "").toLowerCase();
                                if (seenNorm.has(stripped)) return false;
                                seenNorm.add(stripped);
                                if (stripped === iocNorm || stripped === iocNorm + "/") return false;
                                const iocNoWww = iocNorm.replace(/^www\./i, "");
                                const strippedNoWww = stripped.replace(/^www\./i, "");
                                if (strippedNoWww === iocNoWww || strippedNoWww === iocNoWww + "/") return false;
                                // Domain-only (no path) → check DOMAIN card too
                                const isDomainOnly = !stripped.includes("/");
                                const wasPivotAdded = isPivotAdded(isDomainOnly ? "DOMAIN" : "URL", stripped);
                                if (!wasPivotAdded && (existingUrls.has(stripped) || (isDomainOnly && existingDomains.has(stripped)))) return false;
                                if (fileUrls.has(u.toLowerCase().replace(/\/+$/, ""))) return false;
                                if (dismissedPivots.has(`url::${stripped}::${arr[i]}`)) return false;
                                return true;
                              });
                              const hasFiles = d.urlscan?.files && d.urlscan.files.filter((f) => !dismissedPivots.has(`file::${f.sha256 || f.filename}::${arr[i]}`)).length > 0;
                              // Passive DNS pivots — filter out anything already in cards
                              const pdnsRecords = (d.otxPDNS?.records || []).filter((r) => {
                                const target = cat === "DOMAIN" ? r.address : r.hostname;
                                if (!target) return false;
                                const t = target.toLowerCase();
                                if (t === iocNorm) return false;
                                if (dismissedPivots.has(`pdns::${t}::${arr[i]}`)) return false;
                                // Filter out ones already in cards (unless previously added as pivot)
                                if (cat === "DOMAIN") {
                                  if (!isPivotAdded(ipCat(t), t) && existingIPs.has(t)) return false;
                                } else {
                                  if (!isPivotAdded("DOMAIN", t) && existingDomains.has(t)) return false;
                                }
                                return true;
                              });
                              const hasContacted = (d.urlscan?.contactedIPs || []).length > 0 || (d.urlscan?.contactedDomains || []).length > 0;
                              if (!newUrls.length && !hasFiles && !pdnsRecords.length && !hasContacted) return null;
                              return secRow("Pivots", (
                                  <div className="flex flex-col gap-0.5 w-full">
                                    {newUrls.map((su, ui) => {
                                      const u = typeof su === "string" ? su : su.url;
                                      const shot = typeof su === "string" ? null : su.screenshot;
                                      const uNorm = u.replace(/^https?:\/\//i, "").replace(/\/+$/, "");
                                      const targetCat = uNorm.includes("/") ? "URL" : "DOMAIN";
                                      const added = isPivotAdded(targetCat, uNorm);
                                      return (
                                        <span key={`u${ui}`} className="rounded-full px-2 py-0.5 flex items-center gap-1.5" style={{ color: "#7c9cff", backgroundColor: "rgba(124,156,255,0.06)", border: "1px solid rgba(124,156,255,0.2)" }}>
                                          <span className="break-all flex-1">{u}</span>
                                          {shot && (
                                          <span className="relative inline-block shrink-0">
                                            <a href={shot} target="_blank" rel="noreferrer noopener"
                                              className="peer text-[9px] px-1 py-0.5 rounded inline-block"
                                              style={{ color: "#c084fc", border: "1px solid rgba(192,132,252,0.3)", backgroundColor: "rgba(192,132,252,0.08)", textDecoration: "none" }}>🖥️</a>
                                            <span className="hidden peer-hover:block fixed z-[9999] rounded-lg shadow-2xl pointer-events-none"
                                              style={{ border: "2px solid rgba(192,132,252,0.5)", backgroundColor: "#0a0e14", padding: "4px", width: "400px", maxWidth: "90vw", left: "50%", top: "50%", transform: "translate(-50%, -50%)" }}>
                                              <img src={shot} alt="Screenshot" loading="lazy"
                                                style={{ width: "100%", borderRadius: "6px", display: "block" }}
                                                onError={(e) => { e.target.parentElement.style.display = "none"; }} />
                                              <p className="text-[9px] text-center mt-1" style={{ color: "#5d7382" }}>{uNorm}</p>
                                            </span>
                                          </span>
                                          )}
                                          {added ? (
                                            <>
                                              <span className="rounded px-1.5 py-0.5 font-bold shrink-0" style={{ color: "#04111a", backgroundColor: "#00ff9c", fontSize: "9px", lineHeight: 1 }}>Added to {targetCat}</span>
                                              <button onClick={() => removePivotIOC(targetCat, uNorm)} className="rounded px-1.5 py-0.5 font-bold shrink-0" style={{ color: "#ff6b6b", backgroundColor: "rgba(255,107,107,0.15)", fontSize: "9px", lineHeight: 1, cursor: "pointer", border: "1px solid rgba(255,107,107,0.3)" }}>Remove</button>
                                            </>
                                          ) : (
                                            <button onClick={() => addPivotIOC(targetCat, uNorm, `Urlscan scan of ${arr[i]}`)} className="rounded px-1.5 py-0.5 font-bold shrink-0" style={{ color: "#04111a", backgroundColor: "#7c9cff", fontSize: "9px", lineHeight: 1, cursor: "pointer", border: "none" }}>+ Add as IOC</button>
                                          )}
                                          <button onClick={() => dismissPivot(`url::${uNorm}::${arr[i]}`)} className="rounded p-0.5 shrink-0" style={{ color: "#5d7382", cursor: "pointer", border: "none", background: "none" }}><X size={10} /></button>
                                        </span>
                                      );
                                    })}
                                    {(d.urlscan?.files || []).filter((f) => !dismissedPivots.has(`file::${f.sha256 || f.filename}::${arr[i]}`)).map((f, fi) => {
                                      const hashAdded = f.sha256 && isPivotAdded("SHA256", f.sha256);
                                      const fileAdded = f.filename && isPivotAdded("FILE_NAME", f.filename);
                                      const urlAdded = f.url && isPivotAdded("URL", f.url.replace(/^https?:\/\//i, "").replace(/\/+$/, ""));
                                      return (
                                        <span key={`f${fi}`} className="rounded-full px-2 py-0.5 flex items-center gap-1.5 flex-wrap" style={{ color: "#94a3b8", backgroundColor: "rgba(148,163,184,0.06)", border: "1px solid rgba(148,163,184,0.2)" }}>
                                          <span className="break-all flex-1">
                                            {f.filename ? <span style={{ color: "#fbbf24" }}>{f.filename}</span> : null}
                                            {f.url ? <>{f.filename ? " · " : ""}<span style={{ color: "#7c9cff" }}>{f.url}</span></> : null}
                                            {f.sha256 ? <>{(f.filename || f.url) ? " · " : ""}<span style={{ color: "#ff4d6d" }}>{f.sha256.slice(0, 16)}…</span></> : null}
                                            {f.size ? ` · ${Math.round(f.size / 1024)}KB` : ""}
                                          </span>
                                          <span className="flex gap-1 shrink-0 flex-wrap">
                                            {f.sha256 && (hashAdded
                                              ? <button onClick={() => removePivotIOC("SHA256", f.sha256)} className="rounded px-1.5 py-0.5 font-bold" style={{ color: "#ff6b6b", backgroundColor: "rgba(255,107,107,0.15)", fontSize: "9px", lineHeight: 1, cursor: "pointer", border: "1px solid rgba(255,107,107,0.3)" }}>Remove Hash</button>
                                              : <button onClick={() => addPivotIOC("SHA256", f.sha256, `${f.filename || "File"} on ${arr[i]}`)} className="rounded px-1.5 py-0.5 font-bold" style={{ color: "#04111a", backgroundColor: "#ff4d6d", fontSize: "9px", lineHeight: 1, cursor: "pointer", border: "none" }}>+ Hash</button>
                                            )}
                                            {f.filename && (fileAdded
                                              ? <button onClick={() => removePivotIOC("FILE_NAME", f.filename)} className="rounded px-1.5 py-0.5 font-bold" style={{ color: "#ff6b6b", backgroundColor: "rgba(255,107,107,0.15)", fontSize: "9px", lineHeight: 1, cursor: "pointer", border: "1px solid rgba(255,107,107,0.3)" }}>Remove File</button>
                                              : <button onClick={() => addPivotIOC("FILE_NAME", f.filename, `File on ${arr[i]}`)} className="rounded px-1.5 py-0.5 font-bold" style={{ color: "#04111a", backgroundColor: "#fbbf24", fontSize: "9px", lineHeight: 1, cursor: "pointer", border: "none" }}>+ File</button>
                                            )}
                                            {f.url && (urlAdded
                                              ? <button onClick={() => removePivotIOC("URL", f.url.replace(/^https?:\/\//i, "").replace(/\/+$/, ""))} className="rounded px-1.5 py-0.5 font-bold" style={{ color: "#ff6b6b", backgroundColor: "rgba(255,107,107,0.15)", fontSize: "9px", lineHeight: 1, cursor: "pointer", border: "1px solid rgba(255,107,107,0.3)" }}>Remove URL</button>
                                              : <button onClick={() => addPivotIOC("URL", f.url.replace(/^https?:\/\//i, "").replace(/\/+$/, ""), `File URL on ${arr[i]}`)} className="rounded px-1.5 py-0.5 font-bold" style={{ color: "#04111a", backgroundColor: "#7c9cff", fontSize: "9px", lineHeight: 1, cursor: "pointer", border: "none" }}>+ URL</button>
                                            )}
                                          </span>
                                          <button onClick={() => dismissPivot(`file::${f.sha256 || f.filename}::${arr[i]}`)} className="rounded p-0.5 shrink-0" style={{ color: "#5d7382", cursor: "pointer", border: "none", background: "none" }}><X size={10} /></button>
                                        </span>
                                      );
                                    })}
                                    {pdnsRecords.length > 0 && (
                                      <div className="flex items-center gap-1.5 mt-1 mb-0.5">
                                        <span className="text-[9px] uppercase tracking-widest font-bold" style={{ color: "#5d7382" }}>Passive DNS</span>
                                        <span className="text-[9px]" style={{ color: "#5d7382" }}>· {d.otxPDNS.unique || pdnsRecords.length} unique {cat === "DOMAIN" ? "IPs" : "hosts"} from {d.otxPDNS.total} observations{d.otxPDNS.currentCount != null ? ` · ${d.otxPDNS.currentCount} current` : ""}</span>
                                        <button onClick={() => setPdnsExpanded((p) => ({ ...p, [eKey]: !p[eKey] }))}
                                          className="text-[9px] rounded px-1.5 py-0.5 font-bold ml-1"
                                          style={{ color: "#7c9cff", backgroundColor: "rgba(124,156,255,0.1)", border: "1px solid rgba(124,156,255,0.3)", cursor: "pointer" }}>
                                          {pdnsExpanded[eKey] ? "Grouped view" : "Show all records"}
                                        </button>
                                      </div>
                                    )}
                                    {pdnsRecords.map((r, pi) => {
                                      // For DOMAIN queries, pivot the IP addresses. For IP queries, pivot the hostnames.
                                      const target = cat === "DOMAIN" ? r.address : r.hostname;
                                      const targetCat = cat === "DOMAIN" ? ipCat(r.address) : "DOMAIN";
                                      const added = isPivotAdded(targetCat, target);
                                      const rowKey = `${eKey}::${String(target).toLowerCase()}`;
                                      const multiObs = (r.obs || 1) > 1;
                                      const rowOpen = pdnsExpanded[eKey] || pdnsRowOpen[rowKey];
                                      return (
                                        <div key={`pd${pi}`}>
                                        <span className="rounded-full px-2 py-0.5 flex items-center gap-1.5" style={{ color: "#94a3b8", backgroundColor: "rgba(148,163,184,0.05)", border: "1px solid rgba(148,163,184,0.2)" }}>
                                          <span className="flex-1 min-w-0 flex flex-wrap items-center gap-1.5">
                                            <span style={{ color: "#7c9cff", fontWeight: 600 }}>{target}</span>
                                            {(() => {
                                              const shot = enrichCache[`${targetCat}::${target}`]?.data?.urlscan?.screenshot
                                                || enrichCache[`DOMAIN::${target}`]?.data?.urlscan?.screenshot
                                                || enrichCache[`URL::${target}`]?.data?.urlscan?.screenshot;
                                              if (!shot) return null;
                                              return (
                                                <span className="relative group/shot inline-flex">
                                                  <span className="text-[9px] rounded px-1 cursor-help" style={{ color: "#00e5ff", backgroundColor: "rgba(0,229,255,0.1)", border: "1px solid rgba(0,229,255,0.3)" }}>🖼️</span>
                                                  <img src={shot} alt="preview" loading="lazy"
                                                    className="hidden group-hover/shot:block absolute z-40 rounded-lg"
                                                    style={{ bottom: "120%", left: 0, width: 240, border: "1px solid rgba(0,229,255,0.4)", boxShadow: "0 0 24px rgba(0,0,0,0.6)" }} />
                                                </span>
                                              );
                                            })()}
                                            {r.recordType && <span className="text-[9px] px-1 rounded" style={{ color: "#94a3b8", backgroundColor: "rgba(148,163,184,0.12)" }}>{r.recordType}</span>}
                                            <span className="text-[9px] px-1 rounded font-bold" style={{
                                              color: r.current ? "#00ff9c" : "#8aa0ad",
                                              backgroundColor: r.current ? "rgba(0,255,156,0.12)" : "rgba(138,160,173,0.1)",
                                              border: `1px solid ${r.current ? "rgba(0,255,156,0.3)" : "rgba(138,160,173,0.25)"}`,
                                            }}>{r.current ? "CURRENT" : "HISTORICAL"}</span>
                                            <span className="text-[10px]" style={{ color: "#5d7382" }}>{fmtDate(r.first)} → {fmtDate(r.last)}</span>
                                            {multiObs && (
                                              <button onClick={() => setPdnsRowOpen((p) => ({ ...p, [rowKey]: !p[rowKey] }))}
                                                className="text-[9px] px-1 rounded font-bold"
                                                style={{ color: "#c084fc", backgroundColor: "rgba(192,132,252,0.12)", border: "1px solid rgba(192,132,252,0.3)", cursor: "pointer" }}
                                                title="Show individual observation windows">
                                                {r.obs} obs {rowOpen ? "▾" : "▸"}
                                              </button>
                                            )}
                                            {r.asn && cat === "DOMAIN" && <span className="text-[10px]" style={{ color: "#8aa0ad" }}>· {r.asn}</span>}
                                            {r.country && cat === "DOMAIN" && <span className="text-[10px]" style={{ color: "#8aa0ad" }}>· {r.country}</span>}
                                          </span>
                                          {added ? (
                                            <>
                                              <span className="rounded px-1.5 py-0.5 font-bold shrink-0" style={{ color: "#04111a", backgroundColor: "#00ff9c", fontSize: "9px", lineHeight: 1 }}>Added</span>
                                              <button onClick={() => removePivotIOC(targetCat, target)} className="rounded px-1.5 py-0.5 font-bold shrink-0" style={{ color: "#ff6b6b", backgroundColor: "rgba(255,107,107,0.15)", fontSize: "9px", lineHeight: 1, cursor: "pointer", border: "1px solid rgba(255,107,107,0.3)" }}>Remove</button>
                                            </>
                                          ) : (
                                            <button onClick={() => addPivotIOC(targetCat, target, `Passive DNS of ${arr[i]}`)} className="rounded px-1.5 py-0.5 font-bold shrink-0" style={{ color: "#04111a", backgroundColor: "#7c9cff", fontSize: "9px", lineHeight: 1, cursor: "pointer", border: "none" }}>+ Add as IOC</button>
                                          )}
                                          <button onClick={() => dismissPivot(`pdns::${target.toLowerCase()}::${arr[i]}`)} className="rounded p-0.5 shrink-0" style={{ color: "#5d7382", cursor: "pointer", border: "none", background: "none" }}><X size={10} /></button>
                                        </span>
                                        {multiObs && rowOpen && (r.windows || []).length > 0 && (
                                          <div className="ml-4 mt-0.5 mb-1 flex flex-col gap-0.5">
                                            {r.windows.map((w, wi) => (
                                              <span key={wi} className="text-[9px]" style={{ color: "#5d7382" }}>
                                                ↳ {fmtDate(w.first)} → {fmtDate(w.last)}
                                              </span>
                                            ))}
                                          </div>
                                        )}
                                        </div>
                                      );
                                    })}
                                    {/* Contacted infrastructure from urlscan result detail */}
                                    {(() => {
                                      const cIPs = (d.urlscan?.contactedIPs || []).filter((ip) => {
                                        const n = ip.toLowerCase();
                                        if (n === iocNorm) return false;
                                        if (dismissedPivots.has(`contact::${n}::${arr[i]}`)) return false;
                                        if (!isPivotAdded(ipCat(n), n) && existingIPs.has(n)) return false;
                                        return true;
                                      });
                                      const cDoms = (d.urlscan?.contactedDomains || []).filter((dom) => {
                                        const n = dom.toLowerCase();
                                        if (n === iocNorm) return false;
                                        if (dismissedPivots.has(`contact::${n}::${arr[i]}`)) return false;
                                        if (!isPivotAdded("DOMAIN", n) && existingDomains.has(n)) return false;
                                        return true;
                                      });
                                      if (!cIPs.length && !cDoms.length) return null;
                                      const rows = [...cIPs.map((v) => ({ v, cat: ipCat(v) })), ...cDoms.map((v) => ({ v, cat: "DOMAIN" }))];
                                      return (
                                        <>
                                          <div className="flex items-center gap-1.5 mt-1 mb-0.5">
                                            <span className="text-[9px] uppercase tracking-widest font-bold" style={{ color: "#5d7382" }}>Contacted Infrastructure</span>
                                            <span className="text-[9px]" style={{ color: "#5d7382" }}>· hosts this page communicated with (CDN/analytics filtered)</span>
                                          </div>
                                          {rows.map((row, ci) => {
                                            const added = isPivotAdded(row.cat, row.v);
                                            return (
                                              <span key={`c${ci}`} className="rounded-full px-2 py-0.5 flex items-center gap-1.5" style={{ color: "#fb923c", backgroundColor: "rgba(251,146,60,0.06)", border: "1px solid rgba(251,146,60,0.25)" }}>
                                                <span className="flex-1 min-w-0 flex flex-wrap items-center gap-1.5">
                                                  <span style={{ color: "#fb923c", fontWeight: 600 }}>{row.v}</span>
                                                  <span className="text-[9px] px-1 rounded" style={{ color: "#94a3b8", backgroundColor: "rgba(148,163,184,0.12)" }}>{row.cat}</span>
                                                  {(() => {
                                                    const shot = enrichCache[`${row.cat}::${row.v}`]?.data?.urlscan?.screenshot
                                                      || enrichCache[`DOMAIN::${row.v}`]?.data?.urlscan?.screenshot
                                                      || enrichCache[`URL::${row.v}`]?.data?.urlscan?.screenshot;
                                                    if (!shot) return null;
                                                    return (
                                                      <span className="relative group/shot2 inline-flex">
                                                        <span className="text-[9px] rounded px-1 cursor-help" style={{ color: "#00e5ff", backgroundColor: "rgba(0,229,255,0.1)", border: "1px solid rgba(0,229,255,0.3)" }}>🖼️</span>
                                                        <img src={shot} alt="preview" loading="lazy"
                                                          className="hidden group-hover/shot2:block absolute z-40 rounded-lg"
                                                          style={{ bottom: "120%", left: 0, width: 240, border: "1px solid rgba(0,229,255,0.4)", boxShadow: "0 0 24px rgba(0,0,0,0.6)" }} />
                                                      </span>
                                                    );
                                                  })()}
                                                </span>
                                                {added ? (
                                                  <>
                                                    <span className="rounded px-1.5 py-0.5 font-bold shrink-0" style={{ color: "#04111a", backgroundColor: "#00ff9c", fontSize: "9px", lineHeight: 1 }}>Added</span>
                                                    <button onClick={() => removePivotIOC(row.cat, row.v)} className="rounded px-1.5 py-0.5 font-bold shrink-0" style={{ color: "#ff6b6b", backgroundColor: "rgba(255,107,107,0.15)", fontSize: "9px", lineHeight: 1, cursor: "pointer", border: "1px solid rgba(255,107,107,0.3)" }}>Remove</button>
                                                  </>
                                                ) : (
                                                  <button onClick={() => addPivotIOC(row.cat, row.v, `Contacted by ${arr[i]}`)} className="rounded px-1.5 py-0.5 font-bold shrink-0" style={{ color: "#04111a", backgroundColor: "#fb923c", fontSize: "9px", lineHeight: 1, cursor: "pointer", border: "none" }}>+ Add as IOC</button>
                                                )}
                                                <button onClick={() => dismissPivot(`contact::${row.v.toLowerCase()}::${arr[i]}`)} className="rounded p-0.5 shrink-0" style={{ color: "#5d7382", cursor: "pointer", border: "none", background: "none" }}><X size={10} /></button>
                                              </span>
                                            );
                                          })}
                                        </>
                                      );
                                    })()}
                                  </div>
                              ));
                            })()}
                          </div>
                          );
                        })()}
                        {enr && !enr.loading && !enr.data && enr.error && (
                          <p className="ml-4 mb-1 text-[10px] font-bold" style={{ color: "#5d7382" }}>⚪ Unknown - Check VirusTotal.</p>
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
                    <CopyBtn label="QRadar AQL" copied={copied === "reg-aql"} onClick={() => copyText(buildAQL(visibleRegDetails), "reg-aql")} color={c} />
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
                    {huntAQL(cat, arr) && <CopyBtn label="QRadar AQL" copied={copied === `${cat}-hunt-aql`} onClick={() => copyText(huntAQL(cat, arr), `${cat}-hunt-aql`)} color={c} />}
                    {huntSigma(cat, arr, sourceUrl) && <CopyBtn label="Sigma Rule" copied={copied === `${cat}-hunt-sigma`} onClick={() => copyText(huntSigma(cat, arr, sourceUrl), `${cat}-hunt-sigma`)} color={c} />}
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

        {references.length > 0 && (
          <div className="rounded-xl overflow-hidden mt-4" style={{ backgroundColor: "rgba(10,14,20,0.72)", border: "1px solid rgba(120,160,180,0.12)", backdropFilter: "blur(6px)" }}>
            <div className="flex items-center justify-between px-4 py-2.5" style={{ borderBottom: "1px solid rgba(120,160,180,0.1)", backgroundColor: "rgba(120,160,180,0.04)" }}>
              <div className="flex items-center gap-2">
                <FileText size={14} style={{ color: "#5d7382" }} />
                <span className="text-xs font-bold uppercase tracking-widest" style={{ color: "#7f95a3" }}>References</span>
              </div>
              <span className="text-xs rounded-full px-2 py-0.5" style={{ color: "#5d7382", border: "1px solid rgba(120,160,180,0.2)" }}>{references.length}</span>
            </div>
            <div className="px-4 py-2 overflow-y-auto" style={{ maxHeight: 200 }}>
              {references.map((ref, i) => (
                <div key={i} className="flex items-center gap-2 py-0.5">
                  <span className="text-xs" style={{ color: "#5d738255", userSelect: "none" }}>›</span>
                  <a href={ref.includes("://") ? ref : "https://" + ref} target="_blank" rel="noreferrer noopener"
                    className="text-xs break-all hover:underline" style={{ color: "#5d7382" }}>
                    {ref}
                  </a>
                </div>
              ))}
            </div>
            <div className="px-3 py-2" style={{ borderTop: "1px solid rgba(120,160,180,0.08)" }}>
              <CopyBtn label="Copy All" copied={copied === "refs-all"} onClick={() => copyText(references.join("\n"), "refs-all")} color="#5d7382" />
            </div>
          </div>
        )}

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

// ============================================================
//  ThreatGraph — force-directed infrastructure graph on Canvas.
//  Nodes: IOCs + derived infrastructure (serving IPs, passive-DNS
//  IPs, hosted file hashes). Edges: real hunting relationships.
//  Verdict-driven glow, particle-flow edges, hover spotlight,
//  drag, zoom, entrance animation.
// ============================================================
// Error boundary so a graph render error can never black-screen the whole app.
class GraphErrorBoundary extends Component {
  constructor(props) { super(props); this.state = { failed: false }; }
  static getDerivedStateFromError() { return { failed: true }; }
  componentDidCatch(err) { console.warn("ThreatGraph error (contained):", err?.message || err); }
  render() {
    if (this.state.failed) {
      return (
        <div className="rounded-xl p-6 text-center" style={{ background: "rgba(10,14,20,0.72)", border: "1px solid rgba(255,77,109,0.3)" }}>
          <p className="text-sm" style={{ color: "#ff8a9b" }}>The graph hit a rendering issue and was paused to protect the page.</p>
          <button onClick={() => this.setState({ failed: false })}
            className="mt-3 rounded-lg px-3 py-1.5 text-xs font-semibold"
            style={{ color: "#04111a", background: "#00e5ff", border: "none", cursor: "pointer" }}>
            Reload graph
          </button>
        </div>
      );
    }
    return this.props.children;
  }
}

function ThreatGraph({ iocData, enrichCache, colorFor, enrichIOC, copyText, addPivotIOC, isPivotAdded, removeIoc, anyEnriched, hashCollapseAnims = [] }) {
  const canvasRef = useRef(null);
  const wrapRef = useRef(null);
  const stateRef = useRef({ nodes: [], edges: [], t: 0 });
  const camRef = useRef({ x: 0, y: 0, zoom: 1, dragNode: null, panning: false, lastX: 0, lastY: 0, hover: null });
  const [dims, setDims] = useState({ w: 900, h: 600 });
  const [hoverInfo, setHoverInfo] = useState(null);
  const [selected, setSelected] = useState(null);       // node for the floating action panel
  const [fullscreen, setFullscreen] = useState(false);
  const [hiddenCats, setHiddenCats] = useState({});     // { CAT: true } to hide a type
  const [hiddenVerdicts, setHiddenVerdicts] = useState({}); // { Malicious: true } to hide
  const [hideDerived, setHideDerived] = useState(false);
  const [hideOrphans, setHideOrphans] = useState(false);
  const [isolateMalicious, setIsolateMalicious] = useState(false);
  const [isolateSharedPivots, setIsolateSharedPivots] = useState(false);
  const [showSearch, setShowSearch] = useState(false);
  const [searchQuery, setSearchQuery] = useState("");
  const [nodeActionState, setNodeActionState] = useState({}); // { nodeId: "enriching"|"added" }
  const [copiedNodeId, setCopiedNodeId] = useState(null);
  const [hiddenNodes, setHiddenNodes] = useState(new Set()); // manually hidden from graph
  const [searchMatches, setSearchMatches] = useState([]);
  const [searchMatchIdx, setSearchMatchIdx] = useState(0);

  // ---- Build the graph model from IOCs + enrichment ----
  const model = useMemo(() => {
    if (!iocData) return { nodes: [], edges: [], stats: { nodes: 0, edges: 0, derived: 0 } };
    const nodes = new Map(); // id -> node
    const edges = [];
    const norm = (v) => String(v).toLowerCase().replace(/^https?:\/\//, "").replace(/\/+$/, "");

    const verdictOf = (cat, val) => enrichCache[`${cat}::${val}`]?.data?._verdict || null;
    const addNode = (id, label, cat, derived, verdict) => {
      const key = norm(id);
      if (nodes.has(key)) {
        // Upgrade a derived node to a real one if it also appears as an IOC
        if (!derived) { const n = nodes.get(key); n.derived = false; if (verdict) n.verdict = verdict; }
        return nodes.get(key);
      }
      const n = {
        id: key, label: label || id, cat, derived: !!derived,
        verdict: verdict || null,
        x: (Math.random() - 0.5) * 200, y: (Math.random() - 0.5) * 200,
        vx: 0, vy: 0,
        r: derived ? 7 : 11,
      };
      nodes.set(key, n);
      return n;
    };
    const addEdge = (aId, bId, kind, color) => {
      const a = norm(aId), b = norm(bId);
      if (a === b || !nodes.has(a) || !nodes.has(b)) return;
      edges.push({ a, b, kind, color: color || "rgba(120,160,180,0.35)" });
    };

    // Categories that don't represent network/file infrastructure and add no
    // value as graph nodes (MITRE techniques, CVEs, YARA rules, etc.).
    const GRAPH_SKIP_CATS = new Set(["MITRE_ATTACK", "CVE", "YARA"]);

    // 1. Primary IOC nodes
    Object.entries(iocData).forEach(([cat, arr]) => {
      if (!Array.isArray(arr)) return;
      if (GRAPH_SKIP_CATS.has(cat)) return;
      arr.forEach((val) => addNode(val, val, cat, false, verdictOf(cat, val)));
    });

    // 2. Derived nodes + edges from enrichment
    Object.entries(iocData).forEach(([cat, arr]) => {
      if (GRAPH_SKIP_CATS.has(cat)) return;
      if (!Array.isArray(arr)) return;
      arr.forEach((val) => {
        const d = enrichCache[`${cat}::${val}`]?.data;
        if (!d) return;
        const srcId = norm(val);

        // Serving IP (strong: same box)
        if (d.urlscan?.servingIP && norm(d.urlscan.servingIP) !== srcId) {
          const ipNode = addNode(d.urlscan.servingIP, d.urlscan.servingIP, ipCat(d.urlscan.servingIP), true, null);
          if (d.urlscan.servingASNName) ipNode.asn = d.urlscan.servingASNName;
          addEdge(val, d.urlscan.servingIP, "serves", "rgba(0,229,255,0.5)");
        }

        // Passive DNS — current resolutions only. Historical ones can point at
        // infrastructure long since reassigned to an unrelated party; auto-pivoting
        // on them risks a false bridge. Still visible for manual pivot in the card.
        (d.otxPDNS?.records || []).forEach((r) => {
          if (!r.current) return;
          const target = cat === "DOMAIN" ? r.address : r.hostname;
          if (!target) return;
          const tcat = cat === "DOMAIN" ? ipCat(target) : "DOMAIN";
          addNode(target, target, tcat, true, null);
          addEdge(val, target, "resolved", "rgba(45,212,191,0.4)");
        });

        // Hosted files (strong: same payload)
        (d.urlscan?.files || []).forEach((f) => {
          if (f.sha256) {
            addNode(f.sha256, f.filename ? `${f.filename}` : f.sha256.slice(0, 12) + "…", "SHA256", true, null);
            addEdge(val, f.sha256, "hosts", "rgba(255,77,109,0.45)");
          }
        });

        // Scanned URLs on this host
        (d.urlscan?.scannedUrls || []).forEach((su) => {
          const u = typeof su === "string" ? su : su.url;
          if (!u) return;
          const un = norm(u);
          if (un === srcId) return;
          const ucat = un.includes("/") ? "URL" : "DOMAIN";
          addNode(u, u, ucat, true, null);
          addEdge(val, u, "scanned", "rgba(124,156,255,0.3)");
        });

        // Contacted IPs (urlscan result detail — infra the page talked to)
        (d.urlscan?.contactedIPs || []).forEach((ip) => {
          if (norm(ip) === srcId) return;
          const n = addNode(ip, ip, ipCat(ip), true, null);
          if (n) n.contacted = true;
          addEdge(val, ip, "contacted", "rgba(251,146,60,0.4)");
        });

        // Contacted domains (CDN/analytics already filtered upstream)
        (d.urlscan?.contactedDomains || []).forEach((dom) => {
          if (norm(dom) === srcId) return;
          const n = addNode(dom, dom, "DOMAIN", true, null);
          if (n) n.contacted = true;
          addEdge(val, dom, "contacted", "rgba(251,146,60,0.4)");
        });

        // Loaded-resource hashes (scripts/payloads pulled during the scan)
        (d.urlscan?.resourceHashes || []).forEach((h) => {
          if (!h || typeof h !== "string" || h.length < 32) return;
          addNode(h, h.slice(0, 12) + "…", "SHA256", true, null);
          addEdge(val, h, "loads", "rgba(255,77,109,0.35)");
        });

        // Tri.age C2 URLs — extracted from behavioral analysis of this hash.
        // These are the command-and-control endpoints the malware phoned home to.
        // High-value derived nodes: domain:evil.com, ip:1.2.3.4, or bare URLs.
        (d.triage?.c2Urls || []).forEach((c2) => {
          if (!c2) return;
          const raw = String(c2);
          if (raw.startsWith("domain:")) {
            const dom = raw.slice(7).toLowerCase();
            if (!dom) return;
            const n = addNode(dom, dom, "DOMAIN", true, "Malicious");
            if (n) n.c2 = true;
            addEdge(val, dom, "c2", "rgba(255,77,109,0.6)");
          } else if (raw.startsWith("ip:")) {
            const ip = raw.slice(3);
            if (!ip) return;
            const n = addNode(ip, ip, ipCat(ip), true, "Malicious");
            if (n) n.c2 = true;
            addEdge(val, ip, "c2", "rgba(255,77,109,0.6)");
          } else {
            // Bare URL
            try {
              const u = new URL(raw.includes("://") ? raw : "https://" + raw);
              const n = addNode(raw, u.hostname, "URL", true, "Malicious");
              if (n) n.c2 = true;
              addEdge(val, raw, "c2", "rgba(255,77,109,0.6)");
            } catch { /* skip malformed */ }
          }
        });

        // Hybrid Analysis behavioral pivots — sandbox-observed infrastructure.
        // submit_context is high-value: the URL the sample was downloaded from
        // (creates the download-chain: URL → SHA256, and if the URL's IP is
        // already an IOC, the shared-pivot logic auto-bridges IP → URL → SHA256).
        // hosts / domains / compromised_hosts = contacted infra during detonation.
        (d.hybridAnalysis?.submitContext || []).forEach((sc) => {
          if (!sc || typeof sc !== "string") return;
          try {
            const u = new URL(sc.includes("://") ? sc : "http://" + sc);
            const host = u.hostname;
            // URL node (SHA256 → URL — the URL that dropped/served this sample)
            addNode(sc, sc, "URL", true, "Malicious");
            addEdge(val, sc, "downloaded_from", "rgba(255,77,109,0.55)");
            // Auto-derive host node (URL → IP/DOMAIN) so it can bridge with other IOCs.
            // Classify by whether hostname is IPv4 or a domain.
            const isIP = isIPv4(host) || host.includes(":");
            const hostCat = isIP ? ipCat(host) : "DOMAIN";
            if (norm(host) !== norm(sc)) {
              addNode(host, host, hostCat, true, null);
              addEdge(sc, host, "hosted_on", "rgba(0,229,255,0.4)");
            }
          } catch { /* skip malformed */ }
        });
        // HA contacted hosts (IPs the sample talked to during detonation)
        (d.hybridAnalysis?.hosts || []).forEach((ip) => {
          if (!ip || typeof ip !== "string") return;
          if (norm(ip) === srcId) return;
          const n = addNode(ip, ip, ipCat(ip), true, null);
          if (n) n.contacted = true;
          addEdge(val, ip, "contacted", "rgba(251,146,60,0.4)");
        });
        // HA contacted domains (domains resolved during detonation)
        (d.hybridAnalysis?.domains || []).forEach((dom) => {
          if (!dom || typeof dom !== "string") return;
          if (norm(dom) === srcId) return;
          const n = addNode(dom, dom, "DOMAIN", true, null);
          if (n) n.contacted = true;
          addEdge(val, dom, "contacted", "rgba(251,146,60,0.4)");
        });
        // HA compromised hosts — C2/attacker-controlled infra confirmed by HA
        (d.hybridAnalysis?.compromised || []).forEach((host) => {
          if (!host || typeof host !== "string") return;
          if (norm(host) === srcId) return;
          const isIP = isIPv4(host) || host.includes(":");
          const hcat = isIP ? ipCat(host) : "DOMAIN";
          const n = addNode(host, host, hcat, true, "Malicious");
          if (n) n.c2 = true;
          addEdge(val, host, "c2", "rgba(255,77,109,0.6)");
        });
        // HA related SHA256s from imp_hash/ssdeep/authentihash/domain/ip pivots
        // — samples that share code lineage or infrastructure with this IOC.
        (d.hybridAnalysis?.relatedSHA256s || []).forEach((rh) => {
          if (!rh || typeof rh !== "string") return;
          if (norm(rh) === srcId) return;
          addNode(rh, rh.slice(0, 12) + "…", "SHA256", true, null);
          addEdge(val, rh, "related", "rgba(255,77,109,0.35)");
        });
      });
    });

    // 3. Shared-ASN grouping edges (faint — infrastructure signal)
    const asnGroups = {};
    nodes.forEach((n) => {
      const d = enrichCache[`${n.cat}::${n.id}`]?.data;
      const asn = d?.whoisASN?.asn || d?.urlscan?.servingASN || n.asn;
      if (asn) { (asnGroups[asn] = asnGroups[asn] || []).push(n.id); }
    });
    Object.values(asnGroups).forEach((ids) => {
      if (ids.length < 2 || ids.length > 8) return; // skip singletons and huge shared hosts
      for (let i = 0; i < ids.length - 1; i++) addEdge(ids[i], ids[i + 1], "asn", "rgba(167,139,250,0.18)");
    });

    const nodeArr = Array.from(nodes.values());

    // Mark "bridge" nodes: infrastructure shared between 2+ distinct primary
    // IOCs (e.g. an IP that both abc.com and xyz.com resolve to). These are the
    // most valuable pivots in a graph, so we flag them for standout coloring.
    const primaryNeighbors = {}; // nodeId -> Set of primary IOC ids connected to it
    const primaryIds = new Set(nodeArr.filter((n) => !n.derived).map((n) => n.id));
    edges.forEach((e) => {
      if (e.kind === "asn") return; // ASN grouping edges don't count as pivots
      const aPrim = primaryIds.has(e.a), bPrim = primaryIds.has(e.b);
      if (aPrim && !bPrim) { (primaryNeighbors[e.b] = primaryNeighbors[e.b] || new Set()).add(e.a); }
      if (bPrim && !aPrim) { (primaryNeighbors[e.a] = primaryNeighbors[e.a] || new Set()).add(e.b); }
      // primary-to-primary direct link also makes both bridges
      if (aPrim && bPrim) {
        (primaryNeighbors[e.a] = primaryNeighbors[e.a] || new Set()).add(e.b);
        (primaryNeighbors[e.b] = primaryNeighbors[e.b] || new Set()).add(e.a);
      }
    });
    nodeArr.forEach((n) => {
      n.bridge = (primaryNeighbors[n.id]?.size || 0) >= 2;
    });
    // Flag edges touching a bridge node so they can be drawn to stand out.
    edges.forEach((e) => {
      const aB = nodeArr.find((n) => n.id === e.a)?.bridge;
      const bB = nodeArr.find((n) => n.id === e.b)?.bridge;
      e.toBridge = !!(aB || bB) && e.kind !== "asn";
    });

    const bridgeCount = nodeArr.filter((n) => n.bridge).length;
    // Orphans: nodes with no real (non-asn) connections — islands.
    const connected = new Set();
    edges.forEach((e) => { if (e.kind !== "asn") { connected.add(e.a); connected.add(e.b); } });
    nodeArr.forEach((n) => { n.orphan = !connected.has(n.id); });
    // Per-type counts for the slicer (only categories actually present).
    const typeCountMap = {};
    nodeArr.forEach((n) => { typeCountMap[n.cat] = (typeCountMap[n.cat] || 0) + 1; });
    const typeCounts = Object.entries(typeCountMap).sort((a, b) => b[1] - a[1]);
    return {
      nodes: nodeArr, edges, typeCounts,
      stats: { nodes: nodeArr.length, edges: edges.length, derived: nodeArr.filter((n) => n.derived).length, bridges: bridgeCount, orphans: nodeArr.filter((n) => n.orphan).length },
    };
  }, [iocData, enrichCache]);

  // Seed physics state when model changes. Preserve positions of nodes that
  // already exist (incremental layout) so the graph doesn't re-explode on every
  // enrichment; only brand-new nodes spawn fresh near their parent.
  const prevPosRef = useRef(new Map()); // id -> {x,y,vx,vy}
  const animsRef = useRef([]); // always-fresh ref to hashCollapseAnims
  animsRef.current = hashCollapseAnims;
  useEffect(() => {
    const prev = prevPosRef.current;
    const edgesByNode = {};
    model.edges.forEach((e) => {
      if (e.kind === "asn") return;
      (edgesByNode[e.a] = edgesByNode[e.a] || []).push(e.b);
      (edgesByNode[e.b] = edgesByNode[e.b] || []).push(e.a);
    });
    let newCount = 0;
    model.nodes.forEach((n) => {
      const p = prev.get(n.id);
      if (p) {
        // Existing node — keep its settled position and velocity.
        n.x = p.x; n.y = p.y; n.vx = p.vx * 0.3; n.vy = p.vy * 0.3;
        n.isNew = false;
      } else {
        // New node — spawn near a connected parent that already has a position,
        // so it visibly "flies out" from where it belongs rather than the center.
        const parents = (edgesByNode[n.id] || []).map((pid) => prev.get(pid)).filter(Boolean);
        if (parents.length) {
          const par = parents[0];
          const ang = Math.random() * Math.PI * 2;
          n.x = par.x + Math.cos(ang) * 30; n.y = par.y + Math.sin(ang) * 30;
        } else {
          // Unconnected new node — spawn out toward the periphery so it drifts
          // away rather than crowding the center.
          const ang = Math.random() * Math.PI * 2;
          const R = 360 + Math.random() * 160;
          n.x = Math.cos(ang) * R; n.y = Math.sin(ang) * R;
        }
        n.vx = 0; n.vy = 0; n.isNew = true; n.spawnT = 0;
        newCount++;
      }
    });
    stateRef.current.nodes = model.nodes;
    stateRef.current.edges = model.edges;
    // Only fully re-heat the sim on the very first layout; subsequent enrichments
    // keep it "warm" (low energy) so settled clusters stay calm while new nodes weave in.
    const firstLayout = prev.size === 0;
    stateRef.current.t = firstLayout ? 0 : 480; // 480 = past the hot phase, gentle settle
    stateRef.current.warmKick = newCount > 0 ? 240 : 0; // 4s of extra energy for new nodes

    // Re-point selection/hover to the fresh node object, or clear if it's gone.
    // (A stale `selected` referencing a removed node is what black-screened the app.)
    setSelected((sel) => (sel ? (model.nodes.find((n) => n.id === sel.id) || null) : null));

    if (firstLayout) { camRef.current.x = 0; camRef.current.y = 0; camRef.current.zoom = 1; }
  }, [model]);

  // Keep the position cache updated each frame via a light effect that snapshots
  // on unmount of each model; simpler: snapshot inside the render loop (below).

  // Node visibility per slicer filters. Stored in a ref the render loop reads,
  // plus a state bump to trigger redraws when toggles change.
  const visibleRef = useRef(new Set());
  const [visTick, setVisTick] = useState(0);
  useEffect(() => {
    const malSet = new Set();
    if (isolateMalicious) {
      model.nodes.forEach((n) => { if (n.verdict === "Malicious") malSet.add(n.id); });
      model.edges.forEach((e) => {
        if (malSet.has(e.a)) malSet.add(e.b);
        if (malSet.has(e.b)) malSet.add(e.a);
      });
    }
    // Shared-pivot isolation: keep only bridge nodes + their direct neighbors.
    const pivotSet = new Set();
    if (isolateSharedPivots) {
      model.nodes.forEach((n) => { if (n.bridge) pivotSet.add(n.id); });
      model.edges.forEach((e) => {
        if (e.kind === "asn") return;
        if (pivotSet.has(e.a)) pivotSet.add(e.b);
        if (pivotSet.has(e.b)) pivotSet.add(e.a);
      });
    }

    // Cascade-hide: when a node is manually hidden, also hide derived nodes
    // that only connect to it (orphaned by the hide). Shared nodes stay visible.
    const cascadeHidden = new Set(hiddenNodes);
    if (hiddenNodes.size > 0) {
      model.nodes.forEach((n) => {
        if (!n.derived || cascadeHidden.has(n.id)) return;
        const neighbors = model.edges.filter(e => e.kind !== "asn" && (e.a === n.id || e.b === n.id))
          .map(e => e.a === n.id ? e.b : e.a);
        const allHidden = neighbors.length > 0 && neighbors.every(nb => cascadeHidden.has(nb));
        if (allHidden) cascadeHidden.add(n.id);
      });
    }

    const vis = new Set();
    model.nodes.forEach((n) => {
      if (cascadeHidden.has(n.id)) return;
      if (hiddenCats[n.cat]) return;
      if (n.verdict && hiddenVerdicts[n.verdict]) return;
      if (hideDerived && n.derived) return;
      if (hideOrphans && n.orphan) return;
      if (isolateMalicious && !malSet.has(n.id)) return;
      if (isolateSharedPivots && !pivotSet.has(n.id)) return;
      vis.add(n.id);
    });
    visibleRef.current = vis;
    setVisTick((t) => t + 1);
  }, [model, hiddenCats, hiddenVerdicts, hideDerived, hideOrphans, isolateMalicious, isolateSharedPivots, hiddenNodes]);

  // Resize observer
  useEffect(() => {
    const el = wrapRef.current;
    if (!el) return;
    const ro = new ResizeObserver(() => {
      const r = el.getBoundingClientRect();
      if (fullscreen) {
        setDims({ w: window.innerWidth, h: window.innerHeight });
      } else {
        // Teaser height before any enrichment (just a taste of the constellation);
        // blooms to full height once enrichment data exists.
        const fullH = Math.max(370, Math.min(634, r.width * 0.545)); // 12% less than original
        const h = anyEnriched ? fullH : 168; // teaser also 12% less (190 * 0.88)
        setDims({ w: Math.max(320, r.width), h });
      }
    });
    ro.observe(el);
    return () => ro.disconnect();
  }, [fullscreen, anyEnriched]);

  // Non-passive wheel listener — React's onWheel is passive and can't preventDefault,
  // so the page scrolls while zooming. Attach natively to trap it inside the canvas.
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const CORE_MAX_W = 1280; // matches the app's max-w-7xl content width
    const onWheelNative = (e) => {
      if (!fullscreen) {
        const rect = canvas.getBoundingClientRect();
        const margin = Math.max(0, (rect.width - CORE_MAX_W) / 2);
        const localX = e.clientX - rect.left;
        if (localX < margin || localX > rect.width - margin) return; // edge strip: let the page scroll
      }
      e.preventDefault();
      e.stopPropagation();
      const cam = camRef.current;
      const factor = e.deltaY < 0 ? 1.12 : 0.89;
      cam.zoom = Math.max(0.3, Math.min(3.5, cam.zoom * factor));
    };
    canvas.addEventListener("wheel", onWheelNative, { passive: false });
    return () => canvas.removeEventListener("wheel", onWheelNative);
  }, [fullscreen]);

  // Touch: pinch-to-zoom and one-finger pan (mobile). Native non-passive so the
  // page doesn't scroll/zoom while interacting with the graph.
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    let lastDist = null;
    let lastTouchX = null, lastTouchY = null;
    const dist = (t) => Math.hypot(t[0].clientX - t[1].clientX, t[0].clientY - t[1].clientY);
    const onTouchStart = (e) => {
      if (e.touches.length === 2) { lastDist = dist(e.touches); e.preventDefault(); }
      else if (e.touches.length === 1) { lastTouchX = e.touches[0].clientX; lastTouchY = e.touches[0].clientY; }
    };
    const onTouchMove = (e) => {
      const cam = camRef.current;
      if (e.touches.length === 2) {
        e.preventDefault();
        const d = dist(e.touches);
        if (lastDist != null) {
          const factor = d / lastDist;
          cam.zoom = Math.max(0.3, Math.min(3.5, cam.zoom * factor));
        }
        lastDist = d;
      } else if (e.touches.length === 1 && lastTouchX != null) {
        e.preventDefault();
        const dx = e.touches[0].clientX - lastTouchX, dy = e.touches[0].clientY - lastTouchY;
        cam.x += dx / cam.zoom; cam.y += dy / cam.zoom;
        lastTouchX = e.touches[0].clientX; lastTouchY = e.touches[0].clientY;
      }
    };
    const onTouchEnd = (e) => { if (e.touches.length < 2) lastDist = null; if (e.touches.length === 0) { lastTouchX = null; lastTouchY = null; } };
    canvas.addEventListener("touchstart", onTouchStart, { passive: false });
    canvas.addEventListener("touchmove", onTouchMove, { passive: false });
    canvas.addEventListener("touchend", onTouchEnd, { passive: false });
    return () => {
      canvas.removeEventListener("touchstart", onTouchStart);
      canvas.removeEventListener("touchmove", onTouchMove);
      canvas.removeEventListener("touchend", onTouchEnd);
    };
  }, []);

  // Fullscreen: resize canvas to viewport, lock body scroll, ESC to exit.
  // Capture scroll position before locking so we can restore it on exit —
  // position:fixed + overflow:hidden otherwise jumps the page to the top.
  useEffect(() => {
    if (fullscreen) {
      const savedScrollY = window.scrollY || window.pageYOffset || 0;
      setDims({ w: window.innerWidth, h: window.innerHeight });
      const prevOverflow = document.body.style.overflow;
      document.body.style.overflow = "hidden";
      const onKey = (e) => { if (e.key === "Escape") setFullscreen(false); };
      const onResize = () => setDims({ w: window.innerWidth, h: window.innerHeight });
      window.addEventListener("keydown", onKey);
      window.addEventListener("resize", onResize);
      return () => {
        document.body.style.overflow = prevOverflow;
        window.removeEventListener("keydown", onKey);
        window.removeEventListener("resize", onResize);
        // Restore scroll to where the user was before entering fullscreen.
        window.scrollTo(0, savedScrollY);
      };
    }
  }, [fullscreen]);

  // ---- Physics + render loop ----
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d", { alpha: true });
    const dpr = Math.min(2, window.devicePixelRatio || 1);
    canvas.width = dims.w * dpr;
    canvas.height = dims.h * dpr;
    // Keep canvas on GPU compositing layer to prevent texture eviction
    // when user scrolls away — the main cause of black patches on scroll-back.
    canvas.style.willChange = "transform";
    ctx.scale(dpr, dpr);
    let raf;
    // Force a redraw when the page becomes visible again after being
    // backgrounded/scrolled off — prevents stale GPU texture showing as black.
    const onVisible = () => {
      if (document.visibilityState === "visible") {
        cancelAnimationFrame(raf);
        raf = requestAnimationFrame(step);
      }
    };
    document.addEventListener("visibilitychange", onVisible);

    const catColor = (n) => colorFor(n.cat);
    const verdictColor = (v) => v === "Malicious" ? "#ff4d6d" : v === "Suspicious" ? "#fbbf24" : v === "Whitelisted" ? "#00ff9c" : null;

    const step = () => {
      const S = stateRef.current;
      const cam = camRef.current;
      S.t += 1;
      const N = S.nodes, E = S.edges;
      const cx = dims.w / 2, cy = dims.h / 2;

      // Force simulation. Runs hot on first layout, then stays "warm" — a low
      // baseline of motion so new nodes can weave in without re-exploding the
      // settled graph. warmKick gives brief extra energy right after new nodes arrive.
      if (S.warmKick > 0) S.warmKick -= 1;
      // Physics always runs at some level — never fully stops. This gives:
      // - Pre-enrichment: gentle random drift so the constellation feels alive.
      // - Post-enrichment: slow ambient motion even after nodes settle, for a
      //   cool living-graph feel. Settled nodes use very heavy damping (0.97)
      //   so they barely move, but they're always gently breathing.
      const hot = S.t < 600 || cam.dragNode || S.warmKick > 0;
      // Repulsion runs only during hot phase — it's the main energy injector.
      // In idle mode, settled nodes stay put via heavy damping + tiny drift only.
      if (hot) {
        // Repulsion
        for (let i = 0; i < N.length; i++) {
          const a = N[i];
          for (let j = i + 1; j < N.length; j++) {
            const b = N[j];
            let dx = a.x - b.x, dy = a.y - b.y;
            let dist2 = dx * dx + dy * dy || 0.01;
            const dist = Math.sqrt(dist2);
            const force = 2600 / dist2;
            const fx = (dx / dist) * force, fy = (dy / dist) * force;
            a.vx += fx; a.vy += fy; b.vx -= fx; b.vy -= fy;
          }
        }
        // Spring along edges — during hot phase for all nodes; in idle, still
        // run for new nodes so they travel all the way to their parent position
        // rather than freezing partway (the "stops before reaching parent" bug).
        if (hot) {
          for (const e of E) {
            const a = N.find((n) => n.id === e.a), b = N.find((n) => n.id === e.b);
            if (!a || !b) continue;
            const dx = b.x - a.x, dy = b.y - a.y;
            const dist = Math.sqrt(dx * dx + dy * dy) || 0.01;
            const target = e.kind === "asn" ? 160 : 95;
            const k = (dist - target) * 0.012;
            const fx = (dx / dist) * k, fy = (dy / dist) * k;
            a.vx += fx; a.vy += fy; b.vx -= fx; b.vy -= fy;
          }
        } else {
          // Idle: only run springs involving at least one new node
          for (const e of E) {
            const a = N.find((n) => n.id === e.a), b = N.find((n) => n.id === e.b);
            if (!a || !b || (!a.isNew && !b.isNew)) continue;
            const dx = b.x - a.x, dy = b.y - a.y;
            const dist = Math.sqrt(dx * dx + dy * dy) || 0.01;
            const target = e.kind === "asn" ? 160 : 95;
            const k = (dist - target) * 0.010; // slightly gentler in idle
            const fx = (dx / dist) * k, fy = (dy / dist) * k;
            a.vx += fx; a.vy += fy; b.vx -= fx; b.vy -= fy;
          }
        }
        // Centering + integrate.
        for (const n of N) {
          if (hot) {
            n.vx += (0 - n.x) * 0.0016;
            n.vy += (0 - n.y) * 0.0016;
          }
          if (cam.dragNode === n) { n.vx = 0; n.vy = 0; continue; }
          // Idle drift: only in settled state, very subtle. Pre-enrichment (no edges)
          // gets more drift so the floating constellation looks alive.
          // Post-enrichment: barely perceptible gentle breathing.
          const noEdges = E.length === 0;
          const settled = S.t > 600 && S.warmKick === 0 && !cam.dragNode;
          if (settled) {
            // Pre-enrichment: larger wander so constellation looks alive.
            // Post-enrichment: nearly imperceptible breathing (cap keeps it calm).
            const driftAmp = noEdges ? 0.05 : 0.0006;
            n.vx += (Math.random() - 0.5) * driftAmp;
            n.vy += (Math.random() - 0.5) * driftAmp;
          }
          // Damping: new nodes ease in; hot phase settles firmly; idle is very
          // heavy so settled nodes barely breathe. Also hard-clamp velocity when
          // first entering idle so hot-phase residual doesn't keep nodes dancing.
          const damp = n.isNew ? 0.88 : (hot ? 0.82 : 0.96);
          n.vx *= damp; n.vy *= damp;
          // In idle with edges (enriched graph), hard-cap velocity so residual
          // hot-phase momentum can't cause "constant dancing". Pre-enrichment
          // (no edges) gets no cap so nodes can wander visibly.
          if (!hot && E.length > 0) {
            const maxIdleV = 0.02;
            const speed = Math.sqrt(n.vx * n.vx + n.vy * n.vy);
            if (speed > maxIdleV) { const s = maxIdleV / speed; n.vx *= s; n.vy *= s; }
          }
          n.vx *= damp; n.vy *= damp;
          n.x += n.vx; n.y += n.vy;
          if (n.isNew) {
            n.spawnT = (n.spawnT || 0) + 1;
            if (n.spawnT > 240) n.isNew = false; // graduate after ~4s, matching warmKick
          }
        }
      }
      // Snapshot positions so the next model rebuild can preserve them.
      { const snap = prevPosRef.current; snap.clear(); for (const n of N) snap.set(n.id, { x: n.x, y: n.y, vx: n.vx, vy: n.vy }); }

      // ---- Draw ----
      ctx.clearRect(0, 0, dims.w, dims.h);
      // Background vignette
      const bg = ctx.createRadialGradient(cx, cy, 40, cx, cy, Math.max(dims.w, dims.h) * 0.7);
      bg.addColorStop(0, "rgba(8,12,18,0)");
      bg.addColorStop(1, "rgba(2,4,7,0.5)");
      ctx.fillStyle = bg; ctx.fillRect(0, 0, dims.w, dims.h);

      const toScreen = (n) => ({ x: cx + (n.x + cam.x) * cam.zoom, y: cy + (n.y + cam.y) * cam.zoom });
      const hoverId = cam.hover;
      const neighbors = new Set();
      if (hoverId) {
        for (const e of E) { if (e.a === hoverId) neighbors.add(e.b); if (e.b === hoverId) neighbors.add(e.a); }
      }

      // Edges (with flow particles)
      const vis = visibleRef.current;
      const anyFilter = vis && vis.size !== N.length;
      const isVis = (id) => !anyFilter || vis.has(id);
      for (const e of E) {
        if (anyFilter && (!vis.has(e.a) || !vis.has(e.b))) continue;
        const a = N.find((n) => n.id === e.a), b = N.find((n) => n.id === e.b);
        if (!a || !b) continue;
        const pa = toScreen(a), pb = toScreen(b);
        const dim = hoverId && !(e.a === hoverId || e.b === hoverId);
        // Bridge edges (touching shared-infrastructure pivot nodes) stand out in gold.
        const edgeColor = e.toBridge ? "rgba(255,209,102,0.75)" : e.color;
        ctx.strokeStyle = dim ? "rgba(120,160,180,0.06)" : edgeColor;
        ctx.lineWidth = e.kind === "asn" ? 0.6 : (e.toBridge ? 1.8 : 1.1);
        ctx.beginPath(); ctx.moveTo(pa.x, pa.y); ctx.lineTo(pb.x, pb.y); ctx.stroke();
        // Flow particle
        if (!dim && e.kind !== "asn") {
          const prog = ((S.t * 0.01) + (e.a.charCodeAt(0) % 10) * 0.1) % 1;
          const px = pa.x + (pb.x - pa.x) * prog, py = pa.y + (pb.y - pa.y) * prog;
          ctx.fillStyle = e.toBridge ? "rgba(255,209,102,0.95)" : e.color.replace(/[\d.]+\)$/, "0.9)");
          ctx.beginPath(); ctx.arc(px, py, e.toBridge ? 2.4 : 1.8, 0, Math.PI * 2); ctx.fill();
        }
      }

      // Nodes
      for (const n of N) {
        if (anyFilter && !vis.has(n.id)) continue;
        const p = toScreen(n);
        const base = catColor(n);
        const vc = verdictColor(n.verdict);
        const isHover = hoverId === n.id;
        const isNeighbor = neighbors.has(n.id);
        const dim = hoverId && !isHover && !isNeighbor;
        // New nodes ease up from 0 → full size for a graceful "pop in".
        const spawnScale = n.isNew ? Math.min(1, 0.3 + (n.spawnT || 0) / 90 * 0.7) : 1;
        const R = n.r * cam.zoom * (isHover ? 1.4 : 1) * spawnScale;

        // Pulsing glow for malicious/suspicious; bridge nodes always pulse gold.
        const BRIDGE_GOLD = "#ffd166";
        let glowR = R * 2.4;
        if (n.bridge) glowR *= 1.2 + 0.14 * Math.sin(S.t * 0.07);
        else if (n.verdict === "Malicious") glowR *= 1.15 + 0.12 * Math.sin(S.t * 0.08);
        else if (n.verdict === "Suspicious") glowR *= 1.05 + 0.08 * Math.sin(S.t * 0.06);

        if (!dim) {
          const preGlow = E.length === 0;
          ctx.globalAlpha = preGlow ? 0.45 : 1;
          const g = ctx.createRadialGradient(p.x, p.y, R * 0.5, p.x, p.y, glowR);
          const glowColor = n.bridge ? BRIDGE_GOLD : (vc || base);
          g.addColorStop(0, glowColor + (isHover ? "cc" : n.bridge ? "88" : "66"));
          g.addColorStop(1, glowColor + "00");
          ctx.fillStyle = g;
          ctx.beginPath(); ctx.arc(p.x, p.y, glowR, 0, Math.PI * 2); ctx.fill();
          ctx.globalAlpha = 1;
        }

        // Node body
        const preGraph = E.length === 0; // no relationships yet → dim to background texture
        ctx.globalAlpha = dim ? 0.25 : (preGraph ? 0.4 : 1);
        const body = ctx.createRadialGradient(p.x - R * 0.3, p.y - R * 0.3, R * 0.2, p.x, p.y, R);
        body.addColorStop(0, "#ffffff");
        body.addColorStop(0.3, n.bridge ? BRIDGE_GOLD : base);
        body.addColorStop(1, n.bridge ? "#f59e0b" : (vc || base));
        ctx.fillStyle = body;
        ctx.beginPath(); ctx.arc(p.x, p.y, R, 0, Math.PI * 2); ctx.fill();

        // Ring: bridge = solid gold; contacted = orange dashed (secondary infra);
        // derived = white dashed; primary = solid category color.
        if (n.bridge) {
          ctx.lineWidth = 2.5;
          ctx.strokeStyle = BRIDGE_GOLD;
          ctx.beginPath(); ctx.arc(p.x, p.y, R + 2, 0, Math.PI * 2); ctx.stroke();
        } else if (n.contacted) {
          // Contacted infra (urlscan secondary) — orange dashed ring, visually
          // distinct from serving infra to show "this was talked to, not served from".
          ctx.lineWidth = 1.5;
          ctx.strokeStyle = "rgba(251,146,60,0.8)";
          ctx.setLineDash([3, 2]);
          ctx.beginPath(); ctx.arc(p.x, p.y, R + 1.5, 0, Math.PI * 2); ctx.stroke();
          ctx.setLineDash([]);
        } else {
          ctx.lineWidth = 1.5;
          ctx.strokeStyle = n.derived ? "rgba(255,255,255,0.25)" : (vc || base);
          if (n.derived) ctx.setLineDash([2, 2]);
          ctx.beginPath(); ctx.arc(p.x, p.y, R + 1.5, 0, Math.PI * 2); ctx.stroke();
          ctx.setLineDash([]);
        }

        // Label (only when zoomed enough or hovered)
        if (((cam.zoom > 0.6 || isHover)) && !dim) {
          ctx.globalAlpha = isHover ? 1 : 0.85;
          ctx.font = `${isHover ? 12 : 10}px ui-monospace, monospace`;
          ctx.fillStyle = isHover ? "#eafcff" : "#9fb3bd";
          ctx.textAlign = "center";
          const lbl = n.label.length > 26 ? n.label.slice(0, 24) + "…" : n.label;
          ctx.fillText(lbl, p.x, p.y + R + 12);
        }
        ctx.globalAlpha = 1;
      }

      // ── Hash collapse arc animations ──────────────────────────────
      const _anims = animsRef.current;
      if (_anims && _anims.length > 0) {
        const POS = prevPosRef.current; // Map of id -> {x,y,vx,vy}
        for (const anim of _anims) {
          // Look up in prevPosRef first, fall back to live S.nodes for new nodes
          let fromPos = POS.get(anim.fromId);
          let toPos   = POS.get(anim.toId);
          if (!fromPos) fromPos = N.find(n => n.id === anim.fromId);
          if (!toPos)   toPos   = N.find(n => n.id === anim.toId);
          // Debug: log ONCE per animation to see why lookup fails
          if (!anim._debugged) {
            anim._debugged = true;
            console.log("[HashArc] Attempting animation", anim.id);
            console.log("[HashArc] fromId:", anim.fromId, "found:", !!fromPos);
            console.log("[HashArc] toId:", anim.toId, "found:", !!toPos);
            console.log("[HashArc] All node IDs in graph:", N.map(n => n.id).slice(0, 20));
          }
          if (!fromPos || !toPos) continue;
          const elapsed = Date.now() - anim.startTime;
          const DUR = 1400;
          if (elapsed > DUR) continue;
          const t = Math.min(elapsed / DUR, 1);
          // Convert world positions to screen coords (same formula as toScreen())
          const fx = cx + (fromPos.x + cam.x) * cam.zoom;
          const fy = cy + (fromPos.y + cam.y) * cam.zoom;
          const tx = cx + (toPos.x  + cam.x) * cam.zoom;
          const ty = cy + (toPos.y  + cam.y) * cam.zoom;
          const cx1 = (fx + tx) / 2 + (ty - fy) * 0.4;
          const cy1 = (fy + ty) / 2 - (tx - fx) * 0.4;
          if (t < 0.6) {
            const arcT = t / 0.6;
            const pulse = 0.5 + 0.5 * Math.sin(t * Math.PI * 8);
            ctx.save(); ctx.globalAlpha = 0.7 * pulse; ctx.shadowBlur = 24 * pulse;
            ctx.shadowColor = "#00e5ff"; ctx.beginPath();
            ctx.arc(fx, fy, 14 * cam.zoom, 0, Math.PI * 2);
            ctx.fillStyle = "rgba(0,229,255,0.25)"; ctx.fill(); ctx.restore();
            const endStep = Math.floor(arcT * 30);
            ctx.save(); ctx.globalAlpha = 0.9; ctx.shadowBlur = 10;
            ctx.shadowColor = "#00e5ff"; ctx.strokeStyle = "#00e5ff";
            ctx.lineWidth = 2.5; ctx.beginPath();
            for (let s = 0; s <= endStep; s++) {
              const bt = s / 30;
              const bx = (1-bt)*(1-bt)*fx + 2*(1-bt)*bt*cx1 + bt*bt*tx;
              const by = (1-bt)*(1-bt)*fy + 2*(1-bt)*bt*cy1 + bt*bt*ty;
              s === 0 ? ctx.moveTo(bx, by) : ctx.lineTo(bx, by);
            }
            ctx.stroke(); ctx.restore();
          } else {
            const fadeT = (t - 0.6) / 0.4;
            ctx.save(); ctx.globalAlpha = 0.9 * (1 - fadeT); ctx.shadowBlur = 8;
            ctx.shadowColor = "#00e5ff"; ctx.strokeStyle = "#00e5ff"; ctx.lineWidth = 2;
            ctx.beginPath();
            for (let s = 0; s <= 30; s++) {
              const bt = s / 30;
              const bx = (1-bt)*(1-bt)*fx + 2*(1-bt)*bt*cx1 + bt*bt*tx;
              const by = (1-bt)*(1-bt)*fy + 2*(1-bt)*bt*cy1 + bt*bt*ty;
              s === 0 ? ctx.moveTo(bx, by) : ctx.lineTo(bx, by);
            }
            ctx.stroke(); ctx.restore();
            ctx.save(); ctx.globalAlpha = (1 - fadeT) * 0.6;
            ctx.beginPath(); ctx.arc(fx, fy, 12 * cam.zoom, 0, Math.PI * 2);
            ctx.fillStyle = "rgba(0,229,255,0.3)"; ctx.fill(); ctx.restore();
            const pulse2 = 0.5 + 0.5 * Math.sin(fadeT * Math.PI * 4);
            ctx.save(); ctx.globalAlpha = 0.6 * pulse2 * fadeT; ctx.shadowBlur = 30 * pulse2;
            ctx.shadowColor = "#00ff9c"; ctx.beginPath();
            ctx.arc(tx, ty, 18 * cam.zoom, 0, Math.PI * 2);
            ctx.fillStyle = "rgba(0,255,156,0.2)"; ctx.fill(); ctx.restore();
          }
        }
      }
      // ── end arc animations ─────────────────────────────────────────

      raf = requestAnimationFrame(step);
    };
    raf = requestAnimationFrame(step);
    return () => { cancelAnimationFrame(raf); document.removeEventListener("visibilitychange", onVisible); };
  }, [dims, model, colorFor]);

  // ---- Pointer interaction ----
  const pick = (mx, my) => {
    const S = stateRef.current, cam = camRef.current;
    const cx = dims.w / 2, cy = dims.h / 2;
    const vis = visibleRef.current;
    const anyFilter = vis && vis.size !== S.nodes.length;
    for (let i = S.nodes.length - 1; i >= 0; i--) {
      const n = S.nodes[i];
      if (anyFilter && !vis.has(n.id)) continue;
      const px = cx + (n.x + cam.x) * cam.zoom, py = cy + (n.y + cam.y) * cam.zoom;
      const R = n.r * cam.zoom + 4;
      if ((mx - px) ** 2 + (my - py) ** 2 <= R * R) return n;
    }
    return null;
  };
  const relPos = (e) => {
    const rect = canvasRef.current.getBoundingClientRect();
    return { x: e.clientX - rect.left, y: e.clientY - rect.top };
  };
  const onDown = (e) => {
    const { x, y } = relPos(e);
    const n = pick(x, y);
    const cam = camRef.current;
    cam.downX = x; cam.downY = y; cam.downT = Date.now(); cam.movedFar = false;
    if (n) { cam.dragNode = n; cam.downNode = n; }
    else { cam.panning = true; cam.lastX = x; cam.lastY = y; cam.downNode = null; }
  };
  const onMove = (e) => {
    const { x, y } = relPos(e);
    const cam = camRef.current;
    if (cam.downX != null && ((x - cam.downX) ** 2 + (y - cam.downY) ** 2) > 25) cam.movedFar = true;
    if (cam.dragNode) {
      const cx = dims.w / 2, cy = dims.h / 2;
      cam.dragNode.x = (x - cx) / cam.zoom - cam.x;
      cam.dragNode.y = (y - cy) / cam.zoom - cam.y;
    } else if (cam.panning) {
      cam.x += (x - cam.lastX) / cam.zoom; cam.y += (y - cam.lastY) / cam.zoom;
      cam.lastX = x; cam.lastY = y;
    } else {
      const n = pick(x, y);
      cam.hover = n ? n.id : null;
      if (n) {
        const d = enrichCache[`${n.cat}::${n.id}`]?.data;
        setHoverInfo({ x, y, node: n, verdict: n.verdict, asn: n.asn || d?.whoisASN?.asn || null, country: d?.whoisASN?.country || null });
      } else setHoverInfo(null);
      // Grab cursor over draggable nodes; default elsewhere. Copy is via the
      // action panel (canvas text can't be natively selected).
      canvasRef.current.style.cursor = n ? "grab" : "default";
    }
  };
  const onUp = (e) => {
    const cam = camRef.current;
    // A quick, low-movement press on a node = click → open action panel.
    const clickedNode = cam.downNode; // capture BEFORE we null it below
    const wasClick = clickedNode && !cam.movedFar && (Date.now() - (cam.downT || 0)) < 400;
    if (wasClick) {
      // Close over the captured node, not the mutable ref (which we null out
      // immediately after — the setState updater runs async and would otherwise
      // read cam.downNode as null → "Cannot read properties of null (reading 'id')").
      setSelected((prev) => (prev && prev.id === clickedNode.id ? null : clickedNode));
    }
    cam.dragNode = null; cam.panning = false; cam.downNode = null; cam.downX = null;
    // Close panel ONLY on a deliberate click on the empty canvas background
    // (pointerup with no node hit and no drag). Do NOT close on pointerleave —
    // that fires when the mouse moves toward the panel, which was causing the
    // panel to vanish the moment the cursor left the canvas edge.
    if (!clickedNode && !cam.movedFar && e?.type === "pointerup") setSelected(null);
  };
  // Search: find the first node whose id/label contains the query and ease the
  // camera to center on it, then select it.
  const searchAndFocus = (q, forceIdx) => {
    if (!q || q.trim().length < 2) { setSearchMatches([]); setSearchMatchIdx(0); return; }
    const query = q.trim().toLowerCase();
    const S = stateRef.current, cam = camRef.current;
    const matches = S.nodes.filter((n) =>
      n.id.toLowerCase().includes(query) || String(n.label || "").toLowerCase().includes(query)
    );
    if (!matches.length) { setSearchMatches([]); setSearchMatchIdx(0); return; }
    const idx = forceIdx !== undefined ? forceIdx % matches.length : 0;
    setSearchMatches(matches);
    setSearchMatchIdx(idx);
    const match = matches[idx];
    cam.zoom = Math.max(cam.zoom, 1.4);
    cam.x = -match.x; cam.y = -match.y;
    cam.hover = match.id;
    setSelected(match);
  };

  // Node action handlers for the floating panel.
  const doEnrichNode = (n) => {
    if (!enrichIOC || !n) return;
    setNodeActionState((s) => ({ ...s, [n.id]: "enriching" }));
    try {
      const p = enrichIOC(n.cat, n.id);
      Promise.resolve(p).catch(() => {}).finally(() => {
        setNodeActionState((s) => ({ ...s, [n.id]: undefined }));
      });
    } catch {
      setNodeActionState((s) => ({ ...s, [n.id]: undefined }));
    }
  };
  const doAddIOCNode = (n) => {
    if (!addPivotIOC || !n) return;
    // Map graph node categories to IOC list categories.
    const catMap = { IPV4: "IPV4", IPV6: "IPV6", DOMAIN: "DOMAIN", URL: "URL", SHA256: "SHA256", SHA1: "SHA1", MD5: "MD5", EMAIL: "EMAIL" };
    const cat = catMap[n.cat] || n.cat;
    addPivotIOC(cat, n.id, "graph");
    setNodeActionState((s) => ({ ...s, [n.id]: "added" }));
    setTimeout(() => setNodeActionState((s) => ({ ...s, [n.id]: undefined })), 1500);
  };
  const doCopyNode = (n) => {
    if (copyText) copyText(n.id, `graph-${n.id}`);
    setCopiedNodeId(n.id);
    setTimeout(() => setCopiedNodeId(null), 1400);
  };
  const vtLinkFor = (n) => {
    const v = encodeURIComponent(n.id);
    if (["MD5", "SHA1", "SHA256", "SHA512"].includes(n.cat)) return `https://www.virustotal.com/gui/file/${v}`;
    if (n.cat === "IPV4" || n.cat === "IPV6") return `https://www.virustotal.com/gui/ip-address/${v}`;
    if (n.cat === "URL") return `https://www.virustotal.com/gui/search/${v}`;
    return `https://www.virustotal.com/gui/domain/${v}`;
  };

  if (!iocData || model.nodes.length === 0) {
    return (
      <div className="rounded-xl p-10 text-center" style={{ background: "rgba(10,14,20,0.72)", border: "1px solid rgba(120,160,180,0.16)" }}>
        <p className="text-sm" style={{ color: "#5d7382" }}>No IOCs to graph yet. Extract and enrich indicators to see the infrastructure graph.</p>
      </div>
    );
  }

  const legendItems = [
    ["IPV4", "IP address"], ["DOMAIN", "Domain"], ["URL", "URL"],
    ["SHA256", "File hash"], ["EMAIL", "Email"],
  ];

  // Minimal default state: until relationships exist (edges), hide the stats /
  // legend / slicer so the just-parsed view is calm with a single clear caption.
  const hasGraph = model.stats.edges > 0;

  return (
    <div ref={wrapRef} className={fullscreen ? "overflow-hidden relative" : "rounded-xl overflow-hidden relative"}
      style={fullscreen
        ? { position: "fixed", inset: 0, zIndex: 9999, background: "radial-gradient(1200px 600px at 50% 0%, rgba(0,229,255,0.06), transparent 60%), #05070a" }
        : { background: "radial-gradient(1200px 600px at 50% 0%, rgba(0,229,255,0.06), transparent 60%), #05070a", border: "1px solid rgba(120,160,180,0.2)" }}>
      {!hasGraph && (
        <button onClick={() => setFullscreen((v) => !v)}
          className="absolute z-20 flex items-center gap-1 rounded-md px-2.5 py-1 text-[10px] font-semibold"
          style={{ bottom: 10, right: 10, background: fullscreen ? "#ff4d6d" : "rgba(0,229,255,0.12)", color: fullscreen ? "#fff" : "#00e5ff", border: `1px solid ${fullscreen ? "rgba(255,77,109,0.8)" : "rgba(0,229,255,0.4)"}`, cursor: "pointer" }}>
          {fullscreen ? <><X size={11} /> Exit</> : <><Share2 size={11} /> Fullscreen</>}
        </button>
      )}
      {/* Slicer chip-bar */}
      {hasGraph && (
      <div className="absolute z-10 rounded-lg overflow-hidden"
        style={{ bottom: 8, left: 8, right: 8, background: "rgba(10,14,20,0.90)", border: "1px solid rgba(120,160,180,0.2)", backdropFilter: "blur(8px)" }}>
        {/* Top row: search + fullscreen */}
        <div className="flex items-center justify-between px-2.5 py-1.5 gap-2" style={{ borderBottom: "1px solid rgba(120,160,180,0.12)" }}>
          {/* Search */}
          <div className="flex items-center gap-1.5 flex-1 min-w-0">
            <button onClick={() => { setShowSearch((v) => !v); if (showSearch) { setSearchQuery(""); setSearchMatches([]); } }}
              className="rounded-md p-1.5 flex items-center justify-center shrink-0"
              title="Search nodes (Enter cycles through matches)"
              style={{ background: showSearch ? "#00e5ff" : "rgba(0,229,255,0.12)", color: showSearch ? "#04111a" : "#00e5ff", border: "1px solid rgba(0,229,255,0.4)", cursor: "pointer" }}>
              <Search size={12} />
            </button>
            {showSearch && (
              <>
                {searchMatches.length > 0 && (
                  <span className="text-[10px] font-bold rounded px-1.5 py-0.5 shrink-0"
                    style={{ color: "#00e5ff", background: "rgba(0,229,255,0.12)", border: "1px solid rgba(0,229,255,0.3)", minWidth: 32, textAlign: "center" }}>
                    {searchMatchIdx + 1}/{searchMatches.length}
                  </span>
                )}
                <input autoFocus value={searchQuery}
                  onChange={(e) => { setSearchQuery(e.target.value); setSearchMatchIdx(0); searchAndFocus(e.target.value, 0); }}
                  onKeyDown={(e) => {
                    if (e.key === "Enter") {
                      e.preventDefault();
                      if (!searchMatches.length) { searchAndFocus(searchQuery, 0); return; }
                      const nextIdx = (searchMatchIdx + 1) % searchMatches.length;
                      setSearchMatchIdx(nextIdx);
                      searchAndFocus(searchQuery, nextIdx);
                    }
                    if (e.key === "Escape") { setShowSearch(false); setSearchQuery(""); setSearchMatches([]); setSearchMatchIdx(0); }
                  }}
                  placeholder="Search node…"
                  className="rounded-md px-2 py-0.5 text-[11px] outline-none flex-1 min-w-0"
                  style={{ background: "rgba(0,0,0,0.4)", border: "1px solid rgba(0,229,255,0.3)", color: "#dff" }} />
              </>
            )}
          </div>
          {/* Fullscreen */}
          <button onClick={() => setFullscreen((v) => !v)}
            className="flex items-center gap-1 rounded-md px-2.5 py-1 text-[10px] font-semibold shrink-0"
            title={fullscreen ? "Exit fullscreen (Esc)" : "Enter fullscreen"}
            style={{
              background: fullscreen ? "#ff4d6d" : "rgba(0,229,255,0.12)",
              color: fullscreen ? "#fff" : "#00e5ff",
              border: `1px solid ${fullscreen ? "rgba(255,77,109,0.8)" : "rgba(0,229,255,0.4)"}`,
              cursor: "pointer",
              boxShadow: fullscreen ? "0 0 14px rgba(255,77,109,0.4)" : "none",
            }}>
            {fullscreen ? <><X size={11} /> Exit</> : <><Share2 size={11} /> Fullscreen</>}
          </button>
        </div>
        {/* Bottom row: filter chips */}
        <div className="flex flex-wrap items-center gap-1 px-2.5 py-1.5">
        <span className="text-[9px] uppercase tracking-widest font-bold mr-0.5" style={{ color: "#5d7382" }}>Filter</span>
        {/* Type toggles */}
        {model.typeCounts && model.typeCounts.map(([cat, count]) => {
          const c = colorFor(cat);
          const on = !hiddenCats[cat];
          return (
            <button key={cat} onClick={() => setHiddenCats((h) => ({ ...h, [cat]: on }))}
              className="rounded-full px-2 py-0.5 text-[9px] font-bold flex items-center gap-1"
              style={{ background: on ? `${c}22` : "rgba(120,160,180,0.06)", color: on ? c : "#5d7382", border: `1px solid ${on ? c + "66" : "rgba(120,160,180,0.2)"}`, cursor: "pointer", opacity: on ? 1 : 0.5 }}>
              <span style={{ width: 6, height: 6, borderRadius: 99, background: on ? c : "#5d7382" }} />
              {cat} {count}
            </button>
          );
        })}
        <span style={{ width: 1, height: 14, background: "rgba(120,160,180,0.25)", margin: "0 2px" }} />
        {/* Verdict filters */}
        {["Malicious", "Suspicious", "Whitelisted"].map((v) => {
          const vcol = v === "Malicious" ? "#ff4d6d" : v === "Suspicious" ? "#fbbf24" : "#00ff9c";
          const on = !hiddenVerdicts[v];
          return (
            <button key={v} onClick={() => setHiddenVerdicts((h) => ({ ...h, [v]: on }))}
              className="rounded-full px-2 py-0.5 text-[9px] font-bold"
              style={{ background: on ? `${vcol}22` : "rgba(120,160,180,0.06)", color: on ? vcol : "#5d7382", border: `1px solid ${on ? vcol + "66" : "rgba(120,160,180,0.2)"}`, cursor: "pointer", opacity: on ? 1 : 0.5 }}>
              {v === "Malicious" ? "🔴" : v === "Suspicious" ? "🟡" : "🟢"} {v}
            </button>
          );
        })}
        <span style={{ width: 1, height: 14, background: "rgba(120,160,180,0.25)", margin: "0 2px" }} />
        {/* Structural toggles */}
        <button onClick={() => setHideDerived((v) => !v)}
          className="rounded-full px-2 py-0.5 text-[9px] font-bold"
          style={{ background: hideDerived ? "rgba(192,132,252,0.25)" : "rgba(120,160,180,0.06)", color: hideDerived ? "#c084fc" : "#8aa0ad", border: `1px solid ${hideDerived ? "rgba(192,132,252,0.5)" : "rgba(120,160,180,0.2)"}`, cursor: "pointer" }}>
          {hideDerived ? "◇ derived hidden" : "◆ hide derived"}
        </button>
        <button onClick={() => setIsolateMalicious((v) => !v)}
          className="rounded-full px-2 py-0.5 text-[9px] font-bold"
          style={{ background: isolateMalicious ? "rgba(255,77,109,0.25)" : "rgba(120,160,180,0.06)", color: isolateMalicious ? "#ff4d6d" : "#8aa0ad", border: `1px solid ${isolateMalicious ? "rgba(255,77,109,0.5)" : "rgba(120,160,180,0.2)"}`, cursor: "pointer" }}>
          ⌖ isolate malicious
        </button>
        {model.stats.orphans > 0 && (
          <button onClick={() => setHideOrphans((v) => !v)}
            className="rounded-full px-2 py-0.5 text-[9px] font-bold"
            style={{ background: hideOrphans ? "rgba(120,160,180,0.25)" : "rgba(120,160,180,0.06)", color: hideOrphans ? "#e6f0f3" : "#8aa0ad", border: "1px solid rgba(120,160,180,0.3)", cursor: "pointer" }}>
            {hideOrphans ? `○ ${model.stats.orphans} orphans hidden` : `● hide ${model.stats.orphans} orphans`}
          </button>
        )}
        {/* Shared pivots toggle — only when bridges exist */}
        {model.stats.bridges > 0 && (
          <button onClick={() => setIsolateSharedPivots((v) => !v)}
            className="rounded-full px-2 py-0.5 text-[9px] font-bold"
            style={{ background: isolateSharedPivots ? "rgba(255,209,102,0.3)" : "rgba(120,160,180,0.06)", color: isolateSharedPivots ? "#ffd166" : "#8aa0ad", border: `1px solid ${isolateSharedPivots ? "rgba(255,209,102,0.6)" : "rgba(120,160,180,0.2)"}`, cursor: "pointer" }}>
            ◈ shared pivots {isolateSharedPivots ? "only" : `(${model.stats.bridges})`}
          </button>
        )}
        </div>
      </div>
      )}
      {/* Stats bar — minimal (just node count) before graph forms, full after */}
      <div className="absolute top-3 left-3 z-10 flex items-center gap-3 rounded-lg px-3 py-1.5 text-[11px]"
        style={{ background: "rgba(10,14,20,0.8)", border: "1px solid rgba(120,160,180,0.2)", backdropFilter: "blur(6px)", color: "#9fb3bd" }}>
        <span><span style={{ color: "#00ff9c", fontWeight: 700 }}>{model.stats.nodes}</span> nodes</span>
        {hasGraph && <span><span style={{ color: "#00e5ff", fontWeight: 700 }}>{model.stats.edges}</span> links</span>}
        {hasGraph && <span><span style={{ color: "#c084fc", fontWeight: 700 }}>{model.stats.derived}</span> derived</span>}
        {hasGraph && model.stats.bridges > 0 && <span><span style={{ color: "#ffd166", fontWeight: 700 }}>{model.stats.bridges}</span> shared</span>}
      </div>
      {/* Legend — only once relationships exist */}
      {hasGraph && (
      <div className="absolute top-3 right-3 z-10 flex flex-wrap gap-2 rounded-lg px-3 py-1.5 max-w-[60%] justify-end"
        style={{ background: "rgba(10,14,20,0.8)", border: "1px solid rgba(120,160,180,0.2)", backdropFilter: "blur(6px)" }}>
        {legendItems.map(([cat, label]) => (
          <span key={cat} className="flex items-center gap-1 text-[10px]" style={{ color: "#9fb3bd" }}>
            <span style={{ width: 8, height: 8, borderRadius: 99, background: colorFor(cat), boxShadow: `0 0 6px ${colorFor(cat)}` }} />
            {label}
          </span>
        ))}
        <span className="flex items-center gap-1 text-[10px]" style={{ color: "#9fb3bd" }}>
          <span style={{ width: 8, height: 8, borderRadius: 99, border: "1.5px dashed rgba(255,255,255,0.4)" }} /> derived
        </span>
        <span className="flex items-center gap-1 text-[10px]" style={{ color: "rgba(251,146,60,0.9)" }}>
          <span style={{ width: 8, height: 8, borderRadius: 99, border: "1.5px dashed rgba(251,146,60,0.8)" }} /> contacted
        </span>
        <span className="flex items-center gap-1 text-[10px]" style={{ color: "#ffd166" }}>
          <span style={{ width: 8, height: 8, borderRadius: 99, background: "#ffd166", boxShadow: "0 0 6px #ffd166" }} /> shared pivot
        </span>
      </div>
      )}
      {!anyEnriched && (
        <div className="absolute z-10 pointer-events-none"
          style={{ top: "50%", left: "50%", transform: "translate(-50%, -50%)" }}>
          <div className="rounded-xl px-5 py-3 text-center"
            style={{ background: "rgba(10,14,20,0.92)", border: "1px solid rgba(0,229,255,0.3)", boxShadow: "0 0 32px rgba(0,229,255,0.15)", backdropFilter: "blur(8px)" }}>
            <div className="text-sm font-semibold" style={{ color: "#00e5ff" }}>✨ Enrich indicators to reveal the infrastructure graph</div>
            <div className="text-[10px] mt-1" style={{ color: "#5d7382" }}>Click Enrich All on any card, or enrich individual IOCs</div>
          </div>
        </div>
      )}

      <canvas ref={canvasRef}
        style={{ width: dims.w, height: dims.h, display: "block", touchAction: "none", transition: "height 0.6s cubic-bezier(0.22,1,0.36,1)" }}
        onPointerDown={onDown} onPointerMove={onMove} onPointerUp={onUp}
        onPointerLeave={() => { const cam = camRef.current; cam.dragNode = null; cam.panning = false; }}
        onDoubleClick={(e) => { e.preventDefault(); e.stopPropagation(); }}
      />

      {/* Hover card */}
      {hoverInfo && (
        <div className="absolute z-20 pointer-events-none rounded-lg px-3 py-2 text-[11px]"
          style={{
            left: Math.min(hoverInfo.x + 14, dims.w - 220), top: Math.min(hoverInfo.y + 14, dims.h - 90),
            background: "rgba(10,14,20,0.95)", border: `1px solid ${colorFor(hoverInfo.node.cat)}66`,
            backdropFilter: "blur(8px)", minWidth: 180, maxWidth: 260,
            boxShadow: `0 0 24px ${colorFor(hoverInfo.node.cat)}33`,
          }}>
          <div className="font-bold break-all mb-1" style={{ color: colorFor(hoverInfo.node.cat) }}>{hoverInfo.node.label}</div>
          <div style={{ color: "#7f95a3" }}>{hoverInfo.node.cat}{hoverInfo.node.derived ? " · derived" : ""}</div>
          {hoverInfo.verdict && (
            <div style={{ color: hoverInfo.verdict === "Malicious" ? "#ff4d6d" : hoverInfo.verdict === "Suspicious" ? "#fbbf24" : "#00ff9c", fontWeight: 700, marginTop: 2 }}>
              {hoverInfo.verdict === "Malicious" ? "🔴" : hoverInfo.verdict === "Suspicious" ? "🟡" : "🟢"} {hoverInfo.verdict}
            </div>
          )}
          {hoverInfo.asn && <div style={{ color: "#a78bfa", marginTop: 2 }}>{hoverInfo.asn}</div>}
          {hoverInfo.country && <div style={{ color: "#8aa0ad" }}>{hoverInfo.country}</div>}
        </div>
      )}

      {/* Node action panel — click a node to open, click canvas to close */}
      {selected && (() => {
        try {
          const st = nodeActionState[selected.id];
          const canEnrich = ["IPV4", "IPV6", "DOMAIN", "URL", "MD5", "SHA1", "SHA256"].includes(selected.cat);
          const isEnriched = !!enrichCache[`${selected.cat}::${selected.id}`]?.data;
          const enrData = enrichCache[`${selected.cat}::${selected.id}`]?.data;
          const c = colorFor(selected.cat) || "#00e5ff";
          const isCopied = copiedNodeId === selected.id;

          // High-level enrichment summary snippets
          const summary = enrData ? [
            enrData._verdict && enrData._verdict !== "Unknown" && { label: "Verdict", value: `${enrData._verdict === "Malicious" ? "🔴" : enrData._verdict === "Suspicious" ? "🟡" : "🟢"} ${enrData._verdict}`, color: enrData._verdict === "Malicious" ? "#ff4d6d" : enrData._verdict === "Suspicious" ? "#fbbf24" : "#00ff9c" },
            enrData.whoisASN?.asn && { label: "ASN", value: enrData.whoisASN.asn },
            enrData.whoisASN?.country && { label: "Country", value: enrData.whoisASN.country },
            enrData.otx?.pulses && { label: "OTX Pulses", value: enrData.otx.pulses },
            enrData.urlscan?.brands?.length && { label: "Impersonates", value: `🎭 ${enrData.urlscan.brands[0]}`, color: "#ff4d6d" },
            enrData.urlscan?.tlsIssuer && { label: "TLS", value: enrData.urlscan.tlsIssuer.split(" ")[0] },
            enrData.abuseipdb?.score != null && { label: "AbuseIPDB", value: `${enrData.abuseipdb.score}%` },
            enrData.urlscan?.firstSeen && { label: "First Seen", value: fmtDate(enrData.urlscan.firstSeen) },
            enrData.malwarebazaar?.fileName && { label: "File", value: enrData.malwarebazaar.fileName },
            enrData.threatfox?.malwareFamily && { label: "Family", value: enrData.threatfox.malwareFamily },
          ].filter(Boolean) : [];

          return (
            <div className="absolute z-30 rounded-xl p-3"
              style={{ top: 52, right: 12, width: 270, background: "rgba(10,14,20,0.97)", border: `1px solid ${c}66`, backdropFilter: "blur(10px)", boxShadow: `0 0 30px ${c}33` }}>
              <div className="flex items-start justify-between gap-2 mb-2">
                <div className="min-w-0">
                  <div className="font-bold break-all text-[12px]" style={{ color: c }}>{selected.label}</div>
                  <div className="text-[10px]" style={{ color: "#7f95a3" }}>
                    {selected.cat}
                    {selected.derived ? " · derived" : " · primary"}
                    {selected.bridge ? " · 🔗 shared pivot" : ""}
                    {selected.contacted ? " · contacted" : ""}
                  </div>
                </div>
                <button onClick={() => setSelected(null)} className="shrink-0 rounded p-0.5" style={{ color: "#5d7382", cursor: "pointer", background: "none", border: "none" }}><X size={13} /></button>
              </div>

              {/* Enrichment summary — shows after enrichment */}
              {summary.length > 0 && (
                <div className="mb-2.5 rounded-lg px-2.5 py-2 flex flex-col gap-1"
                  style={{ background: "rgba(255,255,255,0.03)", border: "1px solid rgba(120,160,180,0.15)" }}>
                  {summary.map((s, i) => (
                    <div key={i} className="flex items-center justify-between text-[10px]">
                      <span style={{ color: "#5d7382" }}>{s.label}</span>
                      <span className="font-semibold" style={{ color: s.color || "#c8d6dd" }}>{s.value}</span>
                    </div>
                  ))}
                </div>
              )}

              {/* Action buttons */}
              <div className="flex flex-wrap gap-1.5">
                {canEnrich && (
                  isEnriched ? (
                    <span className="flex items-center gap-1 rounded-md px-2 py-1 text-[10px] font-bold"
                      style={{ color: "#5d7382", background: "rgba(120,160,180,0.08)", border: "1px solid rgba(120,160,180,0.2)" }}>
                      <Check size={11} /> Enriched
                    </span>
                  ) : (
                    <button onClick={(e) => { e.stopPropagation(); const node = selected; doEnrichNode(node); }}
                      disabled={st === "enriching"}
                      className="flex items-center gap-1 rounded-md px-2 py-1 text-[10px] font-bold"
                      style={{ color: "#04111a", background: "#2dd4bf", border: "none", cursor: st === "enriching" ? "wait" : "pointer", opacity: st === "enriching" ? 0.7 : 1 }}>
                      {st === "enriching" ? <Loader2 size={11} className="animate-spin" /> : <Search size={11} />}
                      {st === "enriching" ? "Enriching…" : "Enrich"}
                    </button>
                  )
                )}
                {selected.derived && (() => {
                  const catMap = { IPV4: "IPV4", IPV6: "IPV6", DOMAIN: "DOMAIN", URL: "URL", SHA256: "SHA256", SHA1: "SHA1", MD5: "MD5", EMAIL: "EMAIL" };
                  const mapped = catMap[selected.cat] || selected.cat;
                  const alreadyIn = (isPivotAdded && isPivotAdded(mapped, selected.id))
                    || (iocData?.[mapped] || []).some((v) => String(v).toLowerCase().replace(/^https?:\/\//, "").replace(/\/+$/, "") === selected.id);
                  if (alreadyIn || st === "added") {
                    return (
                      <span className="flex items-center gap-1 rounded-md px-2 py-1 text-[10px] font-bold"
                        style={{ color: "#04111a", background: "#00ff9c", border: "1px solid rgba(0,255,156,0.4)" }}>
                        <Check size={11} /> In list
                      </span>
                    );
                  }
                  return (
                    <button onClick={(e) => { e.stopPropagation(); doAddIOCNode(selected); }}
                      className="flex items-center gap-1 rounded-md px-2 py-1 text-[10px] font-bold"
                      style={{ color: "#00ff9c", background: "rgba(0,255,156,0.12)", border: "1px solid rgba(0,255,156,0.4)", cursor: "pointer" }}>
                      <Sparkles size={11} /> Add as IOC
                    </button>
                  );
                })()}
                <button onClick={(e) => { e.stopPropagation(); doCopyNode(selected); }}
                  className="flex items-center gap-1 rounded-md px-2 py-1 text-[10px] font-bold transition-colors"
                  style={{ color: isCopied ? "#04111a" : "#00e5ff", background: isCopied ? "#00e5ff" : "rgba(0,229,255,0.12)", border: "1px solid rgba(0,229,255,0.4)", cursor: "pointer" }}>
                  {isCopied ? <Check size={11} /> : <Copy size={11} />} {isCopied ? "Copied!" : "Copy"}
                </button>
                <a href={vtLinkFor(selected)} target="_blank" rel="noreferrer noopener"
                  className="flex items-center gap-1 rounded-md px-2 py-1 text-[10px] font-bold"
                  style={{ color: "#c084fc", background: "rgba(192,132,252,0.12)", border: "1px solid rgba(192,132,252,0.4)", textDecoration: "none" }}>
                  🛡️ VT
                </a>
                {/* Removal buttons */}
                <button onClick={(e) => { e.stopPropagation(); setHiddenNodes((h) => { const n = new Set(h); n.add(selected.id); return n; }); setSelected(null); }}
                  className="flex items-center gap-1 rounded-md px-2 py-1 text-[10px] font-bold w-full mt-1"
                  title="Hide this node from the graph (IOC remains in your list)"
                  style={{ color: "#ff6b6b", background: "rgba(255,107,107,0.08)", border: "1px solid rgba(255,107,107,0.3)", cursor: "pointer" }}>
                  <X size={11} /> Hide from graph
                </button>
                {(() => {
                  // "Remove from graph & list" only when this node is in the IOC list
                  const catMap = { IPV4:"IPV4", IPV6:"IPV6", DOMAIN:"DOMAIN", URL:"URL", SHA256:"SHA256", SHA1:"SHA1", MD5:"MD5", EMAIL:"EMAIL" };
                  const mapped = catMap[selected.cat] || selected.cat;
                  const inList = (iocData?.[mapped] || []).some((v) => String(v).toLowerCase().replace(/^https?:\/\//, "").replace(/\/+$/, "") === selected.id)
                    || (isPivotAdded && isPivotAdded(mapped, selected.id));
                  if (!inList) return null;
                  return (
                    <button onClick={(e) => {
                      e.stopPropagation();
                      setHiddenNodes((h) => { const n = new Set(h); n.add(selected.id); return n; });
                      if (removeIoc) removeIoc(mapped, selected.id);
                      setSelected(null);
                    }}
                      className="flex items-center gap-1 rounded-md px-2 py-1 text-[10px] font-bold w-full"
                      title="Remove from graph and from your IOC list"
                      style={{ color: "#ff4d6d", background: "rgba(255,77,109,0.1)", border: "1px solid rgba(255,77,109,0.4)", cursor: "pointer" }}>
                      <X size={11} /> Remove from graph & list
                    </button>
                  );
                })()}
              </div>
            </div>
          );
        } catch { return null; }
      })()}
    </div>
  );
}

function GButton({ children, onClick, disabled, color, icon, solid, flash }) {
  return (
    <button onClick={onClick} disabled={disabled}
      className="flex items-center gap-1.5 rounded-lg px-3 py-2 text-sm font-semibold transition-all"
      style={{
        color: solid ? "#04111a" : color,
        backgroundColor: solid ? color : `${color}14`,
        border: `1px solid ${color}${solid ? "" : "55"}`,
        boxShadow: flash ? `0 0 28px ${color}cc, 0 0 8px ${color}` : solid ? `0 0 18px ${color}55` : "none",
        transform: flash ? "scale(1.06)" : "scale(1)",
        opacity: disabled ? 0.4 : 1,
        cursor: disabled ? "not-allowed" : "pointer",
        transition: "transform 0.15s, box-shadow 0.15s",
      }}>
      {icon}{children}
    </button>
  );
}

function Tab({ children, active, onClick, icon }) {
  return (
    <button onClick={onClick} className="flex items-center gap-1.5 rounded-md px-3 py-1.5 text-xs font-semibold"
      style={{ color: active ? "#04111a" : "#8aa0ad", backgroundColor: active ? "#d99a4e" : "transparent", boxShadow: active ? "0 0 14px rgba(217,154,78,0.4)" : "none" }}>
      {icon} {children}
    </button>
  );
}

// Relative "time ago" for a feed item's pubDate (RFC 822 or ISO 8601 — the
// native Date constructor parses both).
const wireTimeAgo = (dateStr) => {
  if (!dateStr) return null;
  const d = new Date(dateStr);
  if (isNaN(d)) return null;
  const diffMs = Date.now() - d.getTime();
  if (diffMs < 0) return "just now";
  const mins = Math.floor(diffMs / 60000);
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  const days = Math.floor(hrs / 24);
  return `${days}d ago`;
};

// Editorial text (real headlines, real company names) reads poorly in the
// app's monospace system font at small sizes — this is the one place in the
// app that intentionally switches to a normal UI sans-serif, matching how
// any news/RSS reader sets headline text.
const WIRE_SANS_FONT = '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif';

function ThreatWireThumb({ item }) {
  // 0 = try the article's own image, 1 = try the source favicon, 2 = monogram
  const [stage, setStage] = useState(() => (item.image ? 0 : 1));
  const monogram = (item.name || "?").replace(/[^A-Za-z0-9]/g, "").slice(0, 3).toUpperCase() || "?";

  if (stage === 0 && item.image) {
    return (
      <div className="shrink-0 rounded-md overflow-hidden" style={{ width: 100, height: 72 }}>
        <img src={item.image} alt="" onError={() => setStage(1)}
          style={{ width: "100%", height: "100%", objectFit: "cover", display: "block" }} />
      </div>
    );
  }
  if (stage === 1 && item.favicon) {
    return (
      <div className="shrink-0 rounded-md overflow-hidden relative flex items-center justify-center" style={{ width: 100, height: 72, backgroundColor: `${item.color}1f` }}>
        <div className="absolute inset-0" style={{ opacity: 0.14, backgroundImage: "repeating-linear-gradient(135deg, currentColor 0 2px, transparent 2px 9px)", color: item.color }} />
        <img src={item.favicon} alt="" onError={() => setStage(2)}
          style={{ width: 30, height: 30, objectFit: "contain", position: "relative", borderRadius: 6 }} />
      </div>
    );
  }
  return (
    <div className="shrink-0 rounded-md overflow-hidden relative flex items-center justify-center" style={{ width: 100, height: 72, backgroundColor: `${item.color}1f`, color: item.color }}>
      <div className="absolute inset-0" style={{ opacity: 0.16, backgroundImage: "repeating-linear-gradient(135deg, currentColor 0 2px, transparent 2px 9px)" }} />
      <span className="relative text-[14px] font-bold tracking-wide">{monogram}</span>
    </div>
  );
}

function ThreatWireRow({ item, onHunt }) {
  const freshMs = item.pubDate ? Date.now() - new Date(item.pubDate).getTime() : Infinity;
  const isFresh = freshMs < 3 * 3600000; // under 3h — matches the live-dot treatment in the design pitch

  return (
    <div
      role="button" tabIndex={0}
      onClick={() => onHunt(item.link)}
      onKeyDown={(e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); onHunt(item.link); } }}
      className="flex gap-3 rounded-lg p-3 cursor-pointer"
      style={{
        backgroundColor: "rgba(10,14,20,0.55)",
        border: "1px solid rgba(120,160,180,0.14)",
        transition: "border-color 0.15s, background-color 0.15s",
      }}
      onMouseEnter={(e) => { e.currentTarget.style.borderColor = "rgba(120,160,180,0.32)"; e.currentTarget.style.backgroundColor = "rgba(14,19,26,0.85)"; }}
      onMouseLeave={(e) => { e.currentTarget.style.borderColor = "rgba(120,160,180,0.14)"; e.currentTarget.style.backgroundColor = "rgba(10,14,20,0.55)"; }}
    >
      <ThreatWireThumb item={item} />
      <div className="min-w-0 flex-1 flex flex-col justify-center gap-1.5">
        <div className="flex items-center justify-between gap-2">
          <span className="uppercase truncate" style={{ fontFamily: WIRE_SANS_FONT, fontSize: 11.5, fontWeight: 700, letterSpacing: "1px", color: item.color }}>{item.name}</span>
          {item.pubDate && (
            <span className="shrink-0 flex items-center gap-1.5" style={{ fontFamily: WIRE_SANS_FONT, fontSize: 11.5, color: "#8aa0ad" }}>
              {isFresh && <span className="w-1.5 h-1.5 rounded-full animate-pulse" style={{ backgroundColor: "#00ff9c" }} />}
              {wireTimeAgo(item.pubDate)}
            </span>
          )}
        </div>
        <div style={{ fontFamily: WIRE_SANS_FONT, fontSize: 15.5, fontWeight: 600, lineHeight: 1.4, color: "#eafcff" }}>{item.title}</div>
        <div className="flex items-center justify-between gap-2">
          <span className="truncate" style={{ fontFamily: WIRE_SANS_FONT, fontSize: 11.5, color: "#7f95a3" }}>{item.domain}</span>
          <span className="shrink-0" style={{ fontFamily: WIRE_SANS_FONT, fontSize: 11, fontWeight: 700, color: "#d99a4e", letterSpacing: "0.4px" }}>HUNT THIS →</span>
        </div>
      </div>
    </div>
  );
}

// Continuously auto-scrolls upward like a ticker wheel. Hovering pauses it
// (native wheel-scroll then works normally, revealing older items further
// down); moving the mouse away resumes rolling from wherever it was left.
// The item list is rendered twice back-to-back and scrollTop wraps at the
// halfway point, so the loop is seamless with no visible jump.
function ThreatWireTicker({ items, onHunt }) {
  const containerRef = useRef(null);
  const pausedRef = useRef(false);
  const posRef = useRef(0);

  useEffect(() => {
    const el = containerRef.current;
    if (!el || items.length < 2) return;
    if (window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;

    let lastTs = null;
    let rafId;
    const SPEED_PX_PER_SEC = 26;
    const tick = (ts) => {
      if (lastTs == null) lastTs = ts;
      const dt = (ts - lastTs) / 1000;
      lastTs = ts;
      if (!pausedRef.current) {
        const half = el.scrollHeight / 2;
        if (half > 0) {
          posRef.current += SPEED_PX_PER_SEC * dt;
          if (posRef.current >= half) posRef.current -= half;
          el.scrollTop = posRef.current;
        }
      }
      rafId = requestAnimationFrame(tick);
    };
    rafId = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(rafId);
  }, [items.length]);

  return (
    <div
      ref={containerRef}
      onMouseEnter={() => { pausedRef.current = true; }}
      onMouseLeave={() => { pausedRef.current = false; }}
      onScroll={(e) => { posRef.current = e.currentTarget.scrollTop; }}
      className="flex flex-col gap-2"
      style={{ maxHeight: 460, overflowY: "auto" }}
    >
      {items.map((it) => <ThreatWireRow key={`a-${it.id}`} item={it} onHunt={onHunt} />)}
      {items.length > 1 && items.map((it) => <ThreatWireRow key={`b-${it.id}`} item={it} onHunt={onHunt} />)}
    </div>
  );
}

function ThreatWire({ onHunt }) {
  const [items, setItems] = useState(null); // null = loading, [] = loaded (possibly empty)
  const [failed, setFailed] = useState(false);

  useEffect(() => {
    let cancelled = false;
    fetch(`${WORKER_BASE}/blogs`)
      .then((r) => { if (!r.ok) throw new Error(`HTTP ${r.status}`); return r.json(); })
      .then((j) => { if (!cancelled) setItems(Array.isArray(j.items) ? j.items.filter((b) => !b.error) : []); })
      .catch(() => { if (!cancelled) setFailed(true); });
    return () => { cancelled = true; };
  }, []);

  if (failed || (items && items.length === 0)) return null;

  return (
    <div className="rounded-xl p-4 mb-5" style={{ backgroundColor: "rgba(10,14,20,0.5)", border: "1px solid rgba(120,160,180,0.14)" }}>
      <div className="flex items-center gap-2 mb-1">
        <span className="w-1.5 h-1.5 rounded-full animate-pulse" style={{ backgroundColor: "#d99a4e", boxShadow: "0 0 8px #d99a4e" }} />
        <span className="text-[10px] font-bold uppercase" style={{ letterSpacing: "2.5px", color: "#d99a4e" }}>Live threat intel wire</span>
      </div>
      <div className="mt-3">
        {items === null
          ? (
            <div className="flex flex-col gap-2">
              {Array.from({ length: 4 }).map((_, i) => (
                <div key={i} className="rounded-lg animate-pulse" style={{ height: 72, backgroundColor: "rgba(120,160,180,0.06)" }} />
              ))}
            </div>
          )
          : <ThreatWireTicker items={items} onHunt={onHunt} />}
      </div>
    </div>
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
