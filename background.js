// background.js — VT checker + small cache. NLP is done in content (post-VT).

const VT_API = "YOUR_VT_API_KEY_HERE"; // <-- add your key
const VT_CACHE_TTL_MS = 5 * 60 * 1000;
const vtCache = new Map();

const SKEY_LAST = "CLIXUS_LAST_RESULT"; // for popup display

function b64url(s) {
  const b64 = btoa(unescape(encodeURIComponent(s)));
  return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}
const sleep = (ms) => new Promise(r => setTimeout(r, ms));

async function vtStableStats(url, tries = 6, delay = 800) {
  const id = b64url(url);
  let stats = null;
  for (let i = 0; i < tries; i++) {
    const r = await fetch(`https://www.virustotal.com/api/v3/urls/${id}`, {
      headers: { "x-apikey": VT_API }
    });
    if (!r.ok) throw new Error(`VT urls/${id}: ${r.status} ${r.statusText}`);
    const j = await r.json();
    stats = j?.data?.attributes?.last_analysis_stats || null;

    const total = ["malicious","suspicious","harmless","undetected","timeout","failure","type-unsupported"]
      .reduce((s,k)=> s + Number(stats?.[k] || 0), 0);
    const positives = Number(stats?.malicious||0) + Number(stats?.suspicious||0);
    if (positives > 0 || total >= 60 || i === tries-1) {
      return {
        malicious: Number(stats?.malicious || 0),
        suspicious: Number(stats?.suspicious || 0),
        harmless:   Number(stats?.harmless  || 0),
        undetected: Number(stats?.undetected || 0),
        totalEngines: total
      };
    }
    await sleep(delay);
  }
  return {
    malicious: Number(stats?.malicious || 0),
    suspicious: Number(stats?.suspicious || 0),
    harmless:   Number(stats?.harmless  || 0),
    undetected: Number(stats?.undetected || 0),
    totalEngines: Number(stats ? 60 : 0)
  };
}

async function queryVT(url) {
  const now = Date.now();
  const hit = vtCache.get(url);
  if (hit && (now - hit.ts) < VT_CACHE_TTL_MS) return hit.verdict;

  // nudge freshness
  await fetch("https://www.virustotal.com/api/v3/urls", {
    method: "POST",
    headers: { "x-apikey": VT_API, "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ url })
  }).catch(()=>{});

  const verdict = await vtStableStats(url);
  vtCache.set(url, { ts: now, verdict });
  return verdict;
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg?.type === "CLIXUS_CHECK_URL") {
    queryVT(msg.url)
      .then(v => sendResponse({ verdict: v }))
      .catch(e => sendResponse({ verdict: { error: true, message: String(e) }}));
    return true; // async
  }

  // store last combined result (for popup)
  if (msg?.type === "CLIXUS_SAVE_LAST") {
    chrome.storage.local.set({ [SKEY_LAST]: msg.payload || {} });
  }
});

// optional logs
chrome.webNavigation.onBeforeNavigate.addListener((d)=>{
  if (d.frameId === 0 && /^https?:/i.test(d.url)) console.log("[Clixus/bg] nav:", d.url);
});
