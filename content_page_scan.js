// content_page_scan.js — full-page NLP scan before render (document_start)
// Tuned to be more sensitive to NLP while still prioritizing VirusTotal.
//
// Drop-in replacement. No other files need edits.

(function () {
  /* ---------- UI size tuning (same as before) ---------- */
  const UI = {
    BASE_FONT: 17,
    LINE_HEIGHT: 1.5,
    LOGO: 26,
    TITLE: 18,
    HEADER: 22,
    URL: 13,
    STAT_MAIN: 14,
    STAT_SUB: 13,
    COMBINED: 18,
    BTN: 14
  };

  /* ---------- thresholds & weights (MORE NLP SENSITIVE) ---------- */
  // Keep VT slightly higher weight to retain priority, but boost NLP influence.
  const W_VT_PAGE = 0.55;   // was 0.5
  const W_NLP_PAGE = 0.45;  // was 0.5
  // Lower thresholds so NLP-triggered risk shows up earlier.
  const PAGE_WARN  = 45;    // was 55
  const PAGE_BLOCK = 65;    // was 75

  // Strong VT signals remain authoritative.
  const VT_BLOCK_MAL = 1;   // 1+ malicious vendors => block path
  const VT_BLOCK_SUSP = 2;  // 2+ suspicious vendors => block path

  /* ---------- keyword sets for page NLP ---------- */
  const KEYWORDS = [
    "verify account","password","passcode","otp","kyc","reactivate","blocked","suspended",
    "billing update","refund","appeal","unlock","cvv","ifsc","pin","reset","2fa","signin",
    "login","bank verification","account update","claim prize","winner","urgent",
    "immediately","limited time","within 24 hours","fastag","upi","aadhaar","pan"
  ];
  const BRANDS = [
    "hdfc","sbi","icici","axis","kotak","pnb","idfc","canara","irctc","lic","paytm",
    "phonepe","amazon","flipkart","google","microsoft","apple","facebook","income tax","swiggy","zomato"
  ];

  /* ---------- helpers ---------- */
  function safeSend(msg) {
    return new Promise((resolve) => {
      if (!chrome?.runtime?.sendMessage) return resolve(undefined);
      try { chrome.runtime.sendMessage(msg, resolve); } catch { resolve(undefined); }
    });
  }
  function tokenize(s) { return (s || "").toLowerCase().replace(/[^a-z0-9]+/g, " ").trim(); }
  function countHits(hay, list) {
    const h = " " + tokenize(hay) + " ";
    return list.reduce((c, w) => c + (h.includes(" " + w + " ") ? 1 : 0), 0);
  }
  function vtComponentScore(v) {
    const total = Number(v?.totalEngines || (v?.malicious + v?.suspicious + v?.harmless + v?.undetected) || 70);
    const positives = Number(v?.malicious || 0) + 0.5 * Number(v?.suspicious || 0);
    return Math.max(0, Math.min(100, 100 * (positives / total)));
  }
  function brandPresenceScore(text, host) {
    const apex = (host || "").split(".").slice(-2).join(".").replace(/\./g, "");
    const mentions = BRANDS.filter(b => new RegExp("\\b" + b.replace(/\s+/g, "\\s+") + "\\b", "i").test(text));
    if (!mentions.length) return 0;
    const mismatch = mentions.some(b => !apex.includes(b.replace(/\s+/g, "")));
    return mismatch ? 20 : 0; // was 15
  }

  /* ---------- stronger NLP scoring ---------- */
  function pageNlpScore(fullText, url) {
    let score = 0;
    try {
      const u = new URL(url);
      const host = u.hostname.toLowerCase();
      const text = fullText || "";

      // Count bait words more aggressively.
      const kw = countHits(text, KEYWORDS);
      score += kw * 9; // was 6

      // If lots of bait words, add an extra bump.
      if (kw >= 3) score += 8;
      if (kw >= 6) score += 6;

      // Brand presence mismatch vs domain apex.
      score += brandPresenceScore(text, host);

      // Repetition of OTP/KYC is a strong sign.
      const otpCount = (text.match(/\botp\b/gi) || []).length;
      if (otpCount >= 2) score += 12; // was 8
      if (otpCount >= 4) score += 6;

      const kycCount = (text.match(/\bkyc\b/gi) || []).length;
      if (kycCount >= 2) score += 10; // was 6
      if (kycCount >= 4) score += 4;

      // Clamp 0..100
      return Math.max(0, Math.min(100, score));
    } catch {
      return 0;
    }
  }

  /* ---------- red interstitial (same look as link flow) ---------- */
  function interstitial(payload, onProceed, onCancel) {
    const url = payload?.url || "";
    const vt = payload?.vt || {};
    const nlp = payload?.nlp || { score: 0, kw: 0 };
    const combined = Number(payload?.combined || 0);

    const overlay = document.createElement("div");
    overlay.style.cssText = [
      "position:fixed","inset:0","z-index:2147483647","background:#dc2626",
      "display:flex","align-items:center","justify-content:center","color:#000",
      `font:${UI.BASE_FONT}px/${UI.LINE_HEIGHT} system-ui, Segoe UI, Roboto, Arial, sans-serif`
    ].join(";");

    const brand = document.createElement("div");
    brand.style.cssText = "position:absolute;top:14px;left:16px;display:flex;gap:8px;align-items:center;color:#000";
    const logo = document.createElement("img");
    try { logo.src = chrome.runtime.getURL("assets/icon.png"); }
    catch {
      logo.src = "data:image/svg+xml;charset=UTF-8," + encodeURIComponent(
        "<svg xmlns='http://www.w3.org/2000/svg' width='24' height='24' viewBox='0 0 24 24' fill='none' stroke='black' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'><circle cx='12' cy='12' r='9'/><path d='M8 8l8 8M16 8l-8 8'/></svg>"
      );
    }
    logo.alt = "cliXus"; logo.width = UI.LOGO; logo.height = UI.LOGO;
    const title = document.createElement("div");
    title.textContent = "cliXus";
    title.style.cssText = `font-weight:700;letter-spacing:.2px;color:#000;font-size:${UI.TITLE}px`;
    brand.appendChild(logo); brand.appendChild(title);
    overlay.appendChild(brand);

    const card = document.createElement("div");
    card.style.cssText = "width:min(640px,92%);background:#fff;border-radius:16px;padding:18px 18px 14px;box-shadow:0 12px 30px rgba(0,0,0,.25);color:#000";

    const hdr = document.createElement("div");
    hdr.style.cssText = `font-weight:800;font-size:${UI.HEADER}px;margin-bottom:6px;color:#000`;
    hdr.textContent = "Potentially Risky Page";

    const urlEl = document.createElement("div");
    urlEl.style.cssText = `font-size:${UI.URL}px;color:#000;opacity:.95;word-break:break-all;margin-bottom:10px`;
    urlEl.textContent = url;

    const grid = document.createElement("div");
    grid.style.cssText = "display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-top:4px";

    const vtBox = document.createElement("div");
    vtBox.style.cssText = "background:#ffe4e6;border:1px solid #fecdd3;border-radius:12px;padding:10px;color:#000";
    vtBox.innerHTML = `
      <div style="font-weight:700;margin-bottom:4px;font-size:${UI.STAT_MAIN}px">VirusTotal</div>
      <div style="font-size:${UI.STAT_MAIN}px">malicious: <b>${Number(vt.malicious||0)}</b>, suspicious: <b>${Number(vt.suspicious||0)}</b></div>
      <div style="font-size:${UI.STAT_SUB}px;opacity:.85">engines: ${Number(vt.totalEngines || (vt.malicious+vt.suspicious+vt.harmless+vt.undetected||0))}</div>
      <div style="margin-top:4px;font-size:${UI.STAT_MAIN}px">VT component: <b>${Math.round(Number(vt._score||0))}</b>/100</div>
    `;

    const nlpBox = document.createElement("div");
    nlpBox.style.cssText = "background:#ffe4e6;border:1px solid #fecdd3;border-radius:12px;padding:10px;color:#000";
    nlpBox.innerHTML = `
      <div style="font-weight:700;margin-bottom:4px;font-size:${UI.STAT_MAIN}px">NLP (page text)</div>
      <div style="font-size:${UI.STAT_MAIN}px">score: <b>${Math.round(Number(nlp.score||0))}</b>/100</div>
      <div style="font-size:${UI.STAT_SUB}px;opacity:.85">keywords hit: ${Number(nlp.kw||0)}</div>
    `;

    grid.appendChild(vtBox); grid.appendChild(nlpBox);

    const combo = document.createElement("div");
    combo.style.cssText = `margin-top:12px;font-weight:800;font-size:${UI.COMBINED}px;color:#000`;
    combo.textContent = `Combined risk: ${Math.round(Number(payload?.combined||0))}/100`;

    const row = document.createElement("div");
    row.style.cssText = "display:flex;gap:10px;justify-content:flex-end;margin-top:14px";
    const btnContinue = document.createElement("button");
    btnContinue.textContent = "Continue";
    btnContinue.style.cssText = `padding:10px 14px;border-radius:12px;border:1px solid #d4d4d8;background:#fafafa;color:#000;cursor:pointer;font-size:${UI.BTN}px`;
    const btnBack = document.createElement("button");
    btnBack.textContent = "Go Back";
    btnBack.style.cssText = `padding:10px 14px;border-radius:12px;border:1px solid #000;background:#000;color:#fff;cursor:pointer;font-size:${UI.BTN}px`;

    btnContinue.onclick = () => { overlay.remove(); reveal(); if (onProceed) onProceed(); };
    btnBack.onclick = () => { overlay.remove(); if (onCancel) onCancel(); /* remain */ };

    row.appendChild(btnContinue); row.appendChild(btnBack);
    card.appendChild(hdr); card.appendChild(urlEl); card.appendChild(grid); card.appendChild(combo); card.appendChild(row);
    overlay.appendChild(card);
    document.documentElement.appendChild(overlay);
  }

  /* ---------- shield (hide page) ---------- */
  let shieldEl = null;
  function shield() {
    if (shieldEl) return;
    shieldEl = document.createElement("style");
    shieldEl.id = "clixus-shield";
    shieldEl.textContent = "html,body{opacity:0 !important; transition:opacity .12s ease}";
    document.documentElement.appendChild(shieldEl);
  }
  function reveal() {
    if (!shieldEl) return;
    shieldEl.textContent = "html,body{opacity:1 !important; transition:opacity .12s ease}";
    setTimeout(() => { shieldEl?.remove(); shieldEl = null; }, 160);
  }

  /* ---------- main flow ---------- */
  async function run() {
    try {
      shield(); // hide early

      const url = location.href;

      // Start VT immediately
      const vtResp = await safeSend({ type: "CLIXUS_CHECK_URL", url });
      const vt = vtResp?.verdict || {};
      const vtScore = vtComponentScore(v);
      vt._score = vtScore;

      // Wait for body text
      if (document.readyState === "loading") {
        await new Promise(r => document.addEventListener("DOMContentLoaded", r, { once: true }));
      }
      await new Promise(r => setTimeout(r, 150));

      const text = (document.body && document.body.innerText) ? document.body.innerText.slice(0, 50000) : "";
      const nlpScore = pageNlpScore(text, url);
      const nlp = { score: nlpScore, kw: countHits(text, KEYWORDS) };

      const combined = Math.round(W_VT_PAGE * Number(vtScore) + W_NLP_PAGE * Number(nlpScore));

      const mal  = Number(vt?.malicious  || 0);
      const susp = Number(vt?.suspicious || 0);
      const shouldBlock = (mal >= VT_BLOCK_MAL) || (susp >= VT_BLOCK_SUSP) || (combined >= PAGE_BLOCK);
      const shouldWarn  = !shouldBlock && (combined >= PAGE_WARN);

      // Save for popup
      safeSend({
        type: "CLIXUS_SAVE_LAST",
        payload: {
          ts: Date.now(),
          url,
          vt, nlp,
          combined,
          decision: shouldBlock ? "block" : shouldWarn ? "warn" : "allow",
          mode: "page-scan"
        }
      });

      if (shouldBlock) {
        interstitial({ url, vt, nlp, combined },
          () => { /* Continue anyway */ },
          () => { /* Stay hidden */ }
        );
      } else {
        reveal();
        if (shouldWarn) {
          const t = document.createElement("div");
          t.style.cssText = "position:fixed;right:16px;bottom:16px;background:#111;color:#fff;padding:10px 14px;border-radius:10px;font:14px system-ui;z-index:2147483647";
          t.textContent = `Clixus: Warning — page risk ${combined}/100`;
          document.documentElement.appendChild(t);
          setTimeout(() => t.remove(), 2800);
        }
      }
    } catch (e) {
      reveal(); // fail-open
      console.warn("[Clixus/page-scan] error:", e);
    }
  }

  run(); // start at document_start
})();
