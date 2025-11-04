// content.js — On any link click: scan CURRENT PAGE text, then VT + NLP(link), combine, interstitial on WARN/BLOCK

(function () {
  /* ---------- UI size tuning ---------- */
  const UI = {
    BASE_FONT: 17, LINE_HEIGHT: 1.5, LOGO: 26, TITLE: 18,
    HEADER: 22, URL: 13, STAT_MAIN: 14, STAT_SUB: 13, COMBINED: 18, BTN: 14
  };

  /* ---------- weights & thresholds ---------- */
  // Combine three components:
  //   VT (link)        -> 0.55 (still priority)
  //   NLP(link)        -> 0.25
  //   NLP(page-text)   -> 0.20
  const W_VT = 0.55;
  const W_NLP_LINK = 0.25;
  const W_NLP_PAGE = 0.20;

  const WARN = 50;
  const BLOCK = 70;
  const VT_BLOCK_MAL = 1;   // 1+ malicious vendors
  const VT_BLOCK_SUSP = 2;  // 2+ suspicious vendors

  /* ---------- helpers ---------- */
  function ensureRoot() {
    let r = document.getElementById("clixus-root");
    if (!r) {
      r = document.createElement("div");
      r.id = "clixus-root";
      r.style.zIndex = "2147483647";
      document.documentElement.appendChild(r);
    }
    return r;
  }

  function toast(msg, ttl = 2200) {
    const el = document.createElement("div");
    el.style.cssText =
      "position:fixed;right:16px;bottom:16px;background:#111;color:#fff;padding:10px 14px;border-radius:10px;font:14px system-ui;box-shadow:0 8px 30px rgba(0,0,0,.28)";
    el.textContent = `Clixus: ${msg}`;
    ensureRoot().appendChild(el);
    setTimeout(() => el.remove(), ttl);
  }

  function interstitial(payload, onProceed, onCancel) {
    const url = payload?.url || "";
    const vt = payload?.vt || {};
    const nlpLink = payload?.nlpLink || { score: 0, details: {} };
    const nlpPage = payload?.nlpPage || { score: 0, details: {} };
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
    card.style.cssText = "width:min(700px,94%);background:#fff;border-radius:16px;padding:18px 18px 14px;box-shadow:0 12px 30px rgba(0,0,0,.25);color:#000";

    const hdr = document.createElement("div");
    hdr.style.cssText = `font-weight:800;font-size:${UI.HEADER}px;margin-bottom:6px;color:#000`;
    hdr.textContent = "Potentially Risky Navigation";

    const urlEl = document.createElement("div");
    urlEl.style.cssText = `font-size:${UI.URL}px;color:#000;opacity:.95;word-break:break-all;margin-bottom:10px`;
    urlEl.textContent = url;

    const grid = document.createElement("div");
    grid.style.cssText = "display:grid;grid-template-columns:1fr 1fr 1fr;gap:10px;margin-top:4px";

    const vtBox = document.createElement("div");
    vtBox.style.cssText = "background:#ffe4e6;border:1px solid #fecdd3;border-radius:12px;padding:10px;color:#000";
    vtBox.innerHTML = `
      <div style="font-weight:700;margin-bottom:4px;font-size:${UI.STAT_MAIN}px">VirusTotal</div>
      <div style="font-size:${UI.STAT_MAIN}px">malicious: <b>${Number(vt.malicious||0)}</b>, suspicious: <b>${Number(vt.suspicious||0)}</b></div>
      <div style="font-size:${UI.STAT_SUB}px;opacity:.85">engines: ${Number(vt.totalEngines || (vt.malicious+vt.suspicious+vt.harmless+vt.undetected||0))}</div>
      <div style="margin-top:4px;font-size:${UI.STAT_MAIN}px">component: <b>${Math.round(Number(vt._score||0))}</b>/100</div>
    `;

    const linkBox = document.createElement("div");
    linkBox.style.cssText = "background:#ffe4e6;border:1px solid #fecdd3;border-radius:12px;padding:10px;color:#000";
    linkBox.innerHTML = `
      <div style="font-weight:700;margin-bottom:4px;font-size:${UI.STAT_MAIN}px">NLP (link context)</div>
      <div style="font-size:${UI.STAT_MAIN}px">score: <b>${Math.round(Number(nlpLink.score||0))}</b>/100</div>
      <div style="font-size:${UI.STAT_SUB}px;opacity:.85">tld: ${nlpLink.details?.tld || "-"} • shortener: ${nlpLink.details?.shortener ? "yes":"no"}</div>
    `;

    const pageBox = document.createElement("div");
    pageBox.style.cssText = "background:#ffe4e6;border:1px solid #fecdd3;border-radius:12px;padding:10px;color:#000";
    pageBox.innerHTML = `
      <div style="font-weight:700;margin-bottom:4px;font-size:${UI.STAT_MAIN}px">NLP (page text)</div>
      <div style="font-size:${UI.STAT_MAIN}px">score: <b>${Math.round(Number(nlpPage.score||0))}</b>/100</div>
      <div style="font-size:${UI.STAT_SUB}px;opacity:.85">keywords hit: ${Number(nlpPage.details?.kwords||0)}</div>
    `;

    grid.appendChild(vtBox);
    grid.appendChild(linkBox);
    grid.appendChild(pageBox);

    const combo = document.createElement("div");
    combo.style.cssText = `margin-top:12px;font-weight:800;font-size:${UI.COMBINED}px;color:#000`;
    combo.textContent = `Combined risk: ${Math.round(combined)}/100`;

    const row = document.createElement("div");
    row.style.cssText = "display:flex;gap:10px;justify-content:flex-end;margin-top:14px";
    const btnContinue = document.createElement("button");
    btnContinue.textContent = "Continue";
    btnContinue.style.cssText = `padding:10px 14px;border-radius:12px;border:1px solid #d4d4d8;background:#fafafa;color:#000;cursor:pointer;font-size:${UI.BTN}px`;
    const btnBack = document.createElement("button");
    btnBack.textContent = "Go Back";
    btnBack.style.cssText = `padding:10px 14px;border-radius:12px;border:1px solid #000;background:#000;color:#fff;cursor:pointer;font-size:${UI.BTN}px`;

    btnContinue.onclick = () => { overlay.remove(); onProceed && onProceed(); };
    btnBack.onclick = () => { overlay.remove(); onCancel && onCancel(); };

    row.appendChild(btnContinue); row.appendChild(btnBack);
    card.appendChild(hdr); card.appendChild(urlEl); card.appendChild(grid); card.appendChild(combo); card.appendChild(row);
    overlay.appendChild(card);
    document.documentElement.appendChild(overlay);
  }

  function safeSend(msg) {
    return new Promise((resolve) => {
      if (!chrome?.runtime?.sendMessage) return resolve(undefined);
      try { chrome.runtime.sendMessage(msg, resolve); } catch { resolve(undefined); }
    });
  }
  async function vtCheck(url) {
    const resp = await safeSend({ type: "CLIXUS_CHECK_URL", url });
    return resp?.verdict || { error: true };
  }
  function neighborTextAround(el) {
    const prev = el?.previousElementSibling?.textContent || "";
    const next = el?.nextElementSibling?.textContent || "";
    return (prev + " " + next).slice(0, 400);
  }
  function vtComponentScore(v) {
    const total = Number(v?.totalEngines || (v?.malicious + v?.suspicious + v?.harmless + v?.undetected) || 70);
    const positives = Number(v?.malicious || 0) + 0.5 * Number(v?.suspicious || 0);
    return Math.max(0, Math.min(100, 100 * (positives / total)));
  }

  /* ---------- main: intercept clicks ---------- */
  function hook() {
    document.addEventListener("click", async (e) => {
      const a = e.target.closest && e.target.closest("a[href]");
      if (!a) return;

      const url = a.href;
      if (!/^https?:/i.test(url)) return;

      // pause nav & outrun site handlers
      e.preventDefault();
      e.stopPropagation();
      e.stopImmediatePropagation();

      // 1) NLP — scan CURRENT PAGE text first
      let pageText = "";
      try { pageText = (document.body && document.body.innerText) ? document.body.innerText.slice(0, 50000) : ""; } catch {}
      const nlpPage = window.clixusNlpScoreForPage
        ? window.clixusNlpScoreForPage(pageText, location.href)
        : { score: 0, details: {} };

      // quick heads-up toast while we continue
      toast("Scanning page & URL…");

      // 2) VirusTotal for the destination URL
      const vt = await vtCheck(url);
      if (vt?.error) { window.location.href = url; return; }
      const vtScore = vtComponentScore(vt);
      vt._score = vtScore;

      // 3) NLP — link context (anchor + neighbors)
      const nlpLink = window.clixusNlpScoreForLink
        ? window.clixusNlpScoreForLink(url, a.textContent || "", neighborTextAround(a))
        : { score: 0, details: {} };

      // 4) Combine  (VT prioritized, page + link contribute)
      const combined = Math.round(
        W_VT * Number(vtScore) +
        W_NLP_LINK * Number(nlpLink.score || 0) +
        W_NLP_PAGE * Number(nlpPage.score || 0)
      );

      const mal  = Number(vt?.malicious  || 0);
      const susp = Number(vt?.suspicious || 0);
      const shouldBlock = (mal >= VT_BLOCK_MAL) || (susp >= VT_BLOCK_SUSP) || (combined >= BLOCK);
      const shouldWarn  = !shouldBlock && (combined >= WARN);

      // 5) Save result for popup
      safeSend({
        type: "CLIXUS_SAVE_LAST",
        payload: {
          ts: Date.now(),
          url,
          vt,
          nlpLink,
          nlpPage,
          combined,
          decision: shouldBlock ? "block" : shouldWarn ? "warn" : "allow",
          mode: "click+page"
        }
      });

      // 6) Interstitial for both WARN & BLOCK, else allow
      if (shouldBlock || shouldWarn) {
        interstitial(
          { url, vt, nlpLink, nlpPage, combined },
          () => { window.location.href = url; }, // Continue anyway
          () => { /* Stay on page */ }
        );
      } else {
        window.location.href = url; // safe → proceed
      }
    }, true); // capture
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", hook, { once: true });
  } else {
    hook();
  }
})();
