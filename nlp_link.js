// nlp_link.js — lightweight NLP helpers for link & page scoring

(function () {
  // Shared keyword sets (tweak freely)
  const KEYWORDS = [
    "verify account","password","passcode","otp","kyc","reactivate","blocked","suspended",
    "billing update","refund","appeal","unlock","cvv","ifsc","pin","reset","2fa","signin",
    "login","bank verification","account update","claim prize","winner","urgent",
    "immediately","limited time","within 24 hours","fastag","upi","aadhaar","pan"
  ];

  const SHORTENERS = [
    "bit.ly","t.co","tinyurl.com","ow.ly","is.gd","cutt.ly","rebrand.ly","goo.gl"
  ];

  const RISKY_TLDS = [
    "xyz","top","click","link","zip","kim","club","tokyo","site","icu"
  ];

  const BRANDS = [
    "hdfc","sbi","icici","axis","kotak","pnb","idfc","canara","irctc","lic","paytm",
    "phonepe","amazon","flipkart","google","microsoft","apple","facebook","income tax","swiggy","zomato"
  ];

  function tokenize(s) {
    return (s || "").toLowerCase().replace(/[^a-z0-9]+/g, " ").trim();
  }

  function countHits(hay, list) {
    const h = " " + tokenize(hay) + " ";
    return list.reduce((c, w) => c + (h.includes(" " + w + " ") ? 1 : 0), 0);
  }

  function apex(hostname) {
    const parts = (hostname || "").split(".");
    return parts.slice(-2).join(".");
  }

  function brandMismatchScore(text, host) {
    const ax = apex(host).replace(/\./g, "");
    const mentions = BRANDS.filter(b => new RegExp("\\b" + b.replace(/\s+/g, "\\s+") + "\\b", "i").test(text || ""));
    if (!mentions.length) return { bump: 0, brands: [] };
    const mismatch = mentions.some(b => !ax.includes(b.replace(/\s+/g, "")));
    return { bump: mismatch ? 15 : 0, brands: mentions };
  }

  function linkHeuristics(urlStr) {
    try {
      const u = new URL(urlStr);
      const host = u.hostname.toLowerCase();
      const hostTld = host.split(".").pop();
      const isShortener = SHORTENERS.some(s => host.endsWith(s));
      const isRiskyTld = RISKY_TLDS.includes(hostTld);
      const isIP = /^\d{1,3}(\.\d{1,3}){3}$/.test(host);
      const hasAt = urlStr.includes("@");
      const hasPuny = host.startsWith("xn--");
      const tooLong = urlStr.length > 180 || host.split(".").length > 5 || host.split("-").length > 6;

      let bump = 0;
      if (isShortener) bump += 15;
      if (isRiskyTld) bump += 6;
      if (isIP) bump += 10;
      if (hasAt) bump += 8;
      if (hasPuny) bump += 8;
      if (tooLong) bump += 6;

      const qp = u.search.toLowerCase();
      const qBaits = ["otp","kyc","pass","password","account","billing","token","reset"];
      const qHits = qBaits.filter(k => qp.includes(k)).length;
      bump += qHits * 4;

      return {
        details: { tld: hostTld || "-", shortener: isShortener, ip: isIP, puny: hasPuny, long: tooLong, atSign: hasAt },
        bump
      };
    } catch {
      return { details: { tld: "-", shortener: false }, bump: 0 };
    }
  }

  // Link-level NLP score (URL + anchor + neighbor text)
  function clixusNlpScoreForLink(url, anchorText = "", neighborText = "") {
    const baseText = [anchorText, neighborText].join(" ");
    const k = countHits(baseText, KEYWORDS);
    const h = linkHeuristics(url);
    const b = brandMismatchScore(baseText, (new URL(url)).hostname);

    let score = 0;
    score += k * 7;                 // bait words around the link
    if (k >= 3) score += 6;
    score += h.bump;                // structural url bumps
    score += b.bump;                // brand mismatch

    score = Math.max(0, Math.min(100, score));
    return { score, details: { ...h.details, kwords: k, brands: b.brands } };
  }

  // Page-level NLP score (full body text)
  function clixusNlpScoreForPage(fullText, currentUrl) {
    const k = countHits(fullText, KEYWORDS);
    const u = new URL(currentUrl);
    const b = brandMismatchScore(fullText, u.hostname);
    let score = 0;
    score += k * 9;
    if (k >= 3) score += 8;
    if (k >= 6) score += 6;

    const otpCount = (fullText.match(/\botp\b/gi) || []).length;
    if (otpCount >= 2) score += 10;
    const kycCount = (fullText.match(/\bkyc\b/gi) || []).length;
    if (kycCount >= 2) score += 8;

    score += b.bump;
    score = Math.max(0, Math.min(100, score));
    return { score, details: { kwords: k, brands: b.brands } };
  }

  // Export onto window for content.js
  window.clixusNlpScoreForLink = clixusNlpScoreForLink;
  window.clixusNlpScoreForPage = clixusNlpScoreForPage;
})();
