// popup.js — read last result saved by content.js and render a compact panel
const KEY = "CLIXUS_LAST_RESULT";

function $(id){ return document.getElementById(id); }

function render(res){
  if (!res) {
    $("panel").style.display = "none";
    $("empty").style.display = "block";
    return;
  }
  $("empty").style.display = "none";
  $("panel").style.display = "block";

  $("url").textContent = res.url || "";
  $("score").textContent = Math.round(res.combined);
  $("bar").value = Math.round(res.combined);

  const vtScore = Math.round(res.vt?._score ?? 0);
  $("vtScore").textContent = `${vtScore}/100`;
  const v = res.vt || {};
  $("vtStats").textContent = `malicious: ${v.malicious} • suspicious: ${v.suspicious} • engines: ${v.totalEngines || (v.malicious+v.suspicious+v.harmless+v.undetected||0)}`;

  $("nlpScore").textContent = `${Math.round(res.nlp?.score ?? 0)}/100`;
  const n = res.nlp || {};
  $("nlpNotes").textContent = `tld: ${n.details?.tld || "-"} • shortener: ${n.details?.shortener ? "yes" : "no"} • ip: ${n.details?.ip ? "yes" : "no"}`;

  const dec = res.decision || "allow";
  $("decision").textContent = dec.toUpperCase();
  $("decision").style.background = dec === "block" ? "#d00000ff" : dec === "warn" ? "#d00000ff" : "#e0f2fe";
  $("decision").style.color = dec === "block" ? "#991b1b" : dec === "warn" ? "#9a3412" : "#075985";
}

async function load(){
  chrome.storage.local.get([KEY], obj => render(obj[KEY]));
}
$("refresh").onclick = load;
load();
