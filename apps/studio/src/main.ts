import {
  auditMemoryBundle,
  compilePromotionManifest,
  createSafeBundle,
  createUnsafeBundle,
} from "@contextquarantine/core";
import type {
  BundleAudit,
  CandidateAudit,
  MemoryBundle,
} from "@contextquarantine/core";
import "./styles.css";

const rootElement = document.querySelector<HTMLDivElement>("#app");
if (!rootElement) throw new Error("Application root was not found.");
const app: HTMLDivElement = rootElement;

const freshBundle = (unsafe = false): MemoryBundle => {
  const now = new Date();
  const value = unsafe ? createUnsafeBundle(now) : createSafeBundle(now);
  return value;
};

let bundle = freshBundle();
let audit: BundleAudit = auditMemoryBundle(bundle);
let selected = audit.candidates[0]!.candidateId;

const escape = (value: string): string =>
  value.replace(/[&<>"']/g, (character) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  })[character]!);

const admissionLabel = (entry: CandidateAudit): string =>
  entry.admission === "promote" ? "PROMOTE" : entry.admission === "quarantine" ? "HOLD" : "REJECT";

function render(): void {
  const chosen = audit.candidates.find((entry) => entry.candidateId === selected) ?? audit.candidates[0]!;
  const candidate = bundle.candidates.find((entry) => entry.id === chosen.candidateId)!;
  const origin = bundle.origins.find((entry) => entry.id === candidate.originId)!;
  app.innerHTML = `
    <header>
      <a class="logo" href="#"><span>CQ</span><b>ContextQuarantine</b></a>
      <nav><span><i></i> deterministic engine</span><a href="https://github.com/vtino17/context-quarantine">GitHub ↗</a></nav>
    </header>
    <main>
      <section class="hero">
        <div>
          <p class="kicker">Persistent memory is a security boundary</p>
          <h1>Inspect before<br><em>you remember.</em></h1>
        </div>
        <p class="hero-copy">A local admission firewall that separates instructions from data, requires independent corroboration, and prevents poisoned context from surviving the session.</p>
      </section>
      <section class="boundary">
        <div class="boundary-label"><span>UNTRUSTED CONTEXT</span><b>MEMORY BOUNDARY</b><span>DURABLE MEMORY</span></div>
        <div class="pipeline">
          <div class="source-node">${bundle.candidates.length}<small>candidates</small></div>
          <div class="flow-line"><i></i></div>
          <div class="gate status-${audit.status}">
            <span>Q</span><b>${audit.status.toUpperCase()}</b><small>${audit.issues.length} signals</small>
          </div>
          <div class="flow-line safe"><i></i></div>
          <div class="memory-node">${audit.promoted}<small>admitted</small></div>
        </div>
      </section>
      <section class="metrics">
        <article><small>Promotion rate</small><strong>${Math.round((audit.promoted / audit.candidates.length) * 100)}%</strong><span>${audit.promoted} clean candidates</span></article>
        <article><small>Quarantined</small><strong>${audit.quarantined}</strong><span>human review required</span></article>
        <article><small>Rejected</small><strong>${audit.rejected}</strong><span>policy violations</span></article>
        <article><small>Origin domains</small><strong>${new Set(bundle.origins.map((entry) => entry.domain)).size}</strong><span>isolated trust zones</span></article>
      </section>
      <section class="workbench">
        <div class="editor-panel">
          <div class="panel-head">
            <div><span>01</span><h2>Memory intake</h2></div>
            <div class="demo-switch">
              <button id="safe-demo">Safe demo</button>
              <button id="attack-demo">Attack demo</button>
            </div>
          </div>
          <textarea id="editor" spellcheck="false">${escape(JSON.stringify(bundle, null, 2))}</textarea>
          <div id="error" class="error"></div>
          <div class="editor-actions"><span>JSON · policy ${escape(bundle.policy.id)}</span><button id="scan">Scan intake <b>⌘↵</b></button></div>
        </div>
        <div class="audit-panel">
          <div class="panel-head"><div><span>02</span><h2>Admission decisions</h2></div><span class="status-badge ${audit.status}">${audit.status}</span></div>
          <div class="candidate-list">
            ${audit.candidates.map((entry) => `
              <button data-candidate="${escape(entry.candidateId)}" class="candidate ${entry.admission} ${entry.candidateId === chosen.candidateId ? "selected" : ""}">
                <span class="decision-icon">${entry.admission === "promote" ? "✓" : entry.admission === "quarantine" ? "△" : "×"}</span>
                <span><b>${escape(entry.candidateId)}</b><small>${escape(bundle.candidates.find((item) => item.id === entry.candidateId)!.content)}</small></span>
                <em>${admissionLabel(entry)}</em>
              </button>`).join("")}
          </div>
          <div class="inspection">
            <div class="inspection-top"><div><p>SELECTED CANDIDATE</p><h3>${escape(candidate.id)}</h3></div><strong class="risk risk-${chosen.admission}">${chosen.riskScore}<small>risk</small></strong></div>
            <p class="candidate-content">“${escape(candidate.content)}”</p>
            <div class="origin-card"><span>${escape(origin.kind)}</span><div><b>${escape(origin.label)}</b><small>${escape(origin.domain)} · ${escape(origin.trust)}</small></div></div>
            <div class="signal-list">
              ${chosen.issues.length === 0
                ? `<div class="all-clear"><b>All admission controls passed</b><span>${chosen.corroboratingDomains.length || 1} trusted/corroborating domain(s)</span></div>`
                : chosen.issues.map((entry) => `<div class="signal ${entry.severity}"><span>${entry.severity}</span><p><b>${escape(entry.code)}</b>${escape(entry.message)}</p></div>`).join("")}
            </div>
          </div>
          <div class="manifest-action"><button id="download" ${audit.status === "blocked" ? "disabled" : ""}>Compile promotion manifest</button><span>SHA-256 bound · local only</span></div>
        </div>
      </section>
      <section class="controls">
        <div class="section-title"><span>03</span><h2>Active policy controls</h2></div>
        <div class="control-grid">
          <article><b>02</b><h3>Corroborating domains</h3><p>Independent origins required for untrusted facts and decisions.</p></article>
          <article><b>${bundle.policy.rules.instructionOriginIds.length.toString().padStart(2, "0")}</b><h3>Instruction authorities</h3><p>Only explicit origins can create durable behavioral instructions.</p></article>
          <article><b>${bundle.policy.rules.maxTtlHours.untrusted}h</b><h3>Untrusted TTL ceiling</h3><p>Short retention limits the half-life of poisoned context.</p></article>
          <article><b>${bundle.policy.rules.protectedNamespaces.length.toString().padStart(2, "0")}</b><h3>Protected namespaces</h3><p>Identity, authority, and credentials remain trust-isolated.</p></article>
        </div>
      </section>
    </main>
    <footer><span>ContextQuarantine v0.1</span><span>No model calls · no network · no telemetry</span></footer>
  `;
  bind();
}

function scan(): void {
  const editor = document.querySelector<HTMLTextAreaElement>("#editor")!;
  const error = document.querySelector<HTMLDivElement>("#error")!;
  try {
    bundle = JSON.parse(editor.value) as MemoryBundle;
    audit = auditMemoryBundle(bundle);
    if (!audit.candidates.some((entry) => entry.candidateId === selected)) selected = audit.candidates[0]!.candidateId;
    render();
  } catch (cause) {
    error.textContent = cause instanceof Error ? cause.message : String(cause);
  }
}

function loadDemo(unsafe: boolean): void {
  bundle = freshBundle(unsafe);
  audit = auditMemoryBundle(bundle);
  selected = audit.candidates[0]!.candidateId;
  render();
}

function download(): void {
  const manifest = compilePromotionManifest({ bundle, audit });
  const blob = new Blob([JSON.stringify(manifest, null, 2)], { type: "application/json" });
  const link = document.createElement("a");
  link.href = URL.createObjectURL(blob);
  link.download = `${bundle.id}.promotion.json`;
  link.click();
  URL.revokeObjectURL(link.href);
}

function bind(): void {
  document.querySelector("#scan")?.addEventListener("click", scan);
  document.querySelector("#safe-demo")?.addEventListener("click", () => loadDemo(false));
  document.querySelector("#attack-demo")?.addEventListener("click", () => loadDemo(true));
  document.querySelector("#download")?.addEventListener("click", download);
  document.querySelectorAll<HTMLButtonElement>("[data-candidate]").forEach((button) =>
    button.addEventListener("click", () => {
      selected = button.dataset.candidate!;
      render();
    })
  );
  document.querySelector("#editor")?.addEventListener("keydown", (event) => {
    if (event instanceof KeyboardEvent && (event.metaKey || event.ctrlKey) && event.key === "Enter") {
      event.preventDefault();
      scan();
    }
  });
}

render();
