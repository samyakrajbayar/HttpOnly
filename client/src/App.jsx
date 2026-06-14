import { useMemo, useState } from "react";
import {
  AlertTriangle,
  CheckCircle2,
  Clock3,
  Code2,
  ExternalLink,
  FileSearch,
  Github,
  Globe2,
  Loader2,
  LockKeyhole,
  ScanLine,
  ShieldAlert,
  ShieldCheck,
  ShieldQuestion
} from "lucide-react";

const examples = [
  "https://example.com",
  "https://github.com/expressjs/express",
  "https://github.com/vitejs/vite"
];

const severityOrder = ["critical", "high", "medium", "low", "info"];

const classificationIcon = {
  Critical: ShieldAlert,
  High: ShieldAlert,
  Medium: AlertTriangle,
  Low: ShieldQuestion,
  Clean: ShieldCheck
};

function App() {
  const [target, setTarget] = useState("https://example.com");
  const [report, setReport] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [activeCategory, setActiveCategory] = useState("All");

  const categories = useMemo(() => {
    if (!report) return ["All"];
    return ["All", ...new Set(report.findings.map((finding) => finding.category))];
  }, [report]);

  const visibleFindings = useMemo(() => {
    if (!report) return [];
    const findings = activeCategory === "All"
      ? report.findings
      : report.findings.filter((finding) => finding.category === activeCategory);

    return [...findings].sort(
      (a, b) => severityOrder.indexOf(a.severity) - severityOrder.indexOf(b.severity)
    );
  }, [report, activeCategory]);

  async function runScan(event) {
    event?.preventDefault();
    setLoading(true);
    setError("");
    setActiveCategory("All");

    try {
      const response = await fetch("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target })
      });
      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || "Scan failed.");
      }

      setReport(data);
    } catch (scanError) {
      setError(scanError.message);
      setReport(null);
    } finally {
      setLoading(false);
    }
  }

  return (
    <main className="app-shell">
      <section className="scan-panel" aria-label="Scanner input">
        <div className="brand-row">
          <div className="brand-mark">
            <ScanLine size={24} />
          </div>
          <div>
            <p className="eyebrow">Sentinel Scan</p>
            <h1>Lightweight Vulnerability Scanner</h1>
          </div>
        </div>

        <form className="scan-form" onSubmit={runScan}>
          <label htmlFor="target">Target URL or GitHub repository</label>
          <div className="input-row">
            <input
              id="target"
              value={target}
              onChange={(event) => setTarget(event.target.value)}
              placeholder="https://example.com"
            />
            <button className="primary-button" type="submit" disabled={loading}>
              {loading ? <Loader2 className="spin" size={18} /> : <FileSearch size={18} />}
              <span>{loading ? "Scanning" : "Scan"}</span>
            </button>
          </div>
        </form>

        <div className="example-grid" aria-label="Example targets">
          {examples.map((example) => (
            <button key={example} type="button" onClick={() => setTarget(example)}>
              {example.includes("github.com") ? <Github size={16} /> : <Globe2 size={16} />}
              <span>{example}</span>
            </button>
          ))}
        </div>

        {error && (
          <div className="error-box">
            <AlertTriangle size={18} />
            <span>{error}</span>
          </div>
        )}

        <div className="capability-list">
          <Capability icon={LockKeyhole} title="Security headers" text="CSP, HSTS, frame, content sniffing, referrer, and permissions policies." />
          <Capability icon={Code2} title="Dependency freshness" text="npm and Python manifests are checked against public package registries." />
          <Capability icon={ShieldQuestion} title="XSS surface" text="Forms and harmless reflected-parameter markers highlight places to review encoding." />
        </div>
      </section>

      <section className="report-panel" aria-label="Scan report">
        {!report && !loading && <EmptyState />}
        {loading && <LoadingState target={target} />}
        {report && !loading && (
          <>
            <ReportHeader report={report} />
            <MetricGrid report={report} />
            <CategoryTabs categories={categories} active={activeCategory} onChange={setActiveCategory} />
            <FindingsList findings={visibleFindings} />
            <EvidencePanel report={report} />
          </>
        )}
      </section>
    </main>
  );
}

function Capability({ icon: Icon, title, text }) {
  return (
    <article className="capability">
      <Icon size={18} />
      <div>
        <h2>{title}</h2>
        <p>{text}</p>
      </div>
    </article>
  );
}

function EmptyState() {
  return (
    <div className="empty-state">
      <ShieldCheck size={44} />
      <h2>Ready for a lightweight security pass</h2>
      <p>Run a scan to receive a risk score, prioritized findings, and evidence grouped by target type.</p>
    </div>
  );
}

function LoadingState({ target }) {
  return (
    <div className="loading-state">
      <Loader2 className="spin" size={42} />
      <h2>Scanning target</h2>
      <p>{target}</p>
      <div className="scan-progress">
        <span />
      </div>
    </div>
  );
}

function ReportHeader({ report }) {
  const Icon = classificationIcon[report.summary.classification] || ShieldQuestion;

  return (
    <header className="report-header">
      <div>
        <p className="eyebrow">Risk classification</p>
        <div className="risk-title">
          <Icon size={28} />
          <h2>{report.summary.classification}</h2>
        </div>
        <a href={report.target} target="_blank" rel="noreferrer">
          {report.target}
          <ExternalLink size={14} />
        </a>
      </div>
      <div className={`score-ring score-${report.summary.classification.toLowerCase()}`}>
        <span>{report.summary.score}</span>
        <small>/100</small>
      </div>
    </header>
  );
}

function MetricGrid({ report }) {
  const metrics = [
    ["Critical", report.summary.counts.critical],
    ["High", report.summary.counts.high],
    ["Medium", report.summary.counts.medium],
    ["Low", report.summary.counts.low],
    ["Info", report.summary.counts.info],
    ["Duration", `${report.durationMs}ms`]
  ];

  return (
    <div className="metric-grid">
      {metrics.map(([label, value]) => (
        <article key={label} className="metric-card">
          <span>{label}</span>
          <strong>{value}</strong>
        </article>
      ))}
    </div>
  );
}

function CategoryTabs({ categories, active, onChange }) {
  return (
    <div className="tabs" role="tablist" aria-label="Finding categories">
      {categories.map((category) => (
        <button
          key={category}
          type="button"
          className={category === active ? "active" : ""}
          onClick={() => onChange(category)}
        >
          {category}
        </button>
      ))}
    </div>
  );
}

function FindingsList({ findings }) {
  if (findings.length === 0) {
    return (
      <div className="no-findings">
        <CheckCircle2 size={22} />
        <span>No findings in this category.</span>
      </div>
    );
  }

  return (
    <div className="findings-list">
      {findings.map((finding) => (
        <article key={finding.id} className={`finding finding-${finding.severity}`}>
          <div className="finding-topline">
            <span className={`severity severity-${finding.severity}`}>{finding.severity}</span>
            <span>{finding.category}</span>
          </div>
          <h3>{finding.title}</h3>
          <p>{finding.description}</p>
          {finding.evidence && <code>{finding.evidence}</code>}
          {finding.recommendation && (
            <div className="recommendation">
              <ShieldCheck size={16} />
              <span>{finding.recommendation}</span>
            </div>
          )}
        </article>
      ))}
    </div>
  );
}

function EvidencePanel({ report }) {
  const isRepo = report.targetType === "github";

  return (
    <div className="evidence-grid">
      <article className="evidence-card">
        <div className="section-title">
          {isRepo ? <Github size={18} /> : <Globe2 size={18} />}
          <h2>{isRepo ? "Repository snapshot" : "HTTP snapshot"}</h2>
        </div>
        <dl>
          {Object.entries(report.status).map(([key, value]) => (
            <div key={key}>
              <dt>{humanize(key)}</dt>
              <dd>{String(value)}</dd>
            </div>
          ))}
        </dl>
      </article>

      <article className="evidence-card">
        <div className="section-title">
          <Clock3 size={18} />
          <h2>{isRepo ? "Dependencies" : "Observed surface"}</h2>
        </div>
        {isRepo ? <DependencyTable dependencies={report.assets.dependencies} /> : <UrlSurface assets={report.assets} />}
      </article>
    </div>
  );
}

function DependencyTable({ dependencies }) {
  if (!dependencies?.length) {
    return <p className="muted">No supported dependencies were detected.</p>;
  }

  return (
    <div className="dependency-table">
      {dependencies.slice(0, 12).map((dependency) => (
        <div key={`${dependency.ecosystem}-${dependency.manifest}-${dependency.name}`}>
          <span>{dependency.name}</span>
          <small>{dependency.current || dependency.declared} {"->"} {dependency.latest || "unknown"}</small>
          <b className={`severity severity-${dependency.severity}`}>{dependency.status}</b>
        </div>
      ))}
    </div>
  );
}

function UrlSurface({ assets }) {
  return (
    <div className="surface-list">
      <div><span>Links checked</span><b>{assets.linksChecked}</b></div>
      <div><span>Scripts detected</span><b>{assets.scriptsDetected}</b></div>
      <div><span>Forms detected</span><b>{assets.forms.length}</b></div>
      <div><span>Headers tracked</span><b>{assets.headers.length}</b></div>
    </div>
  );
}

function humanize(value) {
  return value.replace(/([A-Z])/g, " $1").replace(/^./, (letter) => letter.toUpperCase());
}

export default App;
