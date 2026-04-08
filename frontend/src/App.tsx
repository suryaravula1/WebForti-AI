import {
  Activity,
  AlertCircle,
  BarChart3,
  Bell,
  Bug,
  CheckCircle2,
  ClipboardList,
  Clock3,
  FileCode2,
  FileText,
  Loader2,
  Play,
  Plus,
  RadioTower,
  RefreshCw,
  Server,
  ShieldCheck,
  UserCircle,
  XCircle
} from "lucide-react";
import { FormEvent, ReactNode, useCallback, useEffect, useMemo, useState } from "react";

const API_BASE = import.meta.env.VITE_WEBFORTI_API_BASE ?? "http://localhost:8000";
const API_KEY_STORAGE_KEY = "webforti_api_key";

type JobSummary = {
  job_id: string;
  cve_id: string;
  status: string;
  current_stage?: string;
  submitted_by: string;
  created_at: string;
  updated_at: string;
  error?: string | null;
  has_report?: boolean;
};

type JobEvent = {
  job_id: string;
  stage: string;
  message: string;
  payload?: Record<string, unknown>;
  created_at: string;
};

type Artifact = {
  artifact_type: string;
  content?: string | null;
  language?: string;
  content_hash?: string;
  validation_errors?: string[];
};

type Report = {
  job: JobSummary;
  cve?: {
    cve_id: string;
    title: string;
    description: string;
    severity: string;
    cvss_score?: number | null;
    published_at?: string | null;
  } | null;
  plan?: Record<string, unknown> | null;
  verification?: {
    status: string;
    exploit_executed: boolean;
    exploit_succeeded: boolean;
    rule_alerted: boolean;
    blocked: boolean;
    effectiveness_score: number;
    confidence_score: number;
    evidence?: Record<string, unknown>;
    finished_at?: string;
  } | null;
};

type BundleArtifactResponse =
  | { artifacts: Artifact[] }
  | {
      bundle: {
        exploit?: Artifact;
        rule?: Artifact;
        docker_spec?: Artifact;
      };
    };

type Health = {
  status: string;
  service: string;
};

type EvidenceMetric = {
  label: string;
  value: boolean | undefined;
  detail?: string;
};

type LlmExperiment = {
  experiment_label: string;
  model_name: string;
  model_provider?: string | null;
  topology: string;
  fixture_count: number;
  attempted: number;
  passed: number;
  failed: number;
  denied: number;
  malformed_json: number;
  pass_rate: number;
  fail_rate: number;
  deny_rate: number;
  malformed_json_rate: number;
  avg_seconds?: number | null;
  is_synthetic: boolean;
  updated_at: string;
};

type ActiveView = "analytics" | "submit" | "jobs" | "reports" | "benchmarks";

type ChartBar = {
  label: string;
  value: number;
  detail?: string;
  tone?: "success" | "danger" | "warning" | "neutral";
};

type LatencyPoint = {
  label: string;
  seconds: number;
  status: string;
};

type AnalyticsData = {
  total: number;
  completed: number;
  failed: number;
  running: number;
  reports: number;
  successRate: number;
  failureRate: number;
  runningRate: number;
  reportRate: number;
  avgLatencySeconds: number;
  p95LatencySeconds: number;
  fastestLatencySeconds: number;
  slowestLatencySeconds: number;
  recentLatencies: LatencyPoint[];
  outcomeBars: ChartBar[];
  stageBars: ChartBar[];
};

function App() {
  const [health, setHealth] = useState<Health | null>(null);
  const [jobs, setJobs] = useState<JobSummary[]>([]);
  const [selectedJobId, setSelectedJobId] = useState<string | null>(null);
  const [selectedJob, setSelectedJob] = useState<JobSummary | null>(null);
  const [events, setEvents] = useState<JobEvent[]>([]);
  const [report, setReport] = useState<Report | null>(null);
  const [artifacts, setArtifacts] = useState<Artifact[]>([]);
  const [llmExperiments, setLlmExperiments] = useState<LlmExperiment[]>([]);
  const [loadingExperiments, setLoadingExperiments] = useState(false);
  const [experimentsError, setExperimentsError] = useState<string | null>(null);
  const [activeArtifact, setActiveArtifact] = useState<string>("snort_rule");
  const [activeView, setActiveView] = useState<ActiveView>("reports");
  const [cveId, setCveId] = useState("CVE-2021-41773");
  const [submittedBy, setSubmittedBy] = useState("dashboard");
  const [apiKey] = useState(readInitialApiKey);
  const [preferSeed, setPreferSeed] = useState(true);
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [loadingJobs, setLoadingJobs] = useState(false);
  const [creating, setCreating] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const loadHealth = useCallback(async () => {
    try {
      setHealth(await fetchJson<Health>("/health"));
    } catch {
      setHealth(null);
    }
  }, []);

  const loadJobs = useCallback(async (selectLatest = false) => {
    setLoadingJobs(true);
    try {
      const data = await fetchJson<{ jobs: JobSummary[] }>("/jobs", undefined, apiKey);
      setJobs(data.jobs);
      if (selectLatest && data.jobs.length > 0 && !selectedJobId) {
        setSelectedJobId(data.jobs[0].job_id);
      }
    } catch (exc) {
      setError(toMessage(exc));
    } finally {
      setLoadingJobs(false);
    }
  }, [apiKey, selectedJobId]);

  const loadLlmExperiments = useCallback(async () => {
    setLoadingExperiments(true);
    try {
      const data = await fetchJson<{ experiments: LlmExperiment[] }>("/llm-experimentation", undefined, apiKey);
      setLlmExperiments(data.experiments);
      setExperimentsError(null);
    } catch (exc) {
      setExperimentsError(toMessage(exc));
    } finally {
      setLoadingExperiments(false);
    }
  }, [apiKey]);

  const loadSelectedJob = useCallback(async (jobId: string) => {
    try {
      const [jobData, eventsData] = await Promise.all([
        fetchJson<JobSummary>(`/jobs/${jobId}`, undefined, apiKey),
        fetchJson<{ events: JobEvent[] }>(`/jobs/${jobId}/events`, undefined, apiKey)
      ]);
      const shouldLoadOutputs = Boolean(jobData.has_report) || jobData.status === "completed";
      const [reportData, artifactData] = shouldLoadOutputs
        ? await Promise.all([
            fetchOptional<Report>(`/jobs/${jobId}/report`, apiKey),
            fetchOptional<BundleArtifactResponse>(`/jobs/${jobId}/artifacts`, apiKey)
          ])
        : [null, null];
      setSelectedJob(jobData);
      setEvents(eventsData.events);
      setReport(reportData);
      const normalizedArtifacts = normalizeArtifacts(artifactData);
      setArtifacts(normalizedArtifacts);
      if (!normalizedArtifacts.some((artifact) => artifact.artifact_type === activeArtifact)) {
        setActiveArtifact(normalizedArtifacts[0]?.artifact_type ?? "snort_rule");
      }
    } catch (exc) {
      if (toMessage(exc).startsWith("404:")) {
        setSelectedJobId(null);
        setSelectedJob(null);
        setEvents([]);
        setReport(null);
        setArtifacts([]);
        await loadJobs(true);
        return;
      }
      setError(toMessage(exc));
    }
  }, [activeArtifact, apiKey, loadJobs]);

  useEffect(() => {
    void loadHealth();
    void loadJobs(true);
    void loadLlmExperiments();
  }, [loadHealth, loadJobs, loadLlmExperiments]);

  useEffect(() => {
    if (selectedJobId) {
      void loadSelectedJob(selectedJobId);
    }
  }, [selectedJobId, loadSelectedJob]);

  useEffect(() => {
    if (!autoRefresh) {
      return;
    }
    const interval = window.setInterval(() => {
      void loadHealth();
      void loadJobs(false);
      void loadLlmExperiments();
      if (selectedJobId) {
        void loadSelectedJob(selectedJobId);
      }
    }, 3000);
    return () => window.clearInterval(interval);
  }, [autoRefresh, loadHealth, loadJobs, loadLlmExperiments, loadSelectedJob, selectedJobId]);

  const selectedStatus = selectedJob?.status ?? jobs.find((job) => job.job_id === selectedJobId)?.status ?? "idle";
  const activeArtifactData = artifacts.find((artifact) => artifact.artifact_type === activeArtifact) ?? artifacts[0];
  const verification = report?.verification ?? null;
  const evidence = verification?.evidence ?? {};
  const evidenceMetrics = useMemo(() => buildEvidenceMetrics(evidence, verification), [evidence, verification]);
  const analytics = useMemo(() => buildAnalyticsData(jobs), [jobs]);

  async function submitJob(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError(null);
    setCreating(true);
    try {
      const created = await fetchJson<JobSummary>("/jobs", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          cve_id: cveId.trim().toUpperCase(),
          submitted_by: submittedBy.trim() || "dashboard",
          prefer_seed: preferSeed
        })
      }, apiKey);
      setSelectedJobId(created.job_id);
      await loadJobs(false);
      await loadSelectedJob(created.job_id);
    } catch (exc) {
      setError(toMessage(exc));
    } finally {
      setCreating(false);
    }
  }

  async function refreshAll() {
    setError(null);
    await loadHealth();
    await loadJobs(false);
    await loadLlmExperiments();
    if (selectedJobId) {
      await loadSelectedJob(selectedJobId);
    }
  }

  const viewCopy = getViewCopy(activeView);
  const navItems: { id: ActiveView; label: string; icon: ReactNode }[] = [
    { id: "analytics", label: "Analytics Overview", icon: <BarChart3 size={18} /> },
    { id: "submit", label: "CVE Submission", icon: <Bug size={18} /> },
    { id: "jobs", label: "Job Tracking", icon: <ClipboardList size={18} /> },
    { id: "reports", label: "Verification Reports", icon: <FileText size={18} /> },
    { id: "benchmarks", label: "Model Benchmarks", icon: <Activity size={18} /> }
  ];

  const selectedSummary = (
    <section className="summary-band">
      <div>
        <p className="eyebrow">Selected Job</p>
        <h2>{selectedJob?.cve_id ?? "No job selected"}</h2>
        <p>{selectedJob ? shortId(selectedJob.job_id) : "Submit or select a job to inspect verification output."}</p>
        {selectedJob && (
          <div className="summary-meta">
            <span>{selectedJob.submitted_by}</span>
            <span>Updated {formatTime(selectedJob.updated_at)}</span>
          </div>
        )}
      </div>
      <StatusPill label={selectedStatus} status={selectedStatus} />
    </section>
  );

  const submitPanel = (
    <section className="panel">
      <div className="panel-heading">
        <div>
          <h2>Run CVE</h2>
          <p>{API_BASE}</p>
        </div>
        <Server size={19} />
      </div>
      <form className="submit-form" onSubmit={(event) => void submitJob(event)}>
        <label>
          CVE ID
          <input value={cveId} onChange={(event) => setCveId(event.target.value)} placeholder="CVE-2021-41773" />
        </label>
        <label>
          Submitted by
          <input value={submittedBy} onChange={(event) => setSubmittedBy(event.target.value)} />
        </label>
        <label className="checkbox-row">
          <input type="checkbox" checked={preferSeed} onChange={(event) => setPreferSeed(event.target.checked)} />
          Use seeded CVE when available
        </label>
        <button className="primary-button" type="submit" disabled={creating || !cveId.trim()}>
          {creating ? <Loader2 className="spin" size={17} /> : <Play size={17} />}
          Run pipeline
        </button>
      </form>
    </section>
  );

  const jobsPanel = (
    <section className="panel jobs-panel">
      <div className="panel-heading">
        <div>
          <h2>Jobs</h2>
          <p>{loadingJobs ? "Refreshing" : `${jobs.length} available`}</p>
        </div>
        <label className="switch-row">
          <input type="checkbox" checked={autoRefresh} onChange={(event) => setAutoRefresh(event.target.checked)} />
          Auto
        </label>
      </div>
      <div className="job-list">
        {jobs.map((job) => (
          <button
            className={`job-row ${job.job_id === selectedJobId ? "selected" : ""}`}
            key={job.job_id}
            onClick={() => setSelectedJobId(job.job_id)}
          >
            <span>
              <strong>{job.cve_id}</strong>
              <small>{shortId(job.job_id)} / {formatClock(job.updated_at)}</small>
            </span>
            <StatusPill label={job.status} status={job.status} />
          </button>
        ))}
        {jobs.length === 0 && <p className="empty-state">No jobs yet.</p>}
      </div>
    </section>
  );

  const verificationPanel = (
    <article className="panel report-panel">
      <div className="panel-heading">
        <div>
          <h2>Verification</h2>
          <p>{report?.verification?.finished_at ? formatTime(report.verification.finished_at) : "Waiting for report"}</p>
        </div>
        <ShieldCheck size={19} />
      </div>
      {report?.verification ? (
        <>
          <div className="score-grid">
            <Metric label="Status" value={report.verification.status.toUpperCase()} tone={report.verification.status} />
            <Metric label="Effectiveness" value={formatScore(report.verification.effectiveness_score)} />
            <Metric label="Confidence" value={formatScore(report.verification.confidence_score)} />
          </div>
          <div className="evidence-grid">
            {evidenceMetrics.map((metric) => (
              <EvidenceItem key={metric.label} metric={metric} />
            ))}
          </div>
          {report.cve && (
            <div className="cve-summary">
              <h3>{report.cve.title}</h3>
              <p>{report.cve.description}</p>
            </div>
          )}
        </>
      ) : (
        <p className="empty-state">Report is not available yet.</p>
      )}
    </article>
  );

  const timelinePanel = (
    <article className="panel timeline-panel">
      <div className="panel-heading">
        <div>
          <h2>Timeline</h2>
          <p>{events.length} events</p>
        </div>
        <Activity size={19} />
      </div>
      <ol className="timeline">
        {events.map((event, index) => (
          <li key={`${event.created_at}-${index}`}>
            <span className="timeline-dot" />
            <div>
              <strong>{formatStage(event.stage)}</strong>
              <p>{event.message}</p>
              <small>{formatTime(event.created_at)}</small>
            </div>
          </li>
        ))}
        {events.length === 0 && <p className="empty-state">No events loaded.</p>}
      </ol>
    </article>
  );

  const artifactPanel = (
    <section className="panel artifact-panel">
      <div className="panel-heading">
        <div>
          <h2>Artifacts</h2>
          <p>{artifacts.length > 0 ? `${artifacts.length} generated files` : "Waiting for artifacts"}</p>
        </div>
        <FileCode2 size={19} />
      </div>
      <div className="artifact-tabs" role="tablist" aria-label="Generated artifacts">
        {artifacts.map((artifact) => (
          <button
            key={artifact.artifact_type}
            className={artifact.artifact_type === activeArtifact ? "active" : ""}
            onClick={() => setActiveArtifact(artifact.artifact_type)}
            aria-selected={artifact.artifact_type === activeArtifact}
          >
            {artifactLabel(artifact.artifact_type)}
          </button>
        ))}
      </div>
      {activeArtifactData ? (
        <>
          <div className="artifact-meta">
            <span>{activeArtifactData.language ?? "text"}</span>
            <span>{activeArtifactData.content_hash ? shortId(activeArtifactData.content_hash) : "no hash"}</span>
            <span>{activeArtifactData.validation_errors?.length ? "validation errors" : "valid"}</span>
          </div>
          <pre className="code-block"><code>{activeArtifactData.content ?? "Artifact content was not stored."}</code></pre>
        </>
      ) : (
        <p className="empty-state">Artifacts are not available yet.</p>
      )}
    </section>
  );

  const llmPanel = (
    <section className="panel llm-panel">
      <div className="panel-heading">
        <div>
          <h2>Model Benchmarks</h2>
          <p>{loadingExperiments ? "Loading model metrics" : `${llmExperiments.length} model rows from PostgreSQL`}</p>
        </div>
        <BarChart3 size={19} />
      </div>
      {experimentsError ? (
        <p className="empty-state">PostgreSQL metrics unavailable: {experimentsError}</p>
      ) : llmExperiments.length > 0 ? (
        <>
          <div className="llm-summary">
            <Metric label="Attempts" value={String(sumBy(llmExperiments, "attempted"))} />
            <Metric label="Passes" value={String(sumBy(llmExperiments, "passed"))} />
            <Metric label="Denials" value={String(sumBy(llmExperiments, "denied"))} />
          </div>
          <div className="llm-table-wrap">
            <table className="llm-table">
              <thead>
                <tr>
                  <th>Model</th>
                  <th>Provider</th>
                  <th>Attempted</th>
                  <th>Pass</th>
                  <th>Fail</th>
                  <th>Deny</th>
                  <th>Malformed</th>
                  <th>Avg Time</th>
                </tr>
              </thead>
              <tbody>
                {llmExperiments.map((row) => (
                  <tr key={`${row.experiment_label}-${row.model_name}`}>
                    <td>
                      <strong>{row.model_name}</strong>
                      <small>{row.experiment_label}{row.is_synthetic ? " / synthetic" : ""}</small>
                    </td>
                    <td>{row.model_provider ?? "unknown"}</td>
                    <td>{row.attempted}</td>
                    <td>{formatPercent(row.pass_rate)}</td>
                    <td>{formatPercent(row.fail_rate)}</td>
                    <td>{formatPercent(row.deny_rate)}</td>
                    <td>{formatPercent(row.malformed_json_rate)}</td>
                    <td>{row.avg_seconds == null ? "n/a" : `${row.avg_seconds.toFixed(1)}s`}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      ) : (
        <p className="empty-state">No model experimentation rows found in PostgreSQL.</p>
      )}
    </section>
  );

  const analyticsPanel = (
    <section className="workspace">
      <section className="analytics-grid" aria-label="Security automation summary">
        <StatChip label="Pipeline Success" value={formatPercent(analytics.successRate)} icon={<CheckCircle2 size={14} />} />
        <StatChip label="Avg Latency" value={formatDuration(analytics.avgLatencySeconds)} icon={<Clock3 size={14} />} />
        <StatChip label="Failed Jobs" value={String(analytics.failed)} icon={<XCircle size={14} />} />
        <StatChip label="Report Coverage" value={formatPercent(analytics.reportRate)} icon={<RadioTower size={14} />} />
      </section>

      <section className="chart-grid">
        <article className="panel chart-card outcome-chart-card">
          <div className="panel-heading">
            <div>
              <h2>Pipeline Outcomes</h2>
              <p>Completed, failed, and active job rates</p>
            </div>
            <Activity size={19} />
          </div>
          <OutcomeDonut analytics={analytics} />
        </article>

        <article className="panel chart-card latency-chart-card">
          <div className="panel-heading">
            <div>
              <h2>Verification Latency</h2>
              <p>Recent terminal jobs, created-to-updated duration</p>
            </div>
            <Clock3 size={19} />
          </div>
          <LatencyChart points={analytics.recentLatencies} />
          <div className="latency-metrics">
            <Metric label="Average" value={formatDuration(analytics.avgLatencySeconds)} />
            <Metric label="P95" value={formatDuration(analytics.p95LatencySeconds)} />
            <Metric label="Fastest" value={formatDuration(analytics.fastestLatencySeconds)} />
            <Metric label="Slowest" value={formatDuration(analytics.slowestLatencySeconds)} />
          </div>
        </article>

        <article className="panel chart-card">
          <div className="panel-heading">
            <div>
              <h2>Outcome Rate</h2>
              <p>Pipeline completion health across job history</p>
            </div>
            <BarChart3 size={19} />
          </div>
          <HorizontalBars rows={analytics.outcomeBars} maxValue={analytics.total} />
        </article>

        <article className="panel chart-card">
          <div className="panel-heading">
            <div>
              <h2>Stage Distribution</h2>
              <p>Where current jobs sit in the workflow</p>
            </div>
            <ClipboardList size={19} />
          </div>
          <HorizontalBars rows={analytics.stageBars} />
        </article>
      </section>
    </section>
  );

  return (
    <main className="app-frame">
      <aside className="sidebar">
        <div className="sidebar-brand">
          <div className="brand-mark">
            <ShieldCheck size={22} />
          </div>
          <div>
            <strong>WebForti</strong>
            <span>AI Security Platform</span>
          </div>
        </div>

        <nav className="sidebar-nav" aria-label="WebForti sections">
          {navItems.map((item) => (
            <button
              key={item.id}
              className={`sidebar-nav-button ${activeView === item.id ? "active" : ""}`}
              onClick={() => setActiveView(item.id)}
            >
              {item.icon}
              <span>{item.label}</span>
            </button>
          ))}
        </nav>

        <div className="sidebar-footer">
          <UserCircle size={28} />
          <div>
            <strong>Security Admin</strong>
            <span>admin@webforti.ai</span>
          </div>
        </div>
      </aside>

      <section className="app-main">
        <header className="topbar">
          <div className="page-title">
            <p className="eyebrow">{viewCopy.kicker}</p>
            <h1>{viewCopy.title}</h1>
            <p>{viewCopy.description}</p>
          </div>
          <div className="topbar-actions">
            <button className="icon-button" title="Notifications">
              <Bell size={18} />
            </button>
            <button className="primary-button compact-button" type="button" onClick={() => setActiveView("submit")}>
              <Plus size={17} />
              New Scan
            </button>
            <button className="icon-button" onClick={() => void refreshAll()} title="Refresh dashboard">
              <RefreshCw size={18} />
            </button>
            <StatusPill label={health?.service ?? "gateway"} status={health?.status === "ok" ? "ok" : "error"} />
          </div>
        </header>

        {error && (
          <div className="alert" role="alert">
            <AlertCircle size={18} />
            <span>{error}</span>
            <button onClick={() => setError(null)}>Dismiss</button>
          </div>
        )}

        {activeView === "analytics" && (
          analyticsPanel
        )}

        {activeView === "submit" && (
          <section className="layout-grid">
            <aside className="control-column">{submitPanel}</aside>
            <section className="workspace">
              {selectedSummary}
              {jobsPanel}
            </section>
          </section>
        )}

        {activeView === "jobs" && (
          <section className="layout-grid">
            <aside className="control-column">{jobsPanel}</aside>
            <section className="workspace">
              {selectedSummary}
              {timelinePanel}
            </section>
          </section>
        )}

        {activeView === "reports" && (
          <section className="workspace">
            <section className="report-card-grid" aria-label="Verification report cards">
              {jobs.slice(0, 6).map((job) => (
                <button
                  className={`report-card ${job.job_id === selectedJobId ? "selected" : ""}`}
                  key={job.job_id}
                  onClick={() => setSelectedJobId(job.job_id)}
                >
                  <div className="report-card-header">
                    <strong>{job.cve_id}</strong>
                    <StatusPill label={job.status} status={job.status} />
                  </div>
                  <p>{formatStage(job.current_stage ?? job.status)}</p>
                  <dl>
                    <div>
                      <dt>Report</dt>
                      <dd>{job.has_report ? "Available" : "Pending"}</dd>
                    </div>
                    <div>
                      <dt>Submitted</dt>
                      <dd>{job.submitted_by}</dd>
                    </div>
                    <div>
                      <dt>Updated</dt>
                      <dd>{formatClock(job.updated_at)}</dd>
                    </div>
                  </dl>
                  <span>View full report</span>
                </button>
              ))}
              {jobs.length === 0 && <p className="empty-state">No verification reports yet.</p>}
            </section>

            {selectedSummary}
            <section className="detail-grid">
              {verificationPanel}
              {timelinePanel}
            </section>
            {artifactPanel}
          </section>
        )}

        {activeView === "benchmarks" && (
          <section className="workspace">
            {llmPanel}
          </section>
        )}
      </section>
    </main>
  );
}

function getViewCopy(view: ActiveView): { kicker: string; title: string; description: string } {
  switch (view) {
    case "analytics":
      return {
        kicker: "Dashboard",
        title: "Analytics Overview",
        description: "Security automation health, benchmark rows, and current verification coverage."
      };
    case "submit":
      return {
        kicker: "Pipeline",
        title: "CVE Submission",
        description: "Submit a CVE to retrieve context, generate artifacts, and run isolated verification."
      };
    case "jobs":
      return {
        kicker: "Operations",
        title: "Job Tracking",
        description: "Follow queued and running jobs across ingestion, planning, generation, and verification."
      };
    case "reports":
      return {
        kicker: "Evidence",
        title: "Verification Reports",
        description: "Review completed security jobs, generated artifacts, timeline evidence, and defense results."
      };
    case "benchmarks":
      return {
        kicker: "Evaluation",
        title: "Model Benchmarks",
        description: "Compare model behavior across attempted CVE planning and verification benchmark runs."
      };
  }
}

function StatusPill({ label, status }: { label: string; status: string }) {
  const normalized = status.toLowerCase();
  const Icon = normalized === "completed" || normalized === "pass" || normalized === "ok"
    ? CheckCircle2
    : normalized === "failed" || normalized === "fail" || normalized === "error"
      ? XCircle
      : Clock3;
  return (
    <span className={`status-pill ${normalized}`}>
      <Icon size={14} />
      {formatStage(label)}
    </span>
  );
}

function StatChip({ label, value, icon }: { label: string; value: string; icon: ReactNode }) {
  return (
    <span className="stat-chip">
      {icon}
      <small>{label}</small>
      <strong>{value}</strong>
    </span>
  );
}

function Metric({ label, value, tone }: { label: string; value: string; tone?: string }) {
  return (
    <div className={`metric ${tone ?? ""}`}>
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

function EvidenceItem({ metric }: { metric: EvidenceMetric }) {
  const Icon = metric.value ? CheckCircle2 : metric.value === false ? XCircle : Clock3;
  return (
    <div className={`evidence-item ${metric.value ? "pass" : metric.value === false ? "fail" : "pending"}`}>
      <Icon size={17} />
      <span>{metric.label}</span>
      {metric.detail && <small>{metric.detail}</small>}
    </div>
  );
}

function OutcomeDonut({ analytics }: { analytics: AnalyticsData }) {
  const successDegrees = analytics.successRate * 360;
  const failureDegrees = analytics.failureRate * 360;
  const runningDegrees = analytics.runningRate * 360;
  const background = analytics.total
    ? `conic-gradient(#176f5d 0deg ${successDegrees}deg, #9a2634 ${successDegrees}deg ${successDegrees + failureDegrees}deg, #d99a2b ${successDegrees + failureDegrees}deg ${successDegrees + failureDegrees + runningDegrees}deg, #e4ebe7 ${successDegrees + failureDegrees + runningDegrees}deg 360deg)`
    : "conic-gradient(#e4ebe7 0deg 360deg)";
  return (
    <div className="outcome-chart">
      <div className="donut-ring" style={{ background }}>
        <div className="donut-core">
          <strong>{formatPercent(analytics.successRate)}</strong>
          <span>Success</span>
        </div>
      </div>
      <div className="donut-legend">
        {analytics.outcomeBars.map((row) => (
          <div key={row.label}>
            <span className={`legend-dot ${row.tone ?? "neutral"}`} />
            <strong>{row.label}</strong>
            <small>{row.value} / {formatPercent(analytics.total ? row.value / analytics.total : 0)}</small>
          </div>
        ))}
      </div>
    </div>
  );
}

function LatencyChart({ points }: { points: LatencyPoint[] }) {
  const maxSeconds = Math.max(...points.map((point) => point.seconds), 1);
  if (points.length === 0) {
    return <p className="empty-state">No completed or failed job latency data yet.</p>;
  }
  return (
    <div className="latency-chart" aria-label="Recent verification latency chart">
      {points.map((point) => {
        const height = Math.max(8, (point.seconds / maxSeconds) * 100);
        return (
          <div className="latency-bar-column" key={`${point.label}-${point.seconds}`}>
            <div className="latency-bar-track">
              <span
                className={`latency-bar ${point.status === "failed" ? "danger" : "success"}`}
                style={{ height: `${height}%` }}
                title={`${point.label}: ${formatDuration(point.seconds)}`}
              />
            </div>
            <small>{point.label}</small>
          </div>
        );
      })}
    </div>
  );
}

function HorizontalBars({ rows, maxValue }: { rows: ChartBar[]; maxValue?: number }) {
  const max = Math.max(maxValue ?? 0, ...rows.map((row) => row.value), 1);
  if (rows.length === 0) {
    return <p className="empty-state">No chart rows available yet.</p>;
  }
  return (
    <div className="horizontal-bars">
      {rows.map((row) => {
        const width = Math.max(row.value > 0 ? 4 : 0, (row.value / max) * 100);
        return (
          <div className="horizontal-bar-row" key={row.label}>
            <div className="bar-row-label">
              <strong>{row.label}</strong>
              <span>{row.detail ?? row.value}</span>
            </div>
            <div className="horizontal-bar-track">
              <span className={`horizontal-bar ${row.tone ?? "neutral"}`} style={{ width: `${width}%` }} />
            </div>
          </div>
        );
      })}
    </div>
  );
}

async function fetchJson<T>(path: string, init?: RequestInit, apiKey = ""): Promise<T> {
  const headers = new Headers(init?.headers);
  if (apiKey) {
    headers.set("X-WebForti-API-Key", apiKey);
  }
  const response = await fetch(`${API_BASE}${path}`, { ...init, headers });
  if (!response.ok) {
    let detail = response.statusText;
    try {
      const body = await response.json();
      detail = typeof body.detail === "string" ? body.detail : JSON.stringify(body);
    } catch {
      detail = await response.text();
    }
    throw new Error(`${response.status}: ${detail}`);
  }
  return response.json() as Promise<T>;
}

async function fetchOptional<T>(path: string, apiKey = ""): Promise<T | null> {
  try {
    return await fetchJson<T>(path, undefined, apiKey);
  } catch (exc) {
    if (toMessage(exc).startsWith("404:")) {
      return null;
    }
    throw exc;
  }
}

function normalizeArtifacts(response: BundleArtifactResponse | null): Artifact[] {
  if (!response) {
    return [];
  }
  if ("artifacts" in response) {
    return response.artifacts;
  }
  const artifacts: Artifact[] = [];
  if (response.bundle.rule) {
    artifacts.push({ ...response.bundle.rule, artifact_type: response.bundle.rule.artifact_type ?? "snort_rule" });
  }
  if (response.bundle.exploit) {
    artifacts.push({ ...response.bundle.exploit, artifact_type: response.bundle.exploit.artifact_type ?? "exploit_script" });
  }
  if (response.bundle.docker_spec) {
    artifacts.push({ ...response.bundle.docker_spec, artifact_type: response.bundle.docker_spec.artifact_type ?? "docker_spec" });
  }
  return artifacts;
}

function buildEvidenceMetrics(evidence: Record<string, unknown>, verification: Report["verification"]): EvidenceMetric[] {
  if (verification && !hasDockerEvidence(evidence)) {
    return [
      {
        label: "Exploit executed",
        value: verification.exploit_executed,
        detail: stringValue(evidence.mode)
      },
      {
        label: "Rule alerted",
        value: verification.rule_alerted
      },
      {
        label: "Attack blocked",
        value: verification.blocked
      },
      {
        label: "Exploit resisted",
        value: verification.exploit_executed ? !verification.exploit_succeeded : undefined
      },
      {
        label: "Artifact hashes",
        value: Boolean(evidence.rule_hash && evidence.exploit_hash)
      },
      {
        label: "Verification pass",
        value: verification.status.toLowerCase() === "pass"
      }
    ];
  }

  const snortValidation = asObject(evidence.snort_validation);
  const snortPcapDetection = asObject(evidence.snort_pcap_detection);
  const liveRequestDetection = asObject(evidence.snort_live_request_detection);
  return [
    {
      label: "Snort syntax",
      value: toBool(snortValidation.valid),
      detail: stringValue(snortValidation.image)
    },
    {
      label: "PCAP alert",
      value: toBool(snortPcapDetection.alerted) ?? verification?.rule_alerted,
      detail: stringValue(snortPcapDetection.pcap)
    },
    {
      label: "Runtime alert",
      value: toBool(evidence.snort_runtime_alerted) ?? verification?.rule_alerted
    },
    {
      label: "Live request",
      value: toBool(liveRequestDetection.alerted) ?? verification?.exploit_executed,
      detail: stringValue(liveRequestDetection.request_path)
    },
    {
      label: "Interface listener",
      value: toBool(evidence.snort_interface_alerted)
    },
    {
      label: "Proxy block",
      value: toBool(evidence.proxy_alerted) ?? verification?.blocked
    }
  ];
}

function hasDockerEvidence(evidence: Record<string, unknown>): boolean {
  return [
    "snort_validation",
    "snort_pcap_detection",
    "snort_live_request_detection",
    "snort_runtime_alerted",
    "snort_interface_alerted",
    "proxy_alerted"
  ].some((key) => key in evidence);
}

function buildAnalyticsData(jobs: JobSummary[]): AnalyticsData {
  const total = jobs.length;
  const completed = jobs.filter((job) => job.status === "completed").length;
  const failed = jobs.filter((job) => job.status === "failed").length;
  const running = Math.max(total - completed - failed, 0);
  const reports = jobs.filter((job) => job.has_report).length;
  const terminalJobs = jobs.filter((job) => job.status === "completed" || job.status === "failed");
  const durations = terminalJobs.map(jobDurationSeconds).filter((seconds) => Number.isFinite(seconds));
  const terminalTotal = completed + failed;
  const successRate = terminalTotal ? completed / terminalTotal : 0;
  const failureRate = terminalTotal ? failed / terminalTotal : 0;
  const runningRate = total ? running / total : 0;
  const reportRate = total ? reports / total : 0;
  const sortedDurations = [...durations].sort((a, b) => a - b);
  const stageCounts = jobs.reduce<Record<string, number>>((counts, job) => {
    const stage = formatStage(job.current_stage ?? job.status);
    counts[stage] = (counts[stage] ?? 0) + 1;
    return counts;
  }, {});
  const stageBars = Object.entries(stageCounts)
    .map(([label, value]) => ({
      label,
      value,
      detail: `${value} job${value === 1 ? "" : "s"}`,
      tone: label === "Failed" ? "danger" as const : label === "Completed" ? "success" as const : "warning" as const
    }))
    .sort((left, right) => right.value - left.value)
    .slice(0, 7);
  return {
    total,
    completed,
    failed,
    running,
    reports,
    successRate,
    failureRate,
    runningRate,
    reportRate,
    avgLatencySeconds: average(sortedDurations),
    p95LatencySeconds: percentile(sortedDurations, 0.95),
    fastestLatencySeconds: sortedDurations[0] ?? 0,
    slowestLatencySeconds: sortedDurations[sortedDurations.length - 1] ?? 0,
    recentLatencies: terminalJobs
      .slice(0, 9)
      .reverse()
      .map((job) => ({
        label: shortCveChartLabel(job.cve_id),
        seconds: jobDurationSeconds(job),
        status: job.status
      })),
    outcomeBars: [
      {
        label: "Completed",
        value: completed,
        detail: formatPercent(total ? completed / total : 0),
        tone: "success"
      },
      {
        label: "Failed",
        value: failed,
        detail: formatPercent(total ? failed / total : 0),
        tone: "danger"
      },
      {
        label: "Running / Queued",
        value: running,
        detail: formatPercent(total ? running / total : 0),
        tone: "warning"
      },
      {
        label: "Reports Ready",
        value: reports,
        detail: formatPercent(reportRate),
        tone: "neutral"
      }
    ],
    stageBars
  };
}

function jobDurationSeconds(job: JobSummary): number {
  const created = new Date(job.created_at).getTime();
  const updated = new Date(job.updated_at).getTime();
  if (!Number.isFinite(created) || !Number.isFinite(updated) || updated < created) {
    return 0;
  }
  return Math.max(1, Math.round((updated - created) / 1000));
}

function shortCveChartLabel(cveId: string): string {
  const parts = cveId.split("-");
  if (parts.length >= 3) {
    return `${parts[1].slice(-2)}-${parts.slice(2).join("-").slice(0, 6)}`;
  }
  return cveId.length > 8 ? cveId.slice(-8) : cveId;
}

function average(values: number[]): number {
  return values.length ? values.reduce((total, value) => total + value, 0) / values.length : 0;
}

function percentile(values: number[], p: number): number {
  if (values.length === 0) {
    return 0;
  }
  const index = Math.min(values.length - 1, Math.ceil(values.length * p) - 1);
  return values[index];
}

function asObject(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : {};
}

function toBool(value: unknown): boolean | undefined {
  return typeof value === "boolean" ? value : undefined;
}

function stringValue(value: unknown): string | undefined {
  return typeof value === "string" && value ? value : undefined;
}

function artifactLabel(value: string): string {
  return value
    .replace("_script", "")
    .replace("snort_rule", "Snort rule")
    .replace("docker_spec", "Docker spec")
    .replace("exploit", "Exploit");
}

function formatStage(value: string): string {
  return value
    .replace(/_/g, " ")
    .replace(/\b\w/g, (letter) => letter.toUpperCase());
}

function formatScore(value: number): string {
  return `${Math.round(value * 100)}%`;
}

function formatPercent(value: number): string {
  return `${(value * 100).toFixed(1)}%`;
}

function formatDuration(seconds: number): string {
  if (!Number.isFinite(seconds) || seconds <= 0) {
    return "0s";
  }
  if (seconds < 60) {
    return `${Math.round(seconds)}s`;
  }
  const minutes = Math.floor(seconds / 60);
  const remainder = Math.round(seconds % 60);
  if (minutes < 60) {
    return remainder ? `${minutes}m ${remainder}s` : `${minutes}m`;
  }
  const hours = Math.floor(minutes / 60);
  const minuteRemainder = minutes % 60;
  return minuteRemainder ? `${hours}h ${minuteRemainder}m` : `${hours}h`;
}

function sumBy(rows: LlmExperiment[], key: "attempted" | "passed" | "denied"): number {
  return rows.reduce((total, row) => total + row[key], 0);
}

function formatTime(value: string): string {
  return new Intl.DateTimeFormat(undefined, {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    month: "short",
    day: "numeric"
  }).format(new Date(value));
}

function formatClock(value: string): string {
  return new Intl.DateTimeFormat(undefined, {
    hour: "2-digit",
    minute: "2-digit"
  }).format(new Date(value));
}

function shortId(value: string): string {
  return value.length > 12 ? `${value.slice(0, 8)}...` : value;
}

function toMessage(exc: unknown): string {
  return exc instanceof Error ? exc.message : String(exc);
}

function readInitialApiKey(): string {
  return window.localStorage.getItem(API_KEY_STORAGE_KEY) ?? import.meta.env.VITE_WEBFORTI_API_KEY ?? "";
}

export default App;
