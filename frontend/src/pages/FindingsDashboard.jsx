import { useCallback, useEffect, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { listFindings, reportUrl, getScan } from "../api/client.js";
import FindingCard from "../components/FindingCard.jsx";

const MODULES = ["sqli", "xss", "auth", "secrets", "headers"];
const SEV_ORDER = ["critical", "high", "medium", "low"];
const SEV_LABEL = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
};

export default function FindingsDashboard() {
  const { id: scanId } = useParams();
  const navigate = useNavigate();
  const [findings, setFindings] = useState([]);
  const [scan, setScan] = useState(null);
  const [loading, setLoading] = useState(true);
  const [moduleFilter, setModuleFilter] = useState("all");
  const [error, setError] = useState(null);

  const load = useCallback(async () => {
    try {
      const [fs, s] = await Promise.all([listFindings(scanId), getScan(scanId)]);
      setFindings(fs);
      setScan(s);
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  }, [scanId]);

  useEffect(() => {
    load();
  }, [load]);

  const filtered = moduleFilter === "all"
    ? findings
    : findings.filter((f) => f.module === moduleFilter);

  const grouped = SEV_ORDER.map((sev) => ({
    sev,
    items: filtered.filter((f) => f.severity === sev),
  })).filter((g) => g.items.length > 0);

  const total = findings.length;
  const counts = Object.fromEntries(SEV_ORDER.map((s) => [s, 0]));
  findings.forEach((f) => { if (counts[f.severity] != null) counts[f.severity] += 1; });

  const downloadReport = () => {
    const a = document.createElement("a");
    a.href = reportUrl(scanId);
    a.target = "_blank";
    a.rel = "noreferrer";
    a.click();
  };

  if (loading) return <div className="loading">Loading…</div>;
  if (error) return <div className="error-banner">{error}</div>;

  return (
    <div>
      <div className="row between wrap">
        <div>
          <h1 style={{ marginBottom: 4 }}>Findings</h1>
          <p className="muted" style={{ margin: 0 }}>
            Scan {scanId} · {total} finding{total === 1 ? "" : "s"} ·{" "}
            {scan?.completed_at
              ? `completed ${new Date(scan.completed_at).toLocaleString()}`
              : scan?.status}
          </p>
        </div>
        <div className="row">
          <button className="secondary" onClick={() => navigate(-1)}>
            Back
          </button>
          <button onClick={downloadReport}>Export PDF report</button>
        </div>
      </div>

      {total === 0 ? (
        <div className="empty">
          No vulnerabilities detected. This scan found nothing to report.
        </div>
      ) : (
        <>
          <div className="filter-row" style={{ marginTop: 18 }}>
            <button
              type="button"
              className={`filter-chip ${moduleFilter === "all" ? "active" : ""}`}
              onClick={() => setModuleFilter("all")}
            >
              All ({total})
            </button>
            {MODULES.map((m) => {
              const n = findings.filter((f) => f.module === m).length;
              return (
                <button
                  type="button"
                  key={m}
                  className={`filter-chip ${moduleFilter === m ? "active" : ""}`}
                  onClick={() => setModuleFilter(m)}
                >
                  {m} ({n})
                </button>
              );
            })}
          </div>

          <div className="row wrap" style={{ gap: 16, marginBottom: 18 }}>
            {SEV_ORDER.map((s) => (
              <span key={s} className="sev">
                <span
                  className={`sev ${s}`}
                  style={{ color: `var(--${s})` }}
                >
                  <span className="sev-dot" />
                  {SEV_LABEL[s]}: {counts[s]}
                </span>
              </span>
            ))}
          </div>

          {grouped.map(({ sev, items }) => (
            <div key={sev} style={{ marginBottom: 8 }}>
              <h2 style={{ color: `var(--${sev})`, marginBottom: 10 }}>
                {SEV_LABEL[sev]}
              </h2>
              {items.map((f) => (
                <FindingCard key={f.id} finding={f} />
              ))}
            </div>
          ))}
        </>
      )}
    </div>
  );
}
