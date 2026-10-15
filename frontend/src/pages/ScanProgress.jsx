import { useEffect, useRef, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { getScan } from "../api/client.js";

// Mirrors backend RANGE in app/core/worker.py (13-reporting-dashboard-backend.md).
const STAGES = [
  { label: "Crawling…", min: 0, max: 30 },
  { label: "Testing for SQL injection…", min: 30, max: 45 },
  { label: "Testing for XSS…", min: 45, max: 60 },
  { label: "Checking auth & session security…", min: 60, max: 70 },
  { label: "Scanning for exposed secrets…", min: 70, max: 80 },
  { label: "Checking security headers…", min: 80, max: 90 },
  { label: "Generating fix suggestions…", min: 90, max: 95 },
  { label: "Building report…", min: 95, max: 100 },
];

function stageFor(pct) {
  for (const s of STAGES) {
    if (pct < s.max || (pct === 100 && s.max === 100)) {
      if (pct >= s.min) return s.label;
    }
  }
  return STAGES[0].label;
}

const POLL_MS = 2000;
const TERMINAL = new Set(["report_ready", "failed", "completed"]);

export default function ScanProgress() {
  const { id: scanId } = useParams();
  const navigate = useNavigate();
  const [scan, setScan] = useState(null);
  const [error, setError] = useState(null);

  // Keep a ref of whether we've already redirected, so React StrictMode's
  // double-effect doesn't fire two redirects/polls from stale state.
  const redirected = useRef(false);

  useEffect(() => {
    let stop = false;
    let timer = null;

    const poll = async () => {
      if (stop || redirected.current) return;
      try {
        const s = await getScan(scanId);
        setScan(s);
        if (TERMINAL.has(s.status)) {
          if (s.status === "report_ready" && !redirected.current) {
            redirected.current = true;
            stop = true;
            navigate(`/scans/${scanId}/findings`, { replace: true });
            return;
          }
          stop = true;
          return;
        }
      } catch (e) {
        setError(e.message);
      }
      if (!stop && !redirected.current) {
        timer = setTimeout(poll, POLL_MS);
      }
    };

    poll();
    return () => {
      stop = true;
      if (timer) clearTimeout(timer);
    };
  }, [scanId, navigate]);

  if (error && !scan) return <div className="error-banner">{error}</div>;

  const pct = scan?.progress_pct ?? 0;
  const status = scan?.status ?? "queued";
  const failed = status === "failed";

  return (
    <div>
      <h1>Scan in progress</h1>
      <div className="card">
        <div className="progress-track">
          <div className="progress-fill" style={{ width: `${pct}%` }} />
        </div>
        <div className="progress-label">
          <span className="progress-stage">
            {failed ? "Scan failed" : scan ? stageFor(pct) : "Queued…"}
          </span>
          <span>{pct}%</span>
        </div>

        {failed && scan?.error_message && (
          <div className="error-banner" style={{ marginTop: 14 }}>
            {scan.error_message}
          </div>
        )}

        <p className="muted" style={{ marginTop: 12, marginBottom: 0 }}>
          Scan {scanId} · status <b>{status}</b>
          {scan?.started_at && (
            <>
              {" "}
              · started {new Date(scan.started_at).toLocaleTimeString()}
            </>
          )}
        </p>
      </div>

      <button className="secondary" onClick={() => navigate("/")}>
        Back to targets
      </button>
    </div>
  );
}
