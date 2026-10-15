import { useEffect, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { listTargetScans, getTarget, compareScans } from "../api/client.js";

const STATUS_LABEL = {
  resolved: { label: "Resolved", cls: "consented" },
  new: { label: "New", cls: "unconsented" },
  persisting: { label: "Persisting", cls: "medium" },
};

function fmt(iso) {
  return iso ? new Date(iso).toLocaleString() : "—";
}

export default function ScanHistory() {
  const { id: targetId } = useParams();
  const navigate = useNavigate();
  const [target, setTarget] = useState(null);
  const [scans, setScans] = useState([]);
  const [error, setError] = useState(null);
  const [oldId, setOldId] = useState("");
  const [newId, setNewId] = useState("");
  const [compare, setCompare] = useState(null);
  const [comparing, setComparing] = useState(false);

  useEffect(() => {
    (async () => {
      try {
        const [t, s] = await Promise.all([
          getTarget(targetId),
          listTargetScans(targetId),
        ]);
        setTarget(t);
        setScans(s);
        if (s.length >= 2) {
          setOldId(s[s.length - 2].id);
          setNewId(s[s.length - 1].id);
        }
      } catch (e) {
        setError(e.message);
      }
    })();
  }, [targetId]);

  const onCompare = async () => {
    if (!oldId || !newId || oldId === newId) return;
    setComparing(true);
    setCompare(null);
    try {
      const res = await compareScans(oldId, newId);
      setCompare(res);
    } catch (e) {
      setError(e.message);
    } finally {
      setComparing(false);
    }
  };

  const summaryOf = (arr) => {
    const counts = { resolved: 0, new: 0, persisting: 0 };
    arr.forEach((f) => { if (counts[f.status] != null) counts[f.status] += 1; });
    return counts;
  };

  return (
    <div>
      <div className="row between wrap">
        <div>
          <h1 style={{ marginBottom: 4 }}>Scan history</h1>
          <p className="muted" style={{ margin: 0 }}>{target?.domain}</p>
        </div>
        <button className="secondary" onClick={() => navigate("/")}>
          Back to targets
        </button>
      </div>

      {error && <div className="error-banner">{error}</div>}

      <div className="card">
        <h2>Compare two scans</h2>
        <p className="muted" style={{ marginTop: 0 }}>
          Pick an earlier scan and a later scan to see whether the later one
          addressed the earlier findings.
        </p>
        <div className="row wrap">
          <div className="grow">
            <label>Earlier scan (baseline)</label>
            <select
              value={oldId}
              onChange={(e) => setOldId(e.target.value)}
              style={{ background: "var(--panel-2)", color: "var(--text)", border: "1px solid var(--border)", borderRadius: 8, padding: 9, width: "100%" }}
            >
              {scans.map((s) => (
                <option key={s.id} value={s.id}>
                  {fmt(s.started_at)} — {s.status} ({s.progress_pct}%)
                </option>
              ))}
            </select>
          </div>
          <div className="grow">
            <label>Later scan</label>
            <select
              value={newId}
              onChange={(e) => setNewId(e.target.value)}
              style={{ background: "var(--panel-2)", color: "var(--text)", border: "1px solid var(--border)", borderRadius: 8, padding: 9, width: "100%" }}
            >
              {scans.map((s) => (
                <option key={s.id} value={s.id}>
                  {fmt(s.started_at)} — {s.status} ({s.progress_pct}%)
                </option>
              ))}
            </select>
          </div>
          <div style={{ alignSelf: "flex-end" }}>
            <button onClick={onCompare} disabled={!oldId || !newId || oldId === newId || comparing}>
              {comparing ? "Comparing…" : "Compare"}
            </button>
          </div>
        </div>

        {compare && (() => {
          const counts = summaryOf(compare.findings);
          return (
            <div style={{ marginTop: 16 }}>
              <div className="row wrap" style={{ gap: 16, marginBottom: 12 }}>
                <span className="badge consented">Resolved: {counts.resolved}</span>
                <span className="badge unconsented">New: {counts.new}</span>
                <span className="badge medium">Persisting: {counts.persisting}</span>
              </div>
              {compare.findings.length === 0 ? (
                <div className="empty">No overlapping findings between these scans.</div>
              ) : (
                <table>
                  <thead>
                    <tr>
                      <th>Status</th>
                      <th>Module</th>
                      <th>Severity</th>
                      <th>Route</th>
                      <th>Parameter</th>
                    </tr>
                  </thead>
                  <tbody>
                    {compare.findings.map((f, i) => {
                      const s = STATUS_LABEL[f.status] || { label: f.status, cls: "muted" };
                      return (
                        <tr key={i}>
                          <td><span className={`badge ${s.cls}`}>{s.label}</span></td>
                          <td><span className="module-tag">{f.module}</span></td>
                          <td className="mono">{f.severity}</td>
                          <td className="mono">{f.route}</td>
                          <td className="muted">{f.parameter || "—"}</td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              )}
            </div>
          );
        })()}
      </div>

      <h2>All scans for this target</h2>
      {scans.length === 0 ? (
        <div className="empty">No scans yet.</div>
      ) : (
        <div className="card">
          <table>
            <thead>
              <tr>
                <th>Started</th>
                <th>Completed</th>
                <th>Status</th>
                <th>Progress</th>
                <th>Findings</th>
              </tr>
            </thead>
            <tbody>
              {scans.map((s) => (
                <tr key={s.id}>
                  <td>{fmt(s.started_at)}</td>
                  <td>{fmt(s.completed_at)}</td>
                  <td><span className="badge medium">{s.status}</span></td>
                  <td>{s.progress_pct}%</td>
                  <td>
                    {s.status === "report_ready" ? (
                      <button className="ghost" onClick={() => navigate(`/scans/${s.id}/findings`)}>
                        View
                      </button>
                    ) : (
                      <span className="muted">{s.status}</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
