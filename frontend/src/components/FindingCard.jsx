import { useState } from "react";
import SeverityBadge from "./SeverityBadge.jsx";
import { renderEvidence } from "./EvidenceViewer.jsx";
import FixDiffView from "./FixDiffView.jsx";
import {
  getFindingDetail,
  getFix,
  generateFix,
} from "../api/client.js";

export default function FindingCard({ finding }) {
  const [detail, setDetail] = useState(null);
  const [showEvidence, setShowEvidence] = useState(false);
  const [fix, setFix] = useState(null);
  const [fixing, setFixing] = useState(false);
  const [error, setError] = useState(null);

  const loadDetail = async () => {
    if (detail) return detail;
    const d = await getFindingDetail(finding.id);
    setDetail(d);
    return d;
  };

  const toggleEvidence = async () => {
    if (!showEvidence && !detail) {
      setError(null);
      const d = await loadDetail();
      setDetail(d);
      // Auto-load fix suggestion alongside evidence.
      try {
        const f = await getFix(finding.id);
        setFix(f);
      } catch {
        setFix(null);
      }
      setShowEvidence(true);
    } else {
      setShowEvidence(!showEvidence);
    }
  };

  const onGenerateFix = async () => {
    setFixing(true);
    setError(null);
    try {
      const f = await generateFix(finding.id);
      setFix(f);
    } catch (e) {
      setError(e.message);
    } finally {
      setFixing(false);
    }
  };

  return (
    <details className="finding">
      <summary>
        <SeverityBadge severity={finding.severity} />
        <span className="module-tag">{finding.module}</span>
        <span className="grow">
          <b>{finding.subtype}</b> ·{" "}
          <span className="mono">{finding.route}</span>
          {finding.parameter && (
            <span className="muted"> ?{finding.parameter}=</span>
          )}
        </span>
        <span className="toggle-link" onClick={toggleEvidence}>
          {showEvidence ? "Hide evidence" : "Evidence"}
        </span>
      </summary>
      <div className="body">
        <p className="muted" style={{ marginTop: 0 }}>
          {finding.evidence_summary}
        </p>
        {error && <div className="error-banner">{error}</div>}
        {showEvidence && detail && renderEvidence(detail.module, detail.evidence)}
        {showEvidence &&
          (fix ? (
            <FixDiffView
              diff={fix.diff}
              explanation={fix.explanation}
              modelUsed={fix.model_used}
            />
          ) : (
            <div style={{ marginTop: 12 }}>
              <button className="secondary" onClick={onGenerateFix} disabled={fixing}>
                {fixing ? "Generating fix…" : "Generate fix suggestion"}
              </button>
            </div>
          ))}
      </div>
    </details>
  );
}
