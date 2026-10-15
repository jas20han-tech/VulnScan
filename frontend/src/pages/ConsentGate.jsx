import { useEffect, useMemo, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import {
  confirmConsent,
  getConsentPhrase,
  getTarget,
} from "../api/client.js";

// Backend computes the expected phrase from a template + domain. We ask the API
// for the exact string rather than guessing at template internals.
export default function ConsentGate() {
  const { id } = useParams();
  const navigate = useNavigate();

  const [target, setTarget] = useState(null);
  const [expected, setExpected] = useState("");
  const [typed, setTyped] = useState("");
  const [loading, setLoading] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState(null);
  const [done, setDone] = useState(false);

  useEffect(() => {
    (async () => {
      try {
        const [t, p] = await Promise.all([getTarget(id), getConsentPhrase(id)]);
        setTarget(t);
        setExpected(p.phrase || "");
      } catch (e) {
        setError(e.message);
      } finally {
        setLoading(false);
      }
    })();
  }, [id]);

  const matches = useMemo(
    () => expected.length > 0 && typed === expected,
    [typed, expected]
  );

  const onSubmit = async (ev) => {
    ev.preventDefault();
    if (!matches) return;
    setSubmitting(true);
    setError(null);
    try {
      await confirmConsent(id, typed);
      setDone(true);
    } catch (e) {
      setError(e.message);
      setSubmitting(false);
    }
  };

  if (loading) return <div className="loading">Loading…</div>;

  return (
    <div>
      <h1>Authorization gate</h1>
      <p className="muted">
        Target: <b>{target?.domain}</b> · {target?.base_url}
      </p>

      {done || target?.consent_confirmed_at ? (
        <div className="card">
          <h2 style={{ color: "var(--ok)" }}>Consent confirmed</h2>
          <p>
            This target is authorized for scanning. You can now start a scan.
          </p>
          <div className="row">
            <button onClick={() => navigate("/")}>Back to targets</button>
            <button
              className="secondary"
              onClick={() => navigate(`/targets/${id}/scans`)}
            >
              Start a scan
            </button>
          </div>
        </div>
      ) : (
        <form onSubmit={onSubmit} className={`gate ${matches ? "match-ok" : ""}`}>
          <h2 style={{ marginTop: 0 }}>You must confirm authorization to scan</h2>
          <p className="gate-note">
            Scanning a system you do not own or are not authorized to test is
            illegal in most jurisdictions. This step is a real gate — it cannot
            be skipped, and the backend refuses to run a scan until this exact
            phrase is entered. Type the sentence below verbatim to proceed.
          </p>

          <div>
            <label>Required phrase</label>
            <div className="phrase-box">{expected}</div>
          </div>

          <div style={{ marginTop: 16 }}>
            <label>Type the phrase exactly (character-for-character)</label>
            <input
              value={typed}
              onChange={(e) => setTyped(e.target.value)}
              autoComplete="off"
              autoCorrect="off"
              spellCheck={false}
              className="mono"
              placeholder="Start typing the required phrase…"
            />
          </div>

          <div className="row" style={{ marginTop: 14, justifyContent: "space-between" }}>
            <span className={matches ? "muted" : "muted"} style={{ color: matches ? "var(--ok)" : "var(--muted)" }}>
              {typed.length === 0
                ? "Awaiting input…"
                : matches
                ? "Match — you may confirm."
                : `${typed.length}/${expected.length} characters match ${
                    typed.length > expected.length ? "— too long" : "so far"
                  }`}
            </span>
            <div className="row">
              <button
                type="button"
                className="secondary"
                onClick={() => navigate("/")}
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={!matches || submitting}
                style={{
                  background: matches ? "var(--ok)" : undefined,
                  borderColor: matches ? "var(--ok)" : undefined,
                }}
              >
                {submitting ? "Confirming…" : "Confirm authorization"}
              </button>
            </div>
          </div>

          {error && <div className="error-banner">{error}</div>}
        </form>
      )}
    </div>
  );
}
