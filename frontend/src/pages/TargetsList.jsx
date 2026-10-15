import { useCallback, useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  createTarget,
  listTargets,
  startScan,
  ApiError,
} from "../api/client.js";

function prettyDate(iso) {
  if (!iso) return "—";
  return new Date(iso).toLocaleString();
}

export default function TargetsList() {
  const navigate = useNavigate();
  const [targets, setTargets] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const [domain, setDomain] = useState("");
  const [baseUrl, setBaseUrl] = useState("");
  const [ownerNote, setOwnerNote] = useState("");
  const [creating, setCreating] = useState(false);
  const [formError, setFormError] = useState(null);

  const refresh = useCallback(async () => {
    try {
      const data = await listTargets();
      setTargets(data);
      setError(null);
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    refresh();
  }, [refresh]);

  const onSubmit = async (ev) => {
    ev.preventDefault();
    setCreating(true);
    setFormError(null);
    try {
      const t = await createTarget({
        domain: domain.trim(),
        base_url: baseUrl.trim(),
        owner_note: ownerNote.trim(),
      });
      navigate(`/targets/${t.id}/consent`);
    } catch (e) {
      setFormError(e.message);
      setCreating(false);
    }
  };

  const onStartScan = async (id) => {
    try {
      const res = await startScan(id);
      navigate(`/scans/${res.scan_id}`);
    } catch (e) {
      if (e instanceof ApiError && e.code === "consent_not_confirmed") {
        navigate(`/targets/${id}/consent`);
      } else {
        alert(e.message);
      }
    }
  };

  return (
    <div>
      <h1>Targets</h1>

      {error && <div className="error-banner">{error}</div>}

      <div className="card">
        <h2>Add target</h2>
        <form onSubmit={onSubmit}>
          <div className="form-grid">
            <div className="field">
              <label>Domain</label>
              <input
                value={domain}
                onChange={(e) => setDomain(e.target.value)}
                placeholder="juice-shop.local"
                required
              />
            </div>
            <div className="field">
              <label>Base URL</label>
              <input
                value={baseUrl}
                onChange={(e) => setBaseUrl(e.target.value)}
                placeholder="http://127.0.0.1:8011"
                required
              />
            </div>
            <div className="field" style={{ gridColumn: "1 / -1" }}>
              <label>Owner note (optional)</label>
              <input
                value={ownerNote}
                onChange={(e) => setOwnerNote(e.target.value)}
                placeholder="Who owns this and what is it for?"
              />
            </div>
          </div>
          {formError && <div className="error-banner">{formError}</div>}
          <div style={{ marginTop: 14 }}>
            <button type="submit" disabled={creating}>
              {creating ? "Registering…" : "Add target"}
            </button>
          </div>
        </form>
      </div>

      <h2>Consent and scans</h2>
      {loading ? (
        <div className="loading">Loading…</div>
      ) : targets.length === 0 ? (
        <div className="empty">No targets registered yet.</div>
      ) : (
        <div className="card">
          <table>
            <thead>
              <tr>
                <th>Domain</th>
                <th>Base URL</th>
                <th>Consent</th>
                <th>Added</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {targets.map((t) => (
                <tr key={t.id}>
                  <td>
                    <a href={`#/targets/${t.id}/consent`} onClick={(e) => { e.preventDefault(); navigate(`/targets/${t.id}/consent`); }}>
                      {t.domain}
                    </a>
                  </td>
                  <td className="mono">{t.base_url}</td>
                  <td>
                    {t.consent_confirmed_at ? (
                      <span className="badge consented">Consented</span>
                    ) : (
                      <span className="badge unconsented">Not consented</span>
                    )}
                  </td>
                  <td className="muted">{prettyDate(t.created_at)}</td>
                  <td>
                    <div className="row">
                      <button
                        onClick={() => onStartScan(t.id)}
                        disabled={!t.consent_confirmed_at}
                        title={
                          t.consent_confirmed_at
                            ? "Start a scan"
                            : "Confirm consent before scanning"
                        }
                      >
                        Start Scan
                      </button>
                      {!t.consent_confirmed_at && (
                        <button
                          className="secondary"
                          onClick={() => navigate(`/targets/${t.id}/consent`)}
                        >
                          Confirm Consent
                        </button>
                      )}
                      <button
                        className="ghost"
                        onClick={() => navigate(`/targets/${t.id}/scans`)}
                      >
                        History
                      </button>
                    </div>
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
