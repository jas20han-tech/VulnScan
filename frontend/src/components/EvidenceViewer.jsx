// Renders raw evidence per module type:
//  - sqli:    boolean/time-based lenth diff, sample request/response
//  - xss:     canary token that fired + optional base64 screenshot
//  - auth:    cookie flag checks and session observations
//  - secrets: secret type + redacted match locations
//  - headers: missing/weak header list
export function renderEvidence(module, evidence = {}) {
  switch (module) {
    case "sqli":
      return (
        <>
          <p className="muted">
            {evidence.technique || "?"}-based injection · TRUE payload returned{" "}
            <b>{evidence.true_len ?? "?"}</b> bytes vs FALSE{" "}
            <b>{evidence.false_len ?? "?"}</b> bytes
          </p>
          {evidence.true_response && (
            <div className="evidence-block">{evidence.true_response}</div>
          )}
          {evidence.false_response && (
            <div className="evidence-block">{evidence.false_response}</div>
          )}
        </>
      );
    case "xss":
      return (
        <>
          <p className="muted">
            <b>{evidence.type || "reflected"}</b> XSS · canary token{" "}
            <span className="mono">{evidence.token}</span> fired (execution
            confirmed)
          </p>
          {evidence.poc && <div className="evidence-block">{evidence.poc}</div>}
          {evidence.screenshot && (
            <div className="evidence-block screenshot">
              <img src={evidence.screenshot} alt="XSS execution screenshot" />
            </div>
          )}
        </>
      );
    case "auth":
      return (
        <ul className="muted" style={{ margin: 0, paddingLeft: 18 }}>
          {evidence.check && (
            <li>
              Check <b>{evidence.check}</b> — {evidence.status}
            </li>
          )}
          {Array.isArray(evidence.cookies) && evidence.cookies.length > 0 && (
            <li>
              Cookie flags:{" "}
              {evidence.cookies
                .map((c) => `${c.name}=${c.flags || "none"}`)
                .join(", ")}
            </li>
          )}
          {evidence.observations && (
            <li>{evidence.observations}</li>
          )}
          {Array.isArray(evidence.issues) &&
            evidence.issues.map((i, idx) => <li key={idx}>{i}</li>)}
        </ul>
      );
    case "secrets":
      return (
        <>
          <p className="muted">
            Exposed <b>{evidence.secret_type || "secret"}</b> at{" "}
            {evidence.locations?.length || 0} location(s)
          </p>
          {(evidence.locations || []).map((loc, idx) => (
            <div key={idx} className="evidence-block">
              <span className="muted">{loc.url}</span>
              {"\n"}
              {loc.match}
            </div>
          ))}
        </>
      );
    case "headers":
      return (
        <>
          <p className="muted">Header check: {evidence.status}</p>
          {Array.isArray(evidence.missing) && evidence.missing.length > 0 && (
            <>
              <div className="muted">Missing headers:</div>
              {evidence.missing.map((h, idx) => (
                <div key={idx} className="evidence-block">{h}</div>
              ))}
            </>
          )}
          {evidence.affected_route_count != null && (
            <p className="muted">
              Affected routes: {evidence.affected_route_count}
            </p>
          )}
        </>
      );
    default:
      return <div className="evidence-block">{JSON.stringify(evidence, null, 2)}</div>;
  }
}
