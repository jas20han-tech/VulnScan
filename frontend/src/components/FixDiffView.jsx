export default function FixDiffView({ diff, explanation, modelUsed }) {
  return (
    <div style={{ marginTop: 12 }}>
      <div className="row between" style={{ marginBottom: 6 }}>
        <strong style={{ fontSize: 14 }}>Suggested fix</strong>
        {modelUsed && <span className="muted">via {modelUsed}</span>}
      </div>
      <div className="diff">{diff}</div>
      {explanation && (
        <p className="muted" style={{ marginTop: 8 }}>
          {explanation}
        </p>
      )}
    </div>
  );
}
