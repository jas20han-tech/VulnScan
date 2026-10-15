const SEV_LABEL = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
};

export default function SeverityBadge({ severity }) {
  const cls = SEV_LABEL[severity] ? severity : "info";
  return (
    <span className={`sev ${cls}`} title={severity}>
      <span className="sev-dot" />
      {(SEV_LABEL[severity] || severity).toUpperCase()}
    </span>
  );
}
