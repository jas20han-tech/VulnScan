import { Routes, Route, NavLink } from "react-router-dom";
import TargetsList from "./pages/TargetsList.jsx";
import ConsentGate from "./pages/ConsentGate.jsx";
import ScanProgress from "./pages/ScanProgress.jsx";
import FindingsDashboard from "./pages/FindingsDashboard.jsx";
import ScanHistory from "./pages/ScanHistory.jsx";

export default function App() {
  return (
    <div className="app">
      <header className="topbar">
        <div className="brand">
          VulnScan
          <small>authorized-targets-only web app scanner</small>
        </div>
        <nav className="nav">
          <NavLink to="/" end>
            Targets
          </NavLink>
        </nav>
      </header>

      <Routes>
        <Route path="/" element={<TargetsList />} />
        <Route path="/targets/:id/consent" element={<ConsentGate />} />
        <Route path="/targets/:id/scans" element={<ScanHistory />} />
        <Route path="/scans/:id" element={<ScanProgress />} />
        <Route path="/scans/:id/findings" element={<FindingsDashboard />} />
        <Route path="*" element={<TargetsList />} />
      </Routes>
    </div>
  );
}
