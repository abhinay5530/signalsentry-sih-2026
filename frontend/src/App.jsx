import { Route, Routes } from "react-router-dom";
import Shell from "./layout/Shell.jsx";
import CommandCenter from "./pages/CommandCenter.jsx";
import IpdrExplorer from "./pages/IpdrExplorer.jsx";
import AttackExplorer from "./pages/AttackExplorer.jsx";
import PcapAnalyzer from "./pages/PcapAnalyzer.jsx";
import IncidentDetails from "./pages/IncidentDetails.jsx";
import IpInvestigate from "./pages/IpInvestigate.jsx";
import Reports from "./pages/Reports.jsx";

export default function App() {
  return (
    <Routes>
      <Route element={<Shell />}>
        <Route path="/" element={<CommandCenter />} />
        <Route path="/ipdr" element={<IpdrExplorer />} />
        <Route path="/attacks" element={<AttackExplorer />} />
        <Route path="/pcap" element={<PcapAnalyzer />} />
        <Route path="/event/:id" element={<IncidentDetails />} />
        <Route path="/investigate" element={<IpInvestigate />} />
        <Route path="/reports" element={<Reports />} />
      </Route>
    </Routes>
  );
}
