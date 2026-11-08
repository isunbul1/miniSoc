import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { SOCLayout } from './layouts/SOCLayout';
import { DashboardPage } from './pages/DashboardPage';
import { LogsPage } from './pages/LogsPage';
import { AlertsPage } from './pages/AlertsPage';
import { MitrePlaceholderPage } from './pages/MitrePlaceholderPage';
import { ReportsPlaceholderPage } from './pages/ReportsPlaceholderPage';

function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route element={<SOCLayout />}>
          <Route path="/" element={<DashboardPage />} />
          <Route path="/logs" element={<LogsPage />} />
          <Route path="/alerts" element={<AlertsPage />} />
          <Route path="/mitre" element={<MitrePlaceholderPage />} />
          <Route path="/reports" element={<ReportsPlaceholderPage />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Route>
      </Routes>
    </BrowserRouter>
  );
}

export default App;
