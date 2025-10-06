import React, { useState, useEffect, useCallback } from "react";
import { getCompanies, getVulnsByCompany, updateVuln, setVulnAction, getVulnHistory, setVulnScore } from "./services/api";

function App() {
  const [companies, setCompanies] = useState([]);
  const [vulns, setVulns] = useState([]);
  const [selectedCompany, setSelectedCompany] = useState(null);
  const [vulnHistories, setVulnHistories] = useState({});
  const [companyScore, setCompanyScore] = useState(0);

  // --------------------------------------------------------
  // Helper fonksiyonu: Zafiyet geçmişini istenen formata dönüştürür
  // --------------------------------------------------------
  const getStatusHistoryString = useCallback((history) => {
    const endOfMonths = [];
    const today = new Date();

    for (let i = 5; i >= 0; i--) {
      const d = new Date(today.getFullYear(), today.getMonth() - i + 1, 0);
      endOfMonths.push(d);
    }

    const monthlyStatuses = [];

    for (const monthEnd of endOfMonths) {
      let statusForMonth = 'N/A';

      for (let j = history.length - 1; j >= 0; j--) {
        const entry = history[j];
        const entryDate = new Date(entry.date);

        if (entryDate <= monthEnd) {
          statusForMonth = (entry.status === 'reopened' || entry.status === 'open') ? 'open' : entry.status;
          break;
        }
      }
      monthlyStatuses.push(statusForMonth);
    }
    return monthlyStatuses.join(' ');
  }, []);

  // --------------------------------------------------------
  // Veri Çekme ve Puan Hesaplama Fonksiyonu
  // --------------------------------------------------------
  const fetchAndSetData = useCallback(async (companyName) => {
    const freshVulns = await getVulnsByCompany(companyName);

    const historyPromises = freshVulns.map(v => getVulnHistory(v.id).catch(() => []));
    const allHistories = await Promise.all(historyPromises);

    const newVulnHistories = {};
    freshVulns.forEach((v, index) => {
      newVulnHistories[v.id] = allHistories[index];
    });

    // Şirket puan ortalamasını hesapla
    const openVulns = freshVulns.filter(v => v.status === 'open' && v.score > 0);
    const totalScore = openVulns.reduce((acc, v) => acc + v.score, 0);
    const avgScore = openVulns.length > 0 ? (totalScore / openVulns.length).toFixed(2) : 0;

    setCompanyScore(avgScore);
    setVulns(freshVulns);
    setVulnHistories(newVulnHistories);
  }, []);

  // --------------------------------------------------------
  // useEffect: Başlangıçta şirketleri yükle
  // --------------------------------------------------------
  useEffect(() => {
    getCompanies().then(setCompanies).catch(err => {
      console.error("Şirketler çekilemedi:", err);
    });
  }, []);

  // --------------------------------------------------------
  // Olay İşleyiciler
  // --------------------------------------------------------
  const handleCompanyClick = (companyName) => {
    setSelectedCompany(companyName);
    fetchAndSetData(companyName);
  };

  const handleSetAction = (id, currentAction) => {
    const action = prompt(`Zafiyet ID ${id} için aksiyon girin:`, currentAction);
    if (action === null) return;
    setVulnAction(id, action.trim()).then(() => fetchAndSetData(selectedCompany));
  };

  const handleSetScore = (id, currentScore) => {
    const score = prompt(`Zafiyet ID ${id} için puan girin (0-10):`, currentScore);
    if (score === null || isNaN(parseInt(score, 10))) return;
    setVulnScore(id, parseInt(score, 10)).then(() => fetchAndSetData(selectedCompany));
  };

  // --------------------------------------------------------
  // JSX Render
  // --------------------------------------------------------
  return (
    <div style={{ padding: "20px" }}>
      <h1>Nessus Zafiyet Yönetimi</h1>
      <div style={{ display: "flex" }}>
        <div style={{ flex: 1, marginRight: "20px" }}>
          <h2>Şirketler</h2>
          <ul style={{ listStyleType: 'none', paddingLeft: 0 }}>
            {companies.map((c) => (
              <li
                key={c}
                onClick={() => handleCompanyClick(c)}
                style={{
                  cursor: "pointer",
                  padding: "8px",
                  backgroundColor: c === selectedCompany ? '#e0e0e0' : 'transparent',
                  borderBottom: '1px solid #ddd',
                  marginBottom: '2px',
                  borderRadius: '4px'
                }}
              >
                {c}
              </li>
            ))}
          </ul>
        </div>

        {selectedCompany && (
          <div style={{ flex: 3 }}>
            <h2>
              Zafiyetler: {selectedCompany} | Ortalama Puan: <span style={{ color: 'blue' }}>{companyScore}</span>
            </h2>
            <ul style={{ listStyleType: 'none', paddingLeft: 0 }}>
              {vulns.map((v) => {
                const history = vulnHistories[v.id] || [];
                const historyString = getStatusHistoryString(history);

                return (
                  <li key={v.id} style={{ borderBottom: '1px solid #eee', padding: '10px 0' }}>
                    <strong>{v.name}</strong> (Host ID: {v.host_id}) | Risk: {v.risk} | Puan: <strong>{v.score}</strong>
                    <br />
                    <span style={{ fontSize: '0.9em', color: '#555' }}>
                      <strong>Son 6 Ay Durumları:</strong> {historyString}
                    </span>
                    <br />
                    <span>
                      Status: <span style={{ fontWeight: 'bold', color: v.status === 'open' ? 'red' : 'green' }}>{v.status}</span> | Action: {v.action}
                    </span>
                    <div>
                      <button onClick={() => handleSetAction(v.id, v.action)} style={{ marginLeft: "0px", marginTop: "5px" }}>
                        Set Action
                      </button>
                      <button onClick={() => handleSetScore(v.id, v.score)} style={{ marginLeft: "10px", marginTop: "5px" }}>
                        Set Score
                      </button>
                    </div>
                  </li>
                );
              })}
            </ul>
          </div>
        )}
      </div>
    </div>
  );
}

export default App;