import React, { useState, useEffect, useCallback } from "react";
import { getCompanies, getVulnsByCompany, updateVuln, setVulnAction, getVulnHistory } from "./services/api";

function App() {
  const [companies, setCompanies] = useState([]); // Hostlar yerine şirket listesi
  const [vulns, setVulns] = useState([]);
  const [selectedCompany, setSelectedCompany] = useState(null); // Host ID yerine şirket adı
  const [vulnHistories, setVulnHistories] = useState({});

  // --------------------------------------------------------
  // Helper fonksiyonu: Zafiyet geçmişini istenen formata dönüştürür
  // --------------------------------------------------------
  const getStatusHistoryString = useCallback((history) => {
    const endOfMonths = [];
    const today = new Date();

    // Son 6 ayın son günlerini hesapla (i=0 bu ayın sonu, i=5 ise 5 ay öncesi)
    for (let i = 5; i >= 0; i--) {
        // new Date(yıl, ay, 0) o ayın son gününü verir
        const d = new Date(today.getFullYear(), today.getMonth() - i + 1, 0);
        endOfMonths.push(d);
    }

    const monthlyStatuses = [];

    // Her ay için o ayın sonundaki (veya şimdiki) durumu belirle
    for (const monthEnd of endOfMonths) {
        let statusForMonth = 'N/A'; // Bilinmiyor

        // Bu ayın sonundan önce gerçekleşen son durumu bul
        for (let j = history.length - 1; j >= 0; j--) {
            const entry = history[j];
            const entryDate = new Date(entry.date);

            if (entryDate <= monthEnd) {
                // 'reopened' durumunu 'open' olarak ele al
                statusForMonth = (entry.status === 'reopened' || entry.status === 'open') ? 'open' : entry.status;
                break;
            }
        }

        monthlyStatuses.push(statusForMonth);
    }

    // Dizi elemanlarını boşlukla birleştirerek döndür
    return monthlyStatuses.join(' ');
  }, []);

  // --------------------------------------------------------
  // Veri Çekme Fonksiyonu
  // --------------------------------------------------------
  const fetchAndSetVulns = useCallback(async (companyName) => {
    const freshVulns = await getVulnsByCompany(companyName);

    // Tüm zafiyetlerin geçmişini paralel olarak çek
    const historyPromises = freshVulns.map(v => getVulnHistory(v.id).catch(err => {
        console.error(`Error fetching history for vuln ${v.id}:`, err);
        return [];
    }));

    const allHistories = await Promise.all(historyPromises);

    const newVulnHistories = {};
    freshVulns.forEach((v, index) => {
        newVulnHistories[v.id] = allHistories[index];
    });

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
    fetchAndSetVulns(companyName);
  };

  const handleUpdateStatus = (id, newStatus) => {
    updateVuln(id, newStatus).then((v) => {
      // Durum güncellendiğinde zafiyet listesini ve geçmişini yeniden çek
      fetchAndSetVulns(selectedCompany);
    }).catch(error => {
      console.error("Error updating status:", error);
      alert("Durum güncellemesi başarısız oldu.");
    });
  };

  const handleSetAction = (id, currentAction) => {
    const action = prompt(`Zafiyet ID ${id} için aksiyon girin:`, currentAction);

    if (action === null) return;

    setVulnAction(id, action.trim()).then((v) => {
      // Aksiyon güncellendiğinde zafiyet listesini ve geçmişini yeniden çek
      fetchAndSetVulns(selectedCompany);
    }).catch(error => {
      console.error("Error setting action:", error);
      alert("Aksiyon atama başarısız oldu.");
    });
  };

  // --------------------------------------------------------
  // JSX Render
  // --------------------------------------------------------
  return (
    <div style={{ padding: "20px" }}>
      <h1>Nessus Zafiyet Yönetimi</h1>

      <div style={{ display: "flex" }}>
        {/* Şirket Listesi */}
        <div style={{ flex: 1, marginRight: "20px" }}>
          <h2>Şirketler</h2>
          <ul style={{ listStyleType: 'none', paddingLeft: 0 }}>
            {companies.map((c) => (
              <li
                key={c}
                onClick={() => handleCompanyClick(c)}
                style={{
                    cursor: "pointer",
                    padding: "5px",
                    backgroundColor: c === selectedCompany ? '#f0f0f0' : 'transparent',
                    borderBottom: '1px dotted #eee'
                }}
              >
                {c}
              </li>
            ))}
          </ul>
        </div>

        {/* Zafiyet Listesi */}
        {selectedCompany && (
          <div style={{ flex: 2 }}>
            <h2>Zafiyetler (Şirket: {selectedCompany})</h2>
            <ul style={{ listStyleType: 'none', paddingLeft: 0 }}>
              {vulns.map((v) => {
                const history = vulnHistories[v.id] || [];
                const historyString = getStatusHistoryString(history);

                return (
                  <li key={v.id} style={{ borderBottom: '1px solid #eee', padding: '10px 0' }}>
                    <strong>{v.name}</strong> (Host ID: {v.host_id}) | Risk: {v.risk}
                    <br />
                    <span>
                      **Son 6 Ay Durumları**: {historyString}
                    </span>
                    <br />
                    <span>
                      Status: <span style={{ fontWeight: 'bold', color: v.status === 'open' ? 'red' : 'green' }}>{v.status}</span> | Action: {v.action}
                    </span>
                    <div>
                      <button onClick={() => handleUpdateStatus(v.id, "closed")} style={{ marginLeft: "0px", marginTop: "5px" }}>
                        Close
                      </button>
                      <button onClick={() => handleSetAction(v.id, v.action)} style={{ marginLeft: "10px", marginTop: "5px" }}>
                        Set Action
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