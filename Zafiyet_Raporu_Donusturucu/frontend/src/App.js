import React, { useState, useEffect } from "react";
import { getHosts, getVulns, updateVuln } from "./services/api";

function App() {
  const [hosts, setHosts] = useState([]);
  const [vulns, setVulns] = useState([]);
  const [selectedHost, setSelectedHost] = useState(null);

  useEffect(() => {
    getHosts().then(setHosts);
  }, []);

  const handleHostClick = (id) => {
    setSelectedHost(id);
    getVulns(id).then(setVulns);
  };

  const handleUpdate = (id, newStatus) => {
    updateVuln(id, newStatus).then((v) => {
      setVulns(vulns.map((x) => (x.id === v.id ? v : x)));
    });
  };

  return (
    <div style={{ padding: "20px" }}>
      <h1>Nessus Hosts</h1>
      <ul>
        {hosts.map((h) => (
          <li
            key={h.id}
            onClick={() => handleHostClick(h.id)}
            style={{ cursor: "pointer" }}
          >
            {h.hostname || h.ip} ({h.company})
          </li>
        ))}
      </ul>

      {selectedHost && (
        <div>
          <h2>Vulnerabilities</h2>
          <ul>
            {vulns.map((v) => (
              <li key={v.id}>
                {v.name} | {v.risk} | {v.status}
                <button onClick={() => handleUpdate(v.id, "closed")}>
                  Close
                </button>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}

export default App;
