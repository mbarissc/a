const API_URL = "http://127.0.0.1:8000";

export async function getCompanies() {
  const res = await fetch(`${API_URL}/companies`);
  return res.json();
}

export async function getVulnsByCompany(companyName) {
  const res = await fetch(`${API_URL}/companies/${encodeURIComponent(companyName)}/vulns`);
  return res.json();
}

export async function updateVuln(vulnId, status) {
  const res = await fetch(`${API_URL}/vulns/${vulnId}?status=${status}`, {
    method: "PUT",
  });
  return res.json();
}

export async function setVulnAction(vulnId, action) {
  const res = await fetch(`${API_URL}/vulns/${vulnId}/action?action=${encodeURIComponent(action)}`, {
    method: "PUT",
  });
  return res.json();
}

export async function setVulnScore(vulnId, score) {
  const res = await fetch(`${API_URL}/vulns/${vulnId}/score?score=${score}`, {
    method: "PUT",
  });
  return res.json();
}

export async function getVulnHistory(vulnId) {
  const res = await fetch(`${API_URL}/vulns/${vulnId}/history`);
  return res.json();
}