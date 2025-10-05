const API_URL = "http://127.0.0.1:8000";

export async function getHosts() {
  const res = await fetch(`${API_URL}/hosts`);
  return res.json();
}

export async function getVulns(hostId) {
  const res = await fetch(`${API_URL}/hosts/${hostId}/vulns`);
  return res.json();
}

export async function updateVuln(vulnId, status) {
  const res = await fetch(`${API_URL}/vulns/${vulnId}?status=${status}`, {
    method: "PUT",
  });
  return res.json();
}
