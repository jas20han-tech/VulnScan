// Thin fetch wrappers around the VulnScan API, one function per contract
// endpoint in Documents/04-api-contract.md. All calls go through /api, which
// Vite proxies (rewriting /api/* -> /*) to the backend on :8000 during dev.

const BASE = "/api";

export class ApiError extends Error {
  constructor(status, code, message) {
    super(message || code);
    this.status = status;
    this.code = code;
  }
}

async function request(path, { method = "GET", body } = {}) {
  let res;
  try {
    res = await fetch(`${BASE}${path}`, {
      method,
      headers: body ? { "Content-Type": "application/json" } : undefined,
      body: body ? JSON.stringify(body) : undefined,
    });
  } catch (e) {
    throw new ApiError(0, "network_error", "Cannot reach the VulnScan backend.");
  }

  if (res.status === 204) return null;

  const contentType = res.headers.get("content-type") || "";
  if (contentType.includes("application/json")) {
    const data = await res.json();
    if (!res.ok) {
      // Backend error shape: { "error": code, "message": msg }
      throw new ApiError(res.status, data.error || "unknown", data.message || res.statusText);
    }
    return data;
  }

  if (!res.ok) {
    throw new ApiError(res.status, String(res.status), res.statusText);
  }
  // Non-JSON (e.g. a PDF blob). Return the raw response for the caller.
  return res;
}

// --- Targets & consent -----------------------------------------------------

export function createTarget({ domain, base_url, owner_note }) {
  return request("/targets", { method: "POST", body: { domain, base_url, owner_note } });
}

export function listTargets() {
  return request("/targets");
}

export function getTarget(id) {
  return request(`/targets/${id}`);
}

export function getConsentPhrase(id) {
  return request(`/targets/${id}/consent/phrase`);
}

export function confirmConsent(id, typed_phrase) {
  return request(`/targets/${id}/consent`, { method: "POST", body: { typed_phrase } });
}

export function startScan(id) {
  return request(`/targets/${id}/scans`, { method: "POST" });
}

export function listTargetScans(id) {
  return request(`/targets/${id}/scans`);
}

// --- Scans -----------------------------------------------------------------

export function getScan(id) {
  return request(`/scans/${id}`);
}

export function compareScans(oldId, newId) {
  return request(`/scans/${oldId}/compare/${newId}`);
}

export function reportUrl(scanId) {
  return `${BASE}/scans/${scanId}/report`;
}

// --- Findings --------------------------------------------------------------

export function listFindings(scanId) {
  return request(`/scans/${scanId}/findings`);
}

export function getFindingDetail(id) {
  return request(`/findings/${id}`);
}

export function getFix(id) {
  return request(`/findings/${id}/fix`);
}

export function generateFix(id) {
  return request(`/findings/${id}/fix`, { method: "POST" });
}
