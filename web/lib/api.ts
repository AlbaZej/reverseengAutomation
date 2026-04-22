const API_BASE = "/api";

function getHeaders(): Record<string, string> {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
  };
  if (typeof window !== "undefined") {
    const token = localStorage.getItem("deshifro_token");
    if (token) {
      headers["Authorization"] = `Bearer ${token}`;
    }
  }
  return headers;
}

// --- Auth ---

export async function register(email: string, password: string, name: string) {
  const res = await fetch(`${API_BASE}/auth/register`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, password, name }),
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.detail || "Registration failed");
  localStorage.setItem("deshifro_token", data.token);
  return data;
}

export async function login(email: string, password: string) {
  const res = await fetch(`${API_BASE}/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, password }),
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.detail || "Login failed");
  localStorage.setItem("deshifro_token", data.token);
  return data;
}

export function logout() {
  localStorage.removeItem("deshifro_token");
}

export function isLoggedIn(): boolean {
  if (typeof window === "undefined") return false;
  return !!localStorage.getItem("deshifro_token");
}

export async function getMe() {
  const res = await fetch(`${API_BASE}/auth/me`, { headers: getHeaders() });
  if (!res.ok) return null;
  return res.json();
}

export async function createApiKey(name: string) {
  const res = await fetch(`${API_BASE}/auth/api-keys`, {
    method: "POST",
    headers: getHeaders(),
    body: JSON.stringify({ name }),
  });
  if (!res.ok) throw new Error("Failed to create API key");
  return res.json();
}

// --- Upload & Analysis ---

export async function uploadFile(file: File) {
  const formData = new FormData();
  formData.append("file", file);

  const headers: Record<string, string> = {};
  const token =
    typeof window !== "undefined"
      ? localStorage.getItem("deshifro_token")
      : null;
  if (token) headers["Authorization"] = `Bearer ${token}`;

  const res = await fetch(`${API_BASE}/upload`, {
    method: "POST",
    headers,
    body: formData,
  });
  if (!res.ok) throw new Error(`Upload failed: ${res.statusText}`);
  return res.json();
}

export async function startAnalysis(uploadId: string, quick: boolean = false) {
  const res = await fetch(`${API_BASE}/analyze`, {
    method: "POST",
    headers: getHeaders(),
    body: JSON.stringify({ upload_id: uploadId, quick }),
  });
  if (!res.ok) throw new Error(`Analysis failed: ${res.statusText}`);
  return res.json();
}

export async function getAnalysis(jobId: string) {
  const res = await fetch(`${API_BASE}/analysis/${jobId}`, {
    headers: getHeaders(),
  });
  if (!res.ok) throw new Error(`Failed to get analysis: ${res.statusText}`);
  return res.json();
}

export function getExportUrl(jobId: string, format: string) {
  return `${API_BASE}/export/${jobId}/${format}`;
}

// --- Samples ---

export async function listSamples(params: {
  page?: number;
  search?: string;
  file_type?: string;
  verdict?: string;
  sort?: string;
} = {}) {
  const query = new URLSearchParams();
  if (params.page) query.set("page", String(params.page));
  if (params.search) query.set("search", params.search);
  if (params.file_type) query.set("file_type", params.file_type);
  if (params.verdict) query.set("verdict", params.verdict);
  if (params.sort) query.set("sort", params.sort);

  const res = await fetch(`${API_BASE}/samples?${query}`, {
    headers: getHeaders(),
  });
  if (!res.ok) throw new Error("Failed to load samples");
  return res.json();
}

export async function getSample(id: string) {
  const res = await fetch(`${API_BASE}/samples/${id}`, {
    headers: getHeaders(),
  });
  if (!res.ok) throw new Error("Failed to load sample");
  return res.json();
}

export async function addAnnotation(uploadId: string, content: string, type: string = "note") {
  const res = await fetch(`${API_BASE}/samples/${uploadId}/annotations`, {
    method: "POST",
    headers: getHeaders(),
    body: JSON.stringify({ content, annotation_type: type }),
  });
  if (!res.ok) throw new Error("Failed to add annotation");
  return res.json();
}

export async function updateTags(uploadId: string, tags: string[]) {
  const res = await fetch(`${API_BASE}/samples/${uploadId}/tags`, {
    method: "PUT",
    headers: getHeaders(),
    body: JSON.stringify({ tags }),
  });
  if (!res.ok) throw new Error("Failed to update tags");
  return res.json();
}

// --- Dashboard ---

export async function getDashboardStats() {
  const res = await fetch(`${API_BASE}/dashboard/stats`, {
    headers: getHeaders(),
  });
  if (!res.ok) throw new Error("Failed to load stats");
  return res.json();
}

// --- AI ---

export async function getAiStatus() {
  const res = await fetch(`${API_BASE}/ai/status`);
  return res.json();
}

export async function aiExplain(jobId: string) {
  const res = await fetch(`${API_BASE}/ai/explain?job_id=${jobId}`, {
    method: "POST",
    headers: getHeaders(),
  });
  if (!res.ok) throw new Error("AI explanation failed");
  return res.json();
}

export async function aiAsk(jobId: string, question: string) {
  const res = await fetch(`${API_BASE}/ai/ask`, {
    method: "POST",
    headers: getHeaders(),
    body: JSON.stringify({ job_id: jobId, question }),
  });
  if (!res.ok) throw new Error("AI query failed");
  return res.json();
}

export async function aiGenerateYara(jobId: string) {
  const res = await fetch(`${API_BASE}/ai/generate-yara?job_id=${jobId}`, {
    method: "POST",
    headers: getHeaders(),
  });
  if (!res.ok) throw new Error("YARA generation failed");
  return res.json();
}

// --- Tools ---

export async function getTools() {
  const res = await fetch(`${API_BASE}/tools`);
  return res.json();
}

export async function diffFiles(uploadId1: string, uploadId2: string) {
  const res = await fetch(`${API_BASE}/diff`, {
    method: "POST",
    headers: getHeaders(),
    body: JSON.stringify({ upload_id_1: uploadId1, upload_id_2: uploadId2 }),
  });
  if (!res.ok) throw new Error("Diff failed");
  return res.json();
}

export async function vtLookup(hash: string) {
  const res = await fetch(`${API_BASE}/vt-lookup`, {
    method: "POST",
    headers: getHeaders(),
    body: JSON.stringify({ hash }),
  });
  if (!res.ok) throw new Error("VT lookup failed");
  return res.json();
}
