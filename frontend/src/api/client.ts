const API_BASE_URL = "http://localhost:5048";

export interface LoginResponse {
  token: string;
  expiresAt: string;
}

export interface AnalysisResponse {
  result: string;
  reportId: number;
  severity: string;
}

export interface AuditReport {
  id: number;
  username: string;
  sourceFileName: string;
  analyzedContent: string;
  result: string;
  severity: string;
  createdAt: string;
}

export class ApiError extends Error {
  status: number;
  constructor(message: string, status: number) {
    super(message);
    this.status = status;
  }
}

async function handleResponse<T>(response: Response): Promise<T> {
  if (!response.ok) {
    let message = `Error ${response.status}`;
    try {
      const body = await response.json();
      message = body.message ?? message;
    } catch {
      // sin body JSON, usamos el mensaje genérico
    }
    throw new ApiError(message, response.status);
  }
  return response.json() as Promise<T>;
}

export async function login(username: string, password: string): Promise<LoginResponse> {
  const response = await fetch(`${API_BASE_URL}/api/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password }),
  });
  return handleResponse<LoginResponse>(response);
}

export async function analyzeText(token: string, content: string): Promise<AnalysisResponse> {
  const response = await fetch(`${API_BASE_URL}/api/agent/analyze`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${token}`,
    },
    body: JSON.stringify({ content }),
  });
  return handleResponse<AnalysisResponse>(response);
}

export async function analyzeFile(token: string, file: File): Promise<AnalysisResponse> {
  const formData = new FormData();
  formData.append("file", file);

  const response = await fetch(`${API_BASE_URL}/api/agent/analyze-file`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${token}`,
    },
    body: formData,
  });
  return handleResponse<AnalysisResponse>(response);
}

export async function getReports(token: string): Promise<AuditReport[]> {
  const response = await fetch(`${API_BASE_URL}/api/agent/reports`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  return handleResponse<AuditReport[]>(response);
}
