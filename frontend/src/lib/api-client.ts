/**
 * Thin fetch wrapper for the Insyte API. Every request goes through here
 * so error handling, the base URL, and JSON parsing are consistent across
 * the app - no route calls `fetch()` directly.
 */

const API_URL = import.meta.env.VITE_API_URL ?? "http://localhost:8000";

const TOKEN_STORAGE_KEY = "insyte.auth.token";

/** Module-level auth token, kept in sync with localStorage so the fetch
 * wrapper can attach it without threading React state through every call. */
let authToken: string | null = null;
let unauthorizedHandler: (() => void) | null = null;

export function getAuthToken(): string | null {
  if (authToken) return authToken;
  if (typeof localStorage !== "undefined") {
    try {
      authToken = localStorage.getItem(TOKEN_STORAGE_KEY);
    } catch {
      authToken = null;
    }
  }
  return authToken;
}

export function setAuthToken(token: string | null): void {
  authToken = token;
  if (typeof localStorage === "undefined") return;
  try {
    if (token) localStorage.setItem(TOKEN_STORAGE_KEY, token);
    else localStorage.removeItem(TOKEN_STORAGE_KEY);
  } catch {
    // Private-mode / disabled storage: the in-memory token still works for
    // the current session.
  }
}

/** Registered by the auth provider so a 401 anywhere logs the user out. */
export function setUnauthorizedHandler(handler: (() => void) | null): void {
  unauthorizedHandler = handler;
}

function authHeaders(): Record<string, string> {
  const token = getAuthToken();
  return token ? { Authorization: `Bearer ${token}` } : {};
}

export class ApiError extends Error {
  status: number;
  requestId?: string;
  detail?: unknown;

  constructor(status: number, message: string, requestId?: string, detail?: unknown) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.requestId = requestId;
    this.detail = detail;
  }
}

type RequestOptions = {
  method?: "GET" | "POST" | "PUT" | "DELETE";
  body?: unknown;
  params?: Record<string, string | number | boolean | undefined | null>;
};

function buildUrl(path: string, params?: RequestOptions["params"]): string {
  const url = new URL(`${API_URL}${path}`);
  if (params) {
    for (const [key, value] of Object.entries(params)) {
      if (value !== undefined && value !== null && value !== "") {
        url.searchParams.set(key, String(value));
      }
    }
  }
  return url.toString();
}

export async function apiFetch<T>(path: string, options: RequestOptions = {}): Promise<T> {
  const response = await fetch(buildUrl(path, options.params), {
    method: options.method ?? "GET",
    headers: {
      ...(options.body ? { "Content-Type": "application/json" } : {}),
      ...authHeaders(),
    },
    body: options.body ? JSON.stringify(options.body) : undefined,
  });

  if (response.status === 401) {
    unauthorizedHandler?.();
  }

  if (!response.ok) {
    let payload: { error?: string; request_id?: string; detail?: unknown } = {};
    try {
      payload = await response.json();
    } catch {
      // A non-JSON error body (e.g. an upstream proxy's HTML page) still
      // needs to surface as a readable ApiError rather than a raw parse
      // failure.
    }
    throw new ApiError(
      response.status,
      payload.error ?? `Request failed with status ${response.status}`,
      payload.request_id,
      payload.detail,
    );
  }

  if (response.status === 204) return undefined as T;
  return response.json() as Promise<T>;
}

/** For file downloads (PDF/MD/JSON reports) - returns the blob and the
 * filename the server suggested via Content-Disposition. */
export async function apiDownload(
  path: string,
): Promise<{ blob: Blob; filename: string }> {
  const response = await fetch(buildUrl(path), { headers: authHeaders() });
  if (response.status === 401) {
    unauthorizedHandler?.();
  }
  if (!response.ok) {
    throw new ApiError(response.status, `Download failed with status ${response.status}`);
  }
  const disposition = response.headers.get("content-disposition") ?? "";
  const match = disposition.match(/filename="?([^";]+)"?/);
  const filename = match?.[1] ?? "insyte-report";
  const blob = await response.blob();
  return { blob, filename };
}

export { API_URL };
