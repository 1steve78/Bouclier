const configuredBaseUrl = process.env.NEXT_PUBLIC_API_BASE_URL?.trim();

export function getApiBaseUrl(): string | null {
  return configuredBaseUrl ? configuredBaseUrl.replace(/\/+$/, "") : null;
}

export async function apiRequest<T>(
  path: string,
  init?: RequestInit,
): Promise<T> {
  const baseUrl = getApiBaseUrl();
  if (!baseUrl) {
    throw new Error("The Bouclier API is not configured. Mock data is active.");
  }
  const response = await fetch(`${baseUrl}${path}`, {
    ...init,
    headers: {
      "Content-Type": "application/json",
      ...init?.headers,
    },
  });
  if (!response.ok) {
    throw new Error(`API request failed (${response.status}).`);
  }
  return (await response.json()) as T;
}
