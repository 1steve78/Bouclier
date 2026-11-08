export function isHttpUrlOrDomain(value: string): boolean {
  if (/\s/.test(value)) return false;
  const candidate = value.includes("://") ? value : `https://${value}`;
  try {
    const url = new URL(candidate);
    return (
      (url.protocol === "http:" || url.protocol === "https:") &&
      url.hostname.length > 0 &&
      !url.username &&
      !url.password
    );
  } catch {
    return false;
  }
}
