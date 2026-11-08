/**
 * Utility functions for timezone-aware time formatting in the SOC UI.
 */

/**
 * Returns the browser's current timezone string formatted as `(UTC±H)` or `(UTC)`.
 */
export function getTimezoneSuffix(date: Date = new Date()): string {
  const offsetMinutes = -date.getTimezoneOffset();
  if (offsetMinutes === 0) {
    return '(UTC)';
  }
  const sign = offsetMinutes >= 0 ? '+' : '-';
  const hours = Math.floor(Math.abs(offsetMinutes) / 60);
  const minutes = Math.abs(offsetMinutes) % 60;
  if (minutes > 0) {
    return `(UTC${sign}${hours}:${minutes.toString().padStart(2, '0')})`;
  }
  return `(UTC${sign}${hours})`;
}

/**
 * Formats a UTC ISO string into the user's local browser time with a timezone suffix.
 * Example: "2026-11-04 14:57:32 (UTC+3)"
 */
export function formatLocalTime(
  isoString: string | null | undefined,
  includeSeconds: boolean = true
): string {
  if (!isoString) {
    return '—';
  }

  const date = new Date(isoString);
  if (isNaN(date.getTime())) {
    return 'Invalid Date';
  }

  const pad = (n: number) => n.toString().padStart(2, '0');
  const year = date.getFullYear();
  const month = pad(date.getMonth() + 1);
  const day = pad(date.getDate());
  const hours = pad(date.getHours());
  const minutes = pad(date.getMinutes());
  const seconds = pad(date.getSeconds());
  const tz = getTimezoneSuffix(date);

  if (includeSeconds) {
    return `${year}-${month}-${day} ${hours}:${minutes}:${seconds} ${tz}`;
  }
  return `${year}-${month}-${day} ${hours}:${minutes} ${tz}`;
}

/**
 * Formats just the time portion with timezone suffix (e.g., "14:57 (UTC+3)").
 */
export function formatTimeOnly(isoString: string | null | undefined): string {
  if (!isoString) {
    return '—';
  }

  const date = new Date(isoString);
  if (isNaN(date.getTime())) {
    return 'Invalid Date';
  }

  const pad = (n: number) => n.toString().padStart(2, '0');
  const hours = pad(date.getHours());
  const minutes = pad(date.getMinutes());
  const tz = getTimezoneSuffix(date);

  return `${hours}:${minutes} ${tz}`;
}
