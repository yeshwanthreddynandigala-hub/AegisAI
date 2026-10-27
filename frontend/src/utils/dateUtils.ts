/**
 * Unified Date and Timestamp Utilities for AegisAI.
 * 
 * Strict Convention:
 * - All backend telemetry and database records are in UTC.
 * - All API timestamps are serialized with explicit 'Z' UTC indicator.
 * - This module guarantees UTC parsing even if legacy strings lack 'Z'.
 * - Displays in user's browser local time with clear local format.
 * - Explicitly distinguishes historical synthetic demo/benchmark events from live session events.
 */

/**
 * Safely parses any date string into a Date object, strictly treating it as UTC.
 */
export function parseUtcDate(input: string | Date | null | undefined): Date {
  if (!input) return new Date();
  if (input instanceof Date) return input;

  let s = String(input).trim();
  if (!s) return new Date();

  // If already has timezone offset or 'Z', parse directly
  if (s.endsWith('Z') || /[+-]\d{2}:?\d{2}$/.test(s)) {
    return new Date(s);
  }

  // Handle standard ISO without 'Z': "2026-10-27T14:07:46.123456" -> append 'Z'
  if (s.includes('T')) {
    return new Date(`${s}Z`);
  }

  // Handle SQLite / space-separated strings: "2026-10-27 14:07:46" or "2026-10-27 14:07:46.123456"
  if (/^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}/.test(s)) {
    return new Date(`${s.replace(' ', 'T')}Z`);
  }

  // Fallback
  return new Date(s);
}

/**
 * Formats a timestamp into a consistent local date-and-time string.
 * Example: "Oct 27, 2026, 7:37:46 PM"
 */
export function formatLocalDateTime(input: string | Date | null | undefined): string {
  if (!input) return 'N/A';
  const d = parseUtcDate(input);
  if (isNaN(d.getTime())) return 'Invalid Date';

  return new Intl.DateTimeFormat(undefined, {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: 'numeric',
    minute: '2-digit',
    second: '2-digit',
    hour12: true
  }).format(d);
}

/**
 * Formats a timestamp into local time of day only.
 * Example: "7:37:46 PM"
 */
export function formatLocalTime(input: string | Date | null | undefined): string {
  if (!input) return 'N/A';
  const d = parseUtcDate(input);
  if (isNaN(d.getTime())) return 'Invalid Date';

  return new Intl.DateTimeFormat(undefined, {
    hour: 'numeric',
    minute: '2-digit',
    second: '2-digit',
    hour12: true
  }).format(d);
}

/**
 * Formats a timestamp into local date only.
 * Example: "Oct 27, 2026"
 */
export function formatLocalDate(input: string | Date | null | undefined): string {
  if (!input) return 'N/A';
  const d = parseUtcDate(input);
  if (isNaN(d.getTime())) return 'Invalid Date';

  return new Intl.DateTimeFormat(undefined, {
    year: 'numeric',
    month: 'short',
    day: 'numeric'
  }).format(d);
}

/**
 * Formats a timestamp into an explicit, unambiguous UTC string.
 * Example: "2026-10-27 14:07:46 UTC"
 */
export function formatUtcDateTime(input: string | Date | null | undefined): string {
  if (!input) return 'N/A';
  const d = parseUtcDate(input);
  if (isNaN(d.getTime())) return 'Invalid Date';

  const pad = (n: number) => String(n).padStart(2, '0');
  const year = d.getUTCFullYear();
  const month = pad(d.getUTCMonth() + 1);
  const day = pad(d.getUTCDate());
  const hours = pad(d.getUTCHours());
  const minutes = pad(d.getUTCMinutes());
  const seconds = pad(d.getUTCSeconds());

  return `${year}-${month}-${day} ${hours}:${minutes}:${seconds} UTC`;
}

/**
 * Determines whether an event is a historical synthetic demo event.
 * Historical demo events:
 * 1. Originate from initial benchmark runs (sessionId starting with 'bench_')
 * 2. Or have timestamps older than 24 hours prior to current time.
 */
export function isHistoricalDemoEvent(
  input: string | Date | null | undefined,
  sessionId?: string,
  taskId?: string
): boolean {
  if (sessionId && sessionId.startsWith('bench_')) return true;
  if (taskId && taskId.startsWith('bench_task_')) return true;

  if (!input) return false;
  const d = parseUtcDate(input);
  if (isNaN(d.getTime())) return false;

  const now = new Date();
  const diffHours = (now.getTime() - d.getTime()) / (1000 * 60 * 60);
  return diffHours > 24;
}
