/*
 * Display formatting shared by server and client components.
 *
 * Times are shown in UTC: the server (UTC on Vercel) and the browser
 * render the same text, and SOC teams usually compare events in UTC.
 */

const numberFormat = new Intl.NumberFormat("en-US");

export function formatNumber(value: number): string {
  return numberFormat.format(value);
}

const dateTimeFormat = new Intl.DateTimeFormat("en-GB", {
  year: "numeric",
  month: "short",
  day: "2-digit",
  hour: "2-digit",
  minute: "2-digit",
  timeZone: "UTC",
});

/** e.g. "10 Jul 2026, 14:03 UTC"; "—" for missing or invalid input. */
export function formatDateTime(iso: string | null | undefined): string {
  if (!iso) return "—";
  const date = new Date(iso);
  return Number.isNaN(date.getTime()) ? "—" : `${dateTimeFormat.format(date)} UTC`;
}
