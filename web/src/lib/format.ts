// Small presentation helpers shared across pages. Interpretation only — the trust
// core's facts (hashes, signatures) are never reshaped here.

export type Event = {
  id: string;
  target_id: string;
  diff_type: string;
  severity: string;
  layer?: string;
  detected_at?: string;
  evidence: Record<string, unknown>;
  from_hash?: string | null;
  to_hash?: string;
};

export function sevClass(severity: string): string {
  return severity === 'High' ? 'high' : severity === 'Medium' ? 'med' : 'low';
}

export function summarize(ev: Event): string {
  const e = ev.evidence ?? {};
  switch (ev.diff_type) {
    case 'NumericThresholdChange':
      return `${e.context ?? ''} ${e.from} → ${e.to}`.trim();
    case 'TermSubstitution':
      return `"${e.term}" ${e.from}→${e.to} occurrences`;
    case 'SchemaChange':
      return `${e.change} ${e.column ?? ''}`.trim();
    case 'DistributionalShift':
      return e.change === 'row_count'
        ? `rows ${e.from} → ${e.to}`
        : `${e.column} distribution shifted`;
    default:
      return JSON.stringify(e);
  }
}
