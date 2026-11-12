// The public record, typed, plus the presentation helpers every page shares.
//
// Three kinds of information travel in record.json and the site keeps them visibly apart:
// attested leaves (observations, findings), interpretation (explain / state / changes — a
// plain-language reading derived from the leaves), and the operator's own account of its
// checks (monitor). Nothing here reshapes a hash or a signature.

import raw from '../data/record.json';

export type Explain = {
  kind: string;
  title: string;
  summary: string;
  diff?: { before: string; removed: string; added: string; after: string };
};

export type Finding = {
  id: string;
  target_id: string;
  diff_type: string;
  severity: string;
  layer?: string;
  detected_at?: string;
  evidence: Record<string, unknown>;
  from_hash?: string | null;
  to_hash?: string;
  explain?: Explain;
  change_id?: string;
};

export type Endpoint = {
  observation_id?: string;
  observed_at?: string;
  http_status?: number;
  url?: string;
  content_hash?: string;
  warc?: string | null;
} | null;

export type Change = {
  id: string;
  target_id: string;
  detected_at: string;
  severity: string;
  category: 'notable' | 'routine' | 'churn';
  kinds: string[];
  diff_types: string[];
  headline: string;
  points: string[];
  netted: boolean;
  event_ids: string[];
  from: Endpoint;
  to: Endpoint;
  reverted_by: string | null;
  reverts: string | null;
};

export type Observation = {
  id: string;
  content_hash: string;
  fetched_at: string;
  http_status: number;
  url: string;
  warc_record_hash?: string | null;
  warc?: string | null;
};

export type Monitor = {
  last_checked: string | null;
  last_status: string;
  last_answered: string | null;
  consecutive_failures: number;
  last_error: string;
  next_due: string | null;
} | null;

export type State = {
  code: string;
  label: string;
  detail: string;
  http_status: number | null;
  final_url: string | null;
  since: string | null;
};

export type Target = {
  id: string;
  title: string;
  url: string;
  kind: string;
  criteria: string;
  tags: string[];
  criteria_text: string;
  interval_seconds: number | null;
  curated: boolean;
  observations: Observation[];
  events: Finding[];
  monitor: Monitor;
  state: State;
  change_count: number;
  last_change_at: string | null;
};

export type Summary = {
  targets: number;
  states: Record<string, number>;
  observations: number;
  findings: number;
  changes: number;
  notable_changes: number;
  error_page_churn: number;
  first_observed_at: string | null;
  last_observed_at: string | null;
  last_checked_at: string | null;
};

type RawRecord = {
  schema?: string;
  generated_at?: string;
  public_key?: string;
  size?: number;
  checkpoint?: { origin: string; size: number; root: string } | null;
  legend?: Record<string, string>;
  criteria_tags?: Record<string, string>;
  watched_terms?: string[];
  summary?: Summary;
  targets?: Partial<Target>[];
  events?: Finding[];
  changes?: Change[];
};

const source = raw as unknown as RawRecord;

// --- normalisation: a record exported before the reader-facing views existed still renders ---

function fallbackState(observations: Observation[]): State {
  const latest = observations[observations.length - 1];
  if (!latest) {
    return { code: 'pending', label: 'No observations', detail: 'No observation has been recorded yet.', http_status: null, final_url: null, since: null };
  }
  const ok = latest.http_status >= 200 && latest.http_status < 300;
  return {
    code: ok ? 'live' : 'error',
    label: ok ? 'Live' : `HTTP ${latest.http_status}`,
    detail: `The latest observation returned HTTP ${latest.http_status}.`,
    http_status: latest.http_status,
    final_url: null,
    since: latest.fetched_at,
  };
}

function fallbackChanges(events: Finding[]): Change[] {
  return events.map((e) => ({
    id: e.id,
    target_id: e.target_id,
    detected_at: e.detected_at ?? '',
    severity: e.severity,
    category: e.severity === 'High' ? 'notable' : 'routine',
    kinds: ['other'],
    diff_types: [e.diff_type],
    headline: e.explain?.title ?? e.diff_type,
    points: [e.explain?.summary ?? JSON.stringify(e.evidence ?? {})],
    netted: false,
    event_ids: [e.id],
    from: null,
    to: null,
    reverted_by: null,
    reverts: null,
  }));
}

export const events: Finding[] = source.events ?? [];
export const changes: Change[] = source.changes ?? fallbackChanges(events);

export const targets: Target[] = (source.targets ?? []).map((t) => {
  const observations = (t.observations ?? []) as Observation[];
  const own = changes.filter((c) => c.target_id === t.id && c.category !== 'churn');
  return {
    id: t.id ?? '(unknown)',
    title: t.title ?? t.id ?? '(unknown)',
    url: t.url ?? '',
    kind: t.kind ?? 'page',
    criteria: t.criteria ?? '',
    tags: t.tags ?? [],
    criteria_text: t.criteria_text ?? t.criteria ?? '',
    interval_seconds: t.interval_seconds ?? null,
    curated: t.curated ?? true,
    observations,
    events: (t.events ?? []) as Finding[],
    monitor: t.monitor ?? null,
    state: t.state ?? fallbackState(observations),
    change_count: t.change_count ?? own.length,
    last_change_at: t.last_change_at ?? own[0]?.detected_at ?? null,
  };
});

const observationTimes = targets.flatMap((t) => t.observations.map((o) => o.fetched_at)).sort();
const meaningful = changes.filter((c) => c.category !== 'churn');

export const summary: Summary = source.summary ?? {
  targets: targets.length,
  states: targets.reduce<Record<string, number>>((acc, t) => ({ ...acc, [t.state.code]: (acc[t.state.code] ?? 0) + 1 }), {}),
  observations: observationTimes.length,
  findings: events.length,
  changes: meaningful.length,
  notable_changes: meaningful.filter((c) => c.category === 'notable').length,
  error_page_churn: changes.length - meaningful.length,
  first_observed_at: observationTimes[0] ?? null,
  last_observed_at: observationTimes[observationTimes.length - 1] ?? null,
  last_checked_at: null,
};

export const record = {
  schema: source.schema ?? 'verderer.record/v1',
  // When this record was exported. An older export has no stamp; its newest observation is
  // the closest honest stand-in for "how fresh is this page".
  generatedAt: source.generated_at ?? summary.last_observed_at ?? null,
  publicKey: source.public_key ?? '',
  size: source.size ?? 0,
  checkpoint: source.checkpoint ?? null,
  criteriaTags: source.criteria_tags ?? {},
  watchedTerms: source.watched_terms ?? [],
};

// --- lookups -------------------------------------------------------------------------------

const targetIndex = new Map(targets.map((t) => [t.id, t]));
const changeIndex = new Map(changes.map((c) => [c.id, c]));
const eventIndex = new Map(events.map((e) => [e.id, e]));

export const targetById = (id: string): Target | undefined => targetIndex.get(id);
export const changeById = (id: string | null | undefined): Change | undefined => (id ? changeIndex.get(id) : undefined);
export const eventById = (id: string): Finding | undefined => eventIndex.get(id);
export const findingsOf = (change: Change): Finding[] =>
  change.event_ids.map((id) => eventIndex.get(id)).filter((e): e is Finding => e !== undefined);
export const titleOf = (targetId: string): string => targetIndex.get(targetId)?.title ?? targetId;

// --- formatting ----------------------------------------------------------------------------

const DATE = new Intl.DateTimeFormat('en-US', { timeZone: 'UTC', year: 'numeric', month: 'short', day: 'numeric' });
const DATE_TIME = new Intl.DateTimeFormat('en-US', {
  timeZone: 'UTC', year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', hourCycle: 'h23',
});
const MONTH = new Intl.DateTimeFormat('en-US', { timeZone: 'UTC', year: 'numeric', month: 'long' });

function parse(iso: string | null | undefined): Date | null {
  if (!iso) return null;
  const date = new Date(iso);
  return Number.isNaN(date.getTime()) ? null : date;
}

export function fmtDate(iso: string | null | undefined): string {
  const date = parse(iso);
  return date ? DATE.format(date) : '—';
}

export function fmtDateTime(iso: string | null | undefined): string {
  const date = parse(iso);
  return date ? `${DATE_TIME.format(date)} UTC` : '—';
}

export function fmtMonth(iso: string | null | undefined): string {
  const date = parse(iso);
  return date ? MONTH.format(date) : 'Undated';
}

/** A multihash (`1220…`) or leaf hash, shortened for display. The full value stays in `title`/copy. */
export function shortHash(hash: string | null | undefined, length = 10): string {
  if (!hash) return '—';
  const digest = hash.length === 68 && hash.startsWith('1220') ? hash.slice(4) : hash;
  return `${digest.slice(0, length)}…`;
}

export function hostOf(url: string): string {
  try {
    return new URL(url).host.replace(/^www\./, '');
  } catch {
    return url;
  }
}

export function cadence(seconds: number | null): string {
  if (!seconds) return 'not scheduled';
  const hours = seconds / 3600;
  if (hours < 1) return `every ${Math.round(seconds / 60)} minutes`;
  if (hours < 24) return `every ${Number.isInteger(hours) ? hours : hours.toFixed(1)} hours`;
  const days = hours / 24;
  return days === 1 ? 'daily' : `every ${Number.isInteger(days) ? days : days.toFixed(1)} days`;
}

export function plural(count: number, noun: string): string {
  return `${count.toLocaleString('en-US')} ${noun}${count === 1 ? '' : 's'}`;
}

export function sevClass(severity: string): string {
  return severity === 'High' ? 'high' : severity === 'Medium' ? 'med' : 'low';
}

// The order sources are listed in: what needs a reader's attention first.
export const STATE_ORDER = ['failing', 'live', 'blocked', 'gone', 'error', 'unreachable', 'excluded', 'pending'];

export const STATE_NAMES: Record<string, string> = {
  live: 'Live',
  blocked: 'Blocked',
  gone: 'Gone',
  error: 'Erroring',
  failing: 'Not responding',
  unreachable: 'Unreachable',
  excluded: 'Not collected',
  pending: 'Awaiting first check',
};

export const STATE_HELP: Record<string, string> = {
  live: 'Answering normally. Its content is being recorded and compared.',
  blocked: 'The server refuses the collector. The refusal is recorded; the content is not being observed.',
  gone: 'The address returns "not found". The absence is recorded, and the watch continues.',
  error: 'The address returns an error status.',
  failing: 'It used to answer and has stopped responding.',
  unreachable: 'It has never answered. There is nothing to record until it does.',
  excluded: "The site's robots.txt asks crawlers not to fetch it, so it is not fetched.",
  pending: 'No check has completed yet.',
};

/** What the last check found, in a few words — from the operator's own account of its checks. */
export function lastCheckNote(target: Target): string {
  const m = target.monitor;
  if (!m || !m.last_checked) return 'No check recorded yet';
  switch (m.last_status) {
    case 'unchanged':
      return 'nothing new';
    case 'observed':
      return 'recorded a new response';
    case 'skipped':
      return 'not fetched (robots.txt)';
    case 'error':
      return m.consecutive_failures > 1 ? `no response (${m.consecutive_failures} in a row)` : 'no response';
    default:
      return m.last_status || 'checked';
  }
}

export function sortedSources(): Target[] {
  const rank = (t: Target) => {
    const index = STATE_ORDER.indexOf(t.state.code);
    return index === -1 ? STATE_ORDER.length : index;
  };
  return [...targets].sort(
    (a, b) => rank(a) - rank(b) || (b.last_change_at ?? '').localeCompare(a.last_change_at ?? '') || a.title.localeCompare(b.title),
  );
}
