/**
 * The audit log and the security checks without a DOM: the tabs and their URL names, the
 * audit log's filters and search, labels for action codes, the device a
 * log line is about, event details as text, the browser a session used,
 * and the server events per day for the chart.
 *
 * The server writes details and the Hardening checks in English. The
 * formats it writes most are shown in the console language (detailsText,
 * formatDetails, hardeningText); any other text shows as written.
 */

import type { AuditRow } from '#lib/api/audit.ts';

type T = (key: string, params?: Record<string, string | number>) => string;

/** The audit log page (/security-audit): the log and the server's events; your own sessions are on Your account */
export const AUDIT_TABS = ['audit', 'events'] as const;
export type AuditTab = (typeof AUDIT_TABS)[number];

/** ?tab= as a tab, anything else the audit log. The checks moved to /security-checks (lib/redirects.ts) */
export function auditTab(value: string | null | undefined): AuditTab {
	const v = value ?? '';
	return (AUDIT_TABS as readonly string[]).includes(v) ? (v as AuditTab) : 'audit';
}

/** The security checks page (/security-checks): the checks and the hardening settings */
export const CHECKS_TABS = ['checks', 'hardening'] as const;
export type ChecksTab = (typeof CHECKS_TABS)[number];

/** ?tab= as a tab: hardening (also the old "vulnerabilities"), anything else the checks */
export function checksTab(value: string | null | undefined): ChecksTab {
	return value === 'hardening' || value === 'vulnerabilities' ? 'hardening' : 'checks';
}

/* ── Audit log ── */

export const AUDIT_FILTERS = ['bans', 'signins', 'failed', 'devices', 'people', 'settings'] as const;
export type AuditFilter = (typeof AUDIT_FILTERS)[number];

export function isAuditFilter(v: string | null | undefined): v is AuditFilter {
	return !!v && (AUDIT_FILTERS as readonly string[]).includes(v);
}

const CATEGORY_TESTS: Record<AuditFilter, (action: string) => boolean> = {
	bans: (a) => /(^|_)(un)?ban|banned|blocklist|ip_block/.test(a),
	signins: (a) => /^(login|logout|auth_|session_|2fa_|password_)/.test(a),
	failed: (a) => /(login|auth)(_login)?_failed/.test(a),
	devices: (a) => /^(device_|devices_|enrollment_|folder_|peer_|remote_|registration|unattended_)/.test(a),
	people: (a) =>
		/^(user_|role_|permission|group_|org_|organization_|invite|impersonation_|email_|password_|temporary_password|two_factor_|recovery_codes_)/.test(
			a
		),
	settings: (a) =>
		/^(settings|setting_|config|theme_|branding_|backup_|restore|server_|update|smtp|commercialization_|billing_|key_|token_|policy)/.test(
			a
		)
};

/** "Device 900100019 banned", "Approved enrollment for device 900200005", "Banned 900100028 (...)" */
const DEVICE_RE =
	/\b(?:device|Device|Banned|Unbanned|Deleted|Restored|Connected to)\s+([A-Za-z0-9_-]*\d[A-Za-z0-9_-]*)\b/;

export interface AuditEntry {
	key: string;
	time: string;
	who: string;
	userId: string | null;
	action: string;
	label: string;
	device: string;
	/** In the console language where the format is known (detailsText) */
	details: string;
	/** As the server wrote it */
	raw: string;
	ip: string;
}

/** An action code in words: the translation, or "device_group_saved" → "Device group saved" */
export function actionLabel(action: string, t: T): string {
	const raw = String(action || '').trim();
	if (!raw) return '';
	const key = `audit.action_${raw.replace(/[^a-z0-9_]/gi, '_')}`;
	const label = t(key);
	if (label && label !== key) return label;
	const words = raw
		.replace(/[_.-]+/g, ' ')
		.trim()
		.toLowerCase();
	return words.charAt(0).toUpperCase() + words.slice(1);
}

/**
 * The start of a detail line the server writes, in words of the console
 * language. Named groups fill the string's {placeholders}.
 */
const DETAIL_PHRASES: readonly [RegExp, string][] = [
	[/^User logged in$/, 'audit.detail_logged_in'],
	[/^User logged in \(2FA: (?<method>[^)]+)\)$/, 'audit.detail_logged_in_2fa'],
	[/^User logged in via OIDC$/, 'audit.detail_logged_in_oidc'],
	[/^User logged in \(2FA set up at sign-in\)$/, 'audit.detail_logged_in_2fa_setup'],
	[/^User logged out$/, 'audit.detail_logged_out'],
	[/^Username: (?<user>.*)$/, 'audit.detail_username'],
	[/^New login replaced (?<count>\d+) prior session\(s\)$/, 'audit.detail_sessions_replaced'],
	[/^Created user: (?<user>.+) \((?<role>[^()]+)\)$/, 'audit.detail_user_created'],
	[
		/^Approved enrollment for device (?<device>\S+) \(mode: (?<mode>[^)]+)\)$/,
		'audit.detail_enrollment_approved'
	],
	[/^Device (?<device>\S+) tags set to \[(?<tags>.*)\]$/, 'audit.detail_tags_set'],
	[/^Device (?<device>\S+) groups set to \[(?<groups>.*)\]$/, 'audit.detail_groups_set'],
	[/^Created quick support session (?<id>\S+)$/, 'audit.detail_quick_support_created'],
	[/^Ended quick support session (?<id>\S+)$/, 'audit.detail_quick_support_ended'],
	[/^Connected to (?<device>\S+)$/, 'audit.detail_connected_to'],
	[/^Banned (?<device>\S+) \((?<reason>.*)\)$/, 'audit.detail_banned'],
	[/^Deleted (?<device>\S+)$/, 'audit.detail_deleted'],
	[/^Created folder:? (?<name>.+)$/, 'audit.detail_folder_created'],
	[/^Created user group: (?<name>.+)$/, 'audit.detail_user_group_created'],
	[/^Device group (?<name>.+) saved$/, 'audit.detail_device_group_saved'],
	[/^Unattended session to device (?<device>\S+) started$/, 'audit.detail_unattended_started'],
	[/^Unattended session to device (?<device>\S+) ended$/, 'audit.detail_unattended_ended'],
	[/^Unattended session to device (?<device>\S+) refused$/, 'audit.detail_unattended_refused']
];

/** A translation, or null when the language has no string for the key */
function known(t: T, key: string, params?: Record<string, string | number>): string | null {
	const text = t(key, params);
	return text && text !== key ? text : null;
}

/** "ip" to "Adresse": the name of a key=value part, or the name itself */
function fieldName(name: string, t: T): string {
	return known(t, `audit.field_${name}`) ?? name;
}

/** Values the server writes in English, keyed by their text */
const VALUES: Readonly<Record<string, string>> = {
	'queued for approval (managed mode)': 'audit.value_queued_managed',
	idle: 'audit.value_idle',
	support: 'audit.value_support',
	// How an unattended caller came, and why the server refused one
	console: 'audit.value_via_console',
	desktop: 'audit.value_via_desktop',
	too_late: 'audit.value_too_late',
	already_used: 'audit.value_already_used',
	no_permission: 'audit.value_no_permission',
	ask_always: 'audit.value_ask_always',
	not_enabled: 'audit.value_not_enabled',
	outside_schedule: 'audit.value_outside_schedule',
	operator_not_allowed: 'audit.value_operator_not_allowed'
};

function fieldValue(value: string, t: T): string {
	const key = VALUES[value];
	return (key && known(t, key)) || value;
}

const FIELD = /^[A-Za-z][A-Za-z_]*=/;

/**
 * An audit detail line in the console language: "User logged in; ip=10.0.0.5"
 * becomes "Angemeldet; Adresse: 10.0.0.5". The phrase at the start is
 * translated when it is one the server writes often, and each "key=value"
 * part gets its key's name; a line in any other form stays as written.
 */
export function detailsText(details: string, t: T): string {
	const parts = String(details ?? '').split('; ');
	const head = parts[0] ?? '';
	const tail = parts.slice(1);
	if (!tail.every((p) => FIELD.test(p))) return details;
	const fields = FIELD.test(head) ? parts : tail;
	let first: string | null = FIELD.test(head) ? null : head;
	if (first !== null) {
		for (const [re, key] of DETAIL_PHRASES) {
			const m = re.exec(first);
			if (!m) continue;
			first = known(t, key, { ...m.groups }) ?? first;
			break;
		}
	}
	const named = fields.map((p) => {
		const at = p.indexOf('=');
		return `${fieldName(p.slice(0, at), t)}: ${fieldValue(p.slice(at + 1), t)}`;
	});
	return [...(first === null ? [] : [first]), ...named].join('; ');
}

export function toAuditEntries(rows: readonly AuditRow[], t: T): AuditEntry[] {
	return rows.map((r, i) => {
		const m = r.details.match(DEVICE_RE);
		const userId =
			r.user_id === null || r.user_id === undefined || r.user_id === '' ? null : String(r.user_id);
		return {
			key: String(r.id ?? i),
			time: r.created_at,
			who: r.username || (userId ? `#${userId}` : ''),
			userId,
			action: r.action,
			label: actionLabel(r.action, t),
			device: m?.[1] ?? '',
			details: detailsText(r.details, t),
			raw: r.details,
			ip: r.ip_address
		};
	});
}

/** Entries of the chosen kind whose text contains the search */
export function filterAudit(
	entries: readonly AuditEntry[],
	query: string,
	type: AuditFilter | ''
): AuditEntry[] {
	const q = query.trim().toLowerCase();
	const test = type ? CATEGORY_TESTS[type] : null;
	return entries.filter((e) => {
		if (test && !test(e.action.toLowerCase())) return false;
		if (!q) return true;
		return [e.who, e.action, e.label, e.device, e.details, e.raw, e.ip].join(' ').toLowerCase().includes(q);
	});
}

/* ── Server events ── */

export const EVENT_FILTERS = [
	'login_failed',
	'login_success',
	'peer_banned',
	'peer_unbanned',
	'ip_banned',
	'device_approved',
	'config_changed',
	'key_created'
] as const;

/**
 * Event details as one line: "mode: all, version: 3.5". With `t` the names,
 * and the values the server writes in English, are in the console language.
 */
export function formatDetails(details: unknown, t?: T): string {
	if (details === null || details === undefined || details === '') return '';
	if (typeof details !== 'object') return String(details);
	return Object.entries(details as Record<string, unknown>)
		.filter(([, v]) => v !== '' && v !== null && v !== undefined)
		.map(([k, v]) => {
			const value = typeof v === 'object' ? JSON.stringify(v) : String(v);
			return t ? `${fieldName(k, t)}: ${fieldValue(value, t)}` : `${k}: ${value}`;
		})
		.join(', ');
}

/* ── Hardening ── */

/**
 * A Hardening check in the console language. The server sends its two
 * checks in English, with the numbers in the description; those are read
 * back out. Another check, or a description in another form, stays as sent.
 */
export function hardeningText(
	item: { id?: string; name: string; description: string },
	t: T
): { name: string; description: string } {
	const id = item.id ?? '';
	const name = (id && known(t, `security_audit.hardening_${id}`)) || item.name;
	let description: string | null = null;
	if (id === 'session_timeout') {
		const m = /after (\d+) minutes without a request and (\d+) minutes after sign-in/.exec(item.description);
		if (m)
			description = known(t, 'security_audit.hardening_session_timeout_desc', {
				idle: m[1] ?? '',
				max: m[2] ?? ''
			});
	} else if (id === 'single_session') {
		const m = /\(currently (\w+)[;)]/.exec(item.description);
		if (m) {
			const value = m[1] ?? '';
			const limit = value === 'unlimited' ? (known(t, 'security_audit.hardening_unlimited') ?? value) : value;
			description = known(t, 'security_audit.hardening_single_session_desc', { limit });
		}
	}
	return { name, description: description ?? item.description };
}

/** Long details are cut after two lines; shorter ones never get "Show all" */
export const DETAILS_CLAMP = 140;

/* ── Sessions ── */

/** "Chrome 156" and "Windows" from a browser string (either may be empty) */
export function describeUa(ua: string): { browser: string; os: string } {
	const m = (re: RegExp) => ua.match(re)?.[1] ?? '';
	let browser = '';
	if (/Edg\//.test(ua)) browser = `Edge ${m(/Edg\/(\d+)/)}`;
	else if (/OPR\//.test(ua)) browser = `Opera ${m(/OPR\/(\d+)/)}`;
	else if (/Firefox\//.test(ua)) browser = `Firefox ${m(/Firefox\/(\d+)/)}`;
	else if (/Chrome\//.test(ua))
		browser = `${/HeadlessChrome/.test(ua) ? 'Headless Chrome' : 'Chrome'} ${m(/Chrome\/(\d+)/)}`;
	else if (/Safari\//.test(ua)) browser = `Safari ${m(/Version\/(\d+)/)}`;
	let os = '';
	if (/Windows/.test(ua)) os = 'Windows';
	else if (/iPhone|iPad/.test(ua)) os = 'iOS';
	else if (/Mac OS X|Macintosh/.test(ua)) os = 'macOS';
	else if (/Android/.test(ua)) os = 'Android';
	else if (/CrOS/.test(ua)) os = 'ChromeOS';
	else if (/Linux/.test(ua)) os = 'Linux';
	return { browser: browser.trim(), os };
}

export type SessionState = 'current' | 'active' | 'ended';

export function sessionState(s: { current: boolean; active: boolean }): SessionState {
	return s.current ? 'current' : s.active ? 'active' : 'ended';
}
