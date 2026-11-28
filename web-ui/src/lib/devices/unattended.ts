/**
 * What a receiver does with a staff member who connects without someone at
 * the computer clicking Allow, in one sentence for the device page. The
 * same precedence as the server's rule (neodesk-server/policy/unattended,
 * UNATTENDED-CONTRACT.md): steps 1 to 3 decide whether staff may connect
 * without asking at all, the schedule and the allowed operators narrow it,
 * and the sentence names them instead of checking a time or a caller.
 * tests/unit/devices-unattended.test.ts runs the shared rule vectors
 * against it where they fit.
 *
 *   receiverSentence('attended', [], { unattended_enabled: true, ... }, t)
 *     // "Staff can connect without asking, Mon to Fri 8:00 to 18:00."
 */

type T = (key: string, params?: Record<string, string | number>) => string;

/** A device's access policy as the rule reads it (lists, not comma text) */
export interface UnattendedAccess {
	unattended_enabled: boolean;
	schedule_enabled: boolean;
	schedule_days: string[];
	schedule_start: string;
	schedule_end: string;
	schedule_timezone: string;
	allowed_operators: string[];
}

export const DAYS = ['mon', 'tue', 'wed', 'thu', 'fri', 'sat', 'sun'] as const;

/** Whether the device runs the receiver app (it reports itself as NeoDesk Support) */
export function isReceiver(d: { device_type?: unknown; remote_target?: unknown }): boolean {
	return !d.remote_target && String(d.device_type ?? '') === 'neodesk-support';
}

/** A comma list as the server keeps it, without blanks */
export function listOf(text: unknown): string[] {
	return String(text ?? '')
		.split(',')
		.map((s) => s.trim())
		.filter(Boolean);
}

/** The access policy GET /api/devices/:id/access-policy answers, as lists */
export function accessFromAnswer(p: {
	unattended_enabled?: boolean | null;
	schedule_enabled?: boolean | null;
	schedule_days?: string | null;
	schedule_start_time?: string | null;
	schedule_end_time?: string | null;
	schedule_timezone?: string | null;
	allowed_operators?: string | null;
}): UnattendedAccess {
	return {
		unattended_enabled: !!p.unattended_enabled,
		schedule_enabled: !!p.schedule_enabled,
		schedule_days: listOf(p.schedule_days).map((d) => d.toLowerCase()),
		schedule_start: p.schedule_start_time ?? '',
		schedule_end: p.schedule_end_time ?? '',
		schedule_timezone: p.schedule_timezone ?? '',
		allowed_operators: listOf(p.allowed_operators)
	};
}

/**
 * Steps 1 to 3 of the rule: "ask_always" for an organization that always
 * asks, "not_enabled" when the device's own switch is off under any other
 * mode than unattended (also without an access policy), null when staff
 * may connect without asking, narrowed by the schedule and the operators.
 */
export function unattendedClosed(
	mode: string | null | undefined,
	access: UnattendedAccess | null
): 'ask_always' | 'not_enabled' | null {
	const m = String(mode ?? '').trim();
	if (m === 'ask_always') return 'ask_always';
	if (m === 'unattended') return null;
	return access?.unattended_enabled ? null : 'not_enabled';
}

const name = (s: string) => s.trim().toLowerCase();

/**
 * Step 5 as a list: the usernames that may connect without asking, null
 * for everyone. With both lists set only names in both may (compared
 * without case and spaces, shown as the device list writes them).
 */
export function allowedOperators(
	orgOperators: readonly string[],
	device: readonly string[]
): string[] | null {
	const org = orgOperators.map((s) => s.trim()).filter(Boolean);
	const dev = device.map((s) => s.trim()).filter(Boolean);
	if (!org.length && !dev.length) return null;
	if (!org.length) return dev;
	if (!dev.length) return org;
	const inOrg = new Set(org.map(name));
	return dev.filter((d) => inOrg.has(name(d)));
}

const CLOCK = /^([01]\d|2[0-3]):([0-5]\d)$/;

/** "08:00" as "8:00"; null for anything that is not a time of day */
function clock(text: string): string | null {
	const m = CLOCK.exec(text.trim());
	return m ? `${Number(m[1])}:${m[2]}` : null;
}

/** Whether the zone database of this browser knows the IANA zone */
function knownZone(zone: string): boolean {
	if (!zone || zone === 'Local') return false;
	try {
		new Intl.DateTimeFormat('en', { timeZone: zone });
		return true;
	} catch {
		return false;
	}
}

/** "Mon to Fri", "Mon, Wed and Fri", "every day": the listed days in week order */
export function daysText(days: readonly string[], t: T): string {
	// Week positions of the listed days, in week order
	const at = DAYS.flatMap((d, n) => (days.map(name).includes(d) ? [n] : []));
	if (at.length === DAYS.length) return t('devices.unattended_every_day');
	const word = (n: number) => t(`days.${DAYS[n] ?? ''}`);
	// Runs of three or more days in a row read as a range
	const parts: string[] = [];
	let i = 0;
	while (i < at.length) {
		let j = i;
		while (j + 1 < at.length && at[j + 1] === (at[j] ?? -2) + 1) j++;
		if (j - i >= 2) {
			parts.push(t('devices.unattended_day_range', { first: word(at[i] ?? 0), last: word(at[j] ?? 0) }));
		} else {
			for (let k = i; k <= j; k++) parts.push(word(at[k] ?? 0));
		}
		i = j + 1;
	}
	return joinAnd(parts, t);
}

/** "anna", "anna and ben", "anna, ben and carl" */
export function joinAnd(items: readonly string[], t: T): string {
	if (items.length <= 1) return items[0] ?? '';
	return t('devices.unattended_and', { list: items.slice(0, -1).join(', '), last: items.at(-1) ?? '' });
}

/**
 * The schedule in words: "Mon to Fri 8:00 to 18:00", with the time zone
 * when it is not the viewer's; null when the schedule lets nobody in (no
 * days, a bad time, a time zone nobody knows).
 */
export function scheduleText(access: UnattendedAccess, t: T, viewerZone?: string): string | null {
	const start = clock(access.schedule_start);
	const end = clock(access.schedule_end);
	const days = DAYS.filter((d) => access.schedule_days.map(name).includes(d));
	if (!start || !end || !days.length || !knownZone(access.schedule_timezone)) return null;
	const dayWords = daysText(days, t);
	const when =
		start === end
			? t('devices.unattended_when_all_day', { days: dayWords })
			: t('devices.unattended_when', { days: dayWords, start, end });
	const here = viewerZone ?? Intl.DateTimeFormat().resolvedOptions().timeZone;
	return access.schedule_timezone === here
		? when
		: t('devices.unattended_when_zone', { when, zone: access.schedule_timezone });
}

/**
 * The sentence for the device page: who may connect without asking and
 * when, or that someone at the computer must click Allow.
 */
export function receiverSentence(
	mode: string | null | undefined,
	orgOperators: readonly string[],
	access: UnattendedAccess | null,
	t: T,
	viewerZone?: string
): string {
	const ask = t('devices.unattended_line_ask');
	if (unattendedClosed(mode, access)) return ask;
	let when: string | null = null;
	if (access?.schedule_enabled) {
		when = scheduleText(access, t, viewerZone);
		if (!when) return ask;
	}
	const who = allowedOperators(orgOperators, access?.allowed_operators ?? []);
	if (who && !who.length) return ask;
	const whoText = who ? joinAnd(who, t) : null;
	if (when && whoText) return t('devices.unattended_line_when_who', { when, who: whoText });
	if (when) return t('devices.unattended_line_when', { when });
	if (whoText) return t('devices.unattended_line_who', { who: whoText });
	return t('devices.unattended_line_always');
}
