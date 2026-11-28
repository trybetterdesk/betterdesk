import { readFileSync } from 'node:fs';
import path from 'node:path';
import { describe, expect, test } from 'vitest';
import {
	accessFromAnswer,
	allowedOperators,
	daysText,
	receiverSentence,
	scheduleText,
	unattendedClosed,
	type UnattendedAccess
} from '../../src/lib/devices/unattended.ts';

/* The English strings the sentence is made of */
const EN: Record<string, string> = {
	'devices.unattended_line_ask': 'Someone at the computer must click Allow.',
	'devices.unattended_line_always': 'Staff can connect without asking.',
	'devices.unattended_line_when': 'Staff can connect without asking, {when}.',
	'devices.unattended_line_who': 'Staff can connect without asking, only {who}.',
	'devices.unattended_line_when_who': 'Staff can connect without asking, {when}, only {who}.',
	'devices.unattended_when': '{days} {start} to {end}',
	'devices.unattended_when_all_day': '{days} all day',
	'devices.unattended_when_zone': '{when} ({zone} time)',
	'devices.unattended_day_range': '{first} to {last}',
	'devices.unattended_every_day': 'every day',
	'devices.unattended_and': '{list} and {last}',
	'days.mon': 'Mon',
	'days.tue': 'Tue',
	'days.wed': 'Wed',
	'days.thu': 'Thu',
	'days.fri': 'Fri',
	'days.sat': 'Sat',
	'days.sun': 'Sun'
};
const t = (key: string, params: Record<string, string | number> = {}) =>
	(EN[key] ?? key).replace(/\{(\w+)\}/g, (_, k: string) => String(params[k] ?? `{${k}}`));

const BERLIN = 'Europe/Berlin';

function access(over: Partial<UnattendedAccess> = {}): UnattendedAccess {
	return {
		unattended_enabled: true,
		schedule_enabled: false,
		schedule_days: [],
		schedule_start: '',
		schedule_end: '',
		schedule_timezone: '',
		allowed_operators: [],
		...over
	};
}

const office = (over: Partial<UnattendedAccess> = {}) =>
	access({
		schedule_enabled: true,
		schedule_days: ['mon', 'tue', 'wed', 'thu', 'fri'],
		schedule_start: '08:00',
		schedule_end: '18:00',
		schedule_timezone: BERLIN,
		...over
	});

interface Vector {
	name: string;
	mode: string | null;
	org_operators: string[];
	access: UnattendedAccess | null;
	caller: string;
	now: string;
	want: string;
}

const vectors: Vector[] = JSON.parse(
	readFileSync(
		path.resolve(__dirname, '../../../neodesk-server/policy/unattended/testdata/rule-vectors.json'),
		'utf8'
	)
).vectors;

describe('the shared rule vectors', () => {
	test('there are vectors', () => {
		expect(vectors.length).toBeGreaterThan(30);
	});

	test.each(vectors.map((v) => [v.name, v] as const))('steps 1 to 3: %s', (_, v) => {
		const closed = unattendedClosed(v.mode, v.access);
		if (v.want === 'ask_always' || v.want === 'not_enabled') expect(closed).toBe(v.want);
		else expect(closed).toBeNull();
	});

	test.each(
		vectors
			.filter((v) => v.want === 'allow' || v.want === 'operator_not_allowed')
			.map((v) => [v.name, v] as const)
	)('operators: %s', (_, v) => {
		const who = allowedOperators(v.org_operators, v.access?.allowed_operators ?? []);
		const listed = who === null || who.some((n) => n.trim().toLowerCase() === v.caller.trim().toLowerCase());
		expect(listed).toBe(v.want === 'allow');
	});

	test.each(vectors.map((v) => [v.name, v] as const))('a sentence that lets nobody in asks: %s', (_, v) => {
		// A vector the rule refuses before the time or the caller counts
		// must not read as "without asking"
		if (v.want === 'ask_always' || v.want === 'not_enabled')
			expect(receiverSentence(v.mode, v.org_operators, v.access, t, BERLIN)).toBe(
				'Someone at the computer must click Allow.'
			);
	});
});

describe('the sentence on the device page', () => {
	test('the examples of the plan', () => {
		expect(receiverSentence('attended', [], office(), t, BERLIN)).toBe(
			'Staff can connect without asking, Mon to Fri 8:00 to 18:00.'
		);
		expect(receiverSentence(null, [], access({ allowed_operators: ['anna', 'ben'] }), t, BERLIN)).toBe(
			'Staff can connect without asking, only anna and ben.'
		);
		expect(receiverSentence('attended', [], access({ unattended_enabled: false }), t, BERLIN)).toBe(
			'Someone at the computer must click Allow.'
		);
	});

	test('the mode decides first', () => {
		expect(receiverSentence('ask_always', [], office(), t, BERLIN)).toBe(
			'Someone at the computer must click Allow.'
		);
		expect(receiverSentence('unattended', [], null, t, BERLIN)).toBe('Staff can connect without asking.');
		expect(receiverSentence('unattended', [], access({ unattended_enabled: false }), t, BERLIN)).toBe(
			'Staff can connect without asking.'
		);
		expect(receiverSentence(null, [], null, t, BERLIN)).toBe('Someone at the computer must click Allow.');
	});

	test('schedule and operators together, with the zone when it is not the viewer’s', () => {
		expect(
			receiverSentence('unattended', ['Anna'], office({ allowed_operators: ['anna', 'ben'] }), t, 'UTC')
		).toBe('Staff can connect without asking, Mon to Fri 8:00 to 18:00 (Europe/Berlin time), only anna.');
	});

	test('a schedule or lists that let nobody in ask', () => {
		for (const bad of [
			office({ schedule_days: [] }),
			office({ schedule_timezone: 'Europe/Atlantis' }),
			office({ schedule_timezone: '' }),
			office({ schedule_start: '8:00' }),
			office({ schedule_end: '24:00' })
		])
			expect(receiverSentence('attended', [], bad, t, BERLIN)).toBe(
				'Someone at the computer must click Allow.'
			);
		expect(receiverSentence('attended', ['carl'], access({ allowed_operators: ['anna'] }), t, BERLIN)).toBe(
			'Someone at the computer must click Allow.'
		);
		// A schedule that is off counts for nothing
		expect(
			receiverSentence('attended', [], access({ schedule_days: [], schedule_timezone: 'x' }), t, BERLIN)
		).toBe('Staff can connect without asking.');
	});

	test('days in words', () => {
		expect(daysText(['mon', 'tue', 'wed', 'thu', 'fri', 'sat', 'sun'], t)).toBe('every day');
		expect(daysText(['fri', 'mon', 'wed'], t)).toBe('Mon, Wed and Fri');
		expect(daysText(['sat', 'sun'], t)).toBe('Sat and Sun');
		expect(daysText(['mon', 'tue', 'wed', 'sat'], t)).toBe('Mon to Wed and Sat');
		expect(daysText(['TUE'], t)).toBe('Tue');
	});

	test('over midnight and all day', () => {
		expect(scheduleText(office({ schedule_start: '22:00', schedule_end: '06:00' }), t, BERLIN)).toBe(
			'Mon to Fri 22:00 to 6:00'
		);
		expect(scheduleText(office({ schedule_start: '00:00', schedule_end: '00:00' }), t, BERLIN)).toBe(
			'Mon to Fri all day'
		);
	});

	test('the access policy answer as lists', () => {
		expect(
			accessFromAnswer({
				unattended_enabled: true,
				schedule_enabled: true,
				schedule_days: 'Mon, tue,,',
				schedule_start_time: '08:00',
				schedule_end_time: '18:00',
				schedule_timezone: BERLIN,
				allowed_operators: ' anna ,ben,'
			})
		).toEqual(office({ schedule_days: ['mon', 'tue'], allowed_operators: ['anna', 'ben'] }));
		expect(accessFromAnswer({})).toEqual(access({ unattended_enabled: false }));
	});
});
