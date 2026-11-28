/**
 * The audit log, server events and Hardening tab in the console's language
 * (BUGS L323): every action the server writes has its label in every
 * language file, the details the server writes most read in German, and so
 * do the two Hardening checks and the notes of the built-in groups.
 */
import fs from 'node:fs';
import path from 'node:path';
import { beforeAll, describe, expect, test } from 'vitest';
import { setStrings, t } from '../../../src/lib/i18n/i18n.svelte.ts';
import { actionLabel, detailsText, formatDetails, hardeningText } from '../../../src/lib/people/audit.ts';
import { groupNote } from '../../../src/lib/people/users.ts';

const server = path.resolve(__dirname, '../../../../neodesk-server');
const langDir = path.join(server, 'console/static/files/lang');
const read = (code: string) => JSON.parse(fs.readFileSync(path.join(langDir, `${code}.json`), 'utf8'));

/** The audit actions the server writes: the first text argument of its audit calls */
function serverActions(): Set<string> {
	const patterns = [
		/\b(?:audit|Audit|auditAs|auditAction|LogAction)\((?:\s*[^,()"\n]+,){0,2}\s*"([a-z][a-z0-9_.]*)"/g,
		/auditLog\.Log\(\s*"([a-z0-9_.]+)"/g,
		/audit\.Action\(\s*"([a-z0-9_.]+)"\)/g,
		/\bAction\w*\s+Action\s*=\s*"([a-z0-9_.]+)"/g,
		/\bWrite\(\s*ctx\s*,[^,\n]+,\s*"([a-z0-9_.]+)"/g,
		/\bWriteAbout\(\s*[^,\n]+,[^,\n]+,[^,\n]+,\s*"([a-z0-9_.]+)"/g,
		/Action:\s*"([a-z0-9_.]+)"/g
	];
	const found = new Set<string>();
	const walk = (dir: string) => {
		for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
			const full = path.join(dir, entry.name);
			if (entry.isDirectory()) {
				// Test data, the contract suite and the avatar sync (its Action is a result, not an audit entry)
				if (!['testdata', 'contract', 'avatars', 'node_modules'].includes(entry.name)) walk(full);
			} else if (entry.name.endsWith('.go') && !entry.name.endsWith('_test.go')) {
				// Without comment lines (doc examples name made-up actions)
				const source = fs
					.readFileSync(full, 'utf8')
					.split(/\r?\n/)
					.filter((line) => !line.trim().startsWith('//'))
					.join('\n');
				for (const re of patterns) for (const m of source.matchAll(re)) found.add(m[1]!);
			}
		}
	};
	walk(server);
	return found;
}

describe('audit actions in every language', () => {
	// Reading all of the server's Go files takes a few seconds on a busy machine: a longer limit
	test('every action the server writes has a label in every language file, German in de.json', () => {
		const actions = serverActions();
		expect(actions.size).toBeGreaterThan(150);
		const en = read('en').audit;
		const missing: string[] = [];
		for (const file of fs.readdirSync(langDir).filter((f) => f.endsWith('.json'))) {
			const audit = JSON.parse(fs.readFileSync(path.join(langDir, file), 'utf8')).audit ?? {};
			for (const action of actions) {
				const key = `action_${action.replace(/[^a-z0-9_]/gi, '_')}`;
				if (!audit[key]) missing.push(`${file} ${key}`);
				else if (file === 'de.json' && audit[key] === en[key]) missing.push(`${file} ${key} is English`);
			}
		}
		expect(missing).toEqual([]);
	}, 60_000);
});

describe('in German', () => {
	beforeAll(() => {
		setStrings('de', 'ltr', read('de'));
	});

	test('action chips', () => {
		expect(actionLabel('pairing_code_created', t)).toBe('Kopplungscode erstellt');
		expect(actionLabel('sysinfo_updated', t)).toBe('Systeminformationen aktualisiert');
		expect(actionLabel('enrollment_pending', t)).toBe('Registrierung wartet');
		expect(actionLabel('remote_target_created', t)).toBe('Fernziel erstellt');
		expect(actionLabel('conn_end', t)).toBe('Verbindung beendet');
	});

	test('the details the server writes most', () => {
		expect(detailsText('Created user: kbviewer (viewer)', t)).toBe('Konto kbviewer erstellt (viewer)');
		expect(detailsText('User logged in; ip=10.0.0.5; ua=Firefox/132.0; fingerprint=none', t)).toBe(
			'Angemeldet; Adresse: 10.0.0.5; Browser: Firefox/132.0; Fingerabdruck: none'
		);
		expect(detailsText('Approved enrollment for device 900200005 (mode: standard)', t)).toBe(
			'Registrierung von Gerät 900200005 freigegeben (Modus: standard)'
		);
		expect(detailsText('Device 900100019 tags set to [office, finance]', t)).toBe(
			'Tags von Gerät 900100019 gesetzt auf: office, finance'
		);
		expect(
			detailsText(
				'Unattended session to device 900100018 started; helper=Olga Operator (olga); via=console; relay_session=ab12',
				t
			)
		).toBe(
			'Sitzung ohne Nachfrage zu Gerät 900100018 begonnen; Mitarbeiter: Olga Operator (olga); verbunden über: die Webkonsole; Relay-Sitzung: ab12'
		);
		expect(
			detailsText(
				'Unattended session to device 900100018 refused; helper=olga; reason=outside_schedule; relay_session=ab12',
				t
			)
		).toBe(
			'Sitzung ohne Nachfrage zu Gerät 900100018 abgelehnt; Mitarbeiter: olga; Grund: außerhalb der erlaubten Zeiten; Relay-Sitzung: ab12'
		);
		// Anything else stays as the server wrote it
		expect(detailsText('Language xx deleted', t)).toBe('Language xx deleted');
	});

	test('server event details', () => {
		expect(formatDetails({ reason: 'queued for approval (managed mode)', mode: 'managed' }, t)).toBe(
			'Grund: wartet auf Freigabe (verwalteter Modus), Modus: managed'
		);
		expect(formatDetails({ custom: 'x' }, t)).toBe('custom: x');
	});

	test('the two Hardening checks', () => {
		const timeout = hardeningText(
			{
				id: 'session_timeout',
				name: 'Panel Idle and Absolute Session Timeout',
				description:
					'A console session ends after 30 minutes without a request and 480 minutes after sign-in (SESSION_IDLE_TIMEOUT, SESSION_MAX_AGE).'
			},
			t
		);
		expect(timeout.name).toBe('Leerlauf- und Höchstdauer von Konsolensitzungen');
		expect(timeout.description).toContain('nach 30 Minuten ohne Anfrage und 480 Minuten nach der Anmeldung');
		const single = hardeningText(
			{
				id: 'single_session',
				name: 'Concurrent Panel Session Limit per Account',
				description:
					'A new console login ends the least recently active sessions beyond the limit per account (currently unlimited; Settings, Sign-in, or SESSION_MAX_PER_USER when set) and records IP/User-Agent for audit.'
			},
			t
		);
		expect(single.name).toBe('Grenze für Konsolensitzungen pro Konto');
		expect(single.description).toContain(
			'(derzeit keine Grenze; einzustellen unter Einstellungen, Anmeldung'
		);
	});

	test('notes of the built-in groups', () => {
		expect(groupNote('Default user group', t)).toBe('Standard-Benutzergruppe');
		expect(groupNote('Default group created with organization (commercialization)', t)).toBe(
			'Standardgruppe, mit der Organisation erstellt'
		);
		expect(groupNote('Our own note', t)).toBe('Our own note');
	});
});
