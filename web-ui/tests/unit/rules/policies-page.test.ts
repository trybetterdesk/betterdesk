/**
 * The Policies page on the settings pattern (settings-pass-2.md): every
 * setting's control is there at once with "Not set" inside it, one click
 * sets a rule, "Remove the rule" sits beside a set control, a note for a
 * whole group is said once on it, internal keys stay off the screen, and
 * "Remove all rules of this group" shows only where there are rules. Save
 * writes only the changed groups (PUT with the rules, DELETE when none is
 * left) and the toast offers Undo. Every admin role may read; writing
 * needs org.edit (A83).
 */
import { cleanup, render, screen, within } from '@testing-library/svelte';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';

const pageState = vi.hoisted(() => ({
	url: new URL('http://localhost/app/policies/org-1'),
	params: { orgId: 'org-1' } as Record<string, string>
}));
vi.mock('$app/state', () => ({ page: pageState }));
vi.mock('$app/paths', () => ({ resolve: (p: string) => '/app' + (p || '/'), asset: (p: string) => '/' + p }));
vi.mock('$app/navigation', () => ({
	goto: vi.fn(),
	pushState: vi.fn(),
	replaceState: vi.fn(),
	beforeNavigate: vi.fn()
}));
const confirm = vi.hoisted(() => vi.fn(async () => true));
vi.mock('#lib/ui/dialogs.svelte.ts', () => ({ confirm }));

import Page from '../../../src/routes/(console)/policies/[[orgId]]/+page.svelte';
import { session } from '../../../src/lib/state/session.svelte.ts';
import { dismissAll, toasts } from '../../../src/lib/ui/toasts.svelte.ts';

type Fields = Record<
	string,
	{ value: unknown; source: string; server_value?: unknown; server_setting?: unknown }
>;

const GROUP_FIELDS: Record<string, string[]> = {
	connection: ['idle_lock_timeout', 'max_session_duration', 'mode', 'wallpaper'],
	features: ['allow_audio', 'allow_clipboard', 'allow_file_transfer', 'allow_recording'],
	security: [
		'allow_uninstall',
		'allowed_operators',
		'password_max_age_days',
		'password_min_length',
		'password_require_special',
		'require_2fa'
	],
	network: ['allowed_relay_servers', 'block_direct_p2p', 'ip_allowlist'],
	update: ['auto_update', 'channel']
};

/** What the receiver app applies, as the server says (neodesk-client#28) */
const RECEIVER_APPLIES: Record<string, string[]> = {
	connection: ['mode'],
	security: ['allow_uninstall', 'allowed_operators']
};

/** The resolved answer for what the organization stored */
function resolvedFor(stored: Record<string, Record<string, unknown>>, deviceAppApplies = false) {
	const out: Record<string, unknown> = {};
	for (const [group, names] of Object.entries(GROUP_FIELDS)) {
		const values = stored[group] ?? {};
		const fields: Fields = {};
		for (const name of names) {
			const has = name in values;
			fields[name] = { value: has ? values[name] : null, source: has ? 'organization' : 'none' };
		}
		if (group === 'network') {
			fields.block_direct_p2p = {
				...fields.block_direct_p2p!,
				source: 'block_direct_p2p' in values ? 'organization' : 'server',
				server_value: true,
				server_setting: {
					label_key: 'settings.connection_mode_title',
					href: '/settings#connection-mode-section'
				}
			};
		}
		out[group] = {
			set: Object.keys(values).length > 0,
			applied_by: group === 'network' ? 'server' : 'device',
			device_app_applies: group === 'network' ? false : deviceAppApplies,
			receiver_applies: RECEIVER_APPLIES[group] ?? [],
			timing: group === 'network' ? 'server_minute' : 'device_next_check',
			fields
		};
	}
	return out;
}

let writes: { call: string; body: unknown }[] = [];
let stored: Record<string, Record<string, unknown>> = {};
let deviceAppApplies = false;
let deviceCount = 2;

function answer(path: string): unknown {
	switch (path) {
		case '/api/panel/org':
			return { organizations: [{ id: 'org-1', name: 'Front office' }] };
		case '/api/panel/policies/org-1/resolved':
			return resolvedFor(stored, deviceAppApplies);
		case '/api/panel/policies/org-1/audit':
			return { entries: [] };
		case '/api/panel/org/org-1/devices':
			return { devices: Array.from({ length: deviceCount }, (_, i) => ({ id: `d${i}` })) };
		case '/api/panel/roles':
			return {
				success: true,
				data: { roles: [{ name: 'admin' }, { name: 'remote_operator' }], all_permissions: [] }
			};
		case '/api/panel/scaling/relays':
			return [{ id: 'r1', name: 'Frankfurt', address: 'relay-fra.example.net:21117' }];
		default:
			return { success: true };
	}
}

beforeEach(() => {
	writes = [];
	stored = {};
	deviceAppApplies = false;
	deviceCount = 2;
	confirm.mockClear();
	vi.stubGlobal('fetch', async (input: string, init: RequestInit = {}) => {
		const url = new URL(input, location.origin);
		const method = init.method ?? 'GET';
		if (method !== 'GET') {
			const body = init.body ? JSON.parse(String(init.body)) : undefined;
			writes.push({ call: `${method} ${url.pathname}`, body });
			const group = url.pathname.split('/').pop() ?? '';
			if (method === 'PUT') stored[group] = body as Record<string, unknown>;
			if (method === 'DELETE')
				stored = Object.fromEntries(Object.entries(stored).filter(([k]) => k !== group));
		}
		return new Response(JSON.stringify(answer(url.pathname)), {
			status: 200,
			headers: { 'Content-Type': 'application/json' }
		});
	});
});

afterEach(() => {
	cleanup();
	dismissAll();
	vi.unstubAllGlobals();
	session.permissions = [];
	session.user = null;
});

function signIn(role: string, permissions: string[]) {
	session.isSuperAdmin = false;
	session.permissions = permissions;
	session.user = { id: 1, username: 'demo', role, preferredLanguage: null, avatarVersion: null };
}

const EDITOR = ['org.edit', 'org.manage_users', 'user.view', 'device.view', 'server.config'];

async function openPage() {
	render(Page, { params: { orgId: 'org-1' } } as never);
	await vi.waitFor(() =>
		expect(screen.getByRole('heading', { name: 'policies.connection_title' })).toBeInTheDocument()
	);
}

const group = (name: string) => screen.getByRole('heading', { name }).closest('section') as HTMLElement;
/** An on/off setting's Not set / On / Off choice */
const choice = (label: string) => screen.getByRole('radiogroup', { name: label });
const NOTICE = 'No NeoDesk app applies this group yet. It is saved and handed to devices that ask.';

describe('policies page', () => {
	test('server_admin (no org.edit) reads everything but can set nothing and writes nothing', async () => {
		signIn('server_admin', ['server.config', 'user.view', 'device.view']);
		stored = { connection: { mode: 'unattended' } };
		await openPage();
		expect(screen.getByText('You can view this page but not change it.')).toBeInTheDocument();
		expect(screen.getByLabelText('policies.connection_mode')).toBeDisabled();
		for (const radio of within(choice('policies.allow_audio')).getAllByRole('radio'))
			expect(radio).toBeDisabled();
		expect(screen.queryByRole('button', { name: /Remove all rules/ })).toBeNull();
		expect(screen.queryByRole('button', { name: /^Remove the rule/ })).toBeNull();
		expect(writes).toEqual([]);
	});

	test('a group never saved shows every control with "Not set" picked, and no sentence per row', async () => {
		signIn('global_admin', EDITOR);
		await openPage();
		const features = group('policies.features_title');
		const radios = within(features).getAllByRole('radiogroup');
		expect(radios).toHaveLength(4);
		for (const r of radios) expect(within(r).getByRole('radio', { name: 'Not set' })).toBeChecked();
		expect(screen.getByLabelText('policies.connection_mode')).toHaveValue('');
		expect(
			(screen.getByLabelText('policies.connection_mode') as HTMLSelectElement).selectedOptions[0]
		).toHaveTextContent('Not set (each device decides)');
		expect(screen.getByLabelText('policies.idle_lock')).toHaveValue(null);
		// The old two-click way and its sentence under every row are gone
		expect(screen.queryByRole('button', { name: /^Set for this organization/ })).toBeNull();
		expect(screen.queryByText('No rule: each device keeps its own setting.')).toBeNull();
		expect(screen.queryByText('No rule here')).toBeNull();
		// The connection strategy is where "Always connect through a relay" comes from
		const network = group('policies.network_title');
		expect(
			within(choice('policies.block_direct_p2p')).getByRole('radio', { name: 'Server value' })
		).toBeChecked();
		expect(within(network).getByText(/From the server: Always through the relay\./)).toBeInTheDocument();
		expect(within(network).getByRole('link', { name: 'settings.connection_mode_title' })).toHaveAttribute(
			'href',
			'/app/settings#connection-mode-section'
		);
	});

	test('the organization line counts its devices and says devices outside get no policy', async () => {
		signIn('global_admin', EDITOR);
		await openPage();
		await vi.waitFor(() =>
			expect(screen.getByText(/2 devices are in this organization\./)).toBeInTheDocument()
		);
		expect(screen.getByText(/Devices outside any organization get no policy\./)).toBeInTheDocument();
		expect(screen.getByRole('link', { name: 'Put devices into this organization' })).toHaveAttribute(
			'href',
			'/app/organizations/org-1#devices'
		);
	});

	test('an organization without devices says first that its policies reach none', async () => {
		signIn('global_admin', EDITOR);
		deviceCount = 0;
		await openPage();
		const line = await screen.findByText(
			/No device is in this organization yet, so these policies reach none\./
		);
		expect(line).toHaveClass('is-empty');
		// It comes before the first group
		const first = screen.getByRole('heading', { name: 'policies.connection_title' });
		expect(line.compareDocumentPosition(first) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
	});

	test('the device groups say once that no app applies them; the network group says when the server does', async () => {
		signIn('global_admin', EDITOR);
		await openPage();
		for (const g of ['features', 'update'])
			expect(within(group(`policies.${g}_title`)).getAllByText(NOTICE)).toHaveLength(1);
		const network = group('policies.network_title');
		expect(within(network).queryByText(NOTICE)).toBeNull();
		expect(within(network).getByText('policies.effect_server')).toBeInTheDocument();
		// "Devices get this" would contradict the notice: no app gets it yet
		for (const g of ['features', 'update'])
			expect(
				within(group(`policies.${g}_title`)).queryByText(
					'Devices get this when they next ask for their policy.'
				)
			).toBeNull();
		// Sound: the place that turns it off today
		expect(
			within(group('policies.features_title')).getByRole('link', { name: 'Open access rules' })
		).toHaveAttribute('href', '/app/devices#access-rules');
		// Said on the group only, never again on each of its rows
		expect(screen.queryByText('No NeoDesk app applies this yet.')).toBeNull();
		expect(document.getElementById('pol-features-allow-audio')).not.toHaveTextContent(/applies this/);
	});

	test('connection and security name what the receiver app applies and say the desktop app applies none of it yet', async () => {
		signIn('global_admin', EDITOR);
		await openPage();
		for (const [g, label] of [
			['connection', 'policies.connection_mode'],
			['security', 'policies.allow_uninstall, policies.allowed_operators']
		] as const) {
			const box = group(`policies.${g}_title`);
			expect(within(box).queryByText(NOTICE)).toBeNull();
			const notices = within(box).getAllByText(/only the receiver app applies part of this group/);
			expect(notices).toHaveLength(1);
			expect(notices[0]).toHaveTextContent(`group: ${label}.`);
			expect(notices[0]).toHaveTextContent("The NeoDesk desktop app doesn't apply this group yet.");
			// The receiver gets it at its next check, so the timing is said
			expect(
				within(box).getByText('Devices get this when they next ask for their policy.')
			).toBeInTheDocument();
		}
		expect(within(group('policies.features_title')).queryByText(/receiver app/)).toBeNull();
	});

	test('once an app applies the device groups, the notice is gone', async () => {
		signIn('global_admin', EDITOR);
		deviceAppApplies = true;
		await openPage();
		expect(
			within(group('policies.features_title')).getByText(
				'Devices get this when they next ask for their policy.'
			)
		).toBeInTheDocument();
		expect(screen.queryByText(/No NeoDesk app applies this group yet/)).toBeNull();
	});

	test('no internal key is on screen; the filter still finds a setting by it', async () => {
		signIn('global_admin', EDITOR);
		const user = userEvent.setup();
		await openPage();
		expect(screen.queryByText('features.allow_audio')).toBeNull();
		expect(document.getElementById('pol-features-allow-audio')).toHaveAttribute(
			'data-setting',
			'features.allow_audio'
		);
		await user.type(screen.getByRole('searchbox', { name: 'Filter policy settings' }), 'allow_audio');
		expect(document.getElementById('pol-features-allow-audio')).not.toHaveAttribute('hidden');
		expect(document.getElementById('pol-features-allow-clipboard')).toHaveAttribute('hidden');
	});

	test('task 5: sound off where nothing was set is one click, saved as the only rule of the group, with Undo', async () => {
		signIn('global_admin', EDITOR);
		const user = userEvent.setup();
		await openPage();
		await user.click(within(choice('policies.allow_audio')).getByRole('radio', { name: 'Off' }));
		expect(within(choice('policies.allow_audio')).getByRole('radio', { name: 'Off' })).toBeChecked();
		expect(screen.getByText('1 unsaved change')).toBeInTheDocument();
		expect(document.getElementById('pol-features-allow-audio')).toHaveClass('is-set', 'is-changed');
		await user.click(screen.getByRole('button', { name: 'policies.save_button' }));
		await vi.waitFor(() =>
			expect(writes).toEqual([
				{ call: 'PUT /api/panel/policies/org-1/features', body: { allow_audio: false } }
			])
		);
		await vi.waitFor(() =>
			expect(
				screen.getByRole('button', { name: 'Remove all rules of this group: policies.features_title' })
			).toBeInTheDocument()
		);
		const saved = toasts.items.at(-1);
		expect(saved?.message).toMatch(/policies\.allow_audio Off/);
		saved?.action?.onclick();
		await vi.waitFor(() =>
			expect(writes.at(-1)).toEqual({ call: 'DELETE /api/panel/policies/org-1/features', body: undefined })
		);
	});

	test('picking "Not set" again is no change; a number field emptied is no rule', async () => {
		signIn('global_admin', EDITOR);
		stored = { connection: { idle_lock_timeout: 30 } };
		const user = userEvent.setup();
		await openPage();
		const audio = choice('policies.allow_audio');
		await user.click(within(audio).getByRole('radio', { name: 'On' }));
		await user.click(within(audio).getByRole('radio', { name: 'Not set' }));
		expect(screen.queryByText('1 unsaved change')).toBeNull();
		await user.clear(screen.getByLabelText('policies.idle_lock'));
		expect(
			within(document.getElementById('pol-connection-idle-lock-timeout')!).getByText(
				'Not set (each device decides)'
			)
		).toBeInTheDocument();
		await user.click(screen.getByRole('button', { name: 'policies.save_button' }));
		await vi.waitFor(() =>
			expect(writes).toEqual([{ call: 'DELETE /api/panel/policies/org-1/connection', body: undefined }])
		);
	});

	test('"Remove the rule" sits beside a set control and puts the focus on it, now "Not set"', async () => {
		signIn('global_admin', EDITOR);
		stored = { connection: { mode: 'unattended' } };
		const user = userEvent.setup();
		await openPage();
		const remove = screen.getByRole('button', { name: 'Remove the rule: policies.connection_mode' });
		expect(remove.closest('.setting-control')).toContainElement(
			screen.getByLabelText('policies.connection_mode')
		);
		// Only set settings have it
		expect(screen.queryByRole('button', { name: 'Remove the rule: policies.idle_lock' })).toBeNull();
		remove.focus();
		await user.keyboard('{Enter}');
		await vi.waitFor(() => expect(screen.getByLabelText('policies.connection_mode')).toHaveFocus());
		expect(screen.getByLabelText('policies.connection_mode')).toHaveValue('');
	});

	test('changing one setting sends only that group with only its rules', async () => {
		signIn('global_admin', EDITOR);
		stored = { connection: { mode: 'unattended' }, update: { channel: 'beta' } };
		const user = userEvent.setup();
		await openPage();
		await user.selectOptions(screen.getByLabelText('policies.connection_mode'), 'attended');
		await user.click(screen.getByRole('button', { name: 'policies.save_button' }));
		await vi.waitFor(() =>
			expect(writes).toEqual([
				{ call: 'PUT /api/panel/policies/org-1/connection', body: { mode: 'attended' } }
			])
		);
	});

	test('removing the last rule of a group clears the group', async () => {
		signIn('global_admin', EDITOR);
		stored = { update: { channel: 'beta' } };
		const user = userEvent.setup();
		await openPage();
		await user.click(screen.getByRole('button', { name: 'Remove the rule: policies.update_channel' }));
		await user.click(screen.getByRole('button', { name: 'policies.save_button' }));
		await vi.waitFor(() =>
			expect(writes).toEqual([{ call: 'DELETE /api/panel/policies/org-1/update', body: undefined }])
		);
	});

	test('"Remove all rules of this group" shows only on a group with rules, asks, then clears it', async () => {
		signIn('global_admin', EDITOR);
		stored = { security: { require_2fa: true, password_min_length: 12 } };
		const user = userEvent.setup();
		await openPage();
		// A group without rules has nothing to remove
		expect(
			screen.queryByRole('button', { name: 'Remove all rules of this group: policies.update_title' })
		).toBeNull();
		// A button with its outline, not text beside the group's status
		expect(
			screen.getByRole('button', { name: 'Remove all rules of this group: policies.security_title' })
		).not.toHaveClass('btn-ghost');
		await user.click(
			screen.getByRole('button', { name: 'Remove all rules of this group: policies.security_title' })
		);
		expect(confirm).toHaveBeenCalledOnce();
		await vi.waitFor(() =>
			expect(writes).toEqual([{ call: 'DELETE /api/panel/policies/org-1/security', body: undefined }])
		);
		await vi.waitFor(() =>
			expect(
				screen.queryByRole('button', { name: 'Remove all rules of this group: policies.security_title' })
			).toBeNull()
		);
	});

	test('allowed operators are account usernames, one per row, as the server checks them (A279)', async () => {
		signIn('global_admin', EDITOR);
		stored = { security: { allowed_operators: ['remote_operator', 'demo_operator'] } };
		const user = userEvent.setup();
		await openPage();
		await vi.waitFor(() =>
			expect(screen.getByRole('textbox', { name: 'Account 1' })).toHaveValue('remote_operator')
		);
		expect(screen.getByRole('textbox', { name: 'Account 2' })).toHaveValue('demo_operator');
		// No role picker: a role name would never match a caller
		expect(screen.queryByRole('checkbox', { name: 'admin' })).toBeNull();
		await user.click(screen.getByRole('button', { name: 'Add an account' }));
		await user.type(screen.getByRole('textbox', { name: 'Account 3' }), 'anna');
		await user.click(screen.getByRole('button', { name: 'policies.save_button' }));
		await vi.waitFor(() =>
			expect(writes).toEqual([
				{
					call: 'PUT /api/panel/policies/org-1/security',
					body: { allowed_operators: ['remote_operator', 'demo_operator', 'anna'] }
				}
			])
		);
	});

	test('a wrong IP range is named under its own row and nothing is saved (BUGS L395)', async () => {
		signIn('global_admin', EDITOR);
		const user = userEvent.setup();
		await openPage();
		await user.click(screen.getByRole('button', { name: 'Add an IP range' }));
		await user.type(screen.getByRole('textbox', { name: 'IP range 1' }), 'not-a-cidr');
		expect(screen.getByRole('textbox', { name: 'IP range 1' })).toHaveAccessibleDescription(
			'Not an IP address or range.'
		);
		await user.click(screen.getByRole('button', { name: 'policies.save_button' }));
		expect(writes).toEqual([]);
		await user.clear(screen.getByRole('textbox', { name: 'IP range 1' }));
		await user.type(screen.getByRole('textbox', { name: 'IP range 1' }), '10.0.0.0/8');
		await user.click(screen.getByRole('button', { name: 'policies.save_button' }));
		await vi.waitFor(() =>
			expect(writes).toEqual([
				{ call: 'PUT /api/panel/policies/org-1/network', body: { ip_allowlist: ['10.0.0.0/8'] } }
			])
		);
	});

	test('relay servers from the Relay servers list are offered with one click', async () => {
		signIn('global_admin', EDITOR);
		const user = userEvent.setup();
		await openPage();
		await user.click(await screen.findByRole('button', { name: 'Frankfurt (relay-fra.example.net:21117)' }));
		expect(screen.getByRole('textbox', { name: 'Relay server 1' })).toHaveValue(
			'relay-fra.example.net:21117'
		);
		expect(screen.getByText('1 unsaved change')).toBeInTheDocument();
	});
});
