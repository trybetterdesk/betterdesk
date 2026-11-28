/**
 * The guided first join: once a computer joins with the invite, the invite
 * sheet turns into four steps (name, folder, how you reach it, a test
 * session), each saved through the routes the device panel uses; Skip
 * leaves the computer as it joined. A computer that came back with another
 * key gets Approve new key.
 */
import { cleanup, render, screen, waitFor, within } from '@testing-library/svelte';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import { REACH_OPTIONS } from '../../src/lib/onboard/guide.ts';
import { go } from '../../src/lib/onboard/quick-support.ts';
import { session } from '../../src/lib/state/session.svelte.ts';

vi.mock('$app/paths', () => ({ resolve: (p: string) => p || '/', asset: (p: string) => '/' + p }));

const AddComputerDialog = (await import('../../src/lib/onboard/AddComputerDialog.svelte')).default;
const DialogHost = (await import('../../src/lib/ui/DialogHost.svelte')).default;

type Call = { method: string; path: string; body: unknown };
let calls: Call[];
let routes: Record<string, (body: unknown) => { status?: number; body: unknown }>;
let joined: unknown[];
let refused: unknown;

const invite = {
	id: '0123456789abcdef',
	name: "Anna's laptop",
	folder_id: null,
	folder_name: '',
	email: '',
	created_by: 'e2e_admin',
	created_at: '2026-11-25T12:00:00Z',
	expires_at: '2026-12-01T12:00:00Z',
	max_uses: 1,
	uses_left: 1
};
const anna = {
	id: '523456789',
	name: "Anna's laptop",
	hostname: 'anna-pc',
	platform: 'Windows',
	folder_id: null,
	folder_name: '',
	online: true,
	joined_at: '2026-11-25T12:03:00Z'
};

beforeEach(() => {
	session.isSuperAdmin = true;
	calls = [];
	joined = [];
	refused = null;
	routes = {
		'GET /api/onboard/status': () => ({
			body: { success: true, console: { base: 'https://desk.example.com', https: true }, mail: false }
		}),
		'GET /api/onboard/invites': () => ({ body: { success: true, invites: [] } }),
		'POST /api/onboard/invites': () => ({
			status: 201,
			body: {
				success: true,
				invite,
				code: 'ABCD2345',
				display_code: 'ABCD-2345',
				link: 'https://desk.example.com/join/ABCD2345',
				deep_link: 'neodesk://join/desk.example.com/ABCD2345',
				mailed: false
			}
		}),
		'GET /api/onboard/invites/0123456789abcdef': () => ({
			body: { success: true, invite, devices: joined, refused }
		}),
		'PATCH /api/devices/523456789': () => ({ body: { success: true } }),
		'PATCH /api/devices/523456789/folder': () => ({ body: { success: true } }),
		'POST /api/onboard/devices/289485454/approve-key': () => ({ body: { success: true } })
	};
	vi.stubGlobal(
		'fetch',
		vi.fn(async (input: string, init?: RequestInit) => {
			const url = new URL(input, 'http://localhost');
			const method = init?.method ?? 'GET';
			const body = init?.body ? JSON.parse(String(init.body)) : null;
			calls.push({ method, path: url.pathname, body });
			const route = routes[`${method} ${url.pathname}`];
			const out = route ? route(body) : { status: 404, body: { success: false, error: 'nope' } };
			return new Response(JSON.stringify(out.body), {
				status: out.status ?? 200,
				headers: { 'Content-Type': 'application/json' }
			});
		})
	);
});

afterEach(() => {
	cleanup();
	session.isSuperAdmin = false;
	vi.unstubAllGlobals();
	vi.restoreAllMocks();
});

async function makeInvite() {
	render(AddComputerDialog, { folders: [{ id: 7, name: 'Sales', color: '', icon: '' }], onclose: () => {} });
	const user = userEvent.setup();
	await user.click(screen.getByRole('button', { name: 'onboard.invite.create' }));
	expect(await screen.findByText('ABCD-2345')).toBeInTheDocument();
	return user;
}

describe('the guided first join', () => {
	test('the invite sheet follows the join and walks through name, folder, reach and a test session', async () => {
		const opened: string[] = [];
		vi.spyOn(go, 'tab').mockImplementation((url: string) => void opened.push(url));
		const user = await makeInvite();
		expect(await screen.findByText('onboard.guide.waiting_named')).toBeInTheDocument();

		joined = [anna];
		expect(
			await screen.findByRole('heading', { name: 'onboard.guide.joined_title' }, { timeout: 8000 })
		).toBeInTheDocument();
		expect(screen.getByText('onboard.guide.step_of')).toBeInTheDocument();

		// Name
		const name = screen.getByLabelText('onboard.guide.step_name');
		expect(name).toHaveValue("Anna's laptop");
		await user.clear(name);
		await user.type(name, 'Anna PC');
		await user.click(screen.getByRole('button', { name: 'onboard.guide.next' }));
		await waitFor(() =>
			expect(calls.find((c) => c.method === 'PATCH' && c.path === '/api/devices/523456789')?.body).toEqual({
				display_name: 'Anna PC'
			})
		);

		// Folder
		await user.selectOptions(await screen.findByLabelText('onboard.guide.step_folder'), '7');
		await user.click(screen.getByRole('button', { name: 'onboard.guide.next' }));
		await waitFor(() =>
			expect(calls.find((c) => c.path === '/api/devices/523456789/folder')?.body).toEqual({ folderId: 7 })
		);

		// How you reach it: what exists today, no buttons
		for (const key of REACH_OPTIONS) expect(await screen.findByText(key)).toBeInTheDocument();
		await user.click(screen.getByRole('button', { name: 'onboard.guide.next' }));

		// Test session
		await user.click(await screen.findByRole('button', { name: 'onboard.guide.test_start' }));
		// A tab of its own gets the viewer on its own, not a second console (L479)
		expect(opened).toEqual(['/remote/523456789?standalone=1']);
		await user.click(screen.getByRole('button', { name: 'onboard.guide.done' }));
		expect(await screen.findByText('onboard.guide.finished')).toBeInTheDocument();
	}, 20000);

	test('Skip leaves the computer as it joined', async () => {
		const user = await makeInvite();
		joined = [anna];
		await screen.findByRole('heading', { name: 'onboard.guide.joined_title' }, { timeout: 8000 });
		await user.click(screen.getByRole('button', { name: 'onboard.guide.skip' }));
		expect(await screen.findByText('onboard.guide.finished')).toBeInTheDocument();
		expect(calls.some((c) => c.method === 'PATCH')).toBe(false);
	}, 20000);

	test('a receiver is not sent to a password: unattended access follows the policy', async () => {
		const user = await makeInvite();
		joined = [{ ...anna, device_type: 'neodesk-support' }];
		await screen.findByRole('heading', { name: 'onboard.guide.joined_title' }, { timeout: 8000 });
		for (let i = 0; i < 2; i++) await user.click(screen.getByRole('button', { name: 'onboard.guide.next' }));
		expect(await screen.findByText('onboard.guide.reach_policy')).toBeInTheDocument();
		expect(screen.getByText('onboard.guide.reach_accept')).toBeInTheDocument();
		expect(screen.queryByText('onboard.guide.reach_password')).toBeNull();
	}, 20000);

	test('an offline computer gets no test session button, only why', async () => {
		const user = await makeInvite();
		joined = [{ ...anna, online: false }];
		await screen.findByRole('heading', { name: 'onboard.guide.joined_title' }, { timeout: 8000 });
		for (let i = 0; i < 3; i++) await user.click(screen.getByRole('button', { name: 'onboard.guide.next' }));
		expect(await screen.findByText('onboard.guide.test_offline')).toBeInTheDocument();
		expect(screen.queryByRole('button', { name: 'onboard.guide.test_start' })).toBeNull();
	}, 20000);

	test('a computer that was here with another key gets Approve new key, after a confirmation', async () => {
		render(DialogHost);
		const user = await makeInvite();
		refused = {
			device_id: '289485454',
			reason: 'key_changed',
			at: '2026-11-25T12:05:00Z',
			key_request: true
		};
		await user.click(
			await screen.findByRole('button', { name: 'onboard.guide.approve_key' }, { timeout: 8000 })
		);
		// A new key ends the computer's tokens and sessions: the sheet asks
		// first, as the device panel does (L522)
		const ask = await screen.findByRole('dialog', { name: /approve_key_title|Approve new key/ });
		expect(calls.some((c) => c.path.endsWith('/approve-key'))).toBe(false);
		await user.click(
			within(ask).getByRole('button', { name: /^(device_detail.approve_key|Approve new key)$/ })
		);
		expect(
			calls.some((c) => c.method === 'POST' && c.path === '/api/onboard/devices/289485454/approve-key')
		).toBe(true);
		expect(await screen.findByText('onboard.guide.key_approved')).toBeInTheDocument();
	}, 20000);
});
