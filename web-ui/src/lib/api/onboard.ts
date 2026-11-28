/**
 * "Add a computer" (invites, join codes) and "Quick support" (support
 * codes and their sessions). Invites need enrollment.approve, quick
 * support device.connect. A code is shown once: in the answer that makes
 * it. The public routes (/api/onboard/public/...) back the pages /join/<code>
 * and /s/<code>; every code that cannot be used answers the same 404.
 */

import * as v from 'valibot';
import { api, request } from './client.ts';

/** Text the server may leave out or send as null */
const Text = v.optional(
	v.pipe(
		v.nullable(v.union([v.string(), v.number()])),
		v.transform((s) => (s === null ? '' : String(s)))
	),
	''
);
const Bool = v.optional(
	v.pipe(
		v.nullable(v.boolean()),
		v.transform((b) => b === true)
	),
	false
);
const Num = v.optional(
	v.pipe(
		v.nullable(v.number()),
		v.transform((n) => n ?? 0)
	),
	0
);
const Id = v.pipe(v.union([v.string(), v.number()]), v.transform(String));
const FolderId = v.optional(v.nullable(v.number()), null);

export const OnboardStatus = v.object({
	console: v.object({ base: Text, https: Bool }),
	mail: Bool,
	release: v.optional(v.object({ source: Text, tag: Text, verified: Bool, packages: Num, error: Text }), {
		source: '',
		tag: '',
		verified: false,
		packages: 0,
		error: ''
	})
});
export type OnboardStatus = v.InferOutput<typeof OnboardStatus>;

export const Invite = v.object({
	id: Id,
	name: Text,
	folder_id: FolderId,
	folder_name: Text,
	email: Text,
	created_by: Text,
	created_at: Text,
	expires_at: Text,
	max_uses: Num,
	uses_left: Num
});
export type Invite = v.InferOutput<typeof Invite>;

export const SESSION_STATES = [
	'waiting',
	'opened',
	'asking',
	'allowed',
	'declined',
	'ended',
	'expired'
] as const;
export type SessionState = (typeof SESSION_STATES)[number];

export const SupportSession = v.object({
	id: Id,
	status: v.picklist(SESSION_STATES),
	name: Text,
	email: Text,
	folder_id: FolderId,
	created_by: Text,
	created_at: Text,
	expires_at: Text,
	redeemed_at: Text,
	consent_at: Text,
	ended_at: Text,
	ended_by: Text,
	/** Why the server ended it (ended_by refused): a failure reason of failures.ts */
	end_reason: v.optional(Text, ''),
	device_id: Text,
	hostname: Text,
	platform: Text,
	password_ready: Bool
});
export type SupportSession = v.InferOutput<typeof SupportSession>;

/** What the answer to a new invite or session carries besides the record */
const Created = {
	code: Text,
	display_code: Text,
	link: Text,
	deep_link: Text,
	mailed: Bool,
	mail_error: Text
};

export const NewInvite = v.object({ invite: Invite, ...Created });
export type NewInvite = v.InferOutput<typeof NewInvite>;

export const NewSession = v.object({ session: SupportSession, ...Created });
export type NewSession = v.InferOutput<typeof NewSession>;

export interface InviteRequest {
	name?: string;
	folder_id?: number | null;
	email?: string;
	lifetime_hours?: number;
	uses?: number;
	send_email?: boolean;
}

export interface SessionRequest {
	name?: string;
	email?: string;
	folder_id?: number | null;
	send_email?: boolean;
}

const enc = encodeURIComponent;

export function getOnboardStatus(signal?: AbortSignal): Promise<OnboardStatus> {
	return api(OnboardStatus, '/api/onboard/status', { signal });
}

export async function listInvites(signal?: AbortSignal): Promise<Invite[]> {
	return (await api(v.object({ invites: v.array(Invite) }), '/api/onboard/invites', { signal })).invites;
}

export function createInvite(body: InviteRequest): Promise<NewInvite> {
	return api(NewInvite, '/api/onboard/invites', { method: 'POST', body });
}

/** A computer that joined with an invite, as the invite sheet's steps start from it */
export const InviteDevice = v.object({
	id: Id,
	name: Text,
	hostname: Text,
	platform: Text,
	folder_id: FolderId,
	folder_name: Text,
	online: Bool,
	joined_at: Text,
	/** What it runs: "neodesk-support" for the receiver app, "neodesk" for the desktop app, "" until it says */
	device_type: Text
});
export type InviteDevice = v.InferOutput<typeof InviteDevice>;

export const InviteDetail = v.object({
	invite: Invite,
	devices: v.optional(v.array(InviteDevice), []),
	/** The last computer the invite turned away: key_changed (its ID is enrolled with another key) or refused */
	refused: v.optional(
		v.nullable(v.object({ device_id: Text, reason: Text, at: Text, key_request: Bool })),
		null
	)
});
export type InviteDetail = v.InferOutput<typeof InviteDetail>;

/**
 * An invite and the computers that joined with it, also once they used it
 * up; the invite sheet polls it to follow the join. An ApiError 404 once the
 * invite is revoked or past its end.
 */
export function getInvite(id: string, signal?: AbortSignal): Promise<InviteDetail> {
	return api(InviteDetail, `/api/onboard/invites/${enc(id)}`, { signal, activity: false });
}

export async function revokeInvite(id: string): Promise<void> {
	await request(`/api/onboard/invites/${enc(id)}`, { method: 'DELETE' });
}

/** Mail the link of an invite: the browser still has the code, the server only its fingerprint */
export async function mailInvite(id: string, code: string, to: string): Promise<void> {
	await request(`/api/onboard/invites/${enc(id)}/mail`, { method: 'POST', body: { code, to } });
}

export async function listSessions(signal?: AbortSignal): Promise<SupportSession[]> {
	return (await api(v.object({ sessions: v.array(SupportSession) }), '/api/support/sessions', { signal }))
		.sessions;
}

export function createSession(body: SessionRequest): Promise<NewSession> {
	return api(NewSession, '/api/support/sessions', { method: 'POST', body });
}

export async function getSession(id: string, signal?: AbortSignal): Promise<SupportSession> {
	return (await api(v.object({ session: SupportSession }), `/api/support/sessions/${enc(id)}`, { signal }))
		.session;
}

/** The session password the person's app handed over; the server forgets it as it answers */
export async function takeSessionPassword(id: string): Promise<string> {
	return (
		await api(v.object({ password: v.string() }), `/api/support/sessions/${enc(id)}/password`, {
			method: 'POST'
		})
	).password;
}

/** This account's quick support session on a device, as the viewer needs it */
export interface DeviceSupport {
	/** The session password the person's app handed over, '' when the server has none */
	password: string;
	/** The session that runs on the device: the person accepts there, nobody types a password */
	session: { name: string; status: string } | null;
}

/**
 * The password of this account's allowed quick support session on a device,
 * for the browser viewer when the device asks, and the session itself even
 * when the server holds no password (a restart loses it, and it is handed
 * out once).
 */
export async function takeDevicePassword(deviceId: string): Promise<DeviceSupport> {
	try {
		const out = await api(
			v.object({
				password: v.string(),
				session: v.optional(v.nullable(v.object({ name: v.string(), status: v.string() })), null)
			}),
			`/api/support/devices/${enc(deviceId)}/password`,
			{ method: 'POST', allowAnonymous: true, activity: false }
		);
		return { password: out.password, session: out.session ?? null };
	} catch {
		return { password: '', session: null };
	}
}

/**
 * What the quick support app on the device was told about the caller of a
 * relay session (A273): vouched (the person sees Allow), not_allowed_yet
 * (the person has not clicked Allow in the quick support window),
 * not_https, refused, or not_asked (the app did not ask: an app too old to
 * accept by click never does). appHttps is whether the app reaches the
 * console over HTTPS, null when the console has not heard from it.
 */
export interface SupportCaller {
	state: 'vouched' | 'not_allowed_yet' | 'not_https' | 'refused' | 'not_asked';
	appHttps: boolean | null;
}

/** The caller check of this account's quick support session on a device, for the viewer; null when the server can't say */
export async function supportCaller(deviceId: string, session: string): Promise<SupportCaller | null> {
	try {
		const out = await api(
			v.object({
				state: v.picklist(['vouched', 'not_allowed_yet', 'not_https', 'refused', 'not_asked']),
				app_https: v.optional(v.boolean())
			}),
			`/api/support/devices/${enc(deviceId)}/caller`,
			{ method: 'POST', body: { session }, activity: false }
		);
		return { state: out.state, appHttps: out.app_https ?? null };
	} catch {
		return null;
	}
}

export async function endSession(id: string): Promise<SupportSession> {
	return (
		await api(v.object({ session: SupportSession }), `/api/support/sessions/${enc(id)}`, { method: 'DELETE' })
	).session;
}

export async function mailSession(id: string, code: string, to: string): Promise<void> {
	await request(`/api/support/sessions/${enc(id)}/mail`, { method: 'POST', body: { code, to } });
}

/* ── The public pages ── */

export const PublicDownload = v.object({
	os: v.picklist(['windows', 'macos', 'linux']),
	arch: Text,
	format: Text,
	version: Text,
	size: Num,
	file: Text,
	url: Text
});
export type PublicDownload = v.InferOutput<typeof PublicDownload>;

export const PublicCode = v.object({
	kind: v.picklist(['join', 'support']),
	code: Text,
	display_code: Text,
	expires_at: Text,
	/** address: the console's address a client joins with a code alone (http://10.0.0.5:3375) */
	server: v.object({ name: Text, host: Text, https: Bool, address: Text }),
	publisher: Text,
	supporter: Text,
	company: Text,
	downloads: v.optional(v.array(PublicDownload), []),
	install_command: Text,
	run_command: Text,
	deep_link: Text,
	release_error: Text
});
export type PublicCode = v.InferOutput<typeof PublicCode>;

/** The page data of a code; an ApiError with status 404 for any code that cannot be used */
export function getPublicCode(code: string, signal?: AbortSignal): Promise<PublicCode> {
	return api(PublicCode, `/api/onboard/public/${enc(code)}`, { signal, allowAnonymous: true });
}
