/**
 * Devices, folders, tags and device groups (routes/devices.routes.js,
 * routes/folders.routes.js). Shapes are the server's; schemas accept what
 * it sends today (SQLite booleans, nulls) and hand the page clean values.
 */

import * as v from 'valibot';
import { api, request, wrapped, BoolLike, Text, Ok, ApiError, clientMessages } from './client.ts';

const Str = Text;
const Tags = v.pipe(
	v.optional(v.nullable(v.union([v.array(v.string()), v.string()]))),
	v.transform((t) =>
		Array.isArray(t)
			? t
			: String(t ?? '')
					.split(',')
					.map((s) => s.trim())
					.filter(Boolean)
	)
);
const NullableNum = v.pipe(
	v.optional(v.nullable(v.union([v.number(), v.string()]))),
	v.transform((n) => (n === null || n === undefined || n === '' ? null : Number(n)))
);

export const DeviceGroupRow = v.looseObject({
	id: v.optional(v.union([v.number(), v.string()])),
	guid: Str,
	name: Str,
	note: Str,
	source_type: Str,
	tag_filter: Str
});
export type DeviceGroupRow = v.InferOutput<typeof DeviceGroupRow>;

export const Device = v.looseObject({
	id: v.pipe(v.union([v.string(), v.number()]), v.transform(String)),
	hostname: Str,
	display_name: Str,
	username: Str,
	platform: Str,
	os: Str,
	version: Str,
	ip: Str,
	note: Str,
	online: BoolLike,
	signal_ready: BoolLike,
	banned: BoolLike,
	no_signal: BoolLike,
	created_at: Str,
	last_online: Str,
	ban_reason: Str,
	banned_at: Str,
	folder_id: NullableNum,
	tags: Tags,
	status_tier: Str,
	soft_deleted: BoolLike,
	deleted_at: Str,
	device_type: Str,
	client_type: Str,
	cdap_connected: BoolLike,
	mesh_connected: BoolLike,
	linked_peer_id: Str,
	remote_target: BoolLike,
	remote_protocol: Str,
	/* RDP/VNC targets in the list also carry their connection settings */
	host: v.optional(v.nullable(v.string())),
	port: v.optional(v.nullable(v.union([v.number(), v.string()]))),
	credential_mode: v.optional(v.nullable(v.string())),
	tls_mode: v.optional(v.nullable(v.string())),
	cert_fingerprint: v.optional(v.nullable(v.string())),
	enabled: v.optional(v.nullable(v.boolean())),
	name: v.optional(v.nullable(v.string())),
	groups: v.pipe(
		v.optional(v.nullable(v.array(DeviceGroupRow))),
		v.transform((g) => g ?? [])
	),
	/** An RDP or VNC target that is switched off (see listedDevice) */
	disabled: v.optional(v.boolean(), false)
});
export type Device = v.InferOutput<typeof Device>;

/**
 * The server sends a switched-off RDP or VNC target as soft_deleted. It is
 * not deleted: it stays listed as disabled and can be edited.
 */
function listedDevice<T extends { remote_target?: boolean; soft_deleted?: boolean; disabled: boolean }>(
	d: T
): T {
	if (d.remote_target && d.soft_deleted) {
		d.soft_deleted = false;
		d.disabled = true;
	}
	return d;
}

export const DeviceList = wrapped(
	v.looseObject({
		devices: v.array(v.pipe(Device, v.transform(listedDevice))),
		total: v.optional(v.number())
	})
);

export interface ListQuery {
	search?: string;
	status?: 'online' | 'offline' | 'banned' | '';
	hasNotes?: boolean;
	includeDeleted?: boolean;
	sortBy?: 'last_online' | 'id' | 'hostname' | 'created_at' | 'os' | 'version' | 'username' | 'note';
	sortOrder?: 'asc' | 'desc';
}

export async function listDevices(q: ListQuery = {}, signal?: AbortSignal): Promise<Device[]> {
	const out = await api(DeviceList, '/api/devices', {
		signal,
		query: {
			search: q.search,
			status: q.status,
			hasNotes: q.hasNotes ? 'true' : undefined,
			includeDeleted: q.includeDeleted ? 'true' : undefined,
			sortBy: q.sortBy,
			sortOrder: q.sortOrder
		}
	});
	return out.devices;
}

/** A new key an enrolled computer brought to an invite (a reinstall or a reset makes one) */
export const KeyRequest = v.object({
	hostname: Str,
	platform: Str,
	ip: Str,
	requested_at: Str,
	fingerprint: Str
});
export type KeyRequest = v.InferOutput<typeof KeyRequest>;

export const DeviceDetail = v.looseObject({
	...Device.entries,
	sysinfo: v.optional(v.nullable(v.looseObject({}))),
	metrics: v.optional(v.nullable(v.looseObject({}))),
	telemetry: v.optional(v.nullable(v.looseObject({}))),
	connection_mode: v.optional(v.nullable(v.looseObject({}))),
	banned_by: Str,
	key_request: v.optional(v.nullable(KeyRequest)),
	/** It came back with another key, which the server refuses: no session reaches it */
	key_refused: v.optional(v.boolean(), false)
});
export type DeviceDetail = v.InferOutput<typeof DeviceDetail>;

export function getDevice(id: string, signal?: AbortSignal): Promise<DeviceDetail> {
	return api(
		wrapped(v.pipe(DeviceDetail, v.transform(listedDevice))),
		`/api/devices/${encodeURIComponent(id)}`,
		{
			signal
		}
	);
}

export function updateDevice(id: string, fields: { user?: string; note?: string; display_name?: string }) {
	return api(Ok, `/api/devices/${encodeURIComponent(id)}`, { method: 'PATCH', body: fields });
}

export function banDevice(id: string, reason: string) {
	return api(Ok, `/api/devices/${encodeURIComponent(id)}/ban`, { method: 'POST', body: { reason } });
}

export function unbanDevice(id: string) {
	return api(Ok, `/api/devices/${encodeURIComponent(id)}/unban`, { method: 'POST' });
}

export function deleteDevice(id: string, opts: { revoke?: boolean; cascade?: boolean; hard?: boolean } = {}) {
	return request(`/api/devices/${encodeURIComponent(id)}`, {
		method: 'DELETE',
		query: {
			revoke: opts.revoke ? 'true' : undefined,
			cascade: opts.cascade ? 'true' : undefined,
			hard: opts.hard ? 'true' : undefined
		}
	});
}

export const DeviceReach = v.object({
	/** online, or a failure reason of the server (failures.ts): device_offline, device_revoked, ... */
	reason: Text,
	last_online: v.optional(Text, ''),
	/** This account may unblock a revoked or blocked ID */
	can_unblock: v.optional(BoolLike, false)
});
export type DeviceReach = v.InferOutput<typeof DeviceReach>;

/** Why the server can or cannot reach the computer, as it knows it */
export function getDeviceReach(id: string, signal?: AbortSignal): Promise<DeviceReach> {
	return api(DeviceReach, `/api/devices/${encodeURIComponent(id)}/reach`, { signal, activity: false });
}

/** The computer's ID leaves the server's blocklist: it can register and join again */
export function unblockDevice(id: string) {
	return api(Ok, `/api/devices/${encodeURIComponent(id)}/unblock`, { method: 'POST' });
}

export function restoreDevice(id: string) {
	return api(Ok, `/api/devices/${encodeURIComponent(id)}/restore`, { method: 'POST' });
}

export function bulkDeleteDevices(ids: string[]) {
	return api(Ok, '/api/devices/bulk-delete', { method: 'POST', body: { ids } });
}

export function changeDeviceId(id: string, newId: string) {
	return api(Ok, `/api/devices/${encodeURIComponent(id)}/change-id`, { method: 'POST', body: { newId } });
}

/** The computer's new key becomes its key; it rejoins with its invite, its old tokens end */
export function approveDeviceKey(id: string) {
	return api(Ok, `/api/onboard/devices/${encodeURIComponent(id)}/approve-key`, { method: 'POST' });
}

/** Ends every device token of the device; it gets a new one the next time it checks in */
export function issueDeviceToken(id: string) {
	return api(Ok, `/api/devices/${encodeURIComponent(id)}/device-token`, { method: 'POST' });
}

export function setDeviceTags(id: string, tags: string[]) {
	return api(
		wrapped(v.looseObject({ tags: v.array(v.string()) })),
		`/api/devices/${encodeURIComponent(id)}/tags`,
		{
			method: 'PUT',
			body: { tags }
		}
	);
}

/* ── Folders ── */

/**
 * A whole number, or the same in digits: on a PostgreSQL database the Go
 * server created, BIGSERIAL and BIGINT columns come as text ("4")
 */
const WholeNum = v.union([
	v.number(),
	v.pipe(v.string(), v.regex(/^-?\d+$/), v.transform(Number), v.number())
]);

export const Folder = v.looseObject({
	id: WholeNum,
	name: v.string(),
	color: Str,
	icon: Str,
	sort_order: v.optional(WholeNum),
	device_count: v.optional(WholeNum),
	allowed_users: v.optional(v.array(v.string())),
	allowed_groups: v.optional(v.array(v.string()))
});
export type Folder = v.InferOutput<typeof Folder>;

export async function listFolders(signal?: AbortSignal): Promise<Folder[]> {
	const out = await api(wrapped(v.looseObject({ folders: v.array(Folder) })), '/api/folders', { signal });
	return out.folders;
}

/**
 * Folder fields. allowed_users is the comma-separated text the old console
 * sends (the server splits it); allowed_groups are user group GUIDs.
 */
export interface FolderInput {
	name?: string;
	color?: string;
	icon?: string;
	allowed_users?: string;
	allowed_groups?: string[];
}

export function createFolder(f: FolderInput & { name: string }) {
	return api(wrapped(Folder), '/api/folders', { method: 'POST', body: f });
}

export function updateFolder(id: number, f: FolderInput) {
	return api(Ok, `/api/folders/${id}`, { method: 'PATCH', body: f });
}

export function deleteFolder(id: number) {
	return api(Ok, `/api/folders/${id}`, { method: 'DELETE' });
}

/** Move devices into a folder; folderId 0 takes them out of any folder */
export function moveToFolder(folderId: number, deviceIds: string[]) {
	return api(Ok, `/api/folders/${folderId}/devices`, { method: 'POST', body: { deviceIds } });
}

/* ── Tags and device groups ── */

export async function listTags(signal?: AbortSignal): Promise<string[]> {
	const out = await api(wrapped(v.looseObject({ tags: v.array(v.string()) })), '/api/tags', { signal });
	return out.tags;
}

export const DeviceGroup = v.looseObject({
	...DeviceGroupRow.entries,
	member_count: v.optional(v.number()),
	allowed_users: v.optional(v.array(v.string())),
	allowed_groups: v.optional(v.array(v.string()))
});
export type DeviceGroup = v.InferOutput<typeof DeviceGroup>;

export async function listDeviceGroups(signal?: AbortSignal): Promise<DeviceGroup[]> {
	const out = await api(wrapped(v.looseObject({ groups: v.array(DeviceGroup) })), '/api/device-groups', {
		signal
	});
	return out.groups;
}

/* ── Calls the device list and the device panel share (lib/devices/actions.svelte.ts) ── */

const enc = encodeURIComponent;

/** Put one device in a folder, or take it out of any folder (null) */
export function setDeviceFolder(id: string, folderId: number | null) {
	return api(Ok, `/api/devices/${enc(id)}/folder`, { method: 'PATCH', body: { folderId } });
}

/** Every group the user can see, and the ones this device is in (tag matches and manual) */
export function getDeviceMemberships(id: string, signal?: AbortSignal) {
	return api(
		wrapped(
			v.looseObject({
				groups: v.optional(v.array(DeviceGroup), []),
				memberships: v.optional(v.array(DeviceGroup), [])
			})
		),
		`/api/devices/${enc(id)}/groups`,
		{ signal }
	);
}

/** Replace the device's manual groups (the server allows at most one) */
export function setDeviceGroups(id: string, groupGuids: string[]) {
	return api(Ok, `/api/devices/${enc(id)}/groups`, { method: 'PUT', body: { groupGuids } });
}

/** Soft-delete several devices at once (no revoke, cascade or hard delete) */
/** Soft-delete several devices; resolves how many the server deleted */
export async function bulkDelete(ids: string[]): Promise<number> {
	const out = await api(
		v.looseObject({ data: v.optional(v.looseObject({ deleted: v.optional(v.number()) })) }),
		'/api/devices/bulk-delete',
		{ method: 'POST', body: { ids } }
	);
	return out.data?.deleted ?? ids.length;
}

export const AccessPolicy = v.looseObject({
	/** The device's organization, "" for none */
	org_id: Str,
	unattended_enabled: BoolLike,
	password_set: BoolLike,
	schedule_enabled: BoolLike,
	schedule_days: Str,
	schedule_start_time: Str,
	schedule_end_time: Str,
	schedule_timezone: Str,
	allowed_operators: Str,
	updated_at: Str,
	updated_by: Str
});
export type AccessPolicy = v.InferOutput<typeof AccessPolicy>;

export interface AccessPolicyInput {
	unattended_enabled: boolean;
	password: string;
	clear_password: boolean;
	schedule_enabled: boolean;
	schedule_days: string;
	schedule_start_time: string;
	schedule_end_time: string;
	schedule_timezone: string;
	allowed_operators: string;
}

/**
 * The server answers a Go failure with HTTP 200 and success:false
 * (BUGS.md); that comes back here as an ApiError like any other failure.
 */
async function checkedOk(path: string, opts: Parameters<typeof request>[1]): Promise<unknown> {
	const data = await request(path, opts);
	if (data && typeof data === 'object' && (data as { success?: unknown }).success === false) {
		const err = (data as { error?: unknown }).error;
		throw new ApiError(
			typeof err === 'string' && err ? err : clientMessages.failed.replace('{status}', '200'),
			200,
			{
				data
			}
		);
	}
	return data;
}

export async function getAccessPolicy(id: string, signal?: AbortSignal): Promise<AccessPolicy> {
	const data = await checkedOk(`/api/devices/${enc(id)}/access-policy`, { signal });
	return v.parse(wrapped(AccessPolicy), data);
}

export async function saveAccessPolicy(id: string, policy: AccessPolicyInput): Promise<void> {
	await checkedOk(`/api/devices/${enc(id)}/access-policy`, { method: 'PUT', body: policy });
}

export type ConnectionMode = 'normal' | 'incoming-only';

export function setConnectionMode(id: string, mode: ConnectionMode, reason: string) {
	return api(Ok, `/api/devices/${enc(id)}/connection-mode`, { method: 'POST', body: { mode, reason } });
}

const TagChange = wrapped(
	v.looseObject({
		updatedDevices: v.optional(v.number(), 0),
		to: v.optional(v.string())
	})
);

/** Rename a tag on every device the user can see (and in tag groups) */
export function renameTag(from: string, to: string) {
	return api(TagChange, '/api/tags/rename', { method: 'POST', body: { from, to } });
}

/** Remove a tag from every device the user can see */
export function deleteTag(tag: string) {
	return api(TagChange, '/api/tags/delete', { method: 'POST', body: { tag } });
}

export interface DeviceGroupInput {
	/** Set when editing; empty creates a group */
	guid: string;
	name: string;
	source_type: 'manual' | 'tag';
	tag_filter: string;
	/** Comma-separated usernames, as the old console sends them */
	allowed_users: string;
	allowed_groups: string[];
	team_id?: string;
}

/** Create a group, or update the one with `guid` */
export function saveDeviceGroup(group: DeviceGroupInput) {
	return api(Ok, '/api/device-groups', { method: 'POST', body: group });
}

export function deleteDeviceGroup(guid: string) {
	return api(Ok, `/api/device-groups/${enc(guid)}`, { method: 'DELETE' });
}
