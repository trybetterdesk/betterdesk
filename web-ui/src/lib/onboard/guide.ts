/**
 * The guided first join (Add a computer): once a computer joins with the
 * invite, the invite sheet walks the admin through four steps. The sheet
 * follows the join by asking the server every few seconds (there is no
 * push of a join to the console).
 */

import type { InviteDetail, InviteDevice } from '#lib/api/onboard.ts';

export const GUIDE_STEPS = ['name', 'folder', 'reach', 'test'] as const;
export type GuideStep = (typeof GUIDE_STEPS)[number];

/** How often the sheet asks whether the computer joined, and whether it is online */
export const FOLLOW_MS = 3000;

/**
 * The ways to reach a joined computer that exist today, as the reach step
 * explains them (language keys below onboard.guide). The full desktop app
 * takes a permanent password someone sets at the computer; the receiver
 * app has none and lets staff in without asking only as the policy says
 * (A279).
 */
export const REACH_OPTIONS = ['onboard.guide.reach_accept', 'onboard.guide.reach_password'] as const;
export const RECEIVER_REACH_OPTIONS = ['onboard.guide.reach_accept', 'onboard.guide.reach_policy'] as const;

/** The device type the receiver app reports (and the Support Agent before it) */
export const RECEIVER_TYPE = 'neodesk-support';

/** The reach step's lines for a computer: the receiver's, or the desktop app's */
export function reachOptions(d: { device_type?: string }): readonly string[] {
	return d.device_type === RECEIVER_TYPE ? RECEIVER_REACH_OPTIONS : REACH_OPTIONS;
}

/** The next computer of the invite to walk through: the first not set up yet in this sheet */
export function nextDevice(detail: InviteDetail | null, done: ReadonlySet<string>): InviteDevice | null {
	return detail?.devices.find((d) => !done.has(d.id)) ?? null;
}

/** The name a joined computer shows: its name, else its host name, else its ID */
export function deviceLabel(d: Pick<InviteDevice, 'id' | 'name' | 'hostname'>): string {
	return d.name || d.hostname || d.id;
}
