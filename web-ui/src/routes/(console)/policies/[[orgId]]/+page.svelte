<!--
  Organization policies (/policies, /policies/<orgId>) on the settings
  template (lib/ui/settings, PATTERN.md). The organization picker comes
  first, with how many devices it holds: policies reach only devices in an
  organization. Then five groups (connection, features, security, network,
  updates), each saying whether the organization set anything, when a
  change takes effect, and, for the four groups only devices apply, which
  of their settings the receiver app applies (session approval, removing
  the app) and that the full desktop app applies none of them yet (GET
  /api/panel/policies/<org>/resolved, receiver_applies and
  device_app_applies).

  Every setting's control is always there, with "not set" inside it
  (settings-pass-2.md rule B): a select whose first choice is "Not set", a
  Not set / On / Off choice for on/off settings ("Server value" first for
  Always connect through a relay, whose server value and its page are
  named under it), an empty number field or list with "Not set" beside
  it. One click sets a rule; "Remove the rule" beside a set control takes
  it away. A set row carries the accent rule. A note that holds for a
  whole group is said once on the group, never on its rows. Edit, then
  save: Save writes only the groups that changed (PUT with the settings
  that have a rule, DELETE when none is left), the toast names the changes
  and offers Undo. "Remove all rules of this group" shows only on a group
  that has a rule and clears it at once, after a question.

  URL: the organization is in the path; choosing another replaces the
  address. With a single organization it opens without one. An unknown ID
  in the address says so.

  Who: the four admin roles (requireAdmin); everyone else gets the 403
  text. Saving needs org.edit; an admin without it sees everything
  read-only. Roles for the operator list need user.view, the relay list
  server.config; without them the lists take typed entries.
-->
<script lang="ts">
	import { tick, untrack } from 'svelte';
	import { goto } from '$app/navigation';
	import { resolve } from '$app/paths';
	import { page } from '$app/state';
	import {
		clearPolicyGroup,
		countOrgDevices,
		getPolicyAudit,
		getResolvedPolicies,
		listOrgs,
		savePolicyGroup,
		type AuditEntry,
		type Org,
		type ResolvedPolicies
	} from '#lib/api/policies.ts';
	import { listRelays } from '#lib/api/scaling.ts';
	import { t, tf } from '#lib/i18n/i18n.svelte.ts';
	import { link } from '#lib/nav.ts';
	import { isAdminRole } from '#lib/rules/access.ts';
	import {
		auditSection,
		auditTime,
		entryOk,
		FIELD_IDS,
		fieldProblems,
		groupBody,
		groupFields,
		kindOf,
		rowId,
		SECTION_TITLE,
		SECTIONS,
		undoWrites,
		valuesFromResolved,
		wholeOk,
		writesFor,
		type GroupWrite,
		type PolicyDraft,
		type Section
	} from '#lib/rules/policies.ts';
	import {
		choiceLabel,
		fieldLabel,
		offWord as policyOff,
		onWord as policyOn,
		valueWords
	} from '#lib/rules/policy-words.ts';
	import { onRefresh } from '#lib/shell/page.svelte.ts';
	import { can, canWrite, session } from '#lib/state/session.svelte.ts';
	import Button from '#lib/ui/Button.svelte';
	import CountLine from '#lib/ui/CountLine.svelte';
	import Empty from '#lib/ui/Empty.svelte';
	import Input from '#lib/ui/Input.svelte';
	import ListRow from '#lib/ui/ListRow.svelte';
	import Notice from '#lib/ui/Notice.svelte';
	import ReadOnlyHint from '#lib/ui/ReadOnlyHint.svelte';
	import RowList from '#lib/ui/RowList.svelte';
	import Select from '#lib/ui/Select.svelte';
	import States from '#lib/ui/States.svelte';
	import Table from '#lib/ui/Table.svelte';
	import Time from '#lib/ui/Time.svelte';
	import User from '#lib/ui/User.svelte';
	import { confirm } from '#lib/ui/dialogs.svelte.ts';
	import ChangesBar from '#lib/ui/settings/ChangesBar.svelte';
	import { SettingsDraft, saveAndConfirm } from '#lib/ui/settings/draft.svelte.ts';
	import { SettingsFilter } from '#lib/ui/settings/filter.svelte.ts';
	import ChoiceSegments from '#lib/ui/settings/ChoiceSegments.svelte';
	import ListEditor from '#lib/ui/settings/ListEditor.svelte';
	import OrgPicker from '#lib/ui/settings/OrgPicker.svelte';
	import { relayOptions } from '#lib/ui/settings/pickers.ts';
	import SettingRow, { type ValueSource } from '#lib/ui/settings/SettingRow.svelte';
	import SettingsGroup from '#lib/ui/settings/SettingsGroup.svelte';
	import SettingsPage from '#lib/ui/settings/SettingsPage.svelte';
	import { toast } from '#lib/ui/toasts.svelte.ts';
	import type { Column } from '#lib/ui/table.ts';

	const allowed = $derived(isAdminRole(session.user?.role));
	const canEdit = $derived(canWrite('org.edit'));

	/* ── Organizations ── */

	let orgs = $state.raw<Org[]>([]);
	let orgsState = $state<'loading' | 'ready' | 'error'>('loading');

	async function loadOrgs() {
		orgsState = 'loading';
		try {
			orgs = await listOrgs();
			orgsState = 'ready';
		} catch {
			orgsState = 'error';
		}
	}

	$effect(() => {
		if (allowed) untrack(() => void loadOrgs());
	});

	const urlOrg = $derived(page.params.orgId ?? null);
	// With one organization there is nothing to choose
	const orgId = $derived(
		urlOrg ?? (orgsState === 'ready' && orgs.length === 1 ? (orgs[0]?.id ?? null) : null)
	);
	const org = $derived(orgs.find((o) => o.id === orgId) ?? null);
	const notFound = $derived(orgsState === 'ready' && !!urlOrg && !org);

	/* ── Names and words of the settings ── */

	/** One sentence per setting: what it does; examples go here, never into a placeholder */
	const help = (field: string): string => {
		switch (field) {
			case 'connection.mode':
				return tf(
					'policies.help_mode',
					"What the receiver app does when staff connect. Attended: someone at the computer clicks Allow, unless the computer's access policy turns on unattended access. Unattended: staff signed in to NeoDesk who may connect to the computer get in without asking, with no password. Always ask: someone at the computer always has to click Allow."
				);
			case 'connection.max_session_duration':
				return tf(
					'policies.help_max_session',
					'A remote session ends after this many minutes, from 0 to 1440.'
				);
			case 'connection.idle_lock_timeout':
				return tf(
					'policies.help_idle_lock',
					'The device locks after this many minutes without input, from 0 to 120.'
				);
			case 'connection.wallpaper':
				return tf('policies.help_wallpaper', 'Whether the desktop picture shows while someone connects.');
			case 'features.allow_file_transfer':
				return tf(
					'policies.help_file_transfer',
					'Whether an operator may copy files to and from the device.'
				);
			case 'features.allow_clipboard':
				return tf('policies.help_clipboard', 'Whether copied text moves between the two computers.');
			case 'features.allow_audio':
				return tf('policies.help_audio', "Whether the operator hears the device's sound during a session.");
			case 'features.allow_recording':
				return tf('policies.help_recording', 'Whether a session may be recorded.');
			case 'security.require_2fa':
				return tf('policies.help_2fa', 'Unattended access to these devices needs a second sign-in step.');
			case 'security.password_min_length':
				return tf(
					'policies.help_password_min',
					'The shortest device password allowed, from 6 to 128 characters.'
				);
			case 'security.password_require_special':
				return tf(
					'policies.help_password_special',
					'Device passwords must contain a character such as ! or #.'
				);
			case 'security.password_max_age_days':
				return tf(
					'policies.help_password_age',
					'Device passwords must be changed after this many days, from 0 to 365. 0 means never.'
				);
			case 'security.allowed_operators':
				return tf(
					'policies.help_operators',
					'Account usernames of the staff who may connect without asking, for example anna. Not set lets everyone who may connect to the computer.'
				);
			case 'security.allow_uninstall':
				return tf(
					'policies.help_allow_uninstall',
					'Off: people at these computers cannot remove the NeoDesk app. Not set allows it.'
				);
			case 'network.block_direct_p2p':
				return tf(
					'policies.help_block_p2p',
					'Connections to these devices never go directly between the two computers, only through a relay server.'
				);
			case 'network.allowed_relay_servers':
				return tf(
					'policies.help_relays',
					"Connections to these devices use the server's relay when it is in this list, else the first one here. For example relay1.example.com:21117."
				);
			case 'network.ip_allowlist':
				return tf(
					'policies.help_ip_ranges',
					'IP addresses or ranges, one per row, for example 192.168.1.0/24.'
				);
			case 'update.auto_update':
				return tf(
					'policies.help_auto_update',
					'The desktop app on these devices installs updates by itself.'
				);
			case 'update.channel':
				return tf('policies.update_channel_hint', 'Which releases the devices install.');
			default:
				return '';
		}
	};

	const onWord = $derived(policyOn());
	const offWord = $derived(policyOff());
	const notSetWord = $derived(tf('policies.not_set_word', 'not set'));
	/** The empty state inside a control: no rule, each device keeps its own setting */
	const notSetOption = $derived(tf('policies.not_set_option', 'Not set (each device decides)'));
	const notSetShort = $derived(tf('policies.not_set_short', 'Not set'));
	const notSetList = $derived(tf('policies.not_set_list', 'Not set (no limit)'));
	const serverValueShort = $derived(tf('policies.server_value_short', 'Server value'));

	/** A value in words, for the list of changes and the toast */
	function words(field: string, value: unknown): string {
		return value === null || value === undefined ? notSetWord : valueWords(field, value);
	}

	const draft = new SettingsDraft<PolicyDraft>(valuesFromResolved(null));
	$effect(() => {
		draft.describe(
			Object.fromEntries(
				FIELD_IDS.map((f) => [f, { label: fieldLabel(f), format: (v: unknown) => words(f, v) }])
			)
		);
	});
	$effect(() => draft.track());
	const filter = new SettingsFilter();

	/* ── The open organization's policies ── */

	let resolved = $state.raw<ResolvedPolicies | null>(null);
	let loadState = $state<'idle' | 'loading' | 'ready' | 'error'>('idle');
	let seq = 0;

	/**
	 * Read the policies in force. A quiet read after a write keeps the
	 * unsaved changes of the groups it did not touch.
	 */
	async function loadPolicies(id: string, quiet = false) {
		const mine = ++seq;
		if (!quiet) loadState = 'loading';
		try {
			const r = await getResolvedPolicies(id);
			if (mine !== seq) return;
			const kept = quiet ? draft.changes.map((c) => [c.field, c.toValue] as const) : [];
			resolved = r;
			draft.load(valuesFromResolved(r));
			for (const [field, value] of kept) draft.set(field, value);
			loadState = 'ready';
		} catch {
			if (mine !== seq || quiet) return;
			loadState = 'error';
		}
	}

	$effect(() => {
		const id = org?.id ?? null;
		untrack(() => {
			if (!id) {
				seq++;
				resolved = null;
				loadState = 'idle';
				audit = null;
				draft.load(valuesFromResolved(null));
				return;
			}
			void loadPolicies(id);
			void loadAudit(id);
			void loadCount(id);
		});
	});

	$effect(() =>
		onRefresh(() => {
			if (!org) return void loadOrgs();
			if (!draft.dirty) void loadPolicies(org.id);
			void loadAudit(org.id);
			void loadCount(org.id);
		})
	);

	/* ── Relay servers for the picker ── */

	let relayOpts = $state.raw<{ value: string; label: string }[]>([]);

	$effect(() => {
		if (!allowed) return;
		const mayRelays = can('server.config');
		untrack(() => {
			if (mayRelays)
				listRelays()
					.then((list) => (relayOpts = relayOptions(list)))
					.catch(() => (relayOpts = []));
		});
	});

	/* ── Choosing an organization ── */

	async function pickOrg(next: string) {
		if (next === (orgId ?? '')) return;
		if (draft.dirty) {
			const ok = await confirm({
				title: t('policies.discard_title'),
				message: t('policies.discard_message'),
				confirmLabel: t('policies.discard_confirm'),
				danger: true
			});
			if (!ok) {
				const el = document.getElementById('policy-org') as HTMLSelectElement | null;
				if (el) el.value = orgId ?? '';
				return;
			}
			draft.discard();
		}
		// A setting the search opened (#pol-…) stays the target in the organization picked
		const path = next
			? resolve('/(console)/policies/[[orgId]]', { orgId: next })
			: resolve('/(console)/policies/[[orgId]]', {});
		// The path comes from resolve() above
		// eslint-disable-next-line svelte/no-navigation-without-resolve
		await goto(`${path}${page.url.hash}`, { replace: true, reset: false });
	}

	/* ── Devices in the organization ── */

	let deviceCount = $state<number | null | undefined>(undefined);

	async function loadCount(id: string) {
		deviceCount = undefined;
		const n = await countOrgDevices(id).catch(() => null);
		if (org?.id === id) deviceCount = n;
	}

	/** How many devices the policies reach; none is the fact that changes everything (rule G) */
	const deviceLine = $derived(
		deviceCount === undefined || deviceCount === null
			? ''
			: deviceCount === 0
				? tf('policies.devices_none', 'No device is in this organization yet, so these policies reach none.')
				: deviceCount === 1
					? tf('policies.devices_in_org_one', '1 device is in this organization.')
					: tf('policies.devices_in_org', '{count} devices are in this organization.', {
							count: deviceCount
						})
	);

	/* ── Writing ── */

	async function runWrites(id: string, writes: readonly GroupWrite[]) {
		const failed: string[] = [];
		for (const w of writes) {
			try {
				if (w.body) await savePolicyGroup(id, w.group, w.body);
				else await clearPolicyGroup(id, w.group);
			} catch (err) {
				failed.push(
					`${t(SECTION_TITLE[w.group])}${err instanceof Error && err.message ? ` (${err.message})` : ''}`
				);
			}
		}
		if (failed.length)
			throw new Error(
				tf('policies.save_failed_groups', 'Not saved: {groups}.', { groups: failed.join(', ') })
			);
	}

	async function afterWrite(id: string) {
		await loadPolicies(id, true);
		void loadAudit(id);
	}

	function problemText(field: string, entry: string): string {
		const kind = kindOf(field);
		if (kind?.kind === 'whole')
			return t('policies.invalid_number', { field: fieldLabel(field), min: kind.min, max: kind.max });
		if (kind?.kind === 'list' && kind.entry === 'relay') return t('policies.invalid_relay', { entry });
		if (kind?.kind === 'list' && kind.entry === 'range') return t('policies.invalid_ip_range', { entry });
		return '';
	}

	async function save() {
		if (!org || !canEdit || draft.busy) return;
		const problems = fieldProblems(draft.values);
		const first = problems[0];
		if (first) {
			draft.error = problemText(first.field, first.entry);
			document.getElementById(rowId(first.field))?.querySelector<HTMLElement>('input, select')?.focus();
			return;
		}
		const id = org.id;
		const before = draft.loaded;
		const writes = writesFor(draft.values, draft.loaded);
		const groups = writes.map((w) => w.group);
		await saveAndConfirm(draft, () => runWrites(id, writes), {
			undo: () => runWrites(id, undoWrites(before, groups)),
			reload: () => afterWrite(id)
		});
	}

	async function removeGroup(group: Section) {
		if (!org || !canEdit) return;
		const id = org.id;
		const name = t(SECTION_TITLE[group]);
		const ok = await confirm({
			title: tf('policies.remove_group_title', 'Remove all rules of {group}?', { group: name }),
			message: tf(
				'policies.remove_group_message',
				'Every {group} setting of {org} goes back to no rule. This is saved at once; other unsaved changes stay.',
				{ group: name, org: org.name || org.id }
			),
			confirmLabel: tf('policies.remove_group_confirm', 'Remove the rules'),
			danger: true
		});
		if (!ok) return;
		const previous = groupBody(group, draft.loaded);
		try {
			await clearPolicyGroup(id, group);
		} catch (err) {
			toast.error(
				`${tf('policies.remove_group_failed', 'The rules were not removed.')} ${err instanceof Error ? err.message : ''}`.trim()
			);
			return;
		}
		// The group's own unsaved changes go with it
		for (const f of groupFields(group)) draft.reset(f);
		await afterWrite(id);
		toast.show({
			type: 'success',
			message: tf('policies.remove_group_done', 'Removed the rules of {group}.', { group: name }),
			action: previous
				? {
						label: tf('settings_ui.undo', 'Undo'),
						onclick: () =>
							void runWrites(id, [{ group, body: previous }])
								.then(async () => {
									await afterWrite(id);
									toast.success(tf('settings_ui.undone', 'The changes are undone.'));
								})
								.catch((err: unknown) =>
									toast.error(
										`${tf('settings_ui.undo_failed', 'Undoing did not work.')} ${err instanceof Error ? err.message : ''}`.trim()
									)
								)
					}
				: undefined
		});
	}

	/* ── What applies now ── */

	const fieldOf = (field: string) => {
		const at = field.indexOf('.');
		return resolved?.[field.slice(0, at)]?.fields[field.slice(at + 1)];
	};

	/** Where the value comes from while the organization has no rule: the server's setting on its own page */
	function fromServer(field: string): ValueSource | null {
		const f = fieldOf(field);
		if (f?.server_setting) {
			const value =
				f.server_value === true
					? tf('policies.server_relay_only', 'Always through the relay')
					: f.server_value === false
						? tf('policies.server_direct_allowed', 'Direct connections allowed')
						: '';
			return {
				kind: 'inherited',
				text: value
					? tf('policies.from_server', 'From the server: {value}.', { value })
					: tf('policies.from_server_unknown', 'From the server.'),
				href: link(f.server_setting.href),
				linkLabel: t(f.server_setting.label_key)
			};
		}
		return null;
	}

	/** "Remove the rule" is gone once pressed: the focus goes to the control, now on "Not set" */
	async function focusControl(field: string) {
		await tick();
		const el = document.getElementById(`${rowId(field)}-control`);
		el?.focus();
	}

	const hasRule = (field: string) => draft.values[field] !== null && draft.values[field] !== undefined;

	/** Set here: kept for screen readers and marks the row. The server's value: said under the row, with its page */
	function sourceOf(field: string): ValueSource | null {
		return hasRule(field)
			? { kind: 'here', text: tf('policies.set_for_org', 'Set for this organization') }
			: fromServer(field);
	}

	/** An emptied list is no rule: an empty list limits nothing, like no rule */
	const listValue = (list: string[]) => (list.length ? list : null);

	const deviceOnly = (g: Section) =>
		resolved?.[g]?.applied_by === 'device' && !resolved?.[g]?.device_app_applies;
	const RECEIVER_SOME =
		"So far only the receiver app applies part of this group: {settings}. The NeoDesk desktop app doesn't apply this group yet. The other settings are saved and handed to devices that ask.";
	/** The group's settings the receiver app applies, by their labels */
	const receiverSettings = (g: Section) =>
		(resolved?.[g]?.receiver_applies ?? []).map((f) => fieldLabel(`${g}.${f}`));

	/** When a change takes effect; nothing while no app applies the group (its notice says so) */
	const groupTiming = (g: Section) =>
		resolved?.[g]?.timing === 'server_minute'
			? t('policies.effect_server')
			: deviceOnly(g) && !receiverSettings(g).length
				? undefined
				: tf('policies.effect_device_next', 'Devices get this when they next ask for their policy.');

	/* ── Options ── */

	const choiceOptions = (field: string) => {
		const kind = kindOf(field);
		return kind?.kind === 'choice' ? kind.options.map((o) => ({ value: o, label: choiceLabel(o) })) : [];
	};
	const switchOptions = (field: string) => [
		{ value: '', label: fieldOf(field)?.server_setting ? serverValueShort : notSetShort },
		{ value: 'on', label: onWord },
		{ value: 'off', label: offWord }
	];

	const sections = $derived([
		...SECTIONS.map((s) => ({ id: `pol-${s}`, label: t(SECTION_TITLE[s]) })),
		{ id: 'pol-audit', label: t('policies.audit_title') }
	]);

	/* ── Change log ── */

	let audit = $state.raw<AuditEntry[] | null>(null);
	let auditError = $state(false);

	async function loadAudit(id: string) {
		auditError = false;
		try {
			const list = await getPolicyAudit(id);
			if (org?.id === id) audit = list;
		} catch {
			if (org?.id === id) auditError = true;
		}
	}

	const sectionName = (cat: string) =>
		(SECTIONS as readonly string[]).includes(cat) ? t(SECTION_TITLE[cat as Section]) : cat;

	const auditColumns = $derived<Column<AuditEntry>[]>([
		{ id: 'time', label: t('policies.col_time'), cell: timeCell, class: 'col-time' },
		{ id: 'policy', label: t('policies.col_policy'), cell: policyCell },
		{ id: 'source', label: t('policies.col_source'), cell: sourceCell }
	]);
	const auditRows = $derived((audit ?? []).map((e, i) => ({ ...e, key: `${auditTime(e)}-${i}` })));
</script>

{#snippet timeCell(e: AuditEntry)}<Time value={auditTime(e)} />{/snippet}

{#snippet policyCell(e: AuditEntry)}{@const cat = auditSection(e)}{#if cat}<span class="policy-group"
			>{sectionName(cat)}</span
		>{:else}<Empty />{/if}{#if e.detail || e.description}<span class="cell-sub"
			>{e.detail || e.description}</span
		>{/if}{/snippet}

{#snippet sourceCell(e: AuditEntry)}{#if e.actor || e.user}<User user={e.actor || e.user} />{:else}<Empty
		/>{/if}{#if e.target}<span class="cell-sub">{e.target}</span>{/if}{/snippet}

{#snippet scope()}
	{#if orgsState === 'ready' && orgs.length}
		<!-- The organization is the scope, not a setting: the settings list has no row for it -->
		<div class="policy-scope" data-search-skip>
			<div class="scope-picker">
				<OrgPicker
					id="policy-org"
					label={t('policies.select_org')}
					{orgs}
					value={org?.id ?? ''}
					placeholder={org ? undefined : t('policies.select_org_placeholder')}
					onchange={(id) => void pickOrg(id)}
				/>
			</div>
			{#if org}
				<p class={['scope-line', deviceCount === 0 && 'is-empty']}>
					{#if deviceLine}{deviceLine}{/if}
					{#if deviceCount !== 0}{tf(
							'policies.outside_orgs',
							'Devices outside any organization get no policy.'
						)}{/if}
					<a href={link(`/organizations/${encodeURIComponent(org.id)}#devices`)}
						>{tf('policies.put_devices', 'Put devices into this organization')}</a
					>
				</p>
			{/if}
		</div>
	{/if}
{/snippet}

{#snippet editor(field: string, f: { id: string; describedby: string | undefined; labelledby: string })}
	{@const kind = kindOf(field)}
	{@const value = draft.values[field]}
	{@const unset = value === null || value === undefined}
	{#if kind?.kind === 'switch'}
		<ChoiceSegments
			id={f.id}
			labelledby={f.labelledby}
			describedby={f.describedby}
			disabled={!canEdit}
			options={switchOptions(field)}
			value={unset ? '' : value ? 'on' : 'off'}
			onchange={(v) => draft.set(field, v === '' ? null : v === 'on')}
		/>
	{:else if kind?.kind === 'choice'}
		<Select
			id={f.id}
			describedby={f.describedby}
			disabled={!canEdit}
			options={[{ value: '', label: notSetOption }, ...choiceOptions(field)]}
			value={unset ? '' : String(value)}
			onchange={(e) => {
				const v = (e.currentTarget as HTMLSelectElement).value;
				draft.set(field, v === '' ? null : v);
			}}
		/>
	{:else if kind?.kind === 'whole'}
		{@const bad = !unset && !wholeOk(field, value)}
		<div class="number-line">
			<Input
				id={f.id}
				describedby={[f.describedby, bad && `${f.id}-error`, unset && `${f.id}-unset`]
					.filter(Boolean)
					.join(' ') || undefined}
				type="number"
				width="short"
				min={kind.min}
				max={kind.max}
				step={1}
				inputmode="numeric"
				invalid={bad}
				disabled={!canEdit}
				value={unset ? '' : (value as number)}
				oninput={(e) => {
					const raw = (e.currentTarget as HTMLInputElement).value;
					draft.set(field, raw === '' ? null : Number(raw));
				}}
			/>
			{#if unset}<span class="unset-hint" id={`${f.id}-unset`}>{notSetOption}</span>{/if}
		</div>
		{#if bad}<p class="field-error" id={`${f.id}-error`}>{problemText(field, '')}</p>{/if}
	{:else if kind?.kind === 'list'}
		{#if unset}<p class="unset-hint list-hint">{notSetList}</p>{/if}
		<ListEditor
			id={f.id}
			describedby={f.describedby}
			disabled={!canEdit}
			items={(value as string[]) ?? []}
			onchange={(list) => draft.set(field, listValue(list))}
			itemLabel={(n) =>
				kind.entry === 'relay'
					? tf('policies.relay_n', 'Relay server {n}', { n })
					: kind.entry === 'range'
						? tf('policies.range_n', 'IP range {n}', { n })
						: tf('policies.operator_n', 'Account {n}', { n })}
			check={(entry) =>
				entryOk(field, entry)
					? ''
					: kind.entry === 'relay'
						? tf(
								'policies.row_bad_relay',
								'Not a server address. Use a host name or address, with a port if needed.'
							)
						: tf('policies.row_bad_range', 'Not an IP address or range.')}
			addLabel={kind.entry === 'relay'
				? tf('policies.add_relay', 'Add a relay server')
				: kind.entry === 'range'
					? tf('policies.add_range', 'Add an IP range')
					: tf('policies.add_operator', 'Add an account')}
			quick={kind.entry === 'relay' ? relayOpts : []}
		/>
	{/if}
{/snippet}

{#snippet row(field: string)}
	<SettingRow
		id={rowId(field)}
		label={fieldLabel(field)}
		help={help(field)}
		keyName={field}
		group={kindOf(field)?.kind === 'switch'}
		source={sourceOf(field)}
		changed={draft.isChanged(field)}
		onreset={canEdit && hasRule(field)
			? () => {
					draft.set(field, null);
					void focusControl(field);
				}
			: undefined}
		resetLabel={tf('policies.remove_rule', 'Remove the rule')}
		noEffect={field === 'network.ip_allowlist'
			? tf(
					'policies.ip_ranges_not_applied',
					'Nothing applies this yet: the server stores the ranges but does not check connections against them.'
				)
			: undefined}
	>
		{#snippet control(f)}{@render editor(field, f)}{/snippet}
	</SettingRow>
{/snippet}

<SettingsPage
	id="policies"
	title={org?.name ? `${t('nav.policies')}: ${org.name}` : t('nav.policies')}
	description={t('policies.page_description')}
	{allowed}
	saveModel={org && loadState === 'ready' ? 'draft' : 'none'}
	filter={org && loadState === 'ready' ? filter : undefined}
	filterLabel={tf('policies.filter', 'Filter policy settings')}
	sections={org && loadState === 'ready' ? sections : []}
	{scope}
>
	<ReadOnlyHint writes={['org.edit']} />

	{#if orgsState === 'loading'}
		<States kind="loading" message={t('policies.loading')} />
	{:else if orgsState === 'error'}
		<States kind="error" message={t('policies.orgs_failed')} onretry={() => void loadOrgs()} />
	{:else if !orgs.length}
		<States kind="empty" message={t('policies.no_orgs')} />
	{:else if notFound}
		<Notice tone="danger" role="alert" message={t('policies.org_not_found')} />
	{/if}

	{#if orgsState === 'ready' && orgs.length && !org}
		<section class="org-pick" aria-labelledby="policy-org-pick-title">
			<h2 id="policy-org-pick-title" class="sr-only">{t('policies.select_org_placeholder')}</h2>
			{#if !notFound}<p class="state-line">{t('policies.pick_org_state')}</p>{/if}
			<div class="org-list" data-sveltekit-replacestate data-sveltekit-noscroll>
				<RowList label={t('policies.select_org_placeholder')}>
					{#each orgs as o (o.id)}
						<ListRow
							title={o.name || o.id}
							href={`${resolve('/(console)/policies/[[orgId]]', { orgId: o.id })}${page.url.hash}`}
						/>
					{/each}
				</RowList>
			</div>
		</section>
	{:else if org && (loadState === 'loading' || loadState === 'idle')}
		<States kind="loading" message={t('policies.loading')} />
	{:else if org && loadState === 'error'}
		<States kind="error" message={t('policies.load_failed')} onretry={() => void loadPolicies(org.id)} />
	{:else if org}
		{#each SECTIONS as g (g)}
			<SettingsGroup
				id={`pol-${g}`}
				title={t(SECTION_TITLE[g])}
				description={t(`policies.${g}_desc`)}
				consequence={groupTiming(g)}
			>
				{#snippet note()}
					{#if deviceOnly(g)}
						<Notice tone="warning" class="group-notice">
							<p>
								{#if receiverSettings(g).length}
									{tf('policies.receiver_applies_some', RECEIVER_SOME, {
										settings: receiverSettings(g).join(', ')
									})}
								{:else}
									{tf(
										'policies.not_applied_yet',
										'No NeoDesk app applies this group yet. It is saved and handed to devices that ask.'
									)}
								{/if}
							</p>
							{#if g === 'features'}
								<p>
									{tf(
										'policies.sound_today',
										"To turn sound off in sessions today, use an access rule with Sound off under Devices, or switch off Sound in a person's console access."
									)}
									<a href={link('/devices#access-rules')}
										>{tf('policies.open_access_rules', 'Open access rules')}</a
									>
								</p>
							{/if}
						</Notice>
					{/if}
				{/snippet}
				{#snippet actions()}
					{#if canEdit && resolved?.[g]?.set}
						<Button
							size="sm"
							aria-label={`${tf('policies.remove_group', 'Remove all rules of this group')}: ${t(SECTION_TITLE[g])}`}
							onclick={() => void removeGroup(g)}
							>{tf('policies.remove_group', 'Remove all rules of this group')}</Button
						>
					{/if}
				{/snippet}
				{#each groupFields(g) as field (field)}{@render row(field)}{/each}
			</SettingsGroup>
		{/each}

		<section class="policy-audit" id="pol-audit" aria-labelledby="pol-audit-title">
			<h2 id="pol-audit-title">{t('policies.audit_title')}</h2>
			<p class="section-note">{t('policies.audit_desc')}</p>
			{#if auditError}
				<States kind="error" message={t('policies.audit_failed')} onretry={() => void loadAudit(org.id)} />
			{:else if audit === null}
				<States kind="loading" message={t('policies.audit_loading')} />
			{:else if !audit.length}
				<States kind="empty" message={t('policies.no_audit')} />
			{:else}
				<CountLine text={t('policies.audit_count')} values={{ count: audit.length }} />
				<Table rows={auditRows} columns={auditColumns} key={(e) => e.key} label={t('policies.audit_title')} />
			{/if}
		</section>
	{/if}

	{#snippet bar()}
		{#if canEdit && org}<ChangesBar {draft} onsave={save} saveLabel={t('policies.save_button')} />{/if}
	{/snippet}
</SettingsPage>

<style>
	/* The picker and the fact that changes everything, on one line (rule G) */
	.policy-scope {
		display: flex;
		flex-wrap: wrap;
		align-items: flex-end;
		gap: var(--space-2) var(--space-5);
	}
	.scope-picker {
		flex: 0 1 22rem;
		min-width: min(100%, 16rem);
	}
	.scope-line {
		flex: 1 1 24rem;
		margin: 0;
		padding-bottom: calc((var(--control-h) - 1.5em) / 2);
		max-width: var(--measure);
		color: var(--text-muted);
	}
	.scope-line.is-empty {
		color: var(--warning);
	}
	.state-line {
		margin: 0;
		max-width: var(--measure);
		color: var(--text-muted);
	}
	.number-line {
		display: flex;
		flex-wrap: wrap;
		align-items: center;
		gap: var(--space-1) var(--space-3);
	}
	.unset-hint {
		color: var(--text-muted);
		font-size: var(--text-sm);
	}
	.list-hint {
		margin: 0 0 var(--space-1);
	}
	.scope-line a {
		margin-inline-start: var(--space-1);
	}
	.org-list {
		max-width: var(--measure);
	}
	.org-pick {
		display: flex;
		flex-direction: column;
		gap: var(--space-3);
	}
	:global(.group-notice) p {
		margin: 0;
	}
	:global(.group-notice) p + p {
		margin-top: var(--space-1);
	}
	.field-error {
		margin: var(--space-1) 0 0;
		color: var(--danger);
		font-size: var(--text-sm);
	}
	.policy-audit {
		display: flex;
		flex-direction: column;
		gap: var(--space-2);
		min-width: 0;
		max-width: var(--settings-max, 72rem);
	}
	.policy-audit h2 {
		margin: 0;
		font-size: var(--text-md);
	}
	.section-note {
		margin: 0;
		color: var(--text-muted);
	}
	.policy-audit :global(.cell-sub) {
		display: block;
		color: var(--text-muted);
		font-size: var(--text-sm);
	}
	.policy-audit :global(td.col-time) {
		white-space: nowrap;
	}
</style>
