<!--
  The guided first join: four short steps for a computer that just joined
  with an invite (lib/onboard/guide.ts), inside the invite sheet.
    1. Name: as the invite or the computer named it; saved with device.edit.
    2. Folder: as the invite put it; saved with device.edit.
    3. How you reach it: the ways that exist today for what the computer
       runs, explained (reachOptions).
    4. Test session: opens the viewer while the computer is online.
  Next saves the step; Skip ends the walk and leaves the rest as it joined.
  A role without device.edit sees the name and folder, read only.
-->
<script lang="ts">
	import { setDeviceFolder, updateDevice, type Folder } from '#lib/api/devices.ts';
	import type { InviteDevice } from '#lib/api/onboard.ts';
	import { t } from '#lib/i18n/i18n.svelte.ts';
	import { can } from '#lib/state/session.svelte.ts';
	import Button from '#lib/ui/Button.svelte';
	import Field from '#lib/ui/Field.svelte';
	import FormStatus from '#lib/ui/FormStatus.svelte';
	import Input from '#lib/ui/Input.svelte';
	import Select, { type SelectOption } from '#lib/ui/Select.svelte';
	import { ICONS } from '#lib/util/display.ts';
	import { GUIDE_STEPS, deviceLabel, reachOptions } from './guide.ts';
	import { go, viewerPath } from './quick-support.ts';

	interface Props {
		device: InviteDevice;
		folders: readonly Folder[];
		/** The walk ended (Done or Skip), with the name and folder it left */
		onfinish: (result: { name: string; folder: string }) => void;
	}

	let { device, folders, onfinish }: Props = $props();

	let step = $state(0);
	// The step's values start from the computer as it joined
	// svelte-ignore state_referenced_locally
	let name = $state(device.name || device.hostname);
	// svelte-ignore state_referenced_locally
	let folder = $state<number>(device.folder_id ?? 0);
	let saving = $state(false);
	let error = $state('');

	const editable = $derived(can('device.edit'));
	const connectable = $derived(can('device.connect'));
	const label = $derived(deviceLabel({ ...device, name: name.trim() || device.name }));
	const current = $derived(GUIDE_STEPS[step]);
	const folderOptions = $derived<SelectOption<number>[]>([
		{ value: 0, label: t('onboard.invite.no_folder') },
		...folders.map((f) => ({ value: f.id, label: f.name }))
	]);
	const folderName = $derived(folders.find((f) => f.id === folder)?.name ?? '');

	async function save(): Promise<boolean> {
		if (!editable) return true;
		if (current === 'name' && name.trim() && name.trim() !== device.name) {
			await updateDevice(device.id, { display_name: name.trim() });
		}
		if (current === 'folder' && folder !== (device.folder_id ?? 0)) {
			await setDeviceFolder(device.id, folder || null);
		}
		return true;
	}

	async function next() {
		if (saving) return;
		saving = true;
		error = '';
		try {
			await save();
			if (step < GUIDE_STEPS.length - 1) step++;
			else onfinish({ name: label, folder: folderName });
		} catch {
			error = t('onboard.guide.save_failed');
		} finally {
			saving = false;
		}
	}

	function skip() {
		onfinish({ name: deviceLabel(device), folder: device.folder_name });
	}

	function submit(e: SubmitEvent) {
		e.preventDefault();
		void next();
	}
</script>

<form class="join-guide" onsubmit={submit} novalidate>
	<div class="step-head">
		<p class="step-of">{t('onboard.guide.step_of', { step: step + 1, count: GUIDE_STEPS.length })}</p>
		<h3>{t(`onboard.guide.step_${current}`)}</h3>
	</div>

	{#if current === 'name'}
		<Field
			label={t('onboard.guide.step_name')}
			hint={editable ? t('onboard.guide.name_hint') : t('onboard.guide.no_permission')}
		>
			{#snippet children(f)}
				<Input
					{...f}
					width="medium"
					maxlength={64}
					autocomplete="off"
					readonly={!editable}
					bind:value={name}
				/>
			{/snippet}
		</Field>
	{:else if current === 'folder'}
		<Field
			label={t('onboard.guide.step_folder')}
			hint={editable ? t('onboard.guide.folder_hint') : t('onboard.guide.no_permission')}
		>
			{#snippet children(f)}
				<Select {...f} options={folderOptions} disabled={!editable} bind:value={folder} />
			{/snippet}
		</Field>
	{:else if current === 'reach'}
		<p>{t('onboard.guide.reach_lead', { name: label })}</p>
		<ul class="reach">
			{#each reachOptions(device) as key (key)}<li>{t(key)}</li>{/each}
		</ul>
	{:else}
		<p>{t('onboard.guide.test_lead')}</p>
		{#if !device.online}
			<p class="muted">{t('onboard.guide.test_offline', { name: label })}</p>
		{:else if connectable}
			<div>
				<Button icon={ICONS.connect} onclick={() => go.tab(viewerPath(device.id))}
					>{t('onboard.guide.test_start')}</Button
				>
			</div>
		{/if}
	{/if}

	<FormStatus message={error} tone={error ? 'error' : 'neutral'} />
	<div class="nav">
		<Button class="skip" onclick={skip}>{t('onboard.guide.skip')}</Button>
		{#if step > 0}<Button onclick={() => (step = step - 1)}>{t('actions.back')}</Button>{/if}
		<Button variant="primary" type="submit" busy={saving}
			>{step < GUIDE_STEPS.length - 1 ? t('onboard.guide.next') : t('onboard.guide.done')}</Button
		>
	</div>
</form>

<style>
	.join-guide {
		display: flex;
		flex-direction: column;
		gap: var(--space-3);
	}
	.join-guide p {
		margin: 0;
	}
	.step-of,
	.muted {
		color: var(--text-muted);
	}
	.step-head {
		display: flex;
		flex-direction: column;
		gap: var(--space-1);
	}
	.step-head h3 {
		margin: 0;
		font-size: var(--text-lg, 1.125rem);
	}
	.step-of {
		font-size: var(--text-sm);
	}
	.reach {
		display: flex;
		flex-direction: column;
		gap: var(--space-2);
		margin: 0;
		padding-inline-start: 1.25rem;
	}
	.nav {
		display: flex;
		flex-wrap: wrap;
		gap: var(--space-2);
		justify-content: flex-end;
		padding-top: var(--space-3);
		border-top: 1px solid var(--rule);
	}
	.nav :global(.skip) {
		margin-inline-end: auto;
	}
</style>
