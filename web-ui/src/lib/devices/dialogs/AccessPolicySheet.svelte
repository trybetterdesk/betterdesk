<!--
  Access policy of one device: unattended access, a schedule and the
  operators allowed to connect without asking, as the server's caller check
  and the receiver apply them (A279). A side sheet (long form). The
  schedule fields show only with the schedule on. The sheet sets no
  password: a receiver has none, and the server never hands a password
  saved here to a device.
-->
<script lang="ts">
	import type { AccessPolicy, AccessPolicyInput } from '#lib/api/devices.ts';
	import { t, tf } from '#lib/i18n/i18n.svelte.ts';
	import Button from '#lib/ui/Button.svelte';
	import Checkbox from '#lib/ui/Checkbox.svelte';
	import Field from '#lib/ui/Field.svelte';
	import FormSection from '#lib/ui/FormSection.svelte';
	import Input from '#lib/ui/Input.svelte';
	import Sheet from '#lib/ui/Sheet.svelte';
	import ShowWhen from '#lib/ui/ShowWhen.svelte';
	import Time from '#lib/ui/Time.svelte';
	import User from '#lib/ui/User.svelte';
	import { createForm, type Form } from '#lib/ui/form.svelte.ts';
	import type { DeviceLike } from '../model.ts';

	let {
		device,
		load,
		save,
		settle
	}: {
		device: DeviceLike;
		load: () => Promise<AccessPolicy>;
		save: (input: AccessPolicyInput) => Promise<void>;
		settle: (done: true | null) => void;
	} = $props();

	const uid = $props.id();
	const DAYS = ['mon', 'tue', 'wed', 'thu', 'fri', 'sat', 'sun'] as const;

	interface Values {
		unattended: boolean;
		schedule: boolean;
		days: string[];
		start: string;
		end: string;
		timezone: string;
		operators: string;
	}

	let policy = $state.raw<AccessPolicy | null>(null);
	let loadError = $state('');
	let form = $state<Form<Values> | null>(null);

	const zones: string[] =
		typeof Intl.supportedValuesOf === 'function' ? Intl.supportedValuesOf('timeZone') : [];

	function valuesFrom(p: AccessPolicy): Values {
		return {
			unattended: p.unattended_enabled ?? false,
			schedule: p.schedule_enabled ?? false,
			days: (p.schedule_days ?? '')
				.split(',')
				.map((d) => d.trim().toLowerCase())
				.filter(Boolean),
			start: p.schedule_start_time || '08:00',
			end: p.schedule_end_time || '18:00',
			timezone: p.schedule_timezone || Intl.DateTimeFormat().resolvedOptions().timeZone,
			operators: p.allowed_operators ?? ''
		};
	}

	$effect(() => {
		let gone = false;
		load().then(
			(p) => {
				if (gone) return;
				policy = p;
				form = createForm<Values>({
					initial: valuesFrom(p),
					submit: async (v) => {
						await save({
							unattended_enabled: v.unattended,
							// An empty password keeps what the server has
							password: '',
							clear_password: false,
							schedule_enabled: v.schedule,
							schedule_days: DAYS.filter((d) => v.days.includes(d)).join(','),
							schedule_start_time: v.start,
							schedule_end_time: v.end,
							schedule_timezone: v.timezone.trim(),
							allowed_operators: v.operators
						});
						settle(true);
					}
				});
			},
			(err: unknown) => {
				if (!gone) loadError = err instanceof Error ? err.message : String(err);
			}
		);
		return () => {
			gone = true;
		};
	});

	function toggleDay(day: string, on: boolean) {
		if (!form) return;
		const v = form.values;
		v.days = on ? [...v.days.filter((d) => d !== day), day] : v.days.filter((d) => d !== day);
	}
</script>

<Sheet
	title={tf('devices.access_policy_title', 'Access policy for {id}', { id: device.id })}
	subtitle={t('devices.access_policy_desc')}
	status={loadError || form?.status.message || ''}
	statusTone={loadError || form?.status.state === 'error' ? 'error' : 'neutral'}
	onclose={() => settle(null)}
>
	{#if form && policy}
		{@const fm = form}
		<form id={form.id} onsubmit={form.onsubmit} novalidate>
			<FormSection title={t('devices.unattended_access')}>
				<Checkbox
					label={t('devices.enable_unattended')}
					hint={t('devices.unattended_hint')}
					bind:checked={form.values.unattended}
				/>
			</FormSection>
			<FormSection title={t('devices.access_schedule')}>
				<Checkbox
					label={t('devices.enable_schedule')}
					hint={tf(
						'devices.schedule_hint',
						'Allows connections only on the chosen days, between the start and end time.'
					)}
					aria-controls="{uid}-schedule"
					bind:checked={form.values.schedule}
				/>
				<ShowWhen id="{uid}-schedule" when={form.values.schedule}>
					<div class="days" role="group" aria-labelledby="{uid}-days">
						<span class="label" id="{uid}-days">{t('devices.allowed_days')}</span>
						<div class="day-row">
							{#each DAYS as day (day)}
								<Checkbox
									inline
									label={t(`days.${day}`)}
									checked={form.values.days.includes(day)}
									onchange={(e) => toggleDay(day, (e.currentTarget as HTMLInputElement).checked)}
								/>
							{/each}
						</div>
					</div>
					<div class="times">
						<Field label={t('devices.start_time')}>
							{#snippet children(f)}
								<Input {...f} type="time" bind:value={fm.values.start} />
							{/snippet}
						</Field>
						<Field label={t('devices.end_time')}>
							{#snippet children(f)}
								<Input {...f} type="time" bind:value={fm.values.end} />
							{/snippet}
						</Field>
					</div>
					<Field
						label={t('devices.timezone')}
						hint={tf(
							'devices.timezone_hint',
							'The days and times count in this time zone, for example Europe/Berlin.'
						)}
					>
						{#snippet children(f)}
							<Input
								{...f}
								width="host"
								list="{uid}-zones"
								autocomplete="off"
								spellcheck="false"
								bind:value={fm.values.timezone}
							/>
							<datalist id="{uid}-zones">
								{#each zones as z (z)}<option value={z}></option>{/each}
							</datalist>
						{/snippet}
					</Field>
				</ShowWhen>
			</FormSection>
			<FormSection title={t('devices.allowed_operators')}>
				<Field label={tf('devices.allowed_operators_field', 'Usernames')} hint={t('devices.operators_hint')}>
					{#snippet children(f)}
						<Input {...f} autocomplete="off" spellcheck="false" bind:value={fm.values.operators} />
					{/snippet}
				</Field>
			</FormSection>
			{#if policy.updated_by}
				<p class="updated">
					{t('devices.last_updated_by')}: <User user={policy.updated_by} />{#if policy.updated_at},
						<Time value={policy.updated_at} relative={false} />{/if}
				</p>
			{/if}
		</form>
	{:else if !loadError}
		<p class="loading">{t('common.loading')}</p>
	{/if}
	{#snippet footer()}
		<Button class="sheet-footer-start" onclick={() => settle(null)}>{t('actions.cancel')}</Button>
		<Button variant="primary" type="submit" form={form?.id} busy={form?.busy} disabled={!form}
			>{t('actions.save')}</Button
		>
	{/snippet}
</Sheet>

<style>
	.updated,
	.loading {
		margin: 0;
	}
	.updated,
	.loading {
		color: var(--text-muted);
		font-size: var(--text-sm);
	}
	.days {
		display: flex;
		flex-direction: column;
		gap: var(--space-1);
	}
	.label {
		font-weight: 600;
	}
	.day-row {
		display: flex;
		flex-wrap: wrap;
		gap: 0 var(--space-4);
	}
	.times {
		display: flex;
		flex-wrap: wrap;
		gap: var(--space-4);
	}
	.times > :global(.form-group) {
		margin: 0;
	}
</style>
