<!--
  Unattended access (Overview, receivers only): one sentence of what the
  receiver does with staff who connect without someone at the computer
  clicking Allow, from the organization's connection mode and allowed
  operators (the resolved policy) and the device's access policy, with the
  same precedence as the server's check (lib/devices/unattended.ts).
  Nothing shows while the mode can't be read (an organization whose
  policies this account doesn't see). Change opens the access policy sheet.
-->
<script lang="ts">
	import { getAccessPolicy } from '#lib/api/devices.ts';
	import { getResolvedPolicies } from '#lib/api/policies.ts';
	import { t } from '#lib/i18n/i18n.svelte.ts';
	import { isAdminRole } from '#lib/rules/access.ts';
	import { session } from '#lib/state/session.svelte.ts';
	import Button from '#lib/ui/Button.svelte';
	import { editAccessPolicy, may } from '../actions.svelte.ts';
	import type { PanelDevice } from '../panel-logic.ts';
	import { accessFromAnswer, receiverSentence } from '../unattended.ts';
	import PanelSection from './PanelSection.svelte';

	let { device }: { device: PanelDevice } = $props();

	let sentence = $state('');
	let reload = $state(0);

	$effect(() => {
		const id = device.id;
		void reload;
		const ctrl = new AbortController();
		sentence = '';
		(async () => {
			const policy = await getAccessPolicy(id, ctrl.signal);
			let mode: string | null = null;
			let operators: string[] = [];
			if (policy.org_id) {
				// The organization's rule decides first; without it the
				// sentence could be wrong, so none shows
				if (!isAdminRole(session.user?.role)) return;
				const resolved = await getResolvedPolicies(policy.org_id, ctrl.signal);
				const m = resolved.connection?.fields.mode;
				mode = m?.source === 'organization' && typeof m.value === 'string' ? m.value : null;
				const ops = resolved.security?.fields.allowed_operators;
				operators =
					ops?.source === 'organization' && Array.isArray(ops.value) ? ops.value.map((x) => String(x)) : [];
			}
			if (!ctrl.signal.aborted) sentence = receiverSentence(mode, operators, accessFromAnswer(policy), t);
		})().catch(() => {
			if (!ctrl.signal.aborted) sentence = '';
		});
		return () => ctrl.abort();
	});

	async function change() {
		if (await editAccessPolicy(device)) reload++;
	}
</script>

{#if sentence}
	<PanelSection title={t('devices.unattended_access')}>
		{#snippet actions()}
			{#if may.edit(device)}
				<Button size="sm" onclick={change}>{t('devices.access_policy_change')}</Button>
			{/if}
		{/snippet}
		<p class="dp-unattended" data-testid="unattended-sentence">{sentence}</p>
	</PanelSection>
{/if}

<style>
	.dp-unattended {
		margin: 0;
	}
</style>
