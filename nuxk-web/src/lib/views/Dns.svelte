<script lang="ts">
  // «DNS»: protected DNS through the tunnels, and the check whether answers
  // are substituted. Devices keep asking the router; with protection on, the
  // router's DNS proxy asks nuxk, and nuxk asks the resolvers over DoH through
  // VLESS or WARP — the provider sees nothing to substitute or block.
  import { api, type DNSCheck, type DNSStatus, type DNSSettings } from '../api';
  import { ago, fmtBytes, plural } from '../ui';

  let s = $state<DNSStatus | null>(null);
  let err = $state('');
  let busy = $state<'' | 'toggle' | 'settings' | 'cache' | 'flush' | 'check'>('');
  let check = $state<DNSCheck | null>(null);
  let extra = $state('');

  async function load() {
    try {
      s = await api.dns();
      err = '';
    } catch (e) {
      err = e instanceof Error ? e.message : String(e);
    }
  }
  $effect(() => {
    void load();
    const t = setInterval(load, 10_000);
    return () => clearInterval(t);
  });

  async function change(what: typeof busy, patch: Partial<DNSSettings>) {
    busy = what;
    err = '';
    try {
      s = await api.setDns(patch);
    } catch (e) {
      err = e instanceof Error ? e.message : String(e);
      await load();
    } finally {
      busy = '';
    }
  }

  function toggle() {
    if (!s) return;
    if (s.settings.enabled) {
      void change('toggle', { enabled: false });
      return;
    }
    const ok = confirm(
      'Это изменит настройки DNS роутера: его DNS-прокси получит ещё один сервер — nuxk (' +
        s.listen +
        ').\n\n' +
        'Устройства спрашивают роутер, как и раньше; маршрутизация по доменам не меняется. ' +
        'Настройка не сохраняется в конфигурацию роутера: после перезагрузки nuxk добавит её сам, при удалении nuxk — уберёт.\n\n' +
        'Сначала nuxk проверит, что серверы DoH отвечают, а после включения — что роутер по-прежнему отвечает на DNS. Если нет — сразу вернёт всё как было.',
    );
    if (ok) void change('toggle', { enabled: true });
  }

  const VIA: { id: DNSSettings['via']; label: string; hint: string }[] = [
    { id: 'auto', label: 'Автоматически', hint: 'VLESS, если он работает, потом WARP, потом напрямую' },
    { id: 'vless', label: 'Через VLESS', hint: 'пока VLESS недоступен — напрямую' },
    { id: 'warp', label: 'Через WARP', hint: 'пока WARP недоступен — напрямую' },
    { id: 'direct', label: 'Напрямую', hint: 'без туннеля; DoH всё равно зашифрован, но его могут заблокировать' },
  ];
  const PATH: Record<string, string> = { vless: 'VLESS', warp: 'WARP', direct: 'Напрямую' };

  function toggleResolver(id: string) {
    if (!s) return;
    const cur = s.settings.resolvers;
    const next = cur.includes(id) ? cur.filter((x) => x !== id) : [...cur, id];
    if (next.length) void change('settings', { resolvers: next });
  }

  async function flush() {
    busy = 'flush';
    err = '';
    try {
      s = await api.flushDnsCache();
    } catch (e) {
      err = e instanceof Error ? e.message : String(e);
    } finally {
      busy = '';
    }
  }

  // how many questions the cache answered, of those that came to nuxk
  const hitRate = $derived.by(() => {
    const c = s?.cache;
    if (!c || c.hits + c.misses === 0) return '';
    const all = c.hits + c.misses;
    return `${Math.round((c.hits / all) * 100)} % · ${c.hits} из ${all}`;
  });

  async function runCheck() {
    busy = 'check';
    err = '';
    try {
      const doms = extra
        .split(/[\s,]+/)
        .map((d) => d.trim().toLowerCase())
        .filter(Boolean)
        .slice(0, 20);
      check = await api.checkDns(doms);
    } catch (e) {
      err = e instanceof Error ? e.message : String(e);
    } finally {
      busy = '';
    }
  }

  const VERDICT: Record<string, { label: string; chip: string }> = {
    ok: { label: 'честно', chip: 'ok' },
    spoofed: { label: 'подмена', chip: 'warn' },
    differs: { label: 'другие адреса', chip: 'deg' },
    error: { label: 'нет ответа', chip: '' },
  };
  const list = (a: string[]) => (a.length ? a.slice(0, 3).join(', ') + (a.length > 3 ? ' …' : '') : '—');
</script>

<div class="grid g2">
  <section class="card">
    <div class="card-head">
      <h2>Защищённый DNS</h2>
      {#if s}
        {#if s.settings.enabled && s.attached}<span class="chip ok">включён</span>
        {:else if s.settings.enabled && s.suspended}<span class="chip warn">приостановлен</span>
        {:else if s.settings.enabled}<span class="chip deg">включён, роутер пока не спрашивает</span>
        {:else}<span class="chip">выключен</span>{/if}
      {/if}
      <span class="spacer"></span>
      {#if s?.can_attach}
        <button class={s.settings.enabled ? 'ghost sm' : 'sm'} onclick={toggle} disabled={!!busy}>
          {busy === 'toggle' ? 'Проверяю…' : s.settings.enabled ? 'Выключить' : 'Включить'}
        </button>
      {/if}
    </div>
    <p class="hint">
      Провайдер подменяет ответы обычного DNS на заглушки — даже к 8.8.8.8. С защитой роутер спрашивает nuxk, а nuxk —
      серверы DoH через туннель: провайдер не видит ни вопроса, ни ответа. Устройства ничего не настраивают.
    </p>
    {#if !s}
      <p class="muted">{err || 'Загрузка…'}</p>
    {:else}
      {#if !s.can_attach && s.cannot}<p class="banner deg note">{s.cannot}</p>{/if}
      {#if s.error}<p class="err-text">{s.error}</p>{/if}
      <dl class="kv top">
        <dt>роутер спрашивает nuxk</dt>
        <dd>
          {#if !s.settings.enabled}—
          {:else if s.attached}да{s.consulted ? '' : ' (контрольный вопрос не дошёл — возможно, роутер пока опрашивает другие серверы)'}
          {:else}нет{/if}
        </dd>
        <dt>вопросов</dt><dd>{s.queries}{s.failed ? ` · без ответа ${s.failed}` : ''}</dd>
        <dt>последний</dt><dd>{s.last_query ? ago(s.last_query) : 'ещё не было'}</dd>
        {#if s.last_path}<dt>ответил</dt><dd>{s.resolver || '—'} · {PATH[s.last_path] ?? s.last_path}</dd>{/if}
        <dt>адрес nuxk</dt><dd class="mono">{s.listen}</dd>
      </dl>
      <div class="divider top"></div>
      <div class="row top">
        <b>Кэш ответов</b>
        {#if s.settings.cache}<span class="chip ok">включён</span>{:else}<span class="chip">выключен</span>{/if}
        <span class="spacer"></span>
        <label class="res">
          <input
            type="checkbox"
            checked={s.settings.cache}
            disabled={!!busy}
            onchange={() => s && change('cache', { cache: !s.settings.cache })}
          />
          запоминать
        </label>
        <button class="ghost sm" onclick={flush} disabled={!!busy || !s.cache.entries}>
          {busy === 'flush' ? 'Очищаю…' : 'Очистить'}
        </button>
      </div>
      <p class="hint top-s">
        nuxk хранит ответ столько, сколько разрешил сервер, а часто нужные адреса обновляет заранее. Если туннели и DoH не
        ответили за 2 секунды — отдаёт последний известный адрес (не старше суток), и открытые раньше сайты продолжают
        работать. Проверка подмены кэш не использует.
      </p>
      {#if s.settings.cache}
        <dl class="kv top-s">
          <dt>в кэше</dt><dd>{plural(s.cache.entries, 'ответ', 'ответа', 'ответов')} · {fmtBytes(s.cache.bytes)}</dd>
          <dt>из кэша</dt><dd>{hitRate || 'пока не было'}</dd>
          <dt>обновлено заранее</dt><dd>{s.cache.refreshed}</dd>
          <dt>выручил при сбое</dt><dd>{s.cache.stale}</dd>
        </dl>
      {/if}
    {/if}
  </section>

  <section class="card">
    <div class="card-head"><h2>Как идут вопросы</h2></div>
    {#if s}
      <div class="via" role="radiogroup" aria-label="Путь">
        {#each VIA as v (v.id)}
          <label class:on={s.settings.via === v.id}>
            <input
              type="radio"
              name="via"
              checked={s.settings.via === v.id}
              disabled={!!busy}
              onchange={() => change('settings', { via: v.id })}
            />
            <span><b>{v.label}</b><small>{v.hint}</small></span>
          </label>
        {/each}
      </div>
      <div class="tbl-wrap top">
        <table>
          <thead><tr><th>путь</th><th>сейчас</th><th>ответов</th><th>время</th><th></th></tr></thead>
          <tbody>
            {#each s.paths as p (p.name)}
              <tr>
                <td><b>{PATH[p.name] ?? p.name}</b>{#if p.iface}<span class="muted mono"> {p.iface}</span>{/if}</td>
                <td>{#if p.up}<span class="chip ok">доступен</span>{:else}<span class="chip">нет</span>{/if}</td>
                <td class="mono">{p.ok}{p.failed ? ` / ✗${p.failed}` : ''}</td>
                <td class="mono">{p.rtt_ms ? `${Math.round(p.rtt_ms)} мс` : '—'}</td>
                <td class="err-cell">{p.last_error ?? ''}</td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
      <p class="hint top">Серверы DoH (по порядку; при сбое — следующий):</p>
      <div class="row">
        {#each s.catalog as r (r.id)}
          <label class="res">
            <input type="checkbox" checked={s.settings.resolvers.includes(r.id)} disabled={!!busy} onchange={() => toggleResolver(r.id)} />
            {r.name}
          </label>
        {/each}
      </div>
    {/if}
  </section>
</div>

<section class="card">
  <div class="card-head">
    <h2>Проверка подмены</h2>
    {#if check}
      <span class="chip {check.plain_spoofed ? 'warn' : 'ok'}"
        >провайдер: {check.plain_spoofed ? `подменяет (${check.plain_spoofed} из ${check.items.length})` : 'подмены не видно'}</span
      >
      <span class="chip {check.router_spoofed ? 'warn' : 'ok'}"
        >роутер: {check.router_spoofed ? `отдаёт подмену (${check.router_spoofed})` : 'честно'}</span
      >
    {/if}
    <span class="spacer"></span>
    <button class="sm" onclick={runCheck} disabled={!!busy}>{busy === 'check' ? 'Проверяю…' : 'Проверить'}</button>
  </div>
  <p class="hint">
    Для заблокированных сайтов-«канареек» и доменов из ваших списков: что отвечает роутер (это получают устройства), что
    отвечает 8.8.8.8, если спросить его обычным DNS через провайдера, и что — через туннель (эталон). «Подмена» — только
    при явных признаках: «сайта нет», частный адрес или один адрес у разных сайтов.
  </p>
  <input class="top" bind:value={extra} placeholder="Свои домены через пробел (необязательно), например rutracker.org" />
  {#if check}
    <div class="tbl-wrap top">
      <table>
        <thead><tr><th>домен</th><th>роутер</th><th>8.8.8.8 обычным DNS</th><th>через туннель</th></tr></thead>
        <tbody>
          {#each check.items as it (it.domain)}
            <tr>
              <td><b>{it.domain}</b></td>
              <td>
                <span class="chip {VERDICT[it.router_verdict]?.chip}">{VERDICT[it.router_verdict]?.label}</span>
                <span class="mono muted small">{list(it.router)}</span>
                {#if it.router_note}<small class="note">{it.router_note}</small>{/if}
              </td>
              <td>
                <span class="chip {VERDICT[it.plain_verdict]?.chip}">{VERDICT[it.plain_verdict]?.label}</span>
                <span class="mono muted small">{list(it.plain)}</span>
                {#if it.plain_note}<small class="note">{it.plain_note}</small>{/if}
              </td>
              <td class="mono small">{list(it.truth)}</td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
    <p class="hint top">
      Эталон шёл {PATH[check.path] ? (check.path === 'direct' ? 'напрямую по DoH' : `через ${PATH[check.path]}`) : '—'} ·
      {ago(check.at)}. Устройства со своим DNS («Частный DNS» на Android, свой VPN) спрашивают мимо роутера — на них эта
      защита не действует.
    </p>
  {/if}
  {#if err}<p class="err-text">{err}</p>{/if}
</section>

<style>
  .top {
    margin-top: 12px;
  }
  .top-s {
    margin-top: 6px;
  }
  .note {
    display: block;
    color: var(--muted);
    margin-top: 2px;
  }
  .muted {
    color: var(--muted);
  }
  .small {
    font-size: 12px;
  }
  .via {
    display: grid;
    gap: 6px;
  }
  .via label {
    display: flex;
    gap: 10px;
    align-items: flex-start;
    padding: 8px 10px;
    border: 1px solid var(--line);
    border-radius: 10px;
    cursor: pointer;
    font-size: 13px;
  }
  .via label.on {
    border-color: color-mix(in srgb, var(--accent) 55%, transparent);
    background: var(--accent-soft);
  }
  .via span {
    display: flex;
    flex-direction: column;
    gap: 2px;
  }
  .via small {
    color: var(--muted);
  }
  .res {
    display: flex;
    gap: 6px;
    align-items: center;
    font-size: 13px;
    margin-right: 12px;
  }
  .err-cell {
    color: var(--muted);
    font-size: 12px;
    max-width: 280px;
    overflow-wrap: anywhere;
  }
  input:not([type]) {
    width: 100%;
  }
</style>
