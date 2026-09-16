// Progressive enhancements for the server-rendered Leptos console.
// No credentials or configuration data are persisted by this script.
(() => {
  const find = (selector) => document.querySelector(selector);
  const drawer = find('#navigation');
  const opener = find('[data-open-nav]');
  opener?.addEventListener('click', () => {
    drawer.showModal();
    opener.setAttribute('aria-expanded', 'true');
  });
  find('[data-close-nav]')?.addEventListener('click', () => drawer.close());
  drawer?.addEventListener('close', () => {
    opener?.setAttribute('aria-expanded', 'false');
    opener?.focus();
  });

  const account = find('[data-account]');
  const menu = find('#account-menu');
  const toggleMenu = (open, focus = true) => {
    if (!menu) return;
    menu.hidden = !open;
    account.setAttribute('aria-expanded', String(open));
    if (focus) (open ? menu.querySelector('[role=menuitem]') : account)?.focus();
  };
  account?.addEventListener('click', () => toggleMenu(menu.hidden));
  account?.addEventListener('keydown', (event) => {
    if (event.key === 'ArrowDown') { event.preventDefault(); toggleMenu(true); }
  });
  document.addEventListener('pointerdown', (event) => {
    if (menu && !event.target.closest('.account')) toggleMenu(false, false);
  });
  document.addEventListener('keydown', (event) => {
    if (event.key === 'Escape') {
      if (menu && !menu.hidden) { toggleMenu(false); return; }
      if (!drawer?.open && find('[data-close-user]')) find('[data-close-user]').click();
    }
  });

  const form = find('.list-controls');
  const input = form?.querySelector('input[type=search]');
  const rows = [...document.querySelectorAll('tr[data-search]')];
  const controls = ['status', 'auth', 'sort'];
  const defaults = { status: 'all', auth: 'all', sort: 'asc' };
  const setState = (url, reset = false, clear = false) => {
    const query = reset || clear ? '' : input.value;
    if (query) url.searchParams.set('q', query); else url.searchParams.delete('q');
    controls.forEach((name) => {
      const value = reset ? defaults[name] : form.elements[name]?.value || defaults[name];
      if (value !== defaults[name]) url.searchParams.set(name, value); else url.searchParams.delete(name);
    });
    return url;
  };
  const filter = () => {
    if (!input) return;
    const query = input.value.trim().toLowerCase();
    const status = form.elements.status.value;
    const auth = form.elements.auth?.value || 'all';
    let count = 0;
    rows.forEach((row) => {
      row.hidden = !row.dataset.search.includes(query)
        || (status !== 'all' && row.dataset.status !== status)
        || (auth !== 'all' && row.dataset.auth !== auth);
      if (!row.hidden) count++;
    });
    // Ranks share the server's deterministic, locale-independent Unicode order.
    const direction = form.elements.sort.value === 'desc' ? -1 : 1;
    rows.sort((a, b) => direction * (Number(a.dataset.rank) - Number(b.dataset.rank)));
    const body = find('[data-filter-table] tbody');
    rows.forEach((row) => body.append(row));
    if (rows.length) {
      find('[data-filter-table]').hidden = !count;
      find('[data-no-results]').hidden = count > 0;
      const counter = find('[data-count]');
      const noun = counter.dataset.count === 'users' ? 'user' : 'application';
      counter.textContent = `${count} ${noun}${count === 1 ? '' : 's'} found`;
    }
    const url = setState(new URL(location.href));
    const selected = rows.find((row) => row.classList.contains('selected'));
    if (find('.user-detail') && (!selected || selected.hidden)) {
      find('.user-detail').remove();
      find('.list-detail').classList.remove('has-detail');
      selected?.classList.remove('selected');
      form.querySelector('input[name=id]')?.remove();
      url.searchParams.delete('id');
    }
    history.replaceState(history.state, '', url);
    document.querySelectorAll('[data-detail-link],[data-close-user]').forEach((link) => {
      link.href = setState(new URL(link.href)).href;
    });
    document.querySelectorAll('[data-clear-search],[data-reset-list]').forEach((link) => {
      const target = new URL(url);
      if (link.closest('[data-no-results]')) target.searchParams.delete('id');
      const clear = link.hasAttribute('data-clear-search');
      link.href = setState(target, !clear, clear).href;
      if (clear) link.hidden = !input.value;
    });
  };
  input?.addEventListener('input', filter);
  controls.forEach((name) => form?.elements[name]?.addEventListener('change', filter));
  form?.addEventListener('submit', (event) => { event.preventDefault(); filter(); });
  document.querySelectorAll('[data-clear-search],[data-reset-list]').forEach((link) => link.addEventListener('click', (event) => {
    if (event.button || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
    event.preventDefault();
    input.value = '';
    if (link.hasAttribute('data-reset-list')) {
      controls.forEach((name) => { if (form.elements[name]) form.elements[name].value = defaults[name]; });
    }
    filter();
    input.focus();
  }));

  document.querySelectorAll('[data-copy]').forEach((button) => button.addEventListener('click', async () => {
    let message;
    try { await navigator.clipboard.writeText(button.dataset.copy); message = 'Copied'; }
    catch {
      message = 'Select text to copy';
      const value = button.closest('.field').querySelector('dd');
      const range = document.createRange(); range.selectNodeContents(value);
      const selection = window.getSelection(); selection.removeAllRanges(); selection.addRange(range);
    }
    button.textContent = message;
    find('#copy-announcement').textContent = message;
    clearTimeout(button.copyTimer);
    button.copyTimer = setTimeout(() => { button.textContent = 'Copy'; }, 2200);
  }));

  // Store only UI navigation state; no user or client record is persisted.
  const remember = (key, value) => { try { sessionStorage.setItem(key, JSON.stringify(value)); } catch {} };
  const recall = (key) => { try { return JSON.parse(sessionStorage.getItem(key)); } catch { return null; } };
  document.querySelectorAll('[data-detail-link]').forEach((link) => link.addEventListener('click', () => {
    remember('admin-list-scroll', { path: location.pathname, y: window.scrollY, rank: link.closest('tr').dataset.rank });
  }));
  const params = new URLSearchParams(location.search);
  if (params.has('id')) {
    (find('[data-close-user]') || find('#main'))?.focus({ preventScroll: true });
  } else {
    const saved = recall('admin-list-scroll');
    if (saved?.path === location.pathname) {
      const link = [...document.querySelectorAll('[data-detail-link]')].find((candidate) => candidate.closest('tr').dataset.rank === saved.rank);
      if (link && !link.closest('tr').hidden) link.focus({ preventScroll: true });
      window.scrollTo(0, saved.y);
    }
  }
  // Cached history entries must revalidate the server session after sign out.
  window.addEventListener('pageshow', (event) => { if (event.persisted) location.reload(); });
})();
