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

  const input = find('input[type=search]');
  const rows = [...document.querySelectorAll('tr[data-search]')];
  const filter = () => {
    if (!input) return;
    const query = input.value.trim().toLocaleLowerCase();
    let count = 0;
    rows.forEach((row) => {
      row.hidden = !row.dataset.search.toLocaleLowerCase().includes(query);
      if (!row.hidden) count++;
    });
    if (rows.length) {
      find('[data-filter-table]').hidden = !count;
      find('[data-no-results]').hidden = count > 0;
      const users = location.pathname.endsWith('/users');
      find('[data-no-results-title]').textContent = users ? `No users match “${input.value}”.` : `No matches for “${input.value}”.`;
      const counter = find('[data-count]');
      if (counter) counter.textContent = users ? `${count} users found` : `${count} ${count === 1 ? 'application' : 'applications'} · includes disabled clients`;
    }
    const url = new URL(location.href);
    if (input.value) url.searchParams.set('q', input.value); else url.searchParams.delete('q');
    history.replaceState(null, '', url);
    document.querySelectorAll('[data-detail-link],[data-close-user]').forEach((link) => {
      const target = new URL(link.href);
      if (input.value) target.searchParams.set('q', input.value); else target.searchParams.delete('q');
      link.href = target.href;
    });
    const clear = find('.search [data-clear-search]');
    if (clear) clear.hidden = !input.value;
  };
  input?.addEventListener('input', filter);
  find('.search')?.addEventListener('submit', (event) => { event.preventDefault(); filter(); });
  document.querySelectorAll('[data-clear-search]').forEach((button) => button.addEventListener('click', () => {
    input.value = ''; filter(); input.focus();
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
    remember('admin-list-scroll', { path: location.pathname, y: window.scrollY, index: [...document.querySelectorAll('[data-detail-link]')].indexOf(link) });
  }));
  const params = new URLSearchParams(location.search);
  if (params.has('id')) {
    (find('[data-close-user]') || find('#main'))?.focus({ preventScroll: true });
  } else {
    const saved = recall('admin-list-scroll');
    if (saved?.path === location.pathname) {
      document.querySelectorAll('[data-detail-link]')[saved.index]?.focus({ preventScroll: true });
      window.scrollTo(0, saved.y);
    }
  }
  // Cached history entries must revalidate the server session after sign out.
  window.addEventListener('pageshow', (event) => { if (event.persisted) location.reload(); });
})();
