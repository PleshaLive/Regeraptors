const SELECTORS = {
  loginView: document.getElementById('login-view'),
  appView: document.getElementById('app-view'),
  loginForm: document.getElementById('login-form'),
  addTargetForm: document.getElementById('add-target-form'),
  targetsBody: document.getElementById('targets-body'),
  targetsMeta: document.getElementById('targets-meta'),
  refreshBtn: document.getElementById('refresh-targets'),
  logoutBtn: document.getElementById('logout-btn'),
  queueMode: document.getElementById('queue-mode'),
  banner: document.getElementById('status-banner'),
  rowTemplate: document.getElementById('target-row-template')
};

class AdminApp {
  constructor() {
    this.state = {
      authenticated: false,
      targets: [],
      config: null
    };
  }

  async init() {
    this.bindEvents();
    await this.refreshSession();
  }

  bindEvents() {
    SELECTORS.loginForm?.addEventListener('submit', (event) => this.handleLogin(event));
    SELECTORS.addTargetForm?.addEventListener('submit', (event) => this.handleAddTarget(event));
    SELECTORS.refreshBtn?.addEventListener('click', () => this.refreshTargets());
    SELECTORS.logoutBtn?.addEventListener('click', () => this.handleLogout());
  }

  async refreshSession() {
    try {
      const response = await fetch('/admin/api/session', {
        credentials: 'include'
      });
      if (!response.ok) {
        throw new Error('Session check failed');
      }
      const { authenticated } = await response.json();
      this.state.authenticated = Boolean(authenticated);
      if (this.state.authenticated) {
        await this.enterApp();
      } else {
        this.showLogin();
      }
    } catch (error) {
      this.showLogin();
      this.setBanner(`Unable to reach server: ${error.message}`, { tone: 'error' });
    }
  }

  showLogin() {
    this.hide(SELECTORS.appView);
    this.show(SELECTORS.loginView);
    SELECTORS.loginForm?.reset();
  }

  async enterApp() {
    this.hide(SELECTORS.loginView);
    this.show(SELECTORS.appView);
    await Promise.all([this.loadConfig(), this.refreshTargets()]);
  }

  async handleLogin(event) {
    event.preventDefault();
    const form = event.currentTarget;
    const payload = new FormData(form);
    const body = {
      username: payload.get('username'),
      password: payload.get('password')
    };
    try {
      const response = await fetch('/admin/api/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify(body)
      });
      if (!response.ok) {
        const { error } = await response.json().catch(() => ({ error: 'Login failed' }));
        throw new Error(error || 'Login failed');
      }
      this.state.authenticated = true;
      await this.enterApp();
      this.setBanner('Signed in successfully');
    } catch (error) {
      this.setBanner(error.message || 'Login failed', { tone: 'error' });
    }
  }

  async handleLogout() {
    try {
      const response = await fetch('/admin/api/logout', {
        method: 'POST',
        credentials: 'include'
      });
      if (!response.ok) {
        throw new Error('Logout failed');
      }
    } catch (error) {
      this.setBanner(error.message || 'Logout failed', { tone: 'error' });
    } finally {
      this.state.authenticated = false;
      this.showLogin();
    }
  }

  async loadConfig() {
    try {
      const response = await fetch('/admin/api/config', {
        credentials: 'include'
      });
      if (!response.ok) {
        throw new Error('Config load failed');
      }
      this.state.config = await response.json();
      const { queueEnabled, forwardFlushMs, retryMax, retryBaseMs, retryJitterMs } = this.state.config;
      const queueLabel = queueEnabled
        ? `Queue ON (flush ${forwardFlushMs} ms)`
        : 'Queue OFF (immediate dispatch)';
      SELECTORS.queueMode.textContent = `${queueLabel} · Retry ${retryMax}x (${retryBaseMs}ms + jitter ${retryJitterMs}ms)`;
    } catch (error) {
      this.state.config = null;
      SELECTORS.queueMode.textContent = 'Unable to load configuration';
      this.setBanner(error.message || 'Failed to load configuration', { tone: 'error' });
    }
  }

  async refreshTargets() {
    try {
      const response = await fetch('/admin/api/targets', {
        credentials: 'include'
      });
      if (!response.ok) {
        throw new Error('Failed to fetch targets');
      }
      this.state.targets = await response.json();
      this.renderTargets();
      this.updateTargetsMeta();
    } catch (error) {
      this.setBanner(error.message || 'Failed to fetch targets', { tone: 'error' });
    }
  }

  updateTargetsMeta() {
    if (!SELECTORS.targetsMeta) {
      return;
    }
    const total = this.state.targets.length;
    const enabled = this.state.targets.filter((target) => target.enabled).length;
    SELECTORS.targetsMeta.textContent = `${enabled}/${total} enabled`;
  }

  renderTargets() {
    const body = SELECTORS.targetsBody;
    if (!body) {
      return;
    }

    body.innerHTML = '';

    if (!this.state.targets.length) {
      const row = document.createElement('tr');
      row.classList.add('empty');
      const cell = document.createElement('td');
      cell.colSpan = 7;
      cell.textContent = 'No targets configured yet.';
      row.append(cell);
      body.append(row);
      return;
    }

    this.state.targets.forEach((target) => {
      const row = this.createRow(target);
      body.append(row);
    });
  }

  createRow(target) {
    const template = SELECTORS.rowTemplate.content.cloneNode(true);
    const row = template.querySelector('tr');
    row.dataset.id = target.id;

    row.querySelector('.target-url').textContent = target.url;
    row.querySelector('.target-status').textContent = target.metrics?.lastStatus || '—';
    row.querySelector('.target-sent').textContent = target.metrics?.sent ?? 0;
    row.querySelector('.target-failed').textContent = target.metrics?.failed ?? 0;
    row.querySelector('.target-latency').textContent = this.formatLatency(target.metrics?.avgLatencyMs);
    row.querySelector('.target-last').textContent = this.formatTimestamp(target.metrics?.lastAttemptAt);

    const enabledCheckbox = row.querySelector('.target-enabled');
    enabledCheckbox.checked = Boolean(target.enabled);
    enabledCheckbox.addEventListener('change', () => this.toggleTarget(target.id, enabledCheckbox.checked));

    row.querySelector('.test-btn').addEventListener('click', () => this.testTarget(row, target.id));
    row.querySelector('.delete-btn').addEventListener('click', () => this.deleteTarget(row, target.id));

    return row;
  }

  async toggleTarget(id, enabled) {
    try {
      const response = await fetch(`/admin/api/targets/${id}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ enabled })
      });
      if (!response.ok) {
        throw new Error('Update failed');
      }
    } catch (error) {
      this.setBanner(error.message || 'Failed to update target', { tone: 'error' });
    } finally {
      await this.refreshTargets();
    }
  }

  async testTarget(row, id) {
    const button = row.querySelector('.test-btn');
    const message = row.querySelector('.row-message');
    try {
      button.disabled = true;
      message.textContent = 'Testing...';
      message.classList.remove('error');
      const response = await fetch(`/admin/api/targets/${id}/test`, {
        method: 'POST',
        credentials: 'include'
      });
      if (!response.ok) {
        const { error } = await response.json().catch(() => ({ error: 'Target test failed' }));
        throw new Error(error || 'Target test failed');
      }
      const { latencyMs } = await response.json();
      message.textContent = `OK (${latencyMs?.toFixed?.(1) ?? latencyMs} ms)`;
      await this.refreshTargets();
    } catch (error) {
      message.textContent = error.message || 'Test failed';
      message.classList.add('error');
    } finally {
      button.disabled = false;
    }
  }

  async deleteTarget(row, id) {
    if (!confirm('Remove this target?')) {
      return;
    }
    const button = row.querySelector('.delete-btn');
    try {
      button.disabled = true;
      const response = await fetch(`/admin/api/targets/${id}`, {
        method: 'DELETE',
        credentials: 'include'
      });
      if (!response.ok) {
        throw new Error('Delete failed');
      }
      this.setBanner('Target removed');
      await this.refreshTargets();
    } catch (error) {
      this.setBanner(error.message || 'Failed to delete target', { tone: 'error' });
    } finally {
      button.disabled = false;
    }
  }

  async handleAddTarget(event) {
    event.preventDefault();
    const form = event.currentTarget;
    const data = new FormData(form);
    const payload = {
      url: data.get('url'),
      enabled: data.get('enabled') === 'on'
    };
    try {
      const response = await fetch('/admin/api/targets', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify(payload)
      });
      if (!response.ok) {
        const { error } = await response.json().catch(() => ({ error: 'Unable to add target' }));
        throw new Error(error || 'Unable to add target');
      }
      form.reset();
      this.setBanner('Target added');
      await this.refreshTargets();
    } catch (error) {
      this.setBanner(error.message || 'Failed to add target', { tone: 'error' });
    }
  }

  formatLatency(value) {
    if (!value && value !== 0) {
      return '—';
    }
    return Number(value).toFixed(1);
  }

  formatTimestamp(isoString) {
    if (!isoString) {
      return '—';
    }
    const date = new Date(isoString);
    if (Number.isNaN(date.getTime())) {
      return '—';
    }
    return date.toLocaleString();
  }

  setBanner(message, options = {}) {
    const element = SELECTORS.banner;
    if (!element) {
      return;
    }
    if (!message) {
      element.classList.add('hidden');
      element.textContent = '';
      element.classList.remove('error');
      return;
    }
    element.textContent = message;
    element.classList.remove('hidden');
    if (options.tone === 'error') {
      element.classList.add('error');
    } else {
      element.classList.remove('error');
    }
    clearTimeout(this.bannerTimeout);
    this.bannerTimeout = window.setTimeout(() => {
      element.classList.add('hidden');
    }, options.timeout ?? 4000);
  }

  show(node) {
    node?.classList.remove('hidden');
  }

  hide(node) {
    node?.classList.add('hidden');
  }
}

document.addEventListener('DOMContentLoaded', () => {
  const app = new AdminApp();
  app.init();
});
