/**
 * Gasha — Enterprise Threat Operations Center Client Engine
 * Asynchronously interacts with Python WSGI / Flask Backend APIs
 */

// Global State
let currentTab = 'dashboard';
let telemetryCache = null;

// ============================================================================
// API FETCH WRAPPER (CSRF-aware)
// ============================================================================
// Fetches the CSRF token from /api/csrf-token on first use, caches it in
// memory, then automatically injects the X-CSRF-Token header on every POST.
// This means all existing code just calls apiFetch() instead of fetch() and
// CSRF is handled transparently.
let _csrfToken = null;

async function _ensureCsrfToken() {
    if (_csrfToken) return _csrfToken;
    try {
        const res = await fetch('/api/csrf-token');
        const json = await res.json();
        if (json && json.csrf_token) {
            _csrfToken = json.csrf_token;
        }
    } catch (e) {
        console.warn('Could not fetch CSRF token:', e);
    }
    return _csrfToken;
}

async function apiFetch(url, options = {}) {
    const headers = { 'Content-Type': 'application/json', ...(options.headers || {}) };
    // Inject CSRF token on all state-changing requests
    if (options.method && options.method.toUpperCase() !== 'GET') {
        const token = await _ensureCsrfToken();
        if (token) headers['X-CSRF-Token'] = token;
    }
    return fetch(url, { ...options, headers });
}

document.addEventListener('DOMContentLoaded', () => {
    document.querySelectorAll(".nav-item").forEach((navItem) => {
        navItem.addEventListener("click", () => {
            const target = navItem.getAttribute("data-target");
            if (target) switchNav(target);
        });
    });
    checkAuthState();
    // Preload the CSRF token so the first scan doesn't wait on an extra round-trip
    _ensureCsrfToken();
    loadRealDashboardTelemetry();
    loadDashboardTelemetry();
    loadPlaybooks();
    loadLearningJourney();

    // ---- Input constraint enforcement ----
    const inputButtonPairs = [
        { inputId: 'targetUrlInput',    btnId: 'btnRunUrlScan' },
        { inputId: 'messageTextInput',  btnId: 'btnRunMsgScan' },
        { inputId: 'emailAuditInput',   btnId: 'btnRunEmailScan' },
        { inputId: 'passwordAuditInput',btnId: 'btnRunPwdAudit' },
        { inputId: 'headerUrlInput',    btnId: 'btnRunHeaderScan' },
        { inputId: 'ipAuditInput',      btnId: 'btnRunIpAudit' },
    ];

    inputButtonPairs.forEach(({ inputId, btnId }) => {
        const input = document.getElementById(inputId);
        const btn = document.getElementById(btnId);
        if (!input || !btn) return;
        // Initially disable if empty
        btn.disabled = input.value.trim().length === 0;
        input.addEventListener('input', () => {
            btn.disabled = input.value.trim().length === 0;
        });
    });

    // ---- Inline validation on blur ----
    const urlInput = document.getElementById('targetUrlInput');
    if (urlInput) {
        urlInput.addEventListener('blur', () => {
            let errEl = urlInput.parentElement.querySelector('.field-error');
            if (!errEl) {
                errEl = document.createElement('span');
                errEl.className = 'field-error';
                urlInput.parentElement.after(errEl);
            }
            const val = urlInput.value.trim();
            errEl.textContent = (val && !val.includes('.'))
                ? 'Enter a valid URL or domain (e.g. example.com)'
                : '';
        });
    }

    const emailInput = document.getElementById('emailAuditInput');
    if (emailInput) {
        emailInput.addEventListener('blur', () => {
            let errEl = emailInput.parentElement.querySelector('.field-error');
            if (!errEl) {
                errEl = document.createElement('span');
                errEl.className = 'field-error';
                emailInput.parentElement.after(errEl);
            }
            const val = emailInput.value.trim();
            errEl.textContent = (val && !val.includes('@'))
                ? 'Enter a valid email address (e.g. user@domain.com)'
                : '';
        });
    }
});

// ============================================================================
// NAVIGATION CONTROLLER & MOBILE DRAWER
// ============================================================================
function switchNav(targetId) {
    currentTab = targetId;
    
    // Update active nav items on sidebar
    document.querySelectorAll('.nav-item').forEach(item => {
        if (item.getAttribute('data-target') === targetId) {
            item.classList.add('active');
        } else {
            item.classList.remove('active');
        }
    });

    // Close mobile drawer if open
    const sidebar = document.getElementById('sidebarNav');
    if (sidebar && sidebar.classList.contains('mobile-open')) {
        sidebar.classList.remove('mobile-open');
    }

    // Update active top link buttons
    document.querySelectorAll('.top-link-btn').forEach(btn => {
        const btnId = btn.id || '';
        if (btnId === `topNav-${targetId}` || (btn.getAttribute('onclick') || '').includes(`'${targetId}'`)) {
            btn.classList.add('active');
        } else {
            btn.classList.remove('active');
        }
    });

    // Update active view panels
    document.querySelectorAll('.view-panel').forEach(panel => {
        if (panel.id === `view-${targetId}`) {
            panel.classList.add('active');
        } else {
            panel.classList.remove('active');
        }
    });

    // Dynamic data loading hooks
    if (targetId === 'learning-journey') {
        loadLearningJourney();
    } else if (targetId === 'dashboard') {
        loadRealDashboardTelemetry();
    } else if (targetId === 'incident-playbooks') {
        loadPlaybooks();
    }

    window.scrollTo({ top: 0, behavior: 'smooth' });
}

function toggleMobileNav() {
    const sidebar = document.getElementById('sidebarNav');
    if (sidebar) {
        sidebar.classList.toggle('mobile-open');
    }
}

// Global Top Search Handler
function handleTopSearch(event) {
    if (event.key === 'Enter') {
        const query = event.target.value.trim();
        if (!query) return;

        // Auto-route based on pattern
        if (query.startsWith('http://') || query.startsWith('https://') || query.includes('.com') || query.includes('.org') || query.includes('.tk') || query.includes('.xyz') || query.includes('.net')) {
            switchNav('url-scanner');
            document.getElementById('targetUrlInput').value = query;
            executeUrlScan();
        } else if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(query)) {
            switchNav('ip-intelligence');
            document.getElementById('ipAuditInput').value = query;
            executeIpAudit();
        } else if (query.includes('@')) {
            switchNav('email-radar');
            document.getElementById('emailAuditInput').value = query;
            executeEmailAudit();
        } else if (/^[a-fA-F0-9]{32,128}$/.test(query)) {
            switchNav('crypto-suite');
            document.getElementById('unknownHashInput').value = query;
            executeHashIdentify();
        } else {
            switchNav('message-analyzer');
            document.getElementById('messageTextInput').value = query;
            executeMessageScan();
        }
    }
}

// ============================================================================
// TOAST MESSAGING & UTILITIES
// ============================================================================
function showToast(message, isError = false) {
    const toast = document.getElementById('socToast');
    if (!toast) return;
    toast.textContent = message;
    toast.className = isError ? 'error' : 'success';
    toast.classList.add('show');
    clearTimeout(toast._timer);
    toast._timer = setTimeout(() => toast.classList.remove('show'), 4000);
}

function escapeHtml(str) {
    if (!str) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

function delay(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

// ============================================================================
// AUTHENTICATION & USER MANAGEMENT (REAL MYSQL DB)
// ============================================================================
let currentUser = null;

async function checkAuthState() {
    try {
        const res = await fetch('/api/auth/me');
        const json = await res.json();
        const container = document.getElementById('topAuthContainer');
        if (!container) return;

        const sidebarProfile = document.getElementById('sidebarUserProfile');

        if (json.authenticated && json.user) {
            currentUser = json.user;
            const initials = (currentUser.username || 'U').substring(0, 2).toUpperCase();
            container.innerHTML = `
                <div class="top-user-chip">
                    <div class="top-avatar-initials">${initials}</div>
                    <div class="top-user-details">
                        <span class="top-user-name">${escapeHtml(currentUser.username)}</span>
                        <span class="top-user-role">${escapeHtml(currentUser.role || 'SecOps Analyst')}</span>
                    </div>
                    <button class="top-logout-btn" onclick="handleLogout()" title="Sign Out">
                        <i class="fa-solid fa-arrow-right-from-bracket"></i>
                    </button>
                </div>
            `;
            if (sidebarProfile) {
                sidebarProfile.innerHTML = `
                    <div class="user-info">
                        <div class="icon-container">
                            <div class="top-avatar-initials" style="width: 44px; height: 44px; font-size: 15px; margin: 0 auto 8px;">${initials}</div>
                        </div>
                        <h4>${escapeHtml(currentUser.username)}</h4>
                        <p>${escapeHtml(currentUser.role || 'SecOps Analyst')}</p>
                        <div style="margin-top: 8px;">
                            <span style="font-size: 11px; font-weight: 700; color: #059669; background: #ecfdf5; padding: 3px 8px; border-radius: 12px; border: 1px solid #a7f3d0;">
                                <i class="fa-solid fa-circle-check"></i> Verified Operator
                            </span>
                        </div>
                    </div>
                `;
            }
        } else {
            currentUser = null;
            container.innerHTML = `
                <button class="top-auth-btn" onclick="openAuthModal('login')">
                    <i class="fa-solid fa-lock"></i>
                    <span>Sign In</span>
                </button>
            `;
            if (sidebarProfile) {
                sidebarProfile.innerHTML = `
                    <div class="user-info" style="cursor: pointer;" onclick="openAuthModal('login')">
                        <div class="icon-container">
                            <div class="top-avatar-initials" style="width: 44px; height: 44px; font-size: 18px; margin: 0 auto 8px; background: #e2e8f0; color: #64748b;">
                                <i class="fa-solid fa-user-lock"></i>
                            </div>
                        </div>
                        <h4>Guest Analyst</h4>
                        <p>Sign in to record scans</p>
                        <button class="btn-primary" style="margin-top: 10px; padding: 6px 14px; font-size: 11px; width: 100%; justify-content: center;" onclick="openAuthModal('login')">
                            <i class="fa-solid fa-right-to-bracket"></i> Sign In / Register
                        </button>
                    </div>
                `;
            }
        }
    } catch (e) {
        console.warn('Auth check failed:', e);
    }
}

function openAuthModal(tab = 'login') {
    const modal = document.getElementById('authModal');
    if (!modal) return;
    switchAuthTab(tab);
    modal.style.display = 'flex';
}

function closeAuthModal() {
    const modal = document.getElementById('authModal');
    if (modal) modal.style.display = 'none';
}

function handleModalBackdropClick(e) {
    if (e.target && e.target.id === 'authModal') {
        closeAuthModal();
    }
}

function switchAuthTab(tab) {
    const btnLogin = document.getElementById('tabBtnLogin');
    const btnRegister = document.getElementById('tabBtnRegister');
    const formLogin = document.getElementById('loginForm');
    const formRegister = document.getElementById('registerForm');

    if (tab === 'login') {
        btnLogin.classList.add('active');
        btnRegister.classList.remove('active');
        formLogin.style.display = 'block';
        formRegister.style.display = 'none';
    } else {
        btnLogin.classList.remove('active');
        btnRegister.classList.add('active');
        formLogin.style.display = 'none';
        formRegister.style.display = 'block';
    }
}

async function handleLoginSubmit(event) {
    event.preventDefault();
    const btn = document.getElementById('btnLoginSubmit');
    const username = document.getElementById('loginUsername').value.trim();
    const password = document.getElementById('loginPassword').value;

    if (!username || !password) {
        showToast('Please provide both username and password.', true);
        return;
    }

    btn.disabled = true;
    btn.innerHTML = `<i class="fa-solid fa-spinner fa-spin"></i> <span>Signing in…</span>`;

    try {
        const res = await apiFetch('/api/auth/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
        });
        const json = await res.json();

        if (json.status !== 'SUCCESS') {
            throw new Error(json.message || 'Authentication failed');
        }

        showToast(`Welcome back, ${json.user.username}! Secure session initiated.`);
        closeAuthModal();
        await checkAuthState();
        await loadRealDashboardTelemetry();
    } catch (err) {
        showToast(err.message, true);
    } finally {
        btn.disabled = false;
        btn.innerHTML = `<span>Sign in</span>`;
    }
}

async function handleRegisterSubmit(event) {
    event.preventDefault();
    const btn = document.getElementById('btnRegSubmit');
    const username = document.getElementById('regUsername').value.trim();
    const email = document.getElementById('regEmail').value.trim();
    const role = document.getElementById('regRole').value;
    const password = document.getElementById('regPassword').value;

    if (!username || !email || !password) {
        showToast('Please complete all required fields.', true);
        return;
    }

    btn.disabled = true;
    btn.innerHTML = `<i class="fa-solid fa-spinner fa-spin"></i> <span>Creating account…</span>`;

    try {
        const res = await apiFetch('/api/auth/register', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, email, password, role })
        });
        const json = await res.json();

        if (json.status !== 'SUCCESS') {
            throw new Error(json.message || 'Registration failed');
        }

        showToast(`Account created for ${json.user.username}! Logged in successfully.`);
        closeAuthModal();
        await checkAuthState();
        await loadRealDashboardTelemetry();
    } catch (err) {
        showToast(err.message, true);
    } finally {
        btn.disabled = false;
        btn.innerHTML = `<span>Create account</span>`;
    }
}

async function handleLogout() {
    try {
        await apiFetch('/api/auth/logout', { method: 'POST' });
        showToast('Secure session terminated. Logged out.');
        await checkAuthState();
        await loadRealDashboardTelemetry();
    } catch (e) {
        console.warn('Logout error:', e);
    }
}

// ============================================================================
// REAL MYSQL DASHBOARD TELEMETRY & AUDIT LOG
// ============================================================================
async function loadRealDashboardTelemetry() {
    try {
        const res = await fetch('/api/dashboard/stats');
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const json = await res.json();
        const data = json.data;

        // Posture Score & Counts
        if (data.metrics) {
            const m = data.metrics;
            const scoreEl = document.getElementById('postureScoreNumber');
            const boxEl = document.getElementById('postureCircleBox');
            if (scoreEl) scoreEl.innerHTML = `${m.defense_score}<small>%</small>`;
            if (boxEl) boxEl.style.setProperty('--i', `${m.defense_score}%`);

            // Update metric grid cards
            const totalEl = document.getElementById('statTotalScans');
            const threatsEl = document.getElementById('statThreatsBlocked');
            const cleanEl = document.getElementById('statCleanScans');
            const defenseEl = document.getElementById('statDefenseScore');
            if (totalEl) totalEl.textContent = m.total_scans;
            if (threatsEl) threatsEl.textContent = m.threats_blocked;
            if (cleanEl) cleanEl.textContent = m.clean_scans;
            if (defenseEl) defenseEl.innerHTML = `${m.defense_score}<small>%</small>`;

            // Update sidebar counters (unique IDs to avoid duplicate-ID stale data)
            const sidebarTotalEl = document.getElementById('sidebarStatTotalScans');
            const sidebarThreatsEl = document.getElementById('sidebarStatThreatsBlocked');
            const sidebarCleanEl = document.getElementById('sidebarStatCleanScans');
            if (sidebarTotalEl) sidebarTotalEl.textContent = m.total_scans;
            if (sidebarThreatsEl) sidebarThreatsEl.textContent = m.threats_blocked;
            if (sidebarCleanEl) sidebarCleanEl.textContent = m.clean_scans;
        }

        // Recent Scans Table (from real MySQL safeguard_db.scans)
        const tbody = document.getElementById('recentScansTbody');
        if (tbody) {
            if (!data.recent_scans || data.recent_scans.length === 0) {
                tbody.innerHTML = `<tr><td colspan="7" style="text-align:center; padding:18px; color:#94a3b8;">No scans recorded yet. Run a URL or Phish scan above to record audit logs.</td></tr>`;
            } else {
                tbody.innerHTML = data.recent_scans.map(s => {
                    const pillClass = s.threat_score >= 60 ? 'danger' : (s.threat_score >= 25 ? 'warning' : 'clean');
                    const targetShort = s.target_input && s.target_input.length > 35 ? s.target_input.substring(0, 32) + '...' : (s.target_input || 'N/A');
                    const dateStr = s.created_at ? new Date(s.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }) : 'Just now';
                    return `
                        <tr>
                            <td style="font-family: var(--font-mono); font-weight: 700; color: var(--accent);">#${s.id}</td>
                            <td><span style="font-weight: 700; font-size: 11px; text-transform: uppercase; color: #475569;">${escapeHtml(s.scan_type)}</span></td>
                            <td title="${escapeHtml(s.target_input || '')}" style="font-family: var(--font-mono); font-size: 12px; color: #1e293b;">${escapeHtml(targetShort)}</td>
                            <td><span class="threat-score-pill ${pillClass}">${escapeHtml(s.verdict || 'EVALUATED')}</span></td>
                            <td><span class="threat-score-pill ${pillClass}">${s.threat_score}/100</span></td>
                            <td><span style="font-size: 11px; color: #64748b; font-weight: 600;">${escapeHtml(s.username || 'SecOps Agent')}</span></td>
                            <td style="font-size: 11px; color: #94a3b8; font-family: var(--font-mono);">${dateStr}</td>
                        </tr>
                    `;
                }).join('');
            }
        }

        // Active Incident Stream (from real MySQL safeguard_db.incidents)
        const calendar = document.getElementById('incidentsCalendar');
        if (calendar && data.incidents) {
            const activityClasses = ['activity-one', 'activity-two', 'activity-three', 'activity-four'];
            calendar.innerHTML = data.incidents.map((inc, idx) => {
                const actClass = activityClasses[idx % activityClasses.length];
                const sev = (inc.severity || 'HIGH').toLowerCase();
                const dayNum = inc.day_number || String(16 - idx);
                const monthStr = (inc.month_label || 'OCT').toUpperCase();
                const statusStr = inc.status || 'MITIGATED';
                return `
                    <div class="day-and-activity ${actClass}" onclick="showToast('${escapeHtml(inc.title)} [${escapeHtml(statusStr)}]')">
                        <div class="day">
                            <h1>${escapeHtml(dayNum)}</h1>
                            <p>${escapeHtml(monthStr)}</p>
                        </div>
                        <div class="activity">
                            <h2>${escapeHtml(inc.title)}</h2>
                            <div class="activity-meta">
                                <span class="activity-pill pill-${sev}">${escapeHtml(inc.severity)}</span>
                                <span>•</span>
                                <span class="activity-node">${escapeHtml(inc.category || inc.target_node)}</span>
                            </div>
                        </div>
                        <div class="activity-status">
                            <span class="badge-status status-${statusStr.toLowerCase()}">${escapeHtml(statusStr)}</span>
                        </div>
                    </div>
                `;
            }).join('');
        }

        // Threat Intel Feed Container (from real MySQL safeguard_db.threat_intel_feed)
        const feedContainer = document.getElementById('threatFeedContainer');
        if (feedContainer && data.threat_feed) {
            feedContainer.innerHTML = data.threat_feed.map((feed, idx) => {
                const cardClass = idx % 2 === 0 ? 'card-one' : 'card-two';
                const avatar = feed.author_avatar || 'https://images.unsplash.com/photo-1535713875002-d1d0cf377fde?w=100&auto=format&fit=crop&q=80';
                const name = feed.author_name || 'SOC Analyst';
                const img = feed.image_url || 'https://images.unsplash.com/photo-1563089145-599997674d42?w=600&auto=format&fit=crop&q=80';
                return `
                    <div class="card ${cardClass}" style="margin-bottom: 14px;">
                        <div class="card-user-info">
                            <img src="${avatar}" alt="${escapeHtml(name)}" />
                            <h2>${escapeHtml(name)}</h2>
                        </div>
                        <img class="card-img" src="${img}" alt="${escapeHtml(feed.title)}" />
                        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:6px; padding:0 2px;">
                            <span style="font-weight:700; font-size:11px; color:var(--accent); font-family:var(--font-mono);">${escapeHtml(feed.preview_tag || 'THREAT INTEL')}</span>
                            <span style="font-size:10px; font-weight:800; padding:2px 7px; border-radius:6px; background:#fee2e2; color:#dc2626; border:1px solid #fca5a5;">${escapeHtml(feed.severity_badge || 'ALERT')}</span>
                        </div>
                        <p style="font-weight:700; color:#1e293b; margin-bottom:4px; font-size:0.95rem;">${escapeHtml(feed.title)}</p>
                        <p style="font-size:12px; color:#64748b; line-height:1.4; margin-bottom:6px;">${escapeHtml(feed.description)}</p>
                        ${feed.footer_note ? `<div style="font-size:11px; color:#475569; background:#f1f5f9; padding:6px 8px; border-radius:8px; margin:6px 0 8px; font-family:var(--font-mono);"><i class="fa-solid fa-circle-info" style="color:var(--accent);"></i> ${escapeHtml(feed.footer_note)}</div>` : ''}
                        <button class="btn" style="margin-top:4px; width:100%; font-size:0.9rem; padding:6px 14px;" onclick="showToast('Investigating: ${escapeHtml(feed.title)}')">Investigate Feed</button>
                    </div>
                `;
            }).join('');
        }

    } catch (e) {
        console.warn('Real dashboard stats load error:', e);
    }
}

// ============================================================================
// DASHBOARD TELEMETRY & CVEs
// ============================================================================
async function loadDashboardTelemetry() {
    try {
        const res = await fetch('/api/threat-intel/feed');
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const json = await res.json();
        const data = json.data;
        telemetryCache = data;

        // Render CVE Table
        const cveBody = document.getElementById('cveTableBody');
        if (cveBody && data.active_global_cves) {
            cveBody.innerHTML = data.active_global_cves.map(c => `
                <tr>
                    <td style="font-family: var(--font-mono); font-weight: 600; color: var(--text);">${c.cve}</td>
                    <td>
                        <span class="badge-pill ${c.cvss >= 9.0 ? 'pill-critical' : 'pill-warning'}">
                            CVSS ${c.cvss.toFixed(1)}
                        </span>
                    </td>
                    <td>${c.title}</td>
                    <td>
                        <span class="badge-pill ${c.status.includes('CRITICAL') ? 'pill-critical' : 'pill-warning'}">
                            ${c.status}
                        </span>
                    </td>
                </tr>
            `).join('');
        }

        // Render MITRE ATT&CK List
        const mitreList = document.getElementById('mitreTechniquesList');
        if (mitreList && data.mitre_top_techniques) {
            mitreList.innerHTML = data.mitre_top_techniques.map(t => `
                <div class="attack-item">
                    <div class="attack-meta">
                        <span class="attack-id">${t.id}</span>
                        <span class="attack-name">${t.name}</span>
                        <span class="attack-tactic">${t.tactic}</span>
                    </div>
                    <span class="attack-share">${t.count}</span>
                </div>
            `).join('');
        }

        // Update metrics
        if (data.telemetry_metrics) {
            const mInter = document.getElementById('m-intercepted');
            const mUrls = document.getElementById('m-urls');
            const mLat = document.getElementById('m-latency');
            if (mInter) mInter.textContent = data.telemetry_metrics.threats_mitigated_24h;
            if (mUrls) mUrls.textContent = data.telemetry_metrics.phishing_domains_indexed;
            if (mLat) mLat.textContent = data.telemetry_metrics.mean_time_to_detect_sec;
        }

    } catch (e) {
        console.warn('Backend telemetry unavailable, using localized heuristic cache:', e);
    }
}

// ============================================================================
// 02. URL SCANNER (REALISTIC LOADING SEQUENCE + MYSQL PERSISTENCE)
// ============================================================================
function fillUrlSample(url) {
    document.getElementById('targetUrlInput').value = url;
    executeUrlScan();
}

async function executeUrlScan() {
    const input = document.getElementById('targetUrlInput');
    const url = input.value.trim();
    if (!url) {
        showToast('Please enter a target URL to evaluate.', true);
        return;
    }

    const btn = document.getElementById('btnRunUrlScan');
    const loader = document.getElementById('urlScanLoader');
    const loaderBar = document.getElementById('urlLoaderBar');
    const loaderStage = document.getElementById('urlLoaderStage');
    const loaderSub = document.getElementById('urlLoaderSub');
    const resultsContainer = document.getElementById('urlResultsContainer');

    btn.disabled = true;
    if (resultsContainer) resultsContainer.style.display = 'none';
    if (loader) loader.style.display = 'flex';

    try {
        // Stage 1: DNS & WHOIS
        if (loaderBar) loaderBar.style.width = '25%';
        if (loaderStage) loaderStage.textContent = 'Stage 1/4: Perimeter Resolvers & DNS Hierarchy';
        if (loaderSub) loaderSub.textContent = 'Resolving DNS A/AAAA records, MX routing, and ASN infrastructure...';
        await delay(450);

        // Stage 2: Lexical & Entropy
        if (loaderBar) loaderBar.style.width = '55%';
        if (loaderStage) loaderStage.textContent = 'Stage 2/4: Lexical & Shannon Entropy Engine';
        if (loaderSub) loaderSub.textContent = 'Evaluating IDN homoglyphs, sub-domain recursion, and algorithmic randomness...';
        await delay(500);

        // Stage 3: Zero-Day Threat Correlation & Network Fetch
        if (loaderBar) loaderBar.style.width = '80%';
        if (loaderStage) loaderStage.textContent = 'Stage 3/4: Threat Pattern Heuristics';
        if (loaderSub) loaderSub.textContent = 'Correlating with known brand impersonation, credential harvesting signatures...';

        const res = await apiFetch('/api/scan/url', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url })
        });
        const json = await res.json();
        
        if (json.status !== 'SUCCESS') {
            throw new Error(json.message || 'Analysis failed');
        }

        // Stage 4: Database Persistence
        if (loaderBar) loaderBar.style.width = '100%';
        if (loaderStage) loaderStage.textContent = 'Stage 4/4: Database Persistence';
        if (loaderSub) loaderSub.textContent = `Writing scan telemetry record #${json.data.scan_id || 'OK'} into audit log...`;
        await delay(400);

        if (loader) loader.style.display = 'none';
        renderUrlResults(json.data);
        await loadRealDashboardTelemetry();
        showToast(`Scan complete: Verdict is ${json.data.verdict}. Saved to database.`);
    } catch (err) {
        if (loader) loader.style.display = 'none';
        showToast(`Scan error: ${err.message}`, true);
    } finally {
        btn.disabled = false;
        btn.querySelector('span').textContent = 'Scan';
    }
}

function renderUrlResults(data) {
    const container = document.getElementById('urlResultsContainer');
    container.style.display = 'block';

    const banner = document.getElementById('urlScoreBanner');
    const dial = banner.querySelector('.score-dial');
    const scoreVal = document.getElementById('urlScoreVal');
    const verdict = document.getElementById('urlVerdict');
    const action = document.getElementById('urlAction');
    const targetDisp = document.getElementById('urlTargetDisplay');
    const dbBadge = document.getElementById('urlDbBadge');

    // Reset classes
    banner.className = `result-score-banner ${data.verdict_class}`;
    dial.className = `score-dial ${data.verdict_class}`;

    scoreVal.textContent = data.risk_score;
    verdict.textContent = `${data.verdict} (SCORE: ${data.risk_score}/100)`;
    action.textContent = `Action Required: ${data.action_recommendation}`;
    targetDisp.textContent = `Target: ${data.url}`;

    if (dbBadge) {
        dbBadge.innerHTML = `<i class="fa-solid fa-database"></i> COMMITTED TO SECURE AUDIT LOG (RECORD #${data.scan_id || 'OK'})`;
    }

    // Indicators
    const indBadge = document.getElementById('indicatorCountBadge');
    indBadge.textContent = `${data.indicators.length} IDENTIFIED`;

    const indList = document.getElementById('urlIndicatorsList');
    if (data.indicators.length === 0) {
        indList.innerHTML = `<div class="indicator-card LOW"><div class="indicator-msg">Zero malicious threat indicators detected. Domain satisfies standard trust profile.</div></div>`;
    } else {
        indList.innerHTML = data.indicators.map(ind => `
            <div class="indicator-card ${ind.severity}">
                <div class="indicator-head">
                    <span class="indicator-type">${escapeHtml(ind.type)}</span>
                    <span class="badge-pill pill-${ind.severity === 'CRITICAL' ? 'critical' : (ind.severity === 'HIGH' ? 'warning' : 'safe')}">
                        ${ind.severity} (+${ind.impact} PTS)
                    </span>
                </div>
                <div class="indicator-msg">${escapeHtml(ind.message)}</div>
            </div>
        `).join('');
    }

    // Telemetry Details
    const telemDetails = document.getElementById('urlTelemetryDetails');
    telemDetails.innerHTML = `
        <div class="telemetry-row">
            <span class="telemetry-row-label">Resolved Hostname</span>
            <span class="telemetry-row-val">${escapeHtml(data.hostname || 'N/A')}</span>
        </div>
        <div class="telemetry-row">
            <span class="telemetry-row-label">Protocol Security</span>
            <span class="telemetry-row-val text-${data.scheme === 'https' ? 'emerald' : 'crimson'}">${(data.scheme || 'HTTP').toUpperCase()} (Port ${data.port})</span>
        </div>
        <div class="telemetry-row">
            <span class="telemetry-row-label">Top-Level Domain (TLD)</span>
            <span class="telemetry-row-val">.${escapeHtml(data.structure.tld || 'unknown')}</span>
        </div>
        <div class="telemetry-row">
            <span class="telemetry-row-label">Shannon Domain Entropy</span>
            <span class="telemetry-row-val">${data.entropy.domain_entropy} bits/sym</span>
        </div>
        <div class="telemetry-row">
            <span class="telemetry-row-label">Path Entropy</span>
            <span class="telemetry-row-val">${data.entropy.path_entropy} bits/sym</span>
        </div>
        <div class="telemetry-row">
            <span class="telemetry-row-label">Direct IP Hostname</span>
            <span class="telemetry-row-val text-${data.structure.is_ip ? 'crimson' : 'emerald'}">${data.structure.is_ip ? 'YES (SUSPICIOUS)' : 'NO (STANDARD FQDN)'}</span>
        </div>
        <div class="telemetry-row">
            <span class="telemetry-row-label">Subdomain Depth</span>
            <span class="telemetry-row-val">${data.structure.subdomains_count} nested levels</span>
        </div>
    `;

    container.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

// ============================================================================
// 03. MESSAGE ANALYZER (REALISTIC LOADING SEQUENCE + MYSQL PERSISTENCE)
// ============================================================================
const MESSAGE_SAMPLES = {
    bank_urgent: "URGENT: Your Chase online banking access has been locked due to unauthorized attempts. Click immediately to verify your identity within 24 hours: http://chase-security-verify.com/unlock or your account will be permanently closed.",
    delivery: "USPS Notification: Your package #US948194 cannot be delivered due to an incorrect postal address. A customs clearance fee of $2.45 is unpaid. Update address here: http://usps-parcel-redelivery.top",
    crypto: "Congratulations! Your wallet was selected for the 1.5 BTC Binance Global Community Airdrop! Claim your reward now: http://binance-airdrop-bonus.xyz/claim. Seed phrase required for ledger verification."
};

function fillMessageSample(type) {
    if (MESSAGE_SAMPLES[type]) {
        document.getElementById('messageTextInput').value = MESSAGE_SAMPLES[type];
        executeMessageScan();
    }
}

async function executeMessageScan() {
    const text = document.getElementById('messageTextInput').value.trim();
    if (!text) {
        showToast('Please provide message or email text.', true);
        return;
    }

    const btn = document.getElementById('btnRunMsgScan');
    const loader = document.getElementById('msgScanLoader');
    const loaderBar = document.getElementById('msgLoaderBar');
    const loaderStage = document.getElementById('msgLoaderStage');
    const loaderSub = document.getElementById('msgLoaderSub');
    const resultsContainer = document.getElementById('messageResultsContainer');

    btn.disabled = true;
    if (resultsContainer) resultsContainer.style.display = 'none';
    if (loader) loader.style.display = 'flex';

    try {
        if (loaderBar) loaderBar.style.width = '30%';
        if (loaderStage) loaderStage.textContent = 'Stage 1/3: Social Engineering NLP Tokenization';
        if (loaderSub) loaderSub.textContent = 'Extracting urgency pressure triggers and coercion linguistics...';
        await delay(450);

        if (loaderBar) loaderBar.style.width = '70%';
        if (loaderStage) loaderStage.textContent = 'Stage 2/3: Credential Harvester & IOC Matching';
        if (loaderSub) loaderSub.textContent = 'Scanning embedded payment links, fake verification forms, and malware lures...';

        const res = await apiFetch('/api/scan/message', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ text })
        });
        const json = await res.json();
        if (json.status !== 'SUCCESS') throw new Error(json.message);

        if (loaderBar) loaderBar.style.width = '100%';
        if (loaderStage) loaderStage.textContent = 'Stage 3/3: Committing to Secure Database';
        if (loaderSub) loaderSub.textContent = `Saving audit telemetry record #${json.data.scan_id || 'OK'} into database...`;
        await delay(350);

        if (loader) loader.style.display = 'none';
        renderMessageResults(json.data);
        await loadRealDashboardTelemetry();
        showToast(`NLP analysis completed: Verdict is ${json.data.verdict}. Saved to database.`);
    } catch (e) {
        if (loader) loader.style.display = 'none';
        showToast(`Analysis error: ${e.message}`, true);
    } finally {
        btn.disabled = false;
    }
}

function renderMessageResults(data) {
    const container = document.getElementById('messageResultsContainer');
    container.style.display = 'block';

    const banner = document.getElementById('msgScoreBanner');
    const dial = banner.querySelector('.score-dial');
    const scoreVal = document.getElementById('msgScoreVal');
    const verdict = document.getElementById('msgVerdict');
    const action = document.getElementById('msgAction');
    const dbBadge = document.getElementById('msgDbBadge');

    banner.className = `result-score-banner ${data.verdict_class}`;
    dial.className = `score-dial ${data.verdict_class}`;

    scoreVal.textContent = data.threat_score;
    verdict.textContent = `${data.verdict} (THREAT SCORE: ${data.threat_score}/100)`;
    if (dbBadge) {
        dbBadge.innerHTML = `<i class="fa-solid fa-database"></i> COMMITTED TO SECURE AUDIT LOG (RECORD #${data.scan_id || 'OK'})`;
    }

    // Vectors
    const vecList = document.getElementById('msgVectorsList');
    if (!data.vectors_detected || data.vectors_detected.length === 0) {
        vecList.innerHTML = `<div class="indicator-card LOW"><div class="indicator-msg">No weaponized social engineering intent vectors detected in payload.</div></div>`;
    } else {
        vecList.innerHTML = data.vectors_detected.map(v => `
            <div class="indicator-card ${v.severity}">
                <div class="indicator-head">
                    <span class="indicator-type">${v.category}</span>
                    <span class="badge-pill pill-${v.severity === 'CRITICAL' ? 'critical' : 'warning'}">${v.severity}</span>
                </div>
                <div class="indicator-msg">${v.description}</div>
                <div style="font-family: var(--font-mono); font-size: 11px; color: var(--color-cyan); margin-top: 4px;">
                    Matched: ${v.matches.join(', ')}
                </div>
            </div>
        `).join('');
    }

    // IOCs
    const iocList = document.getElementById('msgIocsList');
    const urls = data.extracted_iocs.urls || [];
    const phones = data.extracted_iocs.phone_numbers || [];
    const cryptos = data.extracted_iocs.crypto_wallets || [];

    iocList.innerHTML = `
        <div class="telemetry-table">
            <div class="telemetry-row">
                <span class="telemetry-row-label">Embedded Hyperlinks</span>
                <span class="telemetry-row-val text-${urls.length ? 'crimson' : 'emerald'}">${urls.length} link(s)</span>
            </div>
            ${urls.map(u => `<div class="indicator-msg" style="word-break: break-all; font-family: var(--font-mono); color: var(--color-cyan); padding: 4px 0;">🔗 ${u}</div>`).join('')}

            <div class="telemetry-row" style="margin-top: 8px;">
                <span class="telemetry-row-label">Phone Identifiers</span>
                <span class="telemetry-row-val">${phones.length ? phones.join(', ') : 'None'}</span>
            </div>

            <div class="telemetry-row">
                <span class="telemetry-row-label">Crypto Wallets</span>
                <span class="telemetry-row-val">${cryptos.length ? cryptos.join(', ') : 'None'}</span>
            </div>
        </div>
    `;

    container.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

// ============================================================================
// 04. EMAIL BREACH RADAR
// ============================================================================
async function executeEmailAudit() {
    const email = document.getElementById('emailAuditInput').value.trim();
    if (!email) {
        showToast('Please enter an email address.', true);
        return;
    }

    try {
        const res = await apiFetch('/api/scan/email', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email })
        });
        const json = await res.json();
        if (json.status !== 'SUCCESS') throw new Error(json.message);
        renderEmailResults(json.data);
        await loadRealDashboardTelemetry();
    } catch (e) {
        showToast(`Audit failed: ${e.message}`, true);
    }
}

function renderEmailResults(data) {
    const container = document.getElementById('emailResultsContainer');
    container.style.display = 'block';

    const banner = document.getElementById('emailScoreBanner');
    const dial = banner.querySelector('.score-dial');
    const scoreVal = document.getElementById('emailScoreVal');
    const verdict = document.getElementById('emailVerdict');
    const action = document.getElementById('emailAction');

    const tier = data.breaches_detected > 0 ? 'critical' : 'safe';
    banner.className = `result-score-banner ${tier}`;
    dial.className = `score-dial ${tier}`;

    scoreVal.textContent = data.risk_score;
    verdict.textContent = `${data.risk_level} (${data.breaches_detected} KNOWN COMPROMISES)`;
    action.textContent = data.is_disposable ? 'Disposable / temporary domain identified.' : `Domain: ${data.domain}`;

    // Breaches list
    const breachContainer = document.getElementById('breachListContainer');
    if (!data.breach_records || data.breach_records.length === 0) {
        breachContainer.innerHTML = `<div class="indicator-card LOW"><div class="indicator-msg">Zero historical breach records correlated with this identity.</div></div>`;
    } else {
        breachContainer.innerHTML = data.breach_records.map(b => `
            <div class="indicator-card ${b.severity}">
                <div class="indicator-head">
                    <span class="indicator-type">${b.name}</span>
                    <span class="badge-pill pill-critical">${b.breach_date}</span>
                </div>
                <div class="indicator-msg" style="margin-top: 4px;">
                    <strong>Compromised Data:</strong> ${b.compromised_data.join(', ')}
                </div>
                <div style="font-size: 11px; color: var(--text-muted); font-family: var(--font-mono);">
                    Total Exposed Identities: ${(b.pwn_count / 1000000).toFixed(1)} Million
                </div>
            </div>
        `).join('');
    }

    // Remediation list
    const remContainer = document.getElementById('breachRemediationContainer');
    remContainer.innerHTML = `
        <ul class="playbook-steps">
            ${data.remediation_steps.map((step, idx) => `
                <li class="playbook-step">
                    <span class="step-num">${idx + 1}</span>
                    <span>${step}</span>
                </li>
            `).join('')}
        </ul>
    `;

    container.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

// ============================================================================
// 05. HTTP HEADER INSPECTOR
// ============================================================================
async function executeHeaderAudit() {
    const url = document.getElementById('headerUrlInput').value.trim();
    if (!url) {
        showToast('Please enter a target URL/domain.', true);
        return;
    }

    try {
        const res = await apiFetch('/api/audit/headers', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url })
        });
        const json = await res.json();
        if (json.status !== 'SUCCESS') throw new Error(json.message);
        renderHeaderResults(json.data);
        await loadRealDashboardTelemetry();
    } catch (e) {
        showToast(`Header check failed: ${e.message}`, true);
    }
}

function renderHeaderResults(data) {
    const container = document.getElementById('headerResultsContainer');
    container.style.display = 'block';

    const banner = document.getElementById('headerScoreBanner');
    const dial = banner.querySelector('.score-dial');
    const gradeVal = document.getElementById('headerGradeVal');
    const scoreNum = document.getElementById('headerScoreNumber');
    const hostDisp = document.getElementById('headerTargetHost');

    banner.className = `result-score-banner ${data.tier}`;
    dial.className = `score-dial ${data.tier}`;

    gradeVal.textContent = data.security_grade;
    scoreNum.textContent = `PERIMETER SCORE: ${data.security_score}/100`;
    hostDisp.textContent = `Host: ${data.url} (${data.live_connection ? 'Live Probe' : 'Heuristic Mode'})`;

    const tbody = document.getElementById('headersTableBody');
    tbody.innerHTML = data.audit_results.map(h => `
        <tr>
            <td style="font-family: var(--font-mono); font-weight: 500; color: var(--text);">${h.header}</td>
            <td><span class="badge-pill ${h.importance === 'CRITICAL' ? 'pill-critical' : 'pill-warning'}">${h.importance}</span></td>
            <td>
                <span class="badge-pill ${h.present ? 'pill-safe' : 'pill-critical'}">
                    ${h.present ? 'CONFIGURED' : 'MISSING'}
                </span>
            </td>
            <td style="font-family: var(--font-mono); font-size: 11px; max-width: 320px; word-break: break-all;">
                ${h.value || '<span class="text-crimson">Not detected in HTTP response</span>'}
            </td>
        </tr>
    `).join('');

    container.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

// ============================================================================
// 06. PASSWORD FORTRESS
// ============================================================================
let pwdDebounce = null;
function executePasswordAudit() {
    clearTimeout(pwdDebounce);
    pwdDebounce = setTimeout(async () => {
        const password = document.getElementById('passwordAuditInput').value;
        if (!password) {
            document.getElementById('pwdResultsContainer').style.display = 'none';
            return;
        }

        try {
            const res = await apiFetch('/api/audit/password', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ password })
            });
            const json = await res.json();
            if (json.status !== 'SUCCESS') throw new Error(json.message);
            renderPasswordResults(json.data);
            await loadRealDashboardTelemetry();
        } catch (e) {
            console.error('Password audit error:', e);
        }
    }, 180);
}

function renderPasswordResults(data) {
    const container = document.getElementById('pwdResultsContainer');
    container.style.display = 'block';

    const banner = document.getElementById('pwdScoreBanner');
    const dial = banner.querySelector('.score-dial');
    const scoreVal = document.getElementById('pwdScoreVal');
    const verdict = document.getElementById('pwdVerdict');
    const entropyBits = document.getElementById('pwdEntropyBits');

    banner.className = `result-score-banner ${data.tier}`;
    dial.className = `score-dial ${data.tier}`;

    scoreVal.textContent = data.score;
    verdict.textContent = `${data.verdict} (${data.score}/100)`;
    entropyBits.textContent = `${data.entropy_bits} BITS SHANNON ENTROPY | POOL SIZE: ${data.pool_size} CHARS`;

    // Crack times
    const crackTimes = document.getElementById('pwdCrackTimes');
    crackTimes.innerHTML = `
        <div class="telemetry-table">
            <div class="telemetry-row">
                <span class="telemetry-row-label">Desktop CPU (Single-Core 10 MH/s)</span>
                <span class="telemetry-row-val text-${data.tier === 'safe' ? 'emerald' : 'crimson'}">${data.crack_times.desktop_cpu}</span>
            </div>
            <div class="telemetry-row">
                <span class="telemetry-row-label">Consumer GPU Rig (8x RTX 4090 - 150 GH/s)</span>
                <span class="telemetry-row-val text-${data.tier === 'safe' ? 'emerald' : 'crimson'}">${data.crack_times.gpu_rig_rtx4090}</span>
            </div>
            <div class="telemetry-row">
                <span class="telemetry-row-label">Nation-State Distributed Cluster (10 TH/s)</span>
                <span class="telemetry-row-val text-${data.tier === 'safe' ? 'emerald' : 'crimson'}">${data.crack_times.distributed_cluster}</span>
            </div>
        </div>
    `;

    // NIST checks
    const nistDiv = document.getElementById('pwdNistChecks');
    const n = data.nist_compliance;
    nistDiv.innerHTML = `
        <div class="telemetry-table">
            <div class="telemetry-row">
                <span class="telemetry-row-label">Minimum 8 Characters (NIST SP 800-63B)</span>
                <span class="telemetry-row-val text-${n.min_length_8 ? 'emerald' : 'crimson'}">${n.min_length_8 ? 'PASS' : 'FAIL'}</span>
            </div>
            <div class="telemetry-row">
                <span class="telemetry-row-label">Recommended Length (14+ Characters)</span>
                <span class="telemetry-row-val text-${n.recommended_length_14 ? 'emerald' : 'amber'}">${n.recommended_length_14 ? 'PASS' : 'SHORT'}</span>
            </div>
            <div class="telemetry-row">
                <span class="telemetry-row-label">Common Breached Passwords Dictionary</span>
                <span class="telemetry-row-val text-${n.not_in_common_dictionary ? 'emerald' : 'crimson'}">${n.not_in_common_dictionary ? 'CLEAN' : 'LEAKED IN BREACH'}</span>
            </div>
            <div class="telemetry-row">
                <span class="telemetry-row-label">Repetitive Pattern Resistance</span>
                <span class="telemetry-row-val text-${n.no_sequential_repetition ? 'emerald' : 'crimson'}">${n.no_sequential_repetition ? 'PASS' : 'SEQUENTIAL PATTERN'}</span>
            </div>
        </div>
    `;
}

// ============================================================================
// 07. IP INTELLIGENCE
// ============================================================================
async function executeIpAudit() {
    const ip = document.getElementById('ipAuditInput').value.trim();
    if (!ip) {
        showToast('Please enter an IPv4 or IPv6 address.', true);
        return;
    }

    try {
        const res = await apiFetch('/api/audit/ip', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip })
        });
        const json = await res.json();
        if (json.status !== 'SUCCESS') throw new Error(json.message);
        renderIpResults(json.data);
        await loadRealDashboardTelemetry();
    } catch (e) {
        showToast(`IP audit failed: ${e.message}`, true);
    }
}

function renderIpResults(data) {
    const container = document.getElementById('ipResultsContainer');
    container.style.display = 'block';

    const banner = document.getElementById('ipScoreBanner');
    const dial = banner.querySelector('.score-dial');
    const scoreVal = document.getElementById('ipScoreVal');
    const verdict = document.getElementById('ipVerdict');
    const cat = document.getElementById('ipCategory');

    banner.className = `result-score-banner ${data.tier}`;
    dial.className = `score-dial ${data.tier}`;

    scoreVal.textContent = data.threat_score;
    verdict.textContent = `${data.verdict} (${data.threat_score}/100)`;
    cat.textContent = `Category: ${data.category} | Version: IPv${data.version}`;

    const net = data.network_intelligence;
    const details = document.getElementById('ipNetworkDetails');
    details.innerHTML = `
        <div class="telemetry-table">
            <div class="telemetry-row">
                <span class="telemetry-row-label">IP Address</span>
                <span class="telemetry-row-val text-cyan">${data.ip}</span>
            </div>
            <div class="telemetry-row">
                <span class="telemetry-row-label">Autonomous System (ASN)</span>
                <span class="telemetry-row-val">${net.asn}</span>
            </div>
            <div class="telemetry-row">
                <span class="telemetry-row-label">Geographic Origin</span>
                <span class="telemetry-row-val">${net.city}, ${net.country} (${net.country_code})</span>
            </div>
            <div class="telemetry-row">
                <span class="telemetry-row-label">Reverse DNS Hostname</span>
                <span class="telemetry-row-val">${net.reverse_dns}</span>
            </div>
            <div class="telemetry-row">
                <span class="telemetry-row-label">RFC 1918 Private Range</span>
                <span class="telemetry-row-val text-${data.is_private ? 'amber' : 'emerald'}">${data.is_private ? 'YES (PRIVATE SUBNET)' : 'NO (PUBLIC IP)'}</span>
            </div>
        </div>
    `;

    container.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

// ============================================================================
// 08. CRYPTO SUITE
// ============================================================================
async function executeCryptoHashes() {
    const text = document.getElementById('cryptoInputText').value;
    if (!text) {
        showToast('Please enter text to compute hashes.', true);
        return;
    }

    try {
        const res = await apiFetch('/api/crypto/hashes', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ text })
        });
        const json = await res.json();
        if (json.status !== 'SUCCESS') throw new Error(json.message);
        
        const d = json.data;
        const out = document.getElementById('cryptoHashesOutput');
        out.innerHTML = `
            <div class="telemetry-table">
                <div class="telemetry-row">
                    <span class="telemetry-row-label">SHA-256 (Enterprise)</span>
                    <span class="telemetry-row-val text-cyan" style="word-break: break-all; font-size: 11px;">${d.sha256}</span>
                </div>
                <div class="telemetry-row">
                    <span class="telemetry-row-label">SHA-512 (High-Assurance)</span>
                    <span class="telemetry-row-val text-cyan" style="word-break: break-all; font-size: 11px;">${d.sha512}</span>
                </div>
                <div class="telemetry-row">
                    <span class="telemetry-row-label">BLAKE2b (Modern Fast)</span>
                    <span class="telemetry-row-val" style="word-break: break-all; font-size: 11px;">${d.blake2b}</span>
                </div>
                <div class="telemetry-row">
                    <span class="telemetry-row-label">Legacy MD5 (Collision-Prone)</span>
                    <span class="telemetry-row-val text-amber" style="word-break: break-all; font-size: 11px;">${d.legacy_md5.digest}</span>
                </div>
            </div>
        `;
    } catch (e) {
        showToast(`Crypto error: ${e.message}`, true);
    }
}

async function executeHashIdentify() {
    const hash = document.getElementById('unknownHashInput').value.trim();
    if (!hash) {
        showToast('Please enter a hash to identify.', true);
        return;
    }

    try {
        const res = await apiFetch('/api/crypto/identify', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ hash })
        });
        const json = await res.json();
        if (json.status !== 'SUCCESS') throw new Error(json.message);
        
        const d = json.data;
        const out = document.getElementById('hashIdentifyOutput');
        out.innerHTML = `
            <div class="indicator-card LOW">
                <div class="indicator-head">
                    <span class="indicator-type">Length: ${d.length_chars} hex chars (${d.bit_length} bits)</span>
                </div>
                <div class="indicator-msg" style="margin-top: 6px;">
                    <strong>Identified Algorithm Candidates:</strong>
                    <ul style="margin-left: 18px; margin-top: 4px;">
                        ${d.potential_algorithms.map(a => `<li><strong>${a.algo}</strong> (${a.status})</li>`).join('')}
                    </ul>
                </div>
            </div>
        `;
    } catch (e) {
        showToast(`Identification error: ${e.message}`, true);
    }
}

async function executeTransform(operation) {
    const text = document.getElementById('cryptoInputText').value;
    if (!text) {
        showToast('Please enter payload in the left text area first.', true);
        return;
    }

    try {
        const res = await apiFetch('/api/crypto/transform', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ text, operation })
        });
        const json = await res.json();
        if (json.status !== 'SUCCESS') throw new Error(json.message);

        const out = document.getElementById('transformOutput');
        out.innerHTML = `
            <div class="indicator-card LOW">
                <div class="indicator-head">
                    <span class="indicator-type">RESULT: ${operation.toUpperCase()}</span>
                </div>
                <div class="indicator-msg" style="font-family: var(--font-mono); color: var(--color-cyan); word-break: break-all; margin-top: 4px;">
                    ${json.data.result}
                </div>
            </div>
        `;
    } catch (e) {
        showToast(`Transform error: ${e.message}`, true);
    }
}

// ============================================================================
// 09. PLAYBOOKS
// ============================================================================
async function loadPlaybooks() {
    try {
        const res = await fetch('/api/threat-intel/playbooks');
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const json = await res.json();
        const playbooks = json.data;

        const container = document.getElementById('playbooksContainer');
        if (container && playbooks) {
            container.innerHTML = playbooks.map(pb => `
                <div class="playbook-card">
                    <div class="playbook-header">
                        <div>
                            <div class="playbook-title">${pb.title}</div>
                            <div class="playbook-category">${pb.category}</div>
                        </div>
                        <span class="badge-pill pill-${pb.urgency === 'CRITICAL' ? 'critical' : 'warning'}">
                            ${pb.urgency}
                        </span>
                    </div>
                    <ul class="playbook-steps">
                        ${pb.steps.map((st, i) => `
                            <li class="playbook-step">
                                <span class="step-num">${i + 1}</span>
                                <span>${st}</span>
                            </li>
                        `).join('')}
                    </ul>
                </div>
            `).join('');
        }
    } catch (e) {
        console.warn('Playbooks load error:', e);
    }
}

// ============================================================================
// TACTICAL RADAR CANVAS (Enterprise Grid & Scan Line)
// ============================================================================
function initTacticalRadarCanvas() {
    const canvas = document.getElementById('tacticalGridCanvas');
    if (!canvas) return;
    const ctx = canvas.getContext('2d');

    let width = canvas.width = window.innerWidth;
    let height = canvas.height = window.innerHeight;

    window.addEventListener('resize', () => {
        width = canvas.width = window.innerWidth;
        height = canvas.height = window.innerHeight;
    });

    let scanY = 0;
    const gridSize = 48;

    function renderRadar() {
        ctx.clearRect(0, 0, width, height);

        // Tactical Grid
        ctx.strokeStyle = 'rgba(0, 240, 255, 0.04)';
        ctx.lineWidth = 1;

        for (let x = 0; x < width; x += gridSize) {
            ctx.beginPath();
            ctx.moveTo(x, 0);
            ctx.lineTo(x, height);
            ctx.stroke();
        }

        for (let y = 0; y < height; y += gridSize) {
            ctx.beginPath();
            ctx.moveTo(0, y);
            ctx.lineTo(width, y);
            ctx.stroke();
        }

        // Radar Scan Line
        scanY += 1.2;
        if (scanY > height) scanY = 0;

        const grad = ctx.createLinearGradient(0, scanY - 60, 0, scanY);
        grad.addColorStop(0, 'rgba(0, 240, 255, 0)');
        grad.addColorStop(1, 'rgba(0, 240, 255, 0.08)');

        ctx.fillStyle = grad;
        ctx.fillRect(0, scanY - 60, width, 60);

        ctx.strokeStyle = 'rgba(0, 240, 255, 0.35)';
        ctx.beginPath();
        ctx.moveTo(0, scanY);
        ctx.lineTo(width, scanY);
        ctx.stroke();

        requestAnimationFrame(renderRadar);
    }

    renderRadar();
}

// ============================================================================
// CYBERSECURITY LEARNING JOURNEY (VIDEO COURSES, QUIZZES & CHEATSHEETS)
// ============================================================================
let learningCoursesCache = [];
let learningQuizzesCache = [];
let learningMaterialsCache = [];
let activeQuizRunner = null;
let activeMaterialModalData = null;

function switchLearningSubTab(tabName) {
    document.querySelectorAll('.learning-subnav-btn').forEach(btn => {
        btn.classList.remove('active');
    });
    document.querySelectorAll('.learning-tab-content').forEach(pane => {
        pane.classList.remove('active');
    });

    const activeBtn = document.getElementById(`subnav-${tabName}`);
    const activePane = document.getElementById(`learningTab-${tabName}`);
    if (activeBtn) activeBtn.classList.add('active');
    if (activePane) activePane.classList.add('active');
}

async function loadLearningJourney() {
    try {
        // Parallel load from MySQL endpoints
        const [coursesRes, quizzesRes, materialsRes] = await Promise.all([
            fetch('/api/learning/courses'),
            fetch('/api/learning/quizzes'),
            fetch('/api/learning/materials')
        ]);

        if (coursesRes.ok) {
            const json = await coursesRes.json();
            learningCoursesCache = json.data || [];
            renderLearningCourses(learningCoursesCache);
        }

        if (quizzesRes.ok) {
            const json = await quizzesRes.json();
            learningQuizzesCache = json.data || [];
            renderLearningQuizzes(learningQuizzesCache);
        }

        if (materialsRes.ok) {
            const json = await materialsRes.json();
            learningMaterialsCache = json.data || [];
            renderLearningMaterials(learningMaterialsCache);
        }
    } catch (err) {
        console.warn('Failed to load learning journey:', err);
    }
}

function renderLearningCourses(courses) {
    const container = document.getElementById('learningCoursesContainer');
    if (!container) return;

    if (!courses || courses.length === 0) {
        container.innerHTML = `<div class="loading-placeholder">No video courses registered yet. Check MySQL courses table.</div>`;
        return;
    }

    container.innerHTML = courses.map(c => {
        const levelClass = c.level ? `level-${c.level.toLowerCase().replace(/[^a-z]/g, '')}` : 'level-intermediate';
        const lessons = c.lessons || [];
        const lessonsCount = lessons.length;
        const lessonPreviewHtml = lessons.slice(0, 3).map((l, idx) => `
            <div class="lesson-chip">
                <span><strong>${idx + 1}.</strong> ${escapeHtml(l.title)}</span>
                <span>${escapeHtml(l.duration || '')}</span>
            </div>
        `).join('');

        return `
            <div class="course-card">
                <div class="course-thumb-wrap" onclick="openCourseVideo(${c.id})">
                    <img src="${escapeHtml(c.thumbnail_url)}" alt="${escapeHtml(c.title)}" onerror="this.src='https://images.unsplash.com/photo-1526374965328-7f61d4dc18c5?w=600&auto=format&fit=crop&q=80'" />
                    <div class="course-play-overlay">
                        <div class="play-circle-btn">
                            <i class="fa-solid fa-play" style="margin-left: 3px;"></i>
                        </div>
                    </div>
                </div>

                <div class="course-card-body">
                    <div class="course-badge-row">
                        <span class="course-cat-pill">${escapeHtml(c.category)}</span>
                        <span class="course-level-pill ${levelClass}">${escapeHtml(c.level)}</span>
                    </div>

                    <h3>${escapeHtml(c.title)}</h3>
                    <p>${escapeHtml(c.description)}</p>

                    <div class="course-lessons-toggle">
                        <div style="font-size: 11px; font-weight: 800; color: #475569; text-transform: uppercase; margin-bottom: 2px;">
                            Syllabus (${lessonsCount} Modules):
                        </div>
                        ${lessonPreviewHtml}
                    </div>

                    <div class="course-meta-row">
                        <div class="course-instructor">
                            <i class="fa-solid fa-chalkboard-user"></i>
                            <span>${escapeHtml(c.instructor || 'SOC Faculty')}</span>
                        </div>
                        <div class="course-duration">
                            <i class="fa-regular fa-clock"></i> ${escapeHtml(c.duration)}
                        </div>
                    </div>

                    <button class="top-action-btn" style="margin-top: 14px; width: 100%; justify-content: center;" onclick="openCourseVideo(${c.id})">
                        <i class="fa-solid fa-circle-play"></i> Watch Masterclass
                    </button>
                </div>
            </div>
        `;
    }).join('');
}

function openCourseVideo(courseId) {
    const course = learningCoursesCache.find(c => c.id === courseId);
    if (!course) {
        showToast('Course telemetry not found.', true);
        return;
    }

    const modal = document.getElementById('videoModal');
    const iframe = document.getElementById('videoModalIframe');
    const titleEl = document.getElementById('videoModalTitle');
    const metaEl = document.getElementById('videoModalMeta');
    const badgeEl = document.getElementById('videoModalBadge');
    const syllabusList = document.getElementById('videoModalSyllabus');

    if (titleEl) titleEl.textContent = course.title;
    if (metaEl) metaEl.textContent = `Instructor: ${course.instructor} • Duration: ${course.duration} • Level: ${course.level}`;
    if (badgeEl) badgeEl.textContent = course.category.toUpperCase();

    // Set YouTube Embed URL
    let embedUrl = course.video_embed_url;
    if (!embedUrl.includes('autoplay=')) {
        embedUrl += (embedUrl.includes('?') ? '&' : '?') + 'autoplay=1&rel=0';
    }
    if (iframe) iframe.src = embedUrl;

    // Populate Lessons Syllabus
    if (syllabusList && course.lessons) {
        syllabusList.innerHTML = course.lessons.map((lesson, idx) => `
            <div class="syllabus-item" onclick="showToast('Lesson ${idx + 1}: ${escapeHtml(lesson.title)}')">
                <div>
                    <span style="font-family: var(--font-mono); font-weight: 800; color: var(--accent); margin-right: 8px;">#${idx + 1}</span>
                    <strong style="color: #1e293b;">${escapeHtml(lesson.title)}</strong>
                    ${lesson.topics ? `<div style="font-size: 11px; color: #64748b; margin-top: 2px;">Key Focus: ${lesson.topics.map(t => escapeHtml(t)).join(', ')}</div>` : ''}
                </div>
                <div style="font-family: var(--font-mono); font-weight: 700; color: #64748b; font-size: 12px;">
                    ${escapeHtml(lesson.duration || '')}
                </div>
            </div>
        `).join('');
    }

    if (modal) modal.style.display = 'flex';
}

function closeCourseVideo() {
    const modal = document.getElementById('videoModal');
    const iframe = document.getElementById('videoModalIframe');
    if (iframe) iframe.src = '';
    if (modal) modal.style.display = 'none';
}

function handleVideoModalBackdropClick(event) {
    if (event.target && event.target.id === 'videoModal') {
        closeCourseVideo();
    }
}

// ---------------- QUIZ SYSTEM ----------------
function renderLearningQuizzes(quizzes) {
    const container = document.getElementById('learningQuizzesContainer');
    if (!container) return;

    if (!quizzes || quizzes.length === 0) {
        container.innerHTML = `<div class="loading-placeholder">No quizzes registered yet. Check MySQL quizzes table.</div>`;
        return;
    }

    container.innerHTML = quizzes.map(q => {
        const levelClass = q.difficulty ? `level-${q.difficulty.toLowerCase().replace(/[^a-z]/g, '')}` : 'level-intermediate';
        return `
            <div class="quiz-card">
                <div class="quiz-badge-row">
                    <span class="course-cat-pill">${escapeHtml(q.category)}</span>
                    <span class="course-level-pill ${levelClass}">${escapeHtml(q.difficulty)}</span>
                </div>

                <h3>${escapeHtml(q.title)}</h3>

                <div class="quiz-meta-specs">
                    <span><i class="fa-solid fa-circle-question"></i> ${q.questions_count} Questions</span>
                    <span><i class="fa-solid fa-trophy"></i> Pass: ${q.pass_score}%</span>
                </div>

                <button class="top-action-btn" style="margin-top: auto; width: 100%; justify-content: center;" onclick="startQuizRunner(${q.id})">
                    <i class="fa-solid fa-bolt-lightning"></i> Start Knowledge Drill
                </button>
            </div>
        `;
    }).join('');
}

async function startQuizRunner(quizId) {
    try {
        showToast('Loading quiz challenge from MySQL database...');
        const res = await fetch(`/api/learning/quiz/${quizId}`);
        if (!res.ok) throw new Error('Could not fetch quiz questions');
        const json = await res.json();
        const quiz = json.data;

        if (!quiz || !quiz.questions || quiz.questions.length === 0) {
            showToast('Quiz contains no questions.', true);
            return;
        }

        activeQuizRunner = {
            quiz: quiz,
            currentIndex: 0,
            userAnswers: {} // questionId -> selectedOptionIndex
        };

        const listWrap = document.getElementById('quizzesListView');
        const runnerBox = document.getElementById('quizRunnerCard');
        if (listWrap) listWrap.style.display = 'none';
        if (runnerBox) {
            runnerBox.style.display = 'block';
            renderActiveQuizQuestion();
        }
    } catch (err) {
        showToast(err.message, true);
    }
}

function renderActiveQuizQuestion() {
    const runnerBox = document.getElementById('quizRunnerCard');
    if (!runnerBox || !activeQuizRunner) return;

    const { quiz, currentIndex, userAnswers } = activeQuizRunner;
    const questions = quiz.questions;
    const q = questions[currentIndex];
    const totalQ = questions.length;
    const progressPercent = Math.round(((currentIndex + 1) / totalQ) * 100);

    const letters = ['A', 'B', 'C', 'D'];
    const currentSelection = userAnswers[q.id];

    const optionsHtml = q.options.map((opt, idx) => {
        const isSelected = currentSelection === idx;
        return `
            <button class="quiz-option-btn ${isSelected ? 'selected' : ''}" onclick="selectQuizOption(${q.id}, ${idx})">
                <span class="option-letter-badge">${letters[idx]}</span>
                <span>${escapeHtml(opt)}</span>
            </button>
        `;
    }).join('');

    const isLast = currentIndex === totalQ - 1;

    runnerBox.innerHTML = `
        <div class="quiz-runner-header">
            <div>
                <span class="course-cat-pill">${escapeHtml(quiz.category)}</span>
                <h3>${escapeHtml(quiz.title)}</h3>
            </div>
            <button class="btn-back" onclick="exitQuizRunner()"><i class="fa-solid fa-xmark"></i> Exit Drill</button>
        </div>

        <div class="quiz-progress-track">
            <div class="quiz-progress-fill" style="width: ${progressPercent}%;"></div>
        </div>

        <div class="quiz-question-box">
            <div class="quiz-question-number">Question ${currentIndex + 1} of ${totalQ} (${progressPercent}%)</div>
            <div class="quiz-question-text">${escapeHtml(q.question)}</div>
        </div>

        <div class="quiz-options-list">
            ${optionsHtml}
        </div>

        <div class="quiz-controls-row">
            <button class="btn-primary" style="background:#e2e8f0; color:#334155;" onclick="prevQuizQuestion()" ${currentIndex === 0 ? 'disabled style="opacity:0.5; pointer-events:none;"' : ''}>
                <i class="fa-solid fa-arrow-left"></i> Previous
            </button>

            ${isLast ? `
                <button class="top-action-btn" style="padding: 10px 22px; font-size: 0.95rem;" onclick="submitQuizDrill()">
                    <i class="fa-solid fa-cloud-arrow-up"></i> Submit Evaluation & Commit to DB
                </button>
            ` : `
                <button class="top-action-btn" style="padding: 10px 22px; font-size: 0.95rem;" onclick="nextQuizQuestion()">
                    Next Question <i class="fa-solid fa-arrow-right"></i>
                </button>
            `}
        </div>
    `;
}

function selectQuizOption(questionId, optionIndex) {
    if (!activeQuizRunner) return;
    activeQuizRunner.userAnswers[questionId] = optionIndex;
    renderActiveQuizQuestion();
}

function nextQuizQuestion() {
    if (!activeQuizRunner) return;
    if (activeQuizRunner.currentIndex < activeQuizRunner.quiz.questions.length - 1) {
        activeQuizRunner.currentIndex++;
        renderActiveQuizQuestion();
    }
}

function prevQuizQuestion() {
    if (!activeQuizRunner) return;
    if (activeQuizRunner.currentIndex > 0) {
        activeQuizRunner.currentIndex--;
        renderActiveQuizQuestion();
    }
}

function exitQuizRunner() {
    activeQuizRunner = null;
    const listWrap = document.getElementById('quizzesListView');
    const runnerBox = document.getElementById('quizRunnerCard');
    if (listWrap) listWrap.style.display = 'block';
    if (runnerBox) runnerBox.style.display = 'none';
}

async function submitQuizDrill() {
    if (!activeQuizRunner) return;
    const { quiz, userAnswers } = activeQuizRunner;

    // Check if any question remains unanswered
    const unanswered = quiz.questions.filter(q => userAnswers[q.id] === undefined);
    if (unanswered.length > 0) {
        const proceed = confirm(`You have ${unanswered.length} unanswered question(s). Submit evaluation anyway?`);
        if (!proceed) return;
    }

    const runnerBox = document.getElementById('quizRunnerCard');
    if (runnerBox) {
        runnerBox.innerHTML = `
            <div style="text-align:center; padding: 40px 20px;">
                <div class="loader-spinner" style="margin: 0 auto 16px;"></div>
                <h3 style="color:var(--accent); font-weight:800;">Evaluating Heuristics & Recording to MySQL...</h3>
                <p style="color:#64748b; font-size:13px;">Computing compliance score against certified threat standards.</p>
            </div>
        `;
    }

    try {
        const res = await apiFetch('/api/learning/quiz/submit', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                quiz_id: quiz.id,
                answers: userAnswers
            })
        });

        const json = await res.json();
        if (json.status !== 'SUCCESS') throw new Error(json.message || 'Evaluation failed');

        const result = json.data;
        renderQuizEvaluationSummary(quiz, result);
        showToast(`Quiz completed! Score: ${result.score}% (${result.passed ? 'PASSED' : 'RETRY'})`);
    } catch (err) {
        showToast(err.message, true);
        exitQuizRunner();
    }
}

function renderQuizEvaluationSummary(quiz, result) {
    const runnerBox = document.getElementById('quizRunnerCard');
    if (!runnerBox) return;

    const isPassed = result.passed;
    const bannerClass = isPassed ? 'passed' : 'failed';

    const feedbackHtml = (result.feedback || []).map((f, idx) => {
        const isQCorrect = f.is_correct;
        const letters = ['A', 'B', 'C', 'D'];
        const userChoiceText = f.user_choice !== null ? `${letters[f.user_choice]}: ${f.options[f.user_choice]}` : 'Unanswered';
        const correctChoiceText = `${letters[f.correct_choice]}: ${f.options[f.correct_choice]}`;

        return `
            <div class="feedback-item ${isQCorrect ? 'correct' : 'incorrect'}">
                <div class="feedback-q-text">
                    <span style="color:${isQCorrect ? '#10b981' : '#ef4444'}; margin-right: 6px;">
                        <i class="fa-solid ${isQCorrect ? 'fa-circle-check' : 'fa-circle-xmark'}"></i>
                    </span>
                    <strong>Question ${idx + 1}:</strong> ${escapeHtml(f.question)}
                </div>

                <div class="feedback-choice-row">
                    <span class="feedback-choice-pill ${isQCorrect ? 'user-correct' : 'user-wrong'}">
                        Your Choice: ${escapeHtml(userChoiceText)}
                    </span>
                    ${!isQCorrect ? `
                        <span class="feedback-choice-pill correct-ans">
                            Correct Answer: ${escapeHtml(correctChoiceText)}
                        </span>
                    ` : ''}
                </div>

                <div class="feedback-explanation">
                    <i class="fa-solid fa-shield-halved" style="color:var(--accent); margin-right:4px;"></i>
                    <strong>Technical Defense Analysis:</strong> ${escapeHtml(f.explanation || 'Verified defense principle.')}
                </div>
            </div>
        `;
    }).join('');

    runnerBox.innerHTML = `
        <div class="quiz-result-card">
            <div class="quiz-result-banner ${bannerClass}">
                <div class="result-dial-circle">${result.score}%</div>
                <div>
                    <h2 style="font-size:1.35rem; font-weight:800; color:#1e293b; margin:0 0 4px 0;">
                        ${isPassed ? 'SOC Knowledge Drill Passed!' : 'Drill Needs Review'}
                    </h2>
                    <p style="color:#475569; font-size:0.92rem; margin:0 0 8px 0;">
                        ${isPassed ? 'Congratulations! Your detection instincts align with enterprise defensive standards.' : 'Review the technical explanations below and retake the drill to achieve passing score.'}
                    </p>
                    <div class="score-db-badge">
                        <i class="fa-solid fa-database"></i> COMMITTED TO USER QUIZ RESULTS (ID #${result.attempt_id || 'LOG'})
                    </div>
                </div>
            </div>

            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:14px;">
                <h3 style="font-size:1.1rem; font-weight:800; color:#1e293b; margin:0;">Detailed Question Telemetry</h3>
                <div style="display:flex; gap:10px;">
                    <button class="top-action-btn" onclick="startQuizRunner(${quiz.id})">
                        <i class="fa-solid fa-rotate-left"></i> Retake Drill
                    </button>
                    <button class="btn-back" onclick="exitQuizRunner()">
                        <i class="fa-solid fa-arrow-left"></i> All Quizzes
                    </button>
                </div>
            </div>

            <div class="feedback-list">
                ${feedbackHtml}
            </div>
        </div>
    `;
}

// ---------------- COURSE MATERIALS / CHEATSHEETS ----------------
function renderLearningMaterials(materials) {
    const container = document.getElementById('learningMaterialsContainer');
    if (!container) return;

    if (!materials || materials.length === 0) {
        container.innerHTML = `<div class="loading-placeholder">No course materials found in database.</div>`;
        return;
    }

    container.innerHTML = materials.map(m => `
        <div class="material-card">
            <div class="material-badge-row">
                <span class="course-cat-pill">${escapeHtml(m.category)}</span>
                <span style="font-size:11px; font-weight:800; font-family:var(--font-mono); color:#475569;">${escapeHtml(m.file_format)}</span>
            </div>

            <h3>${escapeHtml(m.title)}</h3>
            <p>${escapeHtml(m.description)}</p>

            <div class="material-preview-snippet">${escapeHtml(m.content_preview)}</div>

            <div class="material-actions-row">
                <button class="top-action-btn" style="flex:1; justify-content:center; padding:7px 12px; font-size:0.85rem;" onclick="openMaterialModal(${m.id})">
                    <i class="fa-solid fa-eye"></i> View Cheatsheet
                </button>
                <button class="btn-primary" style="background:#e2e8f0; color:#334155; padding:7px 12px; font-size:0.85rem;" onclick="copyMaterialSnippet(${m.id})" title="Copy snippet to clipboard">
                    <i class="fa-solid fa-copy"></i>
                </button>
            </div>
        </div>
    `).join('');
}

function openMaterialModal(materialId) {
    const mat = learningMaterialsCache.find(m => m.id === materialId);
    if (!mat) {
        showToast('Cheatsheet content not found.', true);
        return;
    }

    activeMaterialModalData = mat;
    const modal = document.getElementById('materialModal');
    const titleEl = document.getElementById('materialModalTitle');
    const typeEl = document.getElementById('materialModalType');
    const metaEl = document.getElementById('materialModalMeta');
    const descEl = document.getElementById('materialModalDesc');
    const codeEl = document.getElementById('materialModalContent');

    if (titleEl) titleEl.textContent = mat.title;
    if (typeEl) typeEl.textContent = `${mat.category.toUpperCase()} • ${mat.type.toUpperCase()}`;
    if (metaEl) metaEl.textContent = `Format: ${mat.file_format} • Size: ${mat.size_label}`;
    if (descEl) descEl.textContent = mat.description;
    if (codeEl) codeEl.textContent = mat.content_preview;

    if (modal) modal.style.display = 'flex';
}

function closeMaterialModal() {
    const modal = document.getElementById('materialModal');
    if (modal) modal.style.display = 'none';
}

function handleMaterialModalBackdropClick(event) {
    if (event.target && event.target.id === 'materialModal') {
        closeMaterialModal();
    }
}

function copyActiveMaterialContent() {
    if (!activeMaterialModalData) return;
    navigator.clipboard.writeText(activeMaterialModalData.content_preview)
        .then(() => showToast(`Cheatsheet "${activeMaterialModalData.title}" copied to clipboard!`))
        .catch(() => showToast('Failed to copy to clipboard', true));
}

function copyMaterialSnippet(matId) {
    const mat = learningMaterialsCache.find(m => m.id === matId);
    if (!mat) return;
    navigator.clipboard.writeText(mat.content_preview)
        .then(() => showToast(`Snippet for "${mat.title}" copied!`))
        .catch(() => showToast('Failed to copy to clipboard', true));
}
