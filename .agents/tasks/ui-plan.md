# SafeGuard UI Overhaul — Implementation Plan
## Norman Design Principles / Enterprise Design System

> **Ground rules for the coder**
> - Do NOT change any `id=`, `data-target=`, or `view-panel` attribute on existing elements.
> - Do NOT rename or remove any existing JS function.
> - Do NOT alter any `fetch('/api/…')` call path or body shape.
> - Run the Flask dev server (`python app.py`) and open the browser after each item to confirm the build is visually correct before moving to the next item.

---

- [ ] 1. **Rewrite `static/css/main.css` — Design tokens, reset, and base typography**

  Replace the entire `@import` line at the top of `main.css` and the `body` / global reset block. Do not touch anything below the body rule yet.

  What to do:
  - Delete the existing `@import url(…)` line (currently loads Nunito + Roboto + JetBrains Mono).
  - Add a new `@import` that loads **Inter** (weights 400/500/600/700) and **JetBrains Mono** (weights 400/500/700) from Google Fonts.
  - Declare all CSS custom properties on `:root`:
    ```
    --color-bg: #0a0e1a
    --color-surface: #111827
    --color-surface-2: #1a2235
    --color-border: #1e2d45
    --color-border-2: #2a3f5f
    --color-primary: #3b82f6
    --color-primary-h: #2563eb
    --color-accent: #6366f1
    --color-critical: #ef4444
    --color-warning: #f59e0b
    --color-safe: #10b981
    --color-info: #3b82f6
    --color-text: #f1f5f9
    --color-text-2: #94a3b8
    --color-text-3: #64748b
    --font-sans: 'Inter', system-ui, sans-serif
    --font-mono: 'JetBrains Mono', monospace
    --radius-input: 6px
    --radius-card: 10px
    --radius-panel: 16px
    --space-1: 4px; --space-2: 8px; --space-3: 12px; --space-4: 16px
    --space-6: 24px; --space-8: 32px; --space-12: 48px
    ```
  - Set `body` background to `var(--color-bg)`, font to `var(--font-sans)`, color to `var(--color-text)`, font-size 14px (base UI size), `min-height: 100vh`.
  - Remove the Unsplash `background-image` URL from `body`.
  - Keep the universal box-sizing reset (`*,*::before,*::after { box-sizing:border-box; padding:0; margin:0 }`).
  - Keep `nav user-select: none` and `nav ul li a text-decoration: none`.

  Files: `static/css/main.css`

  Verify: Open the app in the browser. The page background should be dark navy (`#0a0e1a`), the Unsplash background image should be gone, and all text should render in Inter.

---

- [ ] 2. **`main.css` — App shell layout: top bar, sidebar, content grid**

  Replace all rules for `.app-wrapper`, `.desktop-top-nav`, `main`, `.main-menu`, `.content`, `.left-content`, `.right-content`, `.view-panel` with the new dark layout.

  What to do:
  - `.app-wrapper`: `width:100%; max-width:1400px; margin:0 auto; display:flex; flex-direction:column; min-height:100vh`.
  - `.desktop-top-nav`: `display:flex; align-items:center; justify-content:space-between; background:#0f172a; border-bottom:1px solid var(--color-border); height:60px; padding:0 24px; position:sticky; top:0; z-index:20`. Remove `border-radius`, `margin`, `backdrop-filter`, `box-shadow`, and the white background.
  - `main`: `display:grid; grid-template-columns:220px minmax(0,1fr); flex:1; height:calc(100vh - 60px); overflow:hidden`.
  - `.main-menu` (sidebar): `width:220px; min-width:220px; background:var(--color-bg); border-right:1px solid var(--color-border); overflow-y:auto; padding:16px 0; display:flex; flex-direction:column; height:100%`. Remove the purple `rgb(73,57,113)` background.
  - `.content`: `display:grid; grid-template-columns:minmax(0,1fr) 300px; height:100%; overflow:hidden`.
  - `.left-content`: `padding:20px 24px; overflow-y:auto; background:var(--color-bg); height:100%`. Remove the light grey background.
  - `.right-content`: `width:300px; background:var(--color-surface); border-left:1px solid var(--color-border); padding:16px; overflow-y:auto; height:100%`. Remove the light grey background and inline `315px` width.
  - `.view-panel { display:none }` / `.view-panel.active { display:block }` — keep as-is.

  Files: `static/css/main.css`

  Verify: App renders with a dark 60px top bar, a dark 220px fixed sidebar, and a dark content area. No purple/white backgrounds on shell elements.

---

- [ ] 3. **`main.css` — Sidebar navigation styles**

  Replace all `.nav-item`, `.nav-item a`, `.nav-item.active`, `.nav-text`, `.nav-icon` rules.

  What to do:
  - `.nav-item a`: `display:flex; align-items:center; gap:10px; padding:9px 16px; color:var(--color-text-2); font-size:13px; font-weight:500; border-radius:0; transition:all 0.15s; cursor:pointer; text-decoration:none`. Remove `margin-left`, `border-radius` pill, and `color:#ffffff!important`.
  - `.nav-item a:hover`: `background:var(--color-surface-2); color:var(--color-text)`.
  - `.nav-item.active a`: `color:var(--color-primary); background:rgba(59,130,246,0.08); border-left:3px solid var(--color-primary); padding-left:13px; font-weight:600`. Remove the inverted-tab `<b>` pseudo-corner trick — the `<b>` elements should be `display:none` always.
  - `.nav-item b:nth-child(1), .nav-item b:nth-child(2)`: `display:none!important` — permanently hide the corner decorators.
  - `.nav-icon svg, .nav-icon i`: `width:18px; height:18px; font-size:18px; flex-shrink:0; stroke-width:1.8`.
  - `.nav-text`: `font-size:13px; font-weight:500; white-space:nowrap; overflow:hidden; text-overflow:ellipsis`.
  - `.main-menu h1` (the "SafeGuard" title in the sidebar): `font-size:15px; font-weight:700; color:var(--color-text); padding:0 16px 16px; letter-spacing:0.3px`.

  Files: `static/css/main.css`

  Verify: Sidebar is dark navy. Inactive items show muted text. The active item has a visible blue left border and blue text. No white/purple corner shapes appear.

---

- [ ] 4. **`main.css` — Top bar component styles**

  Replace all `.top-brand*`, `.top-search*`, `.top-nav-*`, `.top-link-btn`, `.top-action-btn`, `.top-user-chip`, `.top-auth-btn`, `.top-defcon-pill`, `.top-hamburger-btn` rules.

  What to do:
  - `.top-brand-icon`: `background:var(--color-primary); border-radius:8px; color:#fff`.
  - `.top-brand-title`: `font-size:15px; font-weight:700; color:var(--color-text)`.
  - `.top-brand-badge`: `font-size:10px; font-weight:600; font-family:var(--font-mono); color:var(--color-text-3)`.
  - `.top-search-input`: `background:var(--color-surface-2); border:1px solid var(--color-border); border-radius:6px; color:var(--color-text); font-size:13px; padding:8px 40px 8px 36px`. Focus state: `border-color:var(--color-primary); box-shadow:0 0 0 3px rgba(59,130,246,0.2)`. Remove `width:360px` expansion on focus.
  - `.top-link-btn`: `color:var(--color-text-2); background:transparent; border:none; font-size:13px; font-weight:500; padding:8px 12px; border-radius:6px; cursor:pointer; display:flex; align-items:center; gap:6px; transition:all 0.15s`.
  - `.top-link-btn:hover`: `background:var(--color-surface-2); color:var(--color-text)`.
  - `.top-link-btn.active`: `background:rgba(59,130,246,0.12); color:var(--color-primary); font-weight:600`.
  - `.top-defcon-pill`: `font-size:11px; font-weight:700; font-family:var(--font-mono); color:var(--color-warning); background:rgba(245,158,11,0.12); border:1px solid rgba(245,158,11,0.3); padding:4px 10px; border-radius:20px`.
  - `.top-action-btn`: `background:var(--color-primary); color:#fff; border:none; padding:8px 16px; border-radius:6px; font-size:13px; font-weight:600; cursor:pointer; display:flex; align-items:center; gap:7px; transition:all 0.18s; box-shadow:0 2px 8px rgba(59,130,246,0.3)`. Hover: `background:var(--color-primary-h); transform:translateY(-1px)`. Active: `transform:translateY(0); box-shadow:none`.
  - `.top-auth-btn`: same as `.top-action-btn` but `background:var(--color-surface-2); color:var(--color-text); border:1px solid var(--color-border)`. Hover: `background:var(--color-primary); color:#fff; border-color:var(--color-primary)`.
  - `.top-user-chip`: `display:flex; align-items:center; gap:8px; background:var(--color-surface-2); border:1px solid var(--color-border); border-radius:20px; padding:4px 10px 4px 4px`.
  - `.top-avatar-initials`: `background:linear-gradient(135deg,var(--color-primary),var(--color-accent)); color:#fff`.
  - `.top-user-name`: `color:var(--color-text); font-size:13px; font-weight:600`.
  - `.top-user-role`: `color:var(--color-text-3); font-size:10px`.
  - `.top-logout-btn`: hover `color:var(--color-critical); background:rgba(239,68,68,0.1)`.
  - `.top-hamburger-btn`: `background:var(--color-surface-2); border:1px solid var(--color-border); color:var(--color-text)`. Keep `display:none` default; shown on mobile.

  Files: `static/css/main.css`

  Verify: Top bar is fully dark. The Quick Scan button is blue. The DEFCON pill is amber on dark. Search input has a dark background with blue focus ring.

---

- [ ] 5. **`main.css` — Shared component library (cards, buttons, badges, inputs)**

  Replace or add all `.sg-*` and existing component rules. These are the building blocks all panels use.

  What to do:

  **Cards:**
  - `.sg-card` (new): `background:var(--color-surface); border:1px solid var(--color-border); border-radius:var(--radius-card); padding:var(--space-4); transition:box-shadow 0.18s, transform 0.18s`. Hover: `box-shadow:0 4px 16px rgba(0,0,0,0.3); transform:translateY(-2px)`.
  - `.tool-view-card`: `background:var(--color-surface); border:1px solid var(--color-border); border-radius:var(--radius-panel); padding:24px`. Remove `box-shadow:rgba(0,0,0,0.08)`.
  - `.panel-card`: `background:var(--color-surface-2); border:1px solid var(--color-border); border-radius:var(--radius-card)`.
  - `.panel-header`: `background:var(--color-surface); border-bottom:1px solid var(--color-border)`. `h3` color: `var(--color-text)`.
  - `.panel-body`: keep as-is.

  **Buttons:**
  - `.btn-primary`: `background:var(--color-primary); color:#fff; border:none; padding:10px 22px; font-size:13px; font-weight:600; border-radius:var(--radius-input); cursor:pointer; display:inline-flex; align-items:center; gap:8px; transition:all 0.18s; box-shadow:0 2px 8px rgba(59,130,246,0.25)`. Hover: `background:var(--color-primary-h); transform:translateY(-1px)`. Active: `transform:translateY(0); box-shadow:none`. Disabled: `opacity:0.5; cursor:not-allowed; transform:none`.
  - `.sg-btn-primary`: alias for `.btn-primary` — add rule `{ @extend same values }`.
  - `.btn-outline` / `.sg-btn-secondary`: `background:transparent; border:1px solid var(--color-border-2); color:var(--color-text-2); border-radius:var(--radius-input); padding:8px 16px; font-size:13px; font-weight:500; cursor:pointer`. Hover: `border-color:var(--color-primary); color:var(--color-primary)`.
  - `.sg-btn-ghost` (new): `background:transparent; border:none; color:var(--color-text-3); padding:6px 10px; border-radius:var(--radius-input); cursor:pointer`. Hover: `background:var(--color-surface-2); color:var(--color-text)`.
  - `.btn-back`: `background:var(--color-surface-2); border:1px solid var(--color-border); color:var(--color-text-2); font-weight:500; padding:6px 14px; border-radius:var(--radius-input); cursor:pointer`. Hover: `border-color:var(--color-primary); color:var(--color-primary)`.
  - `.btn-refresh-sm`: same style as `.btn-back`.
  - `.sample-chip`: `background:var(--color-surface-2); border:1px solid var(--color-border); color:var(--color-text-3); font-family:var(--font-mono); font-size:11px; padding:4px 10px; border-radius:4px; cursor:pointer`. Hover: `border-color:var(--color-primary); color:var(--color-primary)`.
  - `.btn-chip`: same as `.sample-chip`.
  - `.btn`: simplify to `background:var(--color-surface-2); border:1px solid var(--color-border); color:var(--color-text); padding:8px 18px; border-radius:20px; cursor:pointer; font-size:13px`. Remove the gelatine `@keyframes`.

  **Inputs:**
  - `.soc-input` / `.sg-input`: `width:100%; background:var(--color-surface-2); border:1px solid var(--color-border-2); border-radius:var(--radius-input); padding:10px 14px 10px 42px; color:var(--color-text); font-family:var(--font-mono); font-size:13px; outline:none; transition:border-color 0.2s, box-shadow 0.2s`. Focus: `border-color:var(--color-primary); box-shadow:0 0 0 3px rgba(59,130,246,0.2); background:var(--color-surface)`. Placeholder: `color:var(--color-text-3)`.
  - `.soc-textarea` / `.sg-textarea`: same as `.soc-input` but remove left padding override (no icon by default); add `resize:vertical`.
  - `.soc-select`: `background:var(--color-surface-2); border:1px solid var(--color-border-2); border-radius:var(--radius-input); color:var(--color-text); font-size:13px; padding:10px 14px`. Focus same as input.
  - `.input-fa-icon`: `color:var(--color-text-3)`.
  - `.form-label`: `font-size:11px; font-weight:600; color:var(--color-text-2); text-transform:uppercase; letter-spacing:0.5px; margin-bottom:6px`.

  **Badges:**
  - `.sg-badge-critical` (new): `background:rgba(239,68,68,0.12); color:var(--color-critical); border:1px solid rgba(239,68,68,0.3); font-size:10px; font-weight:700; font-family:var(--font-mono); padding:2px 8px; border-radius:20px`.
  - `.sg-badge-warning` (new): same pattern with `var(--color-warning)`.
  - `.sg-badge-safe` (new): same with `var(--color-safe)`.
  - `.sg-badge-info` (new): same with `var(--color-info)`.
  - `.badge-pill` / `.pill-critical` / `.pill-warning` / `.pill-safe`: update to use same color token pattern (dark backgrounds).
  - `.badge-status`: update to dark variants.
  - `.threat-score-pill.clean` / `.warning` / `.danger`: update to dark transparent backgrounds matching the color tokens.
  - `.activity-pill.*`: update to dark transparent backgrounds.

  **Misc:**
  - `.divider-line`: `background:var(--color-border)`.
  - `.scan-bar-container`: keep layout, no color change needed.
  - `.card-bottom-actions`: keep layout.
  - `.samples-label`: `color:var(--color-text-3)`.

  Files: `static/css/main.css`

  Verify: All scan tool panels render with dark surfaces. Buttons are blue on dark. Inputs have visible dark borders and a blue glow on focus. Badge pills use dark transparent backgrounds.

---

- [ ] 6. **`main.css` — Dashboard metric cards (replace bento grid styles)**

  Replace `.activities`, `.activity-container`, `.image-container`, `.overlay`, `.img-one` through `.img-six` rules with new metric card grid styles.

  What to do:
  - `.activities h1` → `.dashboard-section-title`: `font-size:16px; font-weight:600; color:var(--color-text); margin:0 0 16px`.
  - `.activity-container` → `.metric-cards-grid` (new class): `display:grid; grid-template-columns:repeat(auto-fit,minmax(180px,1fr)); gap:16px; margin-bottom:24px`.
  - `.sg-metric-card` (new): `background:var(--color-surface); border:1px solid var(--color-border); border-radius:var(--radius-card); padding:20px; display:flex; flex-direction:column; gap:8px; transition:box-shadow 0.18s, transform 0.18s`. Hover: same lift as `.sg-card`.
  - `.sg-metric-card .metric-label`: `font-size:11px; font-weight:600; color:var(--color-text-3); text-transform:uppercase; letter-spacing:0.5px`.
  - `.sg-metric-card .metric-value`: `font-size:28px; font-weight:700; color:var(--color-text); font-family:var(--font-mono); line-height:1`.
  - `.sg-metric-card .metric-icon`: `width:36px; height:36px; border-radius:8px; display:flex; align-items:center; justify-content:center; font-size:16px`.
  - `.metric-icon.icon-total`: `background:rgba(59,130,246,0.12); color:var(--color-primary)`.
  - `.metric-icon.icon-threats`: `background:rgba(239,68,68,0.12); color:var(--color-critical)`.
  - `.metric-icon.icon-clean`: `background:rgba(16,185,129,0.12); color:var(--color-safe)`.
  - `.metric-icon.icon-score`: `background:rgba(99,102,241,0.12); color:var(--color-accent)`.
  - `.metric-icon.icon-url`: same as `.icon-total`.
  - `.metric-icon.icon-phish`: same as `.icon-threats`.
  - Keep `.image-container`, `.overlay`, `.img-*` rules in the file but set them to `display:none` so old styles do not conflict if any old HTML still references them.

  Files: `static/css/main.css`

  Verify: After the HTML change in item 9, the dashboard header area shows a row of dark metric cards with large numbers, not photo thumbnails.

---

- [ ] 7. **`main.css` — Scan result verdict banner, threat indicator rows, tables, loaders, toast, right panel**

  Update all remaining component rules to use the dark design tokens.

  What to do:

  **Verdict banner (`.result-score-banner`):**
  - Base: `background:var(--color-surface-2); border:1px solid var(--color-border); border-radius:var(--radius-panel); padding:20px 24px; display:flex; align-items:center; gap:24px; margin-bottom:20px`.
  - `.result-score-banner.critical`: `background:rgba(239,68,68,0.08); border-color:rgba(239,68,68,0.3)`.
  - `.result-score-banner.warning`: `background:rgba(245,158,11,0.08); border-color:rgba(245,158,11,0.3)`.
  - `.result-score-banner.safe`: `background:rgba(16,185,129,0.08); border-color:rgba(16,185,129,0.3)`.
  - `.score-dial` base: `border:4px solid var(--color-border-2)`. `.score-dial.critical`: `border-color:var(--color-critical)`. `.score-dial.warning`: `border-color:var(--color-warning)`. `.score-dial.safe`: `border-color:var(--color-safe)`.
  - `.score-val`: `font-size:28px; font-weight:700; color:var(--color-text); font-family:var(--font-mono)`. For the large 48px verdict display, add `.verdict-score-large { font-size:48px }` on `.score-val` inside `.result-score-banner.critical,.safe,.warning`.
  - `.score-verdict`: `font-size:16px; font-weight:600; color:var(--color-text)`.
  - `.score-action`: `font-size:13px; color:var(--color-text-2)`.
  - `.score-target`: `font-family:var(--font-mono); color:var(--color-primary); font-size:12px`.
  - `.score-db-badge`: `background:rgba(16,185,129,0.1); color:var(--color-safe); border:1px solid rgba(16,185,129,0.3)`.
  - `.score-sub`: `color:var(--color-text-3)`.

  **Threat indicator rows (`.indicator-card`, `.sg-indicator-row`):**
  - `.indicator-card`: `background:var(--color-surface-2); border-left:4px solid var(--color-border-2); border-radius:var(--radius-input); padding:12px 14px`.
  - `.indicator-card.CRITICAL`: `border-left-color:var(--color-critical)`.
  - `.indicator-card.HIGH`: `border-left-color:var(--color-warning)`.
  - `.indicator-card.MEDIUM`: `border-left-color:var(--color-info)`.
  - `.indicator-card.LOW`: `border-left-color:var(--color-safe)`.
  - `.indicator-type`: `color:var(--color-text-2); font-family:var(--font-mono)`.
  - `.indicator-msg`: `color:var(--color-text-2); font-size:13px`.

  **Tables (`.table-clean`, `.table-soc`, `.sg-table`):**
  - `th`: `background:var(--color-surface-2); color:var(--color-text-3); border-bottom:1px solid var(--color-border); font-size:11px; font-weight:600; padding:10px 14px; text-transform:uppercase; letter-spacing:0.5px`.
  - `td`: `border-bottom:1px solid var(--color-border); color:var(--color-text-2); padding:11px 14px`.
  - `tr:nth-child(even) td`: `background:rgba(26,34,53,0.5)` (subtle stripe).
  - `tr:hover td`: `background:var(--color-surface-2)`.
  - `.scans-audit-section`: `background:var(--color-surface); border:1px solid var(--color-border); border-radius:var(--radius-panel); padding:20px`.
  - `.audit-table-wrap`: `overflow-x:auto`.

  **Scan loader:**
  - `.scan-loading-card`: `background:var(--color-surface); border:1px solid var(--color-border); border-radius:var(--radius-card); padding:20px 24px`.
  - `.loader-spinner`: `border:4px solid var(--color-border); border-top-color:var(--color-primary); border-right-color:var(--color-accent)`.
  - `.loader-title`: `color:var(--color-primary); font-size:14px; font-weight:600`.
  - `.loader-sub / .loader-step`: `color:var(--color-text-3); font-family:var(--font-mono)`.
  - `.loader-bar-wrap`: `background:var(--color-surface-2)`.
  - `.loader-bar-fill`: `background:linear-gradient(90deg,var(--color-primary),var(--color-accent),var(--color-safe))`.

  **Toast (`.soc-toast`):**
  - Base: `background:var(--color-surface); border:1px solid var(--color-border); color:var(--color-text); font-family:var(--font-mono); font-size:12px; padding:12px 20px; border-radius:var(--radius-input); box-shadow:0 8px 24px rgba(0,0,0,0.4)`.
  - Add `.soc-toast.error { border-color:var(--color-critical) }` and `.soc-toast.success { border-color:var(--color-safe) }`.
  - Keep `position:fixed; bottom:24px; right:24px; z-index:100`. Confirmed position is already bottom-right.

  **Telemetry rows:**
  - `.telemetry-row-label`: `color:var(--color-text-3); font-family:var(--font-mono)`.
  - `.telemetry-row-val`: `color:var(--color-text); font-family:var(--font-mono); font-weight:600`.
  - `.telemetry-row`: `border-bottom:1px solid var(--color-border)`.

  **Inline color utility classes (used by JS render functions):**
  - `.text-emerald` → `color:var(--color-safe)`.
  - `.text-crimson` / `.text-red` → `color:var(--color-critical)`.
  - `.text-amber` → `color:var(--color-warning)`.
  - `.text-cyan` / `.text-blue` → `color:var(--color-primary)`.

  **Right panel components:**
  - `.active-calories`: `background:var(--color-surface-2); border:1px solid var(--color-border); border-radius:var(--radius-card); padding:16px`.
  - `.active-calories h1`: `color:var(--color-text); font-size:14px; font-weight:600`.
  - `.calories-content p span:first-child`: `color:var(--color-text-3)`.
  - `.calories-content p span:last-child`: `color:var(--color-text); font-family:var(--font-mono)`.
  - `.circle`: update conic-gradient to use `var(--color-primary)` and `var(--color-surface-2)`. The `::before` fill: `var(--color-surface-2)`.
  - `.box h2`: `color:var(--color-text)`.
  - `.user-info`: `background:var(--color-surface); border:1px solid var(--color-border); border-radius:var(--radius-card)`.
  - `.user-info h4, .user-info p`: update text colors to `var(--color-text)` and `var(--color-text-2)`.
  - `.friends-activity h1`: `color:var(--color-text); font-size:14px; font-weight:600`.
  - `.card-container .card`: `background:var(--color-surface); border:1px solid var(--color-border); border-radius:var(--radius-input)`.

  **Incident stream:**
  - `.weekly-schedule h1`: `color:var(--color-text); font-size:14px; font-weight:600`.
  - `.day-and-activity`: `background:var(--color-surface-2); border:1px solid var(--color-border); border-radius:var(--radius-input); color:var(--color-text)`. Remove colorful gradient backgrounds on `.activity-one` through `.activity-four`.
  - `.day h1`: `color:var(--color-primary)`.
  - `.day p`: `color:var(--color-text-3)`.
  - `.activity h2`: `color:var(--color-text)!important`.
  - `.activity`: `border-left:2px solid var(--color-border-2)`.

  **Defense benchmarks (`.best-item`):**
  - `.box-one`, `.box-two`, `.box-three`: replace colorful backgrounds with `var(--color-surface-2); border:1px solid var(--color-border)`. Text color: `var(--color-text-2)`.

  **Playbook cards:**
  - `.playbook-card`: `background:var(--color-surface); border:1px solid var(--color-border); border-radius:var(--radius-card)`.
  - `.playbook-title`: `color:var(--color-text)`.
  - `.playbook-category`: `color:var(--color-primary)`.
  - `.step-num`: `background:var(--color-primary)`.
  - `.playbook-step span`: `color:var(--color-text-2)`.

  **Authentication modal:**
  - `.auth-modal-backdrop`: `background:rgba(10,14,26,0.8); backdrop-filter:blur(8px)`.
  - `.auth-modal-card`: `background:var(--color-surface); border:1px solid var(--color-border); border-radius:var(--radius-panel)`.
  - `.auth-modal-tabs`: `background:var(--color-surface-2); border-radius:var(--radius-card)`.
  - `.auth-tab-btn.active`: `background:var(--color-primary); color:#fff`.
  - `.modal-close-btn`: `background:var(--color-surface-2); color:var(--color-text-2)`.

  Files: `static/css/main.css`

  Verify: Run the app. Open URL scanner, scan a sample URL. The verdict banner is dark with red/amber/green border. Indicator rows have colored left borders. The scans table is dark striped. The toast appears bottom-right in dark style.

---

- [ ] 8. **`main.css` — Learning Journey, quiz runner, course cards, responsive / mobile**

  Update the Learning Academy view and remaining responsive rules to use dark tokens.

  What to do:
  - `.learning-hero`: keep gradient, update to `linear-gradient(135deg, #1d4ed8 0%, var(--color-accent) 100%)` (blue-indigo instead of purple). Remove `box-shadow` with old purple color.
  - `.learning-hero h1, .learning-hero p`: keep white.
  - `.learning-subnav`: `border-bottom:1px solid var(--color-border)`.
  - `.learning-subnav-btn`: `color:var(--color-text-3); background:transparent`. Hover: `color:var(--color-text); background:var(--color-surface-2)`. Active: `background:var(--color-primary); color:#fff`.
  - `.course-card`: `background:var(--color-surface); border:1px solid var(--color-border); border-radius:var(--radius-card)`.
  - `.course-card-body h3, p`: `color:var(--color-text)` and `var(--color-text-2)`.
  - `.course-cat-pill`: `background:rgba(59,130,246,0.12); color:var(--color-primary)`.
  - `.course-level-pill.level-advanced`: `background:rgba(239,68,68,0.12); color:var(--color-critical)`.
  - `.course-level-pill.level-intermediate`: `background:rgba(245,158,11,0.12); color:var(--color-warning)`.
  - `.course-level-pill.level-beginner`: `background:rgba(16,185,129,0.12); color:var(--color-safe)`.
  - `.lesson-chip`: `background:var(--color-surface-2); border:1px solid var(--color-border)`.
  - `.quiz-card, .quiz-runner-box`: `background:var(--color-surface); border:1px solid var(--color-border)`.
  - `.quiz-option-btn` (check if rule exists; if not, add): `background:var(--color-surface-2); border:1px solid var(--color-border); color:var(--color-text-2); border-radius:var(--radius-input); padding:10px 14px; cursor:pointer; text-align:left; width:100%`. Selected: `border-color:var(--color-primary); background:rgba(59,130,246,0.1); color:var(--color-text)`.
  - `.quiz-progress-track`: `background:var(--color-surface-2)`. `.quiz-progress-fill`: `background:var(--color-primary)`.
  - `.quiz-question-text`: `color:var(--color-text); font-size:15px; font-weight:500`.
  - `.feedback-item.correct`: `border-left:3px solid var(--color-safe)`. `.feedback-item.incorrect`: `border-left:3px solid var(--color-critical)`.
  - `.material-card`: `background:var(--color-surface); border:1px solid var(--color-border)`.
  - `.material-preview-snippet`: `background:var(--color-surface-2); color:var(--color-text-3); font-family:var(--font-mono); font-size:11px; border-radius:var(--radius-input); padding:8px 10px`.
  - Video modal `.video-modal-card, .material-modal-card`: `background:var(--color-surface); border:1px solid var(--color-border)`.
  - `.video-modal-header, .material-modal-header`: `border-bottom:1px solid var(--color-border)`.
  - `.syllabus-item`: `background:var(--color-surface-2); border:1px solid var(--color-border)`.
  - `.loading-placeholder`: `color:var(--color-text-3)`.

  **Responsive (mobile ≤ 768px):**
  - `@media (max-width: 768px)`: sidebar hidden by default (`display:none`); `.sidebar.mobile-open { display:flex }`. `.top-hamburger-btn { display:flex }`. Content grid becomes single column. `.tool-grid-2` becomes single column. `.scan-bar-container` becomes column layout. `.right-content` hides on mobile. `.mobile-personal-bests { display:block }`.

  Files: `static/css/main.css`

  Verify: Open the Learning Journey view. Courses appear on dark cards. The quiz runner has dark question box and options. Resize browser to < 768px; sidebar hides and hamburger appears.

---

- [ ] 9. **`templates/index.html` — Font link, aria labels, semantic roles, bento grid → metric cards**

  Make the four permitted HTML changes. Do NOT touch any `id=`, `data-target=`, or view-panel wrapper.

  **Change 1 — Google Fonts link (line 8-9 area):**
  Replace:
  ```html
  <link href="https://fonts.googleapis.com/css2?family=Nunito:wght@200;300;400;500;600;700;800;900;1000&family=Roboto:wght@300;400;500;700&family=JetBrains+Mono:wght@400;500;600;700&display=swap" rel="stylesheet">
  ```
  With:
  ```html
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;700&display=swap" rel="stylesheet">
  ```

  **Change 2 — Aria labels on interactive elements missing them:**
  Add `aria-label` attributes to:
  - `#mobileMenuToggle`: already has `title`; add `aria-label="Toggle navigation menu"`.
  - `.top-brand` div (onclick): add `role="button" aria-label="Go to dashboard" tabindex="0"`.
  - `#omniSearchInput`: add `aria-label="Search IOCs, CVEs, domains, hashes, and IPs"`.
  - `.top-link-btn` buttons that only have icons + text: already have text, no change needed.
  - `.top-defcon-pill`: add `role="status" aria-label="Current DEFCON level: 2"`.
  - `#btnRunUrlScan`: add `aria-label="Execute URL scan"`.
  - `#btnRunMsgScan`: add `aria-label="Analyze message for phishing vectors"`.
  - `#btnRunEmailScan`: add `aria-label="Audit email identity against breach databases"`.
  - The password input `#passwordAuditInput`: add `aria-label="Enter password for security audit"`.
  - The header inspector scan button (has no `id`): add `id="btnRunHeaderScan" aria-label="Inspect HTTP security headers"`.
  - IP audit button (no `id`): add `id="btnRunIpScan" aria-label="Analyze IP address"`.
  - Hash identify button: add `aria-label="Identify hash algorithm"`.
  - Sample chip buttons: add `aria-label="Load sample: [description]"` to each (e.g., `aria-label="Load sample: PayPal phishing URL"`).
  - `#authModal` backdrop div: add `role="dialog" aria-modal="true" aria-label="Authentication"`.
  - `#videoModal`: add `role="dialog" aria-modal="true" aria-label="Video course player"`.
  - `#materialModal`: add `role="dialog" aria-modal="true" aria-label="Course material viewer"`.
  - `#tabBtnLogin`, `#tabBtnRegister`: add `aria-selected` (true/false) managed by JS (static HTML: login `aria-selected="true"`, register `aria-selected="false"`).
  - `#socToast`: add `role="alert" aria-live="polite"`.

  **Change 3 — Semantic tags:**
  - Change `.desktop-top-nav`'s element from `<header class="desktop-top-nav">` — it is already a `<header>`, keep it.
  - The sidebar `<nav class="main-menu">` is already semantic, keep it.
  - The `.content` `<section class="content">` is already semantic, keep it.
  - Add `<nav aria-label="Primary navigation">` wrapper around the `.top-links-menu` div (it is already inside `.top-nav-center`, just wrap the `<nav class="top-links-menu">` — it is already a `<nav>`, add `aria-label="Top navigation"` to it).
  - Change the `<main>` element: add `role="main"` (redundant but harmless for older ATs).

  **Change 4 — Replace bento image grid with metric cards (inside `#view-dashboard`, `<div class="activities">`):**
  Replace the entire `<div class="activities">` block (the heading "Perimeter Defense Radars" and the `<div class="activity-container">` containing 6 `.image-container` divs) with:

  ```html
  <div class="activities">
    <h2 class="dashboard-section-title">Operations Overview</h2>
    <div class="metric-cards-grid">
      <!-- Total Scans -->
      <div class="sg-metric-card">
        <div class="metric-icon icon-total"><i class="fa-solid fa-satellite-dish"></i></div>
        <div class="metric-label">Total Scans</div>
        <div class="metric-value" id="statTotalScans">0</div>
      </div>
      <!-- Threats Blocked -->
      <div class="sg-metric-card">
        <div class="metric-icon icon-threats"><i class="fa-solid fa-shield-virus"></i></div>
        <div class="metric-label">Threats Blocked</div>
        <div class="metric-value" id="statThreatsBlocked">0</div>
      </div>
      <!-- Clean Scans -->
      <div class="sg-metric-card">
        <div class="metric-icon icon-clean"><i class="fa-solid fa-circle-check"></i></div>
        <div class="metric-label">Clean Assets</div>
        <div class="metric-value" id="statCleanScans">0</div>
      </div>
      <!-- Defense Score -->
      <div class="sg-metric-card">
        <div class="metric-icon icon-score"><i class="fa-solid fa-gauge-high"></i></div>
        <div class="metric-label">Defense Score</div>
        <div class="metric-value" id="metricDefenseScore">—</div>
      </div>
      <!-- URLs Scanned shortcut -->
      <div class="sg-metric-card" style="cursor:pointer" onclick="switchNav('url-scanner')" role="button" aria-label="Open URL Radar scanner" tabindex="0">
        <div class="metric-icon icon-url"><i class="fa-solid fa-globe"></i></div>
        <div class="metric-label">URL Radar</div>
        <div class="metric-value">→</div>
      </div>
      <!-- Phish NLP shortcut -->
      <div class="sg-metric-card" style="cursor:pointer" onclick="switchNav('message-analyzer')" role="button" aria-label="Open Phish NLP analyzer" tabindex="0">
        <div class="metric-icon icon-phish"><i class="fa-solid fa-brain"></i></div>
        <div class="metric-label">Phish NLP</div>
        <div class="metric-value">→</div>
      </div>
    </div>
  </div>
  ```

  > **Important:** The existing `id="statTotalScans"`, `id="statThreatsBlocked"`, `id="statCleanScans"` are moved here from the right panel. Remove the duplicate IDs from the right panel section (`<div class="active-calories">`). The right panel's `#postureCircleBox` and `#postureScoreNumber` remain in place for the circular score display, but the three stat `<span>` elements must use new IDs (`id="sideTotalScans"`, `id="sideThreatsBlocked"`, `id="sideCleanScans"`) to avoid DOM duplication. Add a step to `loadRealDashboardTelemetry()` in JS (item 11) to populate both the metric card IDs and the side panel IDs. Also add `id="metricDefenseScore"` population in the same function.

  Files: `templates/index.html`

  Verify: Dashboard shows 6 metric cards with icons and numbers. No photo thumbnails. The JS still populates the stat numbers after a telemetry load. No broken IDs in the DOM.

---

- [ ] 10. **`static/js/app.js` — Add `apiFetch()` CSRF wrapper, enhance `showToast()`, add input constraints**

  Add three focused enhancements at the top of `app.js` (before `DOMContentLoaded`). Do NOT change any existing function signatures.

  **Add `apiFetch()` before the `DOMContentLoaded` block:**
  ```javascript
  // CSRF token cache (fetched once on load)
  let _csrfToken = null;

  async function _fetchCsrfToken() {
      // Try the /api/auth/csrf endpoint; fall back to a meta tag
      try {
          const res = await fetch('/api/auth/csrf', { method: 'GET' });
          if (res.ok) {
              const j = await res.json();
              if (j && j.csrf_token) return j.csrf_token;
          }
      } catch (_) { /* not available */ }
      const meta = document.querySelector('meta[name="csrf-token"]');
      return meta ? meta.getAttribute('content') : null;
  }

  /**
   * apiFetch — drop-in replacement for fetch() that injects X-CSRF-Token.
   * Preserves all original method, headers, and body options.
   */
  async function apiFetch(url, options = {}) {
      if (_csrfToken === null) {
          _csrfToken = await _fetchCsrfToken();
      }
      const headers = new Headers(options.headers || {});
      headers.set('Content-Type', headers.get('Content-Type') || 'application/json');
      if (_csrfToken) headers.set('X-CSRF-Token', _csrfToken);
      return fetch(url, { ...options, headers });
  }
  ```

  Then in `DOMContentLoaded`, add `_fetchCsrfToken().then(t => { _csrfToken = t; });` as the first call so the token is warm before the first user action.

  **Replace `showToast()` with an enhanced version** (same function name, same `isError` parameter):
  ```javascript
  function showToast(message, isError = false) {
      const toast = document.getElementById('socToast');
      if (!toast) return;
      // Clear previous state
      toast.classList.remove('show', 'error', 'success');
      toast.textContent = message;
      if (isError) {
          toast.classList.add('error');
      } else {
          toast.classList.add('success');
      }
      toast.classList.add('show');
      clearTimeout(toast._dismissTimer);
      toast._dismissTimer = setTimeout(() => {
          toast.classList.remove('show', 'error', 'success');
      }, 4000);
  }
  ```

  **Add input constraint enforcement** — append a new `initInputConstraints()` function and call it from `DOMContentLoaded`:
  ```javascript
  function initInputConstraints() {
      // Pairs of [inputId, buttonId]
      const pairs = [
          ['targetUrlInput', 'btnRunUrlScan'],
          ['messageTextInput', 'btnRunMsgScan'],
          ['emailAuditInput', 'btnRunEmailScan'],
          ['headerUrlInput', 'btnRunHeaderScan'],
          ['ipAuditInput', 'btnRunIpScan'],
          ['unknownHashInput', null],  // no dedicated btn id yet
          ['cryptoInputText', null],
      ];
      pairs.forEach(([inputId, btnId]) => {
          if (!btnId) return;
          const input = document.getElementById(inputId);
          const btn = document.getElementById(btnId);
          if (!input || !btn) return;
          // Initial state
          btn.disabled = input.value.trim().length === 0;
          // Live enforcement
          input.addEventListener('input', () => {
              btn.disabled = input.value.trim().length === 0;
          });
      });
  }
  ```

  Call `initInputConstraints()` inside `DOMContentLoaded` after the existing calls.

  Files: `static/js/app.js`

  Verify: Open the URL scanner. The "EXECUTE SCAN" button is disabled/greyed when the input is empty and becomes enabled after typing one character. Toast appears bottom-right with green border for success and red border for errors, and auto-dismisses after 4 seconds.

---

- [ ] 11. **`static/js/app.js` — Populate `metricDefenseScore` and side panel stat IDs; add button loading states to scan functions; add blur-validation feedback**

  Three targeted JS changes. All existing function names remain unchanged.

  **11a — Update `loadRealDashboardTelemetry()` to populate new IDs.**
  Inside the `if (data.metrics)` block where `m` is assigned, after the existing `totalEl / threatsEl / cleanEl` assignments, add:
  ```javascript
  // Populate metric card IDs (from item 9 HTML change)
  const metricScoreEl = document.getElementById('metricDefenseScore');
  if (metricScoreEl) metricScoreEl.textContent = `${m.defense_score}%`;

  // Populate duplicate side-panel spans (renamed IDs to avoid DOM collision)
  const sideTotalEl = document.getElementById('sideTotalScans');
  const sideThreatsEl = document.getElementById('sideThreatsBlocked');
  const sideCleanEl = document.getElementById('sideCleanScans');
  if (sideTotalEl) sideTotalEl.textContent = m.total_scans;
  if (sideThreatsEl) sideThreatsEl.textContent = m.threats_blocked;
  if (sideCleanEl) sideCleanEl.textContent = m.clean_scans;
  ```

  **11b — Button loading state pattern.** Add a reusable helper (do not change any scan function signatures):
  ```javascript
  function setBtnLoading(btn, isLoading, originalHTML) {
      if (!btn) return;
      if (isLoading) {
          btn._originalHTML = btn.innerHTML;
          btn.disabled = true;
          btn.innerHTML = `<i class="fa-solid fa-spinner fa-spin"></i> <span>Processing...</span>`;
      } else {
          btn.disabled = false;
          btn.innerHTML = originalHTML || btn._originalHTML || btn.innerHTML;
      }
  }
  ```

  Apply to `executeEmailAudit()` and `executeIpAudit()` (they currently have no loading state). Inside each function:
  - At the start: `const btn = document.getElementById('btnRunEmailScan'); setBtnLoading(btn, true);` (use `btnRunIpScan` for IP).
  - In `finally`: `setBtnLoading(btn, false);`.

  The URL scanner and message scanner already have manual `btn.disabled = true/false` — leave them alone.

  **11c — Blur validation feedback.** Add `initBlurValidation()` and call from `DOMContentLoaded`:
  ```javascript
  function initBlurValidation() {
      const rules = [
          {
              id: 'emailAuditInput',
              test: v => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v),
              msg: 'Enter a valid email address (e.g. user@domain.com)'
          },
          {
              id: 'ipAuditInput',
              test: v => /^(\d{1,3}\.){3}\d{1,3}$/.test(v) || /^[0-9a-fA-F:]+$/.test(v),
              msg: 'Enter a valid IPv4 (e.g. 8.8.8.8) or IPv6 address'
          },
          {
              id: 'headerUrlInput',
              test: v => /^https?:\/\/.+/.test(v) || /^[a-z0-9][-a-z0-9.]+\.[a-z]{2,}$/i.test(v),
              msg: 'Enter a URL or domain (e.g. https://example.com)'
          },
      ];

      rules.forEach(({ id, test, msg }) => {
          const input = document.getElementById(id);
          if (!input) return;

          // Create or reuse an error element below the input's parent
          let errEl = document.getElementById(`${id}-err`);
          if (!errEl) {
              errEl = document.createElement('p');
              errEl.id = `${id}-err`;
              errEl.style.cssText = 'font-size:11px;color:var(--color-critical);margin:4px 0 0;display:none;font-family:var(--font-mono);';
              errEl.setAttribute('role', 'alert');
              input.closest('.input-with-icon, .form-group, .scan-bar-container')
                  ?.parentNode?.insertBefore(errEl, input.closest('.input-with-icon, .form-group, .scan-bar-container')?.nextSibling)
                  || input.parentNode.appendChild(errEl);
          }

          input.addEventListener('blur', () => {
              const v = input.value.trim();
              if (v && !test(v)) {
                  errEl.textContent = msg;
                  errEl.style.display = 'block';
                  input.style.borderColor = 'var(--color-critical)';
              } else {
                  errEl.style.display = 'none';
                  input.style.borderColor = '';
              }
          });

          input.addEventListener('focus', () => {
              errEl.style.display = 'none';
              input.style.borderColor = '';
          });
      });
  }
  ```

  Files: `static/js/app.js`

  Verify:
  - Dashboard loads; metric cards show live numbers from the database.
  - Type an invalid email in the Breach Radar input, tab away — a red inline error message appears below the input field.
  - The email scan button shows a spinner during the fetch and restores on completion.

---

## Verification checklist (run after all items are complete)

1. `python app.py` starts without errors.
2. Open `http://localhost:5000` in browser — dark navy background, no Unsplash image.
3. Dashboard shows 6 metric cards; the Live Scan Audit Log table renders with dark striped rows.
4. Click "URL Radar" in sidebar — active item has blue left border + blue text.
5. Scan `http://secure-login-paypal.verify-account-update.tk/signin` — spinner appears, verdict banner is red/dark with large score number, indicator rows have red left border.
6. Scan button is grey/disabled on empty input; typing one character enables it.
7. Type an invalid email in Breach Radar, tab away — red inline error appears.
8. Toast on a successful scan is dark with green border; toast on error is dark with red border. Both auto-dismiss in 4 seconds.
9. All existing JS function names (`switchNav`, `handleTopSearch`, `showToast`, `executeUrlScan`, `executeMessageScan`, `executeEmailAudit`, `executeHeaderAudit`, `executePasswordAudit`, `executeIpAudit`, `executeCryptoHashes`, `executeHashIdentify`, `executeTransform`, `loadPlaybooks`, `loadLearningJourney`, etc.) still exist and work.
10. The `id="recentScansTbody"` and `id="incidentsCalendar"` elements still exist in the DOM and are populated by `loadRealDashboardTelemetry()`.
