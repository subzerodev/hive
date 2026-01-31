# Navbar Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add a unified navigation header to all HIVE pages (except login pages) showing branding, navigation links, auth status, and logout.

**Architecture:** JavaScript-injected navbar that fetches auth info from a new `/api/auth-info` endpoint, checks session status, and renders appropriate UI. Skips login pages by URL pattern detection.

**Tech Stack:** Go (backend endpoint), Vanilla JavaScript (navbar injection), CSS (styling)

---

## Task 1: Add `/api/auth-info` endpoint

**Files:**
- Modify: `/home/subzerodev/workspace/hive/.worktrees/navbar/main.go:124-125`

**Step 1: Add the auth-info handler**

Add this after line 125 (`http.HandleFunc("/api/reset", api.ResetHandler)`):

```go
	// Auth info endpoint for navbar
	http.HandleFunc("/api/auth-info", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if authType == "none" {
			w.Write([]byte(`{"auth_type":"none"}`))
			return
		}
		fmt.Fprintf(w, `{"auth_type":"%s","session_endpoint":"/vulns/auth/%s/session","dashboard_url":"/vulns/auth/%s/dashboard","logout_url":"/vulns/auth/%s/logout"}`,
			authType, authType, authType, authType)
	})
```

**Step 2: Verify it compiles**

Run: `cd /home/subzerodev/workspace/hive/.worktrees/navbar && go build -o /dev/null .`
Expected: No errors

**Step 3: Commit**

```bash
git add main.go
git commit -m "feat: add /api/auth-info endpoint for navbar"
```

---

## Task 2: Add navbar CSS styles

**Files:**
- Modify: `/home/subzerodev/workspace/hive/.worktrees/navbar/static/css/hive.css`

**Step 1: Add navbar styles at the end of hive.css**

```css
/* Navbar */
.hive-navbar {
    position: fixed;
    top: 0;
    left: 0;
    right: 0;
    height: 50px;
    background: #1a1a2e;
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 0 20px;
    z-index: 1000;
    border-bottom: 2px solid var(--color-primary);
}

.hive-navbar a {
    color: #ffffff;
    text-decoration: none;
}

.hive-navbar a:hover {
    color: var(--color-primary);
    text-decoration: none;
}

.navbar-brand a {
    font-family: var(--font-mono);
    font-size: 20px;
    font-weight: 700;
    letter-spacing: 2px;
    color: var(--color-primary) !important;
}

.navbar-links {
    display: flex;
    gap: 20px;
}

.navbar-links a {
    font-size: 14px;
}

.navbar-auth {
    display: flex;
    align-items: center;
    gap: 15px;
}

.auth-status {
    font-size: 13px;
    color: #888;
}

.logout-btn {
    font-size: 13px;
    padding: 5px 12px;
    background: var(--color-primary);
    color: #fff !important;
    border-radius: 3px;
}

.logout-btn:hover {
    background: var(--color-primary-dark);
}

/* Body padding for navbar */
body.has-navbar {
    padding-top: 70px;
}

/* Responsive */
@media (max-width: 600px) {
    .hive-navbar {
        padding: 0 10px;
    }
    .navbar-links {
        gap: 10px;
    }
    .auth-status {
        display: none;
    }
}
```

**Step 2: Commit**

```bash
git add static/css/hive.css
git commit -m "feat: add navbar CSS styles"
```

---

## Task 3: Create navbar.js

**Files:**
- Create: `/home/subzerodev/workspace/hive/.worktrees/navbar/static/js/navbar.js`

**Step 1: Create the navbar JavaScript file**

```javascript
(function() {
    // Skip login pages
    const path = window.location.pathname;
    const loginPatterns = [
        /\/vulns\/auth\/[^/]+\/login/,
        /\/vulns\/auth\/multi-step\/step[12]/,
        /\/vulns\/auth\/oauth\/(start|authorize)/
    ];

    for (const pattern of loginPatterns) {
        if (pattern.test(path)) return;
    }

    // Fetch auth info and render navbar
    fetch('/api/auth-info')
        .then(r => r.json())
        .then(info => renderNavbar(info))
        .catch(() => renderNavbar({ auth_type: 'none' }));

    function renderNavbar(info) {
        const nav = document.createElement('nav');
        nav.className = 'hive-navbar';

        let linksHtml = '<a href="/vulns/">Vulnerabilities</a>';
        let authHtml = '';

        if (info.auth_type !== 'none') {
            linksHtml += `<a href="${info.dashboard_url}">Dashboard</a>`;

            // Check session status
            checkSession(info).then(session => {
                if (session.authenticated) {
                    document.querySelector('.auth-status').textContent =
                        'Logged in as ' + session.user;
                }
            });

            authHtml = `
                <span class="auth-status"></span>
                <a href="${info.logout_url}" class="logout-btn">Logout</a>
            `;
        }

        nav.innerHTML = `
            <div class="navbar-brand"><a href="/vulns/">HIVE</a></div>
            <div class="navbar-links">${linksHtml}</div>
            <div class="navbar-auth">${authHtml}</div>
        `;

        document.body.insertBefore(nav, document.body.firstChild);
        document.body.classList.add('has-navbar');
    }

    function checkSession(info) {
        const headers = {};

        // For JWT, include token from localStorage
        if (info.auth_type === 'jwt') {
            const token = localStorage.getItem('jwt_token');
            if (token) {
                headers['Authorization'] = 'Bearer ' + token;
            }
        }

        return fetch(info.session_endpoint, { headers })
            .then(r => r.json())
            .catch(() => ({ authenticated: false }));
    }
})();
```

**Step 2: Commit**

```bash
git add static/js/navbar.js
git commit -m "feat: add navbar.js for dynamic navbar injection"
```

---

## Task 4: Add navbar script to vulns/index.html

**Files:**
- Modify: `/home/subzerodev/workspace/hive/.worktrees/navbar/vulns/index.html`

**Step 1: Add script tag before closing body tag**

Find line 69 (`</body>`) and add the script tag before it:

```html
    <script src="/static/js/navbar.js"></script>
</body>
```

**Step 2: Commit**

```bash
git add vulns/index.html
git commit -m "feat: add navbar script to main vulns page"
```

---

## Task 5: Add navbar to form-post dashboard

**Files:**
- Modify: `/home/subzerodev/workspace/hive/.worktrees/navbar/vulns/auth/formpost/handlers.go:83-95`

**Step 1: Update dashboard HTML to include navbar script**

Replace the dashboard function's HTML output (lines 83-95) with:

```go
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head>
<title>Dashboard</title>
<link rel="stylesheet" href="/static/css/hive.css">
</head>
<body>
<div class="container">
<h1>Dashboard (Form POST Auth)</h1>
<p>Welcome, admin! You are authenticated via form POST.</p>
</div>
<script src="/static/js/navbar.js"></script>
</body></html>`)
```

Note: Remove the logout link from the body since it's now in the navbar.

**Step 2: Commit**

```bash
git add vulns/auth/formpost/handlers.go
git commit -m "feat: add navbar to form-post dashboard"
```

---

## Task 6: Add navbar to ajax-json dashboard

**Files:**
- Modify: `/home/subzerodev/workspace/hive/.worktrees/navbar/vulns/auth/ajaxjson/handlers.go`

**Step 1: Find the dashboard handler and add navbar script**

Locate the dashboard HTML output and add `<script src="/static/js/navbar.js"></script>` before `</body>`. Remove inline logout link.

**Step 2: Commit**

```bash
git add vulns/auth/ajaxjson/handlers.go
git commit -m "feat: add navbar to ajax-json dashboard"
```

---

## Task 7: Add navbar to multi-step dashboard

**Files:**
- Modify: `/home/subzerodev/workspace/hive/.worktrees/navbar/vulns/auth/multistep/handlers.go`

**Step 1: Find the dashboard handler and add navbar script**

Locate the dashboard HTML output and add `<script src="/static/js/navbar.js"></script>` before `</body>`. Remove inline logout link.

**Step 2: Commit**

```bash
git add vulns/auth/multistep/handlers.go
git commit -m "feat: add navbar to multi-step dashboard"
```

---

## Task 8: Add navbar to oauth dashboard

**Files:**
- Modify: `/home/subzerodev/workspace/hive/.worktrees/navbar/vulns/auth/oauth/handlers.go`

**Step 1: Find the dashboard handler and add navbar script**

Locate the dashboard HTML output and add `<script src="/static/js/navbar.js"></script>` before `</body>`. Remove inline logout link.

**Step 2: Commit**

```bash
git add vulns/auth/oauth/handlers.go
git commit -m "feat: add navbar to oauth dashboard"
```

---

## Task 9: Add navbar to http-basic dashboard

**Files:**
- Modify: `/home/subzerodev/workspace/hive/.worktrees/navbar/vulns/auth/httpbasic/handlers.go`

**Step 1: Find the protected/dashboard handler and add navbar script**

Locate the protected page HTML output and add `<script src="/static/js/navbar.js"></script>` before `</body>`.

**Step 2: Commit**

```bash
git add vulns/auth/httpbasic/handlers.go
git commit -m "feat: add navbar to http-basic protected page"
```

---

## Task 10: Add navbar to jwt dashboard

**Files:**
- Modify: `/home/subzerodev/workspace/hive/.worktrees/navbar/vulns/auth/jwt/handlers.go`

**Step 1: Find the dashboard/protected handler and add navbar script**

Locate the protected page HTML output and add `<script src="/static/js/navbar.js"></script>` before `</body>`.

**Step 2: Commit**

```bash
git add vulns/auth/jwt/handlers.go
git commit -m "feat: add navbar to jwt protected page"
```

---

## Task 11: Manual testing

**Step 1: Build and run the app**

```bash
cd /home/subzerodev/workspace/hive/.worktrees/navbar
go build -o hive .
AUTH_TYPE=form-post ./hive
```

**Step 2: Test in browser**

1. Visit `http://localhost:8080/vulns/` - Should see navbar with "Vulnerabilities" link only (not logged in)
2. Login via form-post
3. Visit dashboard - Should see navbar with "Vulnerabilities", "Dashboard", auth status, and "Logout"
4. Click "Vulnerabilities" - Should navigate to `/vulns/`
5. Click "Logout" - Should log out and redirect to login page
6. Verify login page does NOT have navbar

**Step 3: Test other auth types**

Repeat for: ajax-json, multi-step, oauth, jwt, http-basic

**Step 4: Test AUTH_TYPE=none**

```bash
AUTH_TYPE=none ./hive
```

Visit `/vulns/` - Should see minimal navbar (just HIVE logo and Vulnerabilities link, no auth elements)

---

## Task 12: Final commit and cleanup

**Step 1: Verify all changes compile**

```bash
go build -o /dev/null .
```

**Step 2: Create summary commit if needed**

If any final tweaks were made during testing, commit them.

---

## Summary

| Task | Description |
|------|-------------|
| 1 | Add `/api/auth-info` endpoint |
| 2 | Add navbar CSS styles |
| 3 | Create navbar.js |
| 4 | Add script to vulns/index.html |
| 5-10 | Add script to each auth dashboard |
| 11 | Manual testing |
| 12 | Final verification |
