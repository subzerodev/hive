# Unified Navigation Header Design

## Summary

Add a consistent navbar to all HIVE pages (except login pages) that shows branding, navigation links, auth status, and logout functionality.

## Background

Currently, after logging in users land on a dashboard with only a "Logout" link. There's no way to navigate to the vulnerabilities page or return to the dashboard from other pages.

## Design

### Navbar Contents

| Element | Description |
|---------|-------------|
| Logo/Title | "HIVE" - links to `/vulns/` |
| Vulnerabilities link | Links to `/vulns/` |
| Dashboard link | Links to current auth type's dashboard (hidden when `AUTH_TYPE=none`) |
| Auth status | "Logged in as admin" (hidden when `AUTH_TYPE=none`) |
| Logout button | Links to current auth type's logout (hidden when `AUTH_TYPE=none`) |

### Implementation Approach

JavaScript-injected navbar via `/static/js/navbar.js`:

1. Script fetches auth info from new `/api/auth-info` endpoint
2. Injects navbar HTML at top of page
3. Checks session status and displays appropriate auth state
4. Skips rendering on login pages (detected by URL pattern)

**Why JavaScript instead of server-side templates?**
- Many pages are static HTML files
- Avoids duplicating navbar HTML in every handler
- Single source of truth for navbar logic

### HTML Structure

```html
<nav class="hive-navbar">
  <div class="navbar-brand">
    <a href="/vulns/">HIVE</a>
  </div>
  <div class="navbar-links">
    <a href="/vulns/">Vulnerabilities</a>
    <a href="/vulns/auth/{type}/dashboard">Dashboard</a>
  </div>
  <div class="navbar-auth">
    <span class="auth-status">Logged in as admin</span>
    <a href="/vulns/auth/{type}/logout" class="logout-btn">Logout</a>
  </div>
</nav>
```

### Auth Info Endpoint

New endpoint: `GET /api/auth-info`

Response when auth enabled:
```json
{
  "auth_type": "form-post",
  "session_endpoint": "/vulns/auth/form-post/session",
  "dashboard_url": "/vulns/auth/form-post/dashboard",
  "logout_url": "/vulns/auth/form-post/logout"
}
```

Response when `AUTH_TYPE=none`:
```json
{
  "auth_type": "none"
}
```

### Styling

- Fixed at top of page
- Dark background (`#1a1a2e`) matching existing theme
- Red accent color (`#e63946`) for hover states
- Responsive - collapses gracefully on mobile
- Body padding-top to prevent content hiding under navbar

## Files to Change

### New Files

| File | Purpose |
|------|---------|
| `/static/js/navbar.js` | Navbar injection and auth logic |

### Modified Files

| File | Change |
|------|--------|
| `/static/css/hive.css` | Add navbar styles |
| `/main.go` | Add `/api/auth-info` endpoint |
| `/vulns/index.html` | Add navbar script tag |
| Dashboard pages in auth handlers | Add navbar script tag |

### Pages with Navbar

- `/vulns/index.html` (main vulnerability listing)
- All dashboard pages (form-post, ajax-json, multi-step, oauth, http-basic, jwt)
- Vulnerability category pages

### Pages without Navbar

- Login pages (`/vulns/auth/*/login`)
- Multi-step auth pages (`/vulns/auth/multi-step/step1`, `step2`)
- OAuth flow pages (`/vulns/auth/oauth/start`, `authorize`)

## JWT/HTTP-Basic Considerations

- **JWT**: Navbar script will include token from localStorage in session check
- **HTTP-Basic**: Browser automatically includes credentials in requests after initial auth

## Out of Scope

- Changing auth type redirect behavior (current 401 responses for JWT/ajax-json are correct real-world behavior)
- Mobile hamburger menu (simple responsive layout is sufficient)
