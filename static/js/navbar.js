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
