(function () {
    let csrfToken = '';

    async function ensureCsrfToken(forceRefresh) {
        if (csrfToken && !forceRefresh) {
            return csrfToken;
        }

        const response = await fetch('csrf_token.php?ts=' + Date.now(), {
            credentials: 'same-origin'
        });
        const data = await response.json();

        if (data && data.success && data.csrf_token) {
            csrfToken = data.csrf_token;
        }

        return csrfToken;
    }

    function withCsrfHeaders(headers) {
        const merged = Object.assign({}, headers || {});
        if (csrfToken) {
            merged['X-CSRF-Token'] = csrfToken;
        }
        return merged;
    }

    window.ensureCsrfToken = ensureCsrfToken;
    window.withCsrfHeaders = withCsrfHeaders;
})();
