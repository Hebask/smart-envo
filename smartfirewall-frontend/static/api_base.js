function currentApiBase() {
    return (window.API_BASE || "").replace(/\/+$/, "");
}

function buildHeaders(extraHeaders = {}, includeJson = true) {
    const headers = {
        ...extraHeaders
    };

    if (window.USER_EMAIL) {
        headers["X-User-Email"] = window.USER_EMAIL;
    }


    if (includeJson && !headers["Content-Type"]) {
        headers["Content-Type"] = "application/json";
    }

    return headers;
}

async function apiFetch(path, options = {}) {
    const url = `${currentApiBase()}${path}`;
    const method = options.method || "GET";
    const isFormData = options.body instanceof FormData;

    const headers = buildHeaders(options.headers || {}, !isFormData);

    const response = await fetch(url, {
        ...options,
        method,
        headers
    });

    if (response.status === 401) {
        window.location.href = "/login";
        return;
    }

    if (!response.ok) {
        let errorText = "";
        try {
            errorText = await response.text();
        } catch (e) {
            errorText = response.statusText;
        }
        throw new Error(`API ${response.status}: ${errorText || response.statusText}`);
    }

    const contentType = response.headers.get("content-type") || "";

    if (contentType.includes("application/json")) {
        return await response.json();
    }

    return await response.text();
}

window.apiFetch = apiFetch;
