// Read auth code from URL parameters
const params = new URLSearchParams(window.location.search);
const code = params.get("code");
const callbackUrl = params.get("callback_url");

// Only offer the complete URL for the supported manual iOS callback.
// Home Assistant still verifies the transaction state and PKCE itself.
if (code && !params.get("error") && callbackUrl) {
    try {
        const callback = new URL(callbackUrl);
        if (
            callback.origin === "https://login.duke-energy.com" &&
            callback.pathname === "/ios/com.duke-energy.app/callback" &&
            !callback.username &&
            !callback.password &&
            callback.searchParams.get("code") === code &&
            callback.searchParams.get("state") === params.get("state") &&
            callback.searchParams.get("state") &&
            !callback.searchParams.has("error")
        ) {
            document.getElementById("callbackSection").style.display = "block";
            document
                .getElementById("copyCallback")
                .addEventListener("click", async () => {
                    await navigator.clipboard.writeText(callbackUrl);
                });
        }
    } catch {
        // Invalid callback URLs must never be offered for copying.
    }
}

if (code) {
    document.getElementById("success").style.display = "block";
    // Mask the code, showing only last 4 characters
    const masked = "•".repeat(Math.max(0, code.length - 4)) + code.slice(-4);
    document.getElementById("authCode").textContent = masked;
} else {
    document.getElementById("noCode").style.display = "block";
    const error = params.get("error");
    if (error) {
        const description = params.get("error_description");
        document.getElementById("noCodeMessage").textContent =
            "Duke Energy returned an error instead of an authorization code:";
        const errorDetail = document.getElementById("errorDetail");
        errorDetail.textContent = description
            ? `${error}: ${description}`
            : error;
        errorDetail.style.display = "block";
    }
}

// Copy handler
document.getElementById("copyCode").addEventListener("click", async () => {
    await navigator.clipboard.writeText(code);
    const toast = document.getElementById("toast");
    toast.classList.add("show");
    setTimeout(() => toast.classList.remove("show"), 2000);
});
