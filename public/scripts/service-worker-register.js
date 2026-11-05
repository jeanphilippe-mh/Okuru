(() => {
  if (!("serviceWorker" in navigator)) return;

  try {
    const workerPath = "/service-worker.js";
    // register() requires a TrustedScriptURL when Trusted Types are enforced.
    const workerURL = window.trustedTypes
      ? window.trustedTypes.createPolicy("okuru-service-worker", {
          createScriptURL: (url) => {
            if (url !== workerPath) throw new TypeError("Unexpected service worker URL");
            return url;
          },
        }).createScriptURL(workerPath)
      : workerPath;

    navigator.serviceWorker.register(workerURL, { scope: "/", updateViaCache: "none" }).catch(() => {
      // A service worker is optional; sharing remains available without it.
    });
  } catch (_) {
    // An unsupported or restricted registration must not break sharing.
  }
})();
