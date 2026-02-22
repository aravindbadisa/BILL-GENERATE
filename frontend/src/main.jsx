import React from "react";
import ReactDOM from "react-dom/client";
import "./styles.css";

const rootEl = document.getElementById("root");

const formatError = (err) => {
  if (!err) return "Unknown error";
  if (typeof err === "string") return err;
  const msg = err && err.message ? String(err.message) : String(err);
  const stack = err && err.stack ? String(err.stack) : "";
  return stack && !stack.includes(msg) ? `${msg}\n\n${stack}` : stack || msg;
};

const renderBootError = (err) => {
  // Expose details for the inline fallback in index.html.
  window.__BILLING_BOOT_ERROR__ = formatError(err);

  if (!rootEl) return;
  rootEl.innerHTML = `
    <div style="font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;padding:24px;color:#0f172a">
      <h1 style="margin:0 0 8px;font-size:20px">App failed to start</h1>
      <p style="margin:0;color:#475569">A JavaScript error happened while starting the app. Refresh (Ctrl+F5). If it still fails, try Incognito.</p>
      <pre style="white-space:pre-wrap;opacity:.85;margin-top:10px">${formatError(err)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")}</pre>
    </div>
  `;
};

window.__BILLING_BOOT_STARTED__ = true;

(async () => {
  try {
    const mod = await import("./App.jsx");
    const App = mod.default;
    ReactDOM.createRoot(rootEl).render(
      <React.StrictMode>
        <App />
      </React.StrictMode>
    );
    window.__BILLING_BOOT_RENDERED__ = true;
  } catch (err) {
    console.error("App bootstrap failed:", err);
    renderBootError(err);
  }
})();
