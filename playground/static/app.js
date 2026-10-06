// Progressive enhancement only: every page works without this script.
(function () {
  "use strict";

  async function load(el, url) {
    el.classList.add("loading");
    try {
      const response = await fetch(url, {
        headers: { "x-playground-partial": "1" },
        credentials: "same-origin",
      });
      el.innerHTML = await response.text();
    } catch (err) {
      el.innerHTML = '<p class="call-error-text">Could not load this panel.</p>';
    } finally {
      el.classList.remove("loading");
    }
  }

  function loadAll(root) {
    root.querySelectorAll("[data-src]").forEach((el) => load(el, el.dataset.src));
  }

  document.addEventListener("click", (event) => {
    const reload = event.target.closest("[data-reload]");
    if (reload) {
      const target = document.querySelector(reload.dataset.reload);
      if (target) load(target, target.dataset.src);
      return;
    }

    const loader = event.target.closest("[data-load]");
    if (loader) {
      const target = document.querySelector(loader.dataset.into);
      document.querySelectorAll("[data-load].active").forEach((b) => b.classList.remove("active"));
      loader.classList.add("active");
      if (target) load(target, loader.dataset.load);
      return;
    }

    const reveal = event.target.closest("[data-reveal]");
    if (reveal) {
      const row = reveal.closest("tr");
      const masked = row.querySelector("[data-masked]");
      const raw = row.querySelector("[data-revealed]");
      const showing = !raw.hidden;
      raw.hidden = showing;
      masked.hidden = !showing;
      reveal.textContent = showing ? "Reveal" : "Hide";
      return;
    }

    const copy = event.target.closest("[data-copy-target]");
    if (copy) {
      const source = copy.nextElementSibling;
      navigator.clipboard.writeText(source.innerText).then(() => {
        copy.textContent = "Copied";
        setTimeout(() => (copy.textContent = "Copy"), 1200);
      });
    }
  });

  document.addEventListener("submit", (event) => {
    const message = event.target.dataset.confirm;
    if (message && !window.confirm(message)) event.preventDefault();
  });

  document.addEventListener("change", (event) => {
    const select = event.target.closest("[data-autosubmit]");
    if (!select) return;
    const form = select.form;
    // Choosing a new API resets the method
    if (select.name === "api") {
      const method = form.querySelector("[name=method]");
      if (method) method.disabled = true;
    }
    form.submit();
  });

  function tickCountdowns() {
    const now = Date.now() / 1000;
    document.querySelectorAll("[data-countdown]").forEach((el) => {
      const left = Math.round(parseFloat(el.dataset.countdown) - now);
      if (left <= 0) {
        el.textContent = "expired";
        return;
      }
      const m = Math.floor(left / 60);
      const s = left % 60;
      el.textContent = m ? `${m}m ${String(s).padStart(2, "0")}s` : `${s}s`;
    });
  }

  document.addEventListener("DOMContentLoaded", () => {
    loadAll(document);
    tickCountdowns();
    setInterval(tickCountdowns, 1000);
  });
})();
