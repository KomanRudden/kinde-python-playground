// Progressive enhancement only: every page works without this script.
(function () {
  "use strict";

  const detailCache = new Map();

  function remember(el) {
    return [...el.querySelectorAll("details[open][data-id]")].map((node) => node.dataset.id);
  }

  function restore(el, open) {
    open.forEach((id) => {
      const node = [...el.querySelectorAll("details[data-id]")].find((item) => item.dataset.id === id);
      if (!node) return;
      node.open = true;
      const slot = node.querySelector(":scope > .run-detail");
      const cached = detailCache.get(id);
      if (slot && cached) {
        slot.innerHTML = cached;
        slot.dataset.loaded = "1";
      }
    });
  }

  async function load(el, url) {
    const open = el.id === "regression-status" ? remember(el) : [];
    el.classList.add("loading");
    try {
      const response = await fetch(url, {
        headers: { "x-playground-partial": "1" },
        credentials: "same-origin",
      });
      el.innerHTML = await response.text();
      if (open.length) restore(el, open);
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

    const opener = event.target.closest("[data-snippet-open]");
    if (opener) {
      document.querySelector(".snippet-modal")?.showModal();
      return;
    }
    if (event.target.classList?.contains("snippet-modal")) {
      event.target.close();
      return;
    }
    const closer = event.target.closest("[data-snippet-close]");
    if (closer) {
      closer.closest("dialog")?.close();
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

  function watch(el) {
    if (!el || el.dataset.watching === "1") return;
    el.dataset.watching = "1";
    const tick = async () => {
      if (!el.isConnected) return;
      await load(el, el.dataset.src);
      if (el.querySelector("[data-running]")) setTimeout(tick, 700);
      else el.dataset.watching = "0";
    };
    setTimeout(tick, 400);
  }

  document.addEventListener("toggle", (event) => {
    const node = event.target;
    if (!(node instanceof HTMLDetailsElement) || !node.classList.contains("run-test") || !node.open) return;
    const slot = node.querySelector(":scope > .run-detail");
    if (!slot || slot.dataset.loaded === "1") return;
    const cached = detailCache.get(node.dataset.id);
    if (cached) {
      slot.innerHTML = cached;
      slot.dataset.loaded = "1";
      return;
    }
    slot.innerHTML = '<p class="muted small">Loading the calls and the result…</p>';
    fetch(node.dataset.detail, { headers: { "x-playground-partial": "1" }, credentials: "same-origin" })
      .then((response) => response.text())
      .then((html) => {
        detailCache.set(node.dataset.id, html);
        if (slot.isConnected) {
          slot.innerHTML = html;
          slot.dataset.loaded = "1";
        }
      })
      .catch(() => {
        slot.innerHTML = '<p class="call-error-text">Could not load this test.</p>';
      });
  }, true);

  document.addEventListener("DOMContentLoaded", () => {
    loadAll(document);
    document.querySelectorAll("[data-poll]").forEach(watch);
    tickCountdowns();
    setInterval(tickCountdowns, 1000);
  });
})();
