// UX helpers: prevent double submit and show loading state (robusto para múltiplos botões submit)
(function () {
  function getSubmitter(ev, form) {
    if (ev && ev.submitter) return ev.submitter;

    // Fallback: botão focado
    var active = document.activeElement;
    if (active && form.contains(active) && (active.type === "submit" || active.getAttribute("type") === "submit")) {
      return active;
    }

    // Último fallback: primeiro submit
    return form.querySelector("button[type='submit'], input[type='submit']");
  }

  function ensureShadowAction(form, submitter) {
    // Alguns navegadores NÃO enviam name/value do botão se ele ficar disabled.
    // Criamos um input hidden com o mesmo name/value para garantir o backend.
    if (!submitter) return;
    var name = submitter.getAttribute("name");
    if (!name) return;

    var value = submitter.getAttribute("value") || "";
    // remove shadow antigo
    var old = form.querySelector("input[type='hidden'][data-shadow-submit='1']");
    if (old) old.remove();

    var hidden = document.createElement("input");
    hidden.type = "hidden";
    hidden.name = name;
    hidden.value = value;
    hidden.setAttribute("data-shadow-submit", "1");
    form.appendChild(hidden);
  }

  function setLoading(btn, loadingText) {
    if (!btn) return;
    if (btn.dataset.loading === "1") return;

    btn.dataset.loading = "1";
    btn.dataset.originalHtml = btn.innerHTML;
    btn.dataset.originalDisabled = btn.disabled ? "1" : "0";

    var text = loadingText || btn.getAttribute("data-loading-text") || "Carregando...";
    btn.disabled = true;
    btn.classList.add("disabled");
    btn.style.pointerEvents = "none";
    btn.setAttribute("aria-busy", "true");
    btn.innerHTML =
      '<span class="spinner-border spinner-border-sm me-2" role="status" aria-hidden="true"></span>' +
      text;
  }

  function restoreButton(btn) {
    if (!btn) return;
    if (btn.dataset.loading !== "1") return;

    btn.innerHTML = btn.dataset.originalHtml || btn.innerHTML;
    btn.disabled = btn.dataset.originalDisabled === "1";
    btn.classList.remove("disabled");
    btn.style.pointerEvents = "";
    btn.removeAttribute("aria-busy");

    delete btn.dataset.loading;
    delete btn.dataset.originalHtml;
    delete btn.dataset.originalDisabled;
  }

  document.addEventListener(
    "submit",
    function (ev) {
      var form = ev.target;
      if (!(form instanceof HTMLFormElement)) return;

      // If the form opts out, do nothing
      if (form.hasAttribute("data-no-loading")) return;

      if (form.dataset.submitting === "1") return;
      form.dataset.submitting = "1";

      var submitter = getSubmitter(ev, form);
      ensureShadowAction(form, submitter);

      // Aplica loading no botão real clicado, senão no primeiro submit
      var btn = null;
      if (submitter && submitter.matches && submitter.matches("button[type='submit']")) btn = submitter;
      if (!btn) btn = form.querySelector("button[type='submit'][data-loading], button[type='submit']");
      if (btn) setLoading(btn);

      // Timeout de segurança: reabilita se o request travar (ex.: 60s)
      var timeoutMs = parseInt(form.getAttribute("data-loading-timeout") || "60000", 10);
      window.setTimeout(function () {
        form.dataset.submitting = "";
        restoreButton(btn);
      }, timeoutMs);
    },
    true
  );

  // Also handle links/buttons that do heavy GETs (optional)
  document.addEventListener(
    "click",
    function (ev) {
      var el = ev.target.closest("[data-click-loading]");
      if (!el) return;
      if (el.tagName === "BUTTON") setLoading(el, el.getAttribute("data-loading-text") || "Carregando...");
    },
    true
  );
})();
