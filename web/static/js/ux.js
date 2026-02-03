// UX helpers: prevent double submit and show loading state
(function () {
  function setLoading(btn, loadingText) {
    if (!btn) return;
    btn.dataset.originalHtml = btn.dataset.originalHtml || btn.innerHTML;
    btn.disabled = true;
    btn.classList.add("disabled");
    var text = loadingText || btn.getAttribute("data-loading-text") || "Carregando...";
    btn.innerHTML = '<span class="spinner-border spinner-border-sm me-2" role="status" aria-hidden="true"></span>' + text;
  }


  function shadowSubmitter(form, btn) {
    if (!form || !btn) return;
    var name = btn.getAttribute("name");
    if (!name) return;
    var value = btn.getAttribute("value") || "";
    // When a submit button is disabled before the request is sent,
    // browsers may omit its name/value. Shadow it into a hidden input.
    var sel = 'input[type="hidden"][data-submit-shadow="' + name.replace(/"/g, '\"') + '"]';
    var existing = form.querySelector(sel);
    if (!existing) {
      existing = document.createElement("input");
      existing.type = "hidden";
      existing.setAttribute("data-submit-shadow", name);
      form.appendChild(existing);
    }
    existing.name = name;
    existing.value = value;
  }

  document.addEventListener("submit", function (ev) {
    var form = ev.target;
    if (!(form instanceof HTMLFormElement)) return;

    // If the form opts out, do nothing
    if (form.hasAttribute("data-no-loading")) return;

    // Use the actual clicked submit button when available (fix for forms with multiple submit buttons)
    var submitter = ev.submitter || null;
    var btn = submitter && submitter.matches && submitter.matches("button[type='submit']") ? submitter : null;
    if (!btn) {
      // Fallback: first submit button
      btn = form.querySelector("button[type='submit'][data-loading], button[type='submit']");
    }
    if (btn) { shadowSubmitter(form, btn); setLoading(btn); }
  }, true);

  // Also handle links/buttons that do heavy GETs (optional)
  document.addEventListener("click", function (ev) {
    var el = ev.target.closest("[data-click-loading]");
    if (!el) return;
    if (el.tagName === "BUTTON") setLoading(el, el.getAttribute("data-loading-text") || "Carregando...");
  }, true);
})();
