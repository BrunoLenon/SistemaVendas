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

  document.addEventListener("submit", function (ev) {
    var form = ev.target;
    if (!(form instanceof HTMLFormElement)) return;

    // If the form opts out, do nothing
    if (form.hasAttribute("data-no-loading")) return;

    // Prefer a button explicitly marked as submit
    var btn = form.querySelector("button[type='submit'][data-loading], button[type='submit']");
    if (btn) setLoading(btn);
  }, true);

  // Also handle links/buttons that do heavy GETs (optional)
  document.addEventListener("click", function (ev) {
    var el = ev.target.closest("[data-click-loading]");
    if (!el) return;
    if (el.tagName === "BUTTON") setLoading(el, el.getAttribute("data-loading-text") || "Carregando...");
  }, true);
})();
