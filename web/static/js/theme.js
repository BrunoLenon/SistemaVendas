
(function () {
  const root = document.documentElement;

  function getTheme() {
    try { return localStorage.getItem("theme") || "light"; } catch(e) { return "light"; }
  }

  function setTheme(theme) {
    root.setAttribute("data-theme", theme);
    try { localStorage.setItem("theme", theme); } catch(e) {}
    updateIcon(theme);
  }

  function updateIcon(theme) {
    const btn = document.getElementById("theme-toggle");
    if (!btn) return;
    btn.textContent = theme === "dark" ? "☀️" : "🌙";
  }

  window.toggleTheme = function () {
    const current = root.getAttribute("data-theme") || getTheme();
    const next = current === "dark" ? "light" : "dark";
    setTheme(next);
  };

  // init
  const initial = root.getAttribute("data-theme") || getTheme();
  setTheme(initial);
})();
