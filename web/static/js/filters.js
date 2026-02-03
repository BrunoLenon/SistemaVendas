
(function () {
  function qs(root, sel) { return root.querySelector(sel); }
  function qsa(root, sel) { return Array.from(root.querySelectorAll(sel)); }

  function escapeHtml(s){
    return String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  }

  function updateHidden(root){
    const name = root.getAttribute("data-ms-name");
    const hiddenBox = root.querySelector("[data-ms-hidden]");
    if (!hiddenBox) return;

    hiddenBox.innerHTML = "";
    const checked = qsa(root, "[data-ms-check]:checked").map(i => i.value);

    checked.forEach(v => {
      const inp = document.createElement("input");
      inp.type = "hidden";
      inp.name = name;
      inp.value = v;
      hiddenBox.appendChild(inp);
    });

    // label
    const label = root.querySelector("[data-ms-label]");
    if (label){
      if (checked.length === 0){
        label.textContent = label.getAttribute("data-placeholder") || "Todas";
      } else if (checked.length === 1){
        label.textContent = checked[0];
      } else {
        label.textContent = checked.length + " selecionados";
      }
    }
  }

  function applySearch(root){
    const search = qs(root, "[data-ms-search]");
    if (!search) return;
    const q = (search.value || "").trim().toLowerCase();
    qsa(root, ".ms-option").forEach(opt => {
      const text = opt.textContent.trim().toLowerCase();
      opt.style.display = (!q || text.includes(q)) ? "" : "none";
    });
  }

  function init(root){
    const label = root.querySelector("[data-ms-label]");
    if (label && !label.getAttribute("data-placeholder")){
      // derive placeholder from initial text (first render)
      label.setAttribute("data-placeholder", label.textContent.trim() || "Todas");
    }

    // initial hidden build
    updateHidden(root);

    function refreshSelectAll(){
      const selAll = qs(root, "[data-ms-selectall]");
      if (!selAll) return;

      const checks = qsa(root, "[data-ms-check]");
      const visible = checks.filter(i => {
        const opt = i.closest(".ms-option");
        return opt && opt.style.display !== "none";
      });
      if (visible.length === 0){
        selAll.checked = false;
        selAll.indeterminate = false;
        return;
      }
      const checkedCount = visible.filter(i => i.checked).length;
      selAll.checked = (checkedCount === visible.length);
      selAll.indeterminate = (checkedCount > 0 && checkedCount < visible.length);
    }

    refreshSelectAll();

    root.addEventListener("change", (e) => {
      if (e.target && e.target.matches("[data-ms-check]")){
        updateHidden(root);
        refreshSelectAll();
      }
    });

    const selAll = qs(root, "[data-ms-selectall]");
    if (selAll){
      selAll.addEventListener("click", () => {
        const want = selAll.checked;
        // aplica somente aos itens visíveis (respeita busca)
        qsa(root, "[data-ms-check]").forEach(i => {
          const opt = i.closest(".ms-option");
          if (!opt || opt.style.display === "none") return;
          i.checked = want;
        });
        updateHidden(root);
        refreshSelectAll();
      });
    }

    const selNone = qs(root, "[data-ms-selectnone]");
    if (selNone){
      selNone.addEventListener("click", () => {
        qsa(root, "[data-ms-check]").forEach(i => i.checked = false);
        updateHidden(root);
        refreshSelectAll();
      });
    }

    const clearBtn = qs(root, "[data-ms-clear]");
    if (clearBtn){
      clearBtn.addEventListener("click", () => {
        qsa(root, "[data-ms-check]").forEach(i => i.checked = false);
        updateHidden(root);
      });
    }

    // Apply: close dropdown safely (without relying on data-bs-toggle inside menu)
    const applyBtn = qs(root, "[data-ms-apply]");
    if (applyBtn){
      applyBtn.addEventListener("click", () => {
        // Keep hidden inputs synced
        updateHidden(root);

        // Close the Bootstrap dropdown if available
        const trigger = qs(root, "[data-ms-button]");
        if (trigger && window.bootstrap && window.bootstrap.Dropdown){
          try {
            const inst = window.bootstrap.Dropdown.getOrCreateInstance(trigger);
            inst.hide();
          } catch (e) {
            // fail silently
          }
        }
      });
    }

    const search = qs(root, "[data-ms-search]");
    if (search){
      search.addEventListener("input", () => { applySearch(root); refreshSelectAll(); });
    }
  }

  document.addEventListener("DOMContentLoaded", () => {
    document.querySelectorAll("[data-ms-root]").forEach(init);

    // Ensure native multi hidden inputs are kept in sync before any form submit
    document.querySelectorAll("form").forEach(form => {
      form.addEventListener("submit", () => {
        document.querySelectorAll("[data-ms-root]").forEach(updateHidden);
      });
    });
  });
})();
