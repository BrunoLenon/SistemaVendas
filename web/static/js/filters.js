
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

    root.addEventListener("change", (e) => {
      if (e.target && e.target.matches("[data-ms-check]")){
        updateHidden(root);
      }
    });

    const clearBtn = qs(root, "[data-ms-clear]");
    if (clearBtn){
      clearBtn.addEventListener("click", () => {
        qsa(root, "[data-ms-check]").forEach(i => i.checked = false);
        updateHidden(root);
      });
    }

    const search = qs(root, "[data-ms-search]");
    if (search){
      search.addEventListener("input", () => applySearch(root));
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
