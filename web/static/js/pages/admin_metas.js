// Admin Metas page helpers:
// - Escada builder (table UI -> hidden textarea "escalas")
// - EMP search filter

(function () {
  function byId(id) { return document.getElementById(id); }

  // --------------------
  // EMP search
  // --------------------
  const empSearch = byId('empSearch');
  const empList = byId('empList');

  if (empSearch && empList) {
    const items = Array.from(empList.querySelectorAll('input[data-emp-search]'));

    function applyEmpFilter() {
      const q = (empSearch.value || '').trim().toLowerCase();
      items.forEach((inp) => {
        const hay = inp.getAttribute('data-emp-search') || '';
        const show = !q || hay.includes(q);
        const row = inp.closest('.form-check');
        if (row) row.style.display = show ? '' : 'none';
      });
    }

    empSearch.addEventListener('input', applyEmpFilter);
  }

  // --------------------
  // Escada builder
  // --------------------
  const table = byId('escadas_table');
  const tbody = table ? table.querySelector('tbody') : null;
  const hidden = byId('escalas_text');
  const btnAdd = byId('escada_add');
  const btnEx = byId('escada_exemplo');

  if (!tbody || !hidden) return;

  function normalizeNumberBR(v) {
    // accepts "10", "10.5", "10,5" => "10,5" (keeps comma)
    const s = String(v ?? '').trim();
    if (!s) return '';
    return s.replace(/\./g, ',');
  }

  function serialize() {
    const rows = Array.from(tbody.querySelectorAll('tr'));
    const lines = rows
      .map((tr) => {
        const lim = tr.querySelector('input[data-field="limite"]')?.value?.trim() || '';
        const bon = tr.querySelector('input[data-field="bonus"]')?.value?.trim() || '';
        if (!lim || !bon) return null;
        // backend expects: limite:bonus (bonus can be comma or dot; keep as typed)
        return `${normalizeNumberBR(lim)}:${normalizeNumberBR(bon)}`;
      })
      .filter(Boolean);

    hidden.value = lines.join('\n');
  }

  function addRow(limite = '', bonus = '') {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td>
        <input class="form-control form-control-sm sv-input" data-field="limite" placeholder="Ex.: 5" value="${String(limite).replace(/"/g, '&quot;')}">
      </td>
      <td>
        <div class="input-group input-group-sm">
          <input class="form-control sv-input" data-field="bonus" placeholder="Ex.: 0,10" value="${String(bonus).replace(/"/g, '&quot;')}">
          <span class="input-group-text sv-input">%</span>
        </div>
      </td>
      <td class="text-end">
        <button type="button" class="btn btn-sm btn-outline-danger" data-action="rm">Remover</button>
      </td>
    `;

    tbody.appendChild(tr);

    tr.querySelectorAll('input').forEach((inp) => {
      inp.addEventListener('input', serialize);
      inp.addEventListener('change', serialize);
    });

    tr.querySelector('[data-action="rm"]').addEventListener('click', () => {
      tr.remove();
      serialize();
    });

    serialize();
  }

  if (btnAdd) {
    btnAdd.addEventListener('click', () => addRow('', ''));
  }

  if (btnEx) {
    btnEx.addEventListener('click', () => {
      if (tbody.querySelectorAll('tr').length > 0) return;
      addRow('5', '0,10');
      addRow('10', '0,20');
      addRow('20', '0,30');
    });
  }

  // If user submitted without adding rows, block submit
  const form = hidden.closest('form');
  if (form) {
    form.addEventListener('submit', (ev) => {
      serialize();
      if (!hidden.value || hidden.value.trim().length === 0) {
        ev.preventDefault();
        alert('Preencha ao menos uma faixa na escada (Limite e Bônus).');
      }
    });
  }
})();
