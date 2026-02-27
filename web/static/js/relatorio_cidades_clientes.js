(() => {
  const cfg = (window.SV_CC_CONFIG || {});
  const getQS = () => {
    const u = new URL(window.location.href);
    return {
      mes: u.searchParams.get('mes') || cfg.mes || '',
      ano: u.searchParams.get('ano') || cfg.ano || '',
      vendedor: u.searchParams.get('vendedor') || cfg.vendedor_default || ''
    };
  };

  const escapeHtml = (s) => (s ?? '').toString()
    .replaceAll('&','&amp;')
    .replaceAll('<','&lt;')
    .replaceAll('>','&gt;')
    .replaceAll('"','&quot;')
    .replaceAll("'",'&#39;');

  const escapeAttr = (s) => escapeHtml(s).replaceAll('`','');

  // Modal (sem Bootstrap JS)
  const svShowModal = (el) => {
    if(!el) return;
    el.style.display = 'block';
    el.classList.add('show');
    el.setAttribute('aria-hidden','false');
    document.body.classList.add('sv-modal-open');

    let bd = document.getElementById('svModalBackdrop');
    if(!bd){
      bd = document.createElement('div');
      bd.id = 'svModalBackdrop';
      bd.className = 'modal-backdrop fade show';
      document.body.appendChild(bd);
      bd.addEventListener('click', () => svHideModal(el));
    }

    const onKey = (e) => { if(e.key === 'Escape') svHideModal(el); };
    el._svOnKey = onKey;
    document.addEventListener('keydown', onKey);
  };

  const svHideModal = (el) => {
    if(!el) return;
    el.classList.remove('show');
    el.style.display = 'none';
    el.setAttribute('aria-hidden','true');
    document.body.classList.remove('sv-modal-open');

    const bd = document.getElementById('svModalBackdrop');
    if(bd) bd.remove();

    if(el._svOnKey){
      document.removeEventListener('keydown', el._svOnKey);
      el._svOnKey = null;
    }
  };

  // Close buttons
  const bindCloseButtons = () => {
    document.querySelectorAll('[data-bs-dismiss="modal"]').forEach(btn => {
      btn.addEventListener('click', () => {
        const modal = btn.closest('.modal');
        if(modal) svHideModal(modal);
      });
    });
  };

  // Tabs
  const bindTabs = () => {
    const btns = document.querySelectorAll('.cc-segbtn');
    const tabC = document.getElementById('tab-cidades');
    const tabK = document.getElementById('tab-clientes');
    btns.forEach(b => b.addEventListener('click', () => {
      btns.forEach(x => x.classList.remove('active'));
      b.classList.add('active');
      const which = b.getAttribute('data-tab');
      if(which === 'clientes'){
        if(tabC) tabC.style.display = 'none';
        if(tabK) tabK.style.display = 'block';
      }else{
        if(tabK) tabK.style.display = 'none';
        if(tabC) tabC.style.display = 'block';
      }
    }));
  };

  // Accordion + actions (delegação)
  const bindPageActions = () => {
    document.addEventListener('click', (ev) => {
      const el = ev.target;

      // Toggle accordion head
      const head = el.closest('.cc-acc-head[data-action="toggle-acc"]');
      if(head){
        const target = head.getAttribute('data-target');
        const item = document.querySelector(`.cc-acc-item[data-emp="${CSS.escape(target)}"]`);
        if(item) item.classList.toggle('open');
        return;
      }

      // Toggle details
      const det = el.closest('[data-action="toggle-details"]');
      if(det){
        ev.preventDefault();
        const emp = det.getAttribute('data-emp');
        const box = document.getElementById('cc-details-' + emp);
        if(box){
          box.style.display = (box.style.display === 'none' || !box.style.display) ? 'block' : 'none';
        }
        return;
      }

      // Open clientes (click in city row)
      const rowCity = el.closest('tr[data-action="open-clientes"]');
      if(rowCity){
        const emp = rowCity.getAttribute('data-emp');
        const cidadeNorm = rowCity.getAttribute('data-cidade-norm');
        const cidadeLabel = rowCity.getAttribute('data-cidade-label');
        openClientesModal(emp, cidadeNorm, cidadeLabel);
        return;
      }

      // Open marcas from Clientes TAB row
      const rowCliTab = el.closest('tr[data-action="open-marcas"]');
      if(rowCliTab){
        const emp = rowCliTab.getAttribute('data-emp');
        const cidadeNorm = rowCliTab.getAttribute('data-cidade-norm') || '';
        const razaoNorm = rowCliTab.getAttribute('data-razao-norm') || '';
        const clienteId = rowCliTab.getAttribute('data-cliente-id') || '';
        const clienteLabel = rowCliTab.getAttribute('data-cliente-label') || '';
        openMarcasModal(emp, cidadeNorm, razaoNorm, clienteId, clienteLabel);
        return;
      }

      // Open marcas (link inside modal clientes)
      const aMarcas = el.closest('a[data-action="open-marcas"]');
      if(aMarcas){
        ev.preventDefault();
        const emp = aMarcas.getAttribute('data-emp');
        const cidadeNorm = aMarcas.getAttribute('data-cidade-norm') || '';
        const razaoNorm = aMarcas.getAttribute('data-razao-norm') || '';
        const clienteId = aMarcas.getAttribute('data-cliente-id') || '';
        const clienteLabel = aMarcas.getAttribute('data-cliente-label') || '';
        openMarcasModal(emp, cidadeNorm, razaoNorm, clienteId, clienteLabel);
        return;
      }

      // Open itens (row inside modal marcas)
      const rowMarca = el.closest('tr[data-action="open-itens"]');
      if(rowMarca){
        const emp = rowMarca.getAttribute('data-emp');
        const cidadeNorm = rowMarca.getAttribute('data-cidade-norm') || '';
        const razaoNorm = rowMarca.getAttribute('data-razao-norm') || '';
        const clienteId = rowMarca.getAttribute('data-cliente-id') || '';
        const clienteLabel = rowMarca.getAttribute('data-cliente-label') || '';
        const marca = rowMarca.getAttribute('data-marca') || '';
        openItensMarcaModal(emp, cidadeNorm, razaoNorm, clienteId, clienteLabel, marca);
        return;
      }
    });
  };

  // ========= Modais / Fetch =========

  const modalClientes = document.getElementById('modalClientes');
  const modalMarcas = document.getElementById('modalMarcas');
  const modalItensMarca = document.getElementById('modalItensMarca');

  const openClientesModal = (emp, cidade_norm, cidade_label) => {
    if(!modalClientes) return;
    const q = getQS();

    const title = document.getElementById('modalClientesTitle');
    const sub = document.getElementById('modalClientesSub');
    if(title) title.textContent = 'Clientes — EMP ' + emp;
    if(sub) sub.textContent = 'Cidade: ' + (cidade_label || cidade_norm);

    const tbody = document.querySelector('#tblClientes tbody');
    if(tbody) tbody.innerHTML = '<tr><td colspan="6" class="sv-muted">Carregando…</td></tr>';

    const url = `/relatorios/cidade-clientes?emp=${encodeURIComponent(emp)}&cidade_norm=${encodeURIComponent(cidade_norm)}&mes=${encodeURIComponent(q.mes)}&ano=${encodeURIComponent(q.ano)}&vendedor=${encodeURIComponent(q.vendedor || '')}`;

    fetch(url)
      .then(r => r.json())
      .then(data => {
        const rows = (data && data.clientes) ? data.clientes : [];
        if(!tbody) return;
        if(!rows.length){
          tbody.innerHTML = '<tr><td colspan="6" class="sv-muted">Sem dados.</td></tr>';
          return;
        }

        tbody.innerHTML = rows.map((r, idx) => {
          const valor = (r.valor_total || 0).toLocaleString('pt-BR', {style:'currency', currency:'BRL'});
          const qtd = (r.qtd_total || 0).toLocaleString('pt-BR');
          const mix = (r.mix_itens || 0).toLocaleString('pt-BR');
          const cliente = (r.cliente || r.cliente_id || '').toString();
          const cliente_id = (r.cliente_id || '').toString();

          return `
            <tr>
              <td class="sv-right">${idx+1}</td>
              <td class="text-nowrap">${escapeHtml(cliente)}</td>
              <td class="text-end sv-right">${escapeHtml(valor)}</td>
              <td class="text-end sv-right">${escapeHtml(qtd)}</td>
              <td class="text-end sv-right">${escapeHtml(mix)}</td>
              <td class="text-end">
                <a class="sv-link"
                   href="#"
                   data-action="open-marcas"
                   data-emp="${escapeAttr(emp)}"
                   data-cidade-norm="${escapeAttr(cidade_norm)}"
                   data-razao-norm=""
                   data-cliente-id="${escapeAttr(cliente_id)}"
                   data-cliente-label="${escapeAttr(cliente)}">Ver marcas</a>
              </td>
            </tr>
          `;
        }).join('');
      })
      .catch(() => {
        if(tbody) tbody.innerHTML = '<tr><td colspan="6" class="sv-muted">Erro ao carregar.</td></tr>';
      });

    svShowModal(modalClientes);
  };

  const openMarcasModal = (emp, cidade_norm, razao_norm, cliente_id, cliente_label) => {
    if(!modalMarcas) return;
    const q = getQS();

    const title = document.getElementById('modalMarcasTitle');
    const sub = document.getElementById('modalMarcasSub');
    if(title) title.textContent = 'Marcas — EMP ' + emp;
    if(sub) sub.textContent = 'Cliente: ' + (cliente_label || cliente_id);

    const tbody = document.querySelector('#tblMarcas tbody');
    if(tbody) tbody.innerHTML = '<tr><td colspan="5" class="sv-muted">Carregando…</td></tr>';

    const params = new URLSearchParams({
      emp: emp,
      mes: q.mes,
      ano: q.ano,
      vendedor: q.vendedor || ''
    });
    if(razao_norm) params.set('razao_norm', razao_norm);
    else if(cliente_id) params.set('cliente_id', cliente_id);
    if(cidade_norm) params.set('cidade_norm', cidade_norm);

    fetch('/relatorios/cliente-marcas?' + params.toString())
      .then(r => r.json())
      .then(data => {
        const rows = (data && data.marcas) ? data.marcas : [];
        if(!tbody) return;
        if(!rows.length){
          tbody.innerHTML = '<tr><td colspan="5" class="sv-muted">Sem dados.</td></tr>';
          return;
        }

        tbody.innerHTML = rows.map((r, idx) => {
          const valor = (r.valor_total || 0).toLocaleString('pt-BR', {style:'currency', currency:'BRL'});
          const qtd = (r.qtd_total || 0).toLocaleString('pt-BR'); // pode vir ausente em versões antigas
          const mix = (r.mix_itens || 0).toLocaleString('pt-BR');
          const marca = (r.marca || '').toString();

          return `
            <tr class="cc-click"
                data-action="open-itens"
                data-emp="${escapeAttr(emp)}"
                data-cidade-norm="${escapeAttr(cidade_norm || '')}"
                data-razao-norm="${escapeAttr(razao_norm || '')}"
                data-cliente-id="${escapeAttr(cliente_id || '')}"
                data-cliente-label="${escapeAttr(cliente_label || cliente_id || '')}"
                data-marca="${escapeAttr(marca)}">
              <td class="sv-right">${idx+1}</td>
              <td class="text-nowrap">${escapeHtml(marca)}</td>
              <td class="text-end sv-right">${escapeHtml(valor)}</td>
              <td class="text-end sv-right">${escapeHtml(qtd)}</td>
              <td class="text-end sv-right">${escapeHtml(mix)}</td>
            </tr>
          `;
        }).join('');
      })
      .catch(() => {
        if(tbody) tbody.innerHTML = '<tr><td colspan="5" class="sv-muted">Erro ao carregar.</td></tr>';
      });

    svShowModal(modalMarcas);
  };

  const openItensMarcaModal = (emp, cidade_norm, razao_norm, cliente_id, cliente_label, marca) => {
    if(!modalItensMarca) return;
    const q = getQS();

    const title = document.getElementById('modalItensMarcaTitle');
    const sub = document.getElementById('modalItensMarcaSub');
    if(title) title.textContent = 'Itens — ' + (marca || 'SEM MARCA') + ' • EMP ' + emp;
    if(sub) sub.textContent = 'Cliente: ' + (cliente_label || cliente_id);

    const tbody = document.querySelector('#tblItensMarca tbody');
    if(tbody) tbody.innerHTML = '<tr><td colspan="5" class="sv-muted">Carregando…</td></tr>';

    const params = new URLSearchParams({
      emp: emp,
      mes: q.mes,
      ano: q.ano,
      vendedor: q.vendedor || '',
      marca: marca || ''
    });
    if(razao_norm) params.set('razao_norm', razao_norm);
    if(cliente_id) params.set('cliente_id', cliente_id);
    if(cidade_norm) params.set('cidade_norm', cidade_norm);

    fetch('/relatorios/cliente-marca-itens?' + params.toString())
      .then(r => r.json())
      .then(data => {
        const rows = (data && data.itens) ? data.itens : [];
        if(!tbody) return;
        if(!rows.length){
          tbody.innerHTML = '<tr><td colspan="5" class="sv-muted">Sem dados.</td></tr>';
          return;
        }

        tbody.innerHTML = rows.map((r, idx) => {
          const cod = (r.mestre || '').toString();
          const des = (r.descricao || '').toString();
          const qtd = (r.qtd_total || 0).toLocaleString('pt-BR');
          const valor = (r.valor_total || 0).toLocaleString('pt-BR', {style:'currency', currency:'BRL'});
          return `
            <tr>
              <td class="sv-right">${idx+1}</td>
              <td class="text-nowrap">${escapeHtml(cod)}</td>
              <td>${escapeHtml(des)}</td>
              <td class="text-end sv-right">${escapeHtml(qtd)}</td>
              <td class="text-end sv-right">${escapeHtml(valor)}</td>
            </tr>
          `;
        }).join('');
      })
      .catch(() => {
        if(tbody) tbody.innerHTML = '<tr><td colspan="5" class="sv-muted">Erro ao carregar.</td></tr>';
      });

    svShowModal(modalItensMarca);
  };

  // Init
  const init = () => {
    bindCloseButtons();
    bindTabs();
    bindPageActions();
  };

  if(document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
  else init();
})();
