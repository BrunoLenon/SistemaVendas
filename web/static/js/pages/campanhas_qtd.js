// Página /campanhas (Campanhas Qtd)
// JS isolado para evitar conflitos globais.
(function () {
  function init() {
    const root = document.getElementById('accRoot');
    if (!root) return;

    // Accordion simples (mantém comportamento leve)
    root.addEventListener('click', (ev) => {
      const head = ev.target.closest('.sv-acc-head');
      if (!head) return;
      const item = head.closest('.sv-acc-item');
      if (!item) return;
      item.classList.toggle('is-open');
    });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
