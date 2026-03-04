// Accordion simples (mantém comportamento leve)
  (function(){
    const root = document.getElementById('accRoot');
    if(!root) return;

    root.addEventListener('click', (ev) => {
      const head = ev.target.closest('.sv-acc-head');
      if(!head) return;
      const item = head.closest('.sv-acc-item');
      if(!item) return;
      item.classList.toggle('is-open');
    });
  })();
