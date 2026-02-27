// "Marcar todas" para checklists
  (function(){
    function checkAll(name){
      var inputs = document.querySelectorAll('input[type="checkbox"][name="'+name+'"]');
      var anyUnchecked = false;
      inputs.forEach(function(i){ if(!i.checked) anyUnchecked = true; });
      inputs.forEach(function(i){ i.checked = anyUnchecked; });
    }
    document.querySelectorAll('[data-sv-checkall]').forEach(function(btn){
      btn.addEventListener('click', function(){
        checkAll(btn.getAttribute('data-sv-checkall'));
      });
    });
  })();

  // Expansão "modelo": abre uma linha abaixo (colspan) em largura total
  (function(){
    function closeAll(exceptId){
      document.querySelectorAll('tr.sv-detail-row').forEach(function(tr){
        if(exceptId && tr.id === exceptId) return;
        tr.style.display = 'none';
      });
      document.querySelectorAll('.js-toggle-camps').forEach(function(btn){
        var isTarget = exceptId && btn.dataset.target === exceptId;
        btn.classList.toggle('is-open', !!isTarget && document.getElementById(exceptId).style.display !== 'none');
        if(!isTarget){
          btn.classList.remove('is-open');
          btn.setAttribute('aria-expanded', 'false');
        }
      });
    }

    document.addEventListener('click', function(ev){
      var btn = ev.target.closest('.js-toggle-camps');
      if(!btn) return;

      var id = btn.dataset.target;
      var row = document.getElementById(id);
      if(!row) return;

      var open = row.style.display !== 'none';
      if(open){
        row.style.display = 'none';
        btn.classList.remove('is-open');
        btn.setAttribute('aria-expanded', 'false');
      }else{
        closeAll(id);
        row.style.display = '';
        btn.classList.add('is-open');
        btn.setAttribute('aria-expanded', 'true');
      }
    });
  })();
