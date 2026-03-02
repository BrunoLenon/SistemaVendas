window.MetaV2 = (function(){
  function mkRow(prefix){
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td><input class="sv-input sv-input-sm" name="${prefix}_limite[]" value=""></td>
      <td><input class="sv-input sv-input-sm" name="${prefix}_recompensa[]" value=""></td>
      <td><button type="button" class="sv-btn sv-btn-danger sv-btn-xs">×</button></td>
    `;
    tr.querySelector('button').addEventListener('click', function(){ delRow(this); });
    return tr;
  }

  function addFaixa(prefix){
    const tbody = document.querySelector(`#tbl_${prefix} tbody`);
    if(!tbody) return;
    tbody.appendChild(mkRow(prefix));
  }

  function delRow(btn){
    const tr = btn.closest('tr');
    if(tr) tr.remove();
  }

  return { addFaixa, delRow };
})();
