
(function(){
  function applyCollapsedState(collapsed){
    document.body.classList.toggle('sidebar-collapsed', !!collapsed);
  }

  function loadState(){
    try{
      return localStorage.getItem('sv_sidebar') === 'collapsed';
    }catch(e){ return false; }
  }

  function saveState(collapsed){
    try{
      localStorage.setItem('sv_sidebar', collapsed ? 'collapsed' : 'expanded');
    }catch(e){}
  }

  function toggle(){
    const collapsed = !document.body.classList.contains('sidebar-collapsed');
    applyCollapsedState(collapsed);
    saveState(collapsed);
  }

  document.addEventListener('DOMContentLoaded', function(){
    applyCollapsedState(loadState());

    const btnTop = document.getElementById('sidebarToggle');
    const btnSide = document.getElementById('sidebarToggleSidebar');
    if(btnTop) btnTop.addEventListener('click', toggle);
    if(btnSide) btnSide.addEventListener('click', toggle);
  });
})();
