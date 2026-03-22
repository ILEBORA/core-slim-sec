__BORA_REGISTER_PLUGIN__('BoraAlertsV2', async function(scope){

  const jquery = await scope.getService('jquery');
  const events = await scope.getService('events');

  /* =========================
     PRIVATE STATE
  ========================= */

  let modal = null;
  let overlay = null;
  let okButton = null;
  let cancelButton = null;
  let activeElement = null;
  let notifierContainer = null;
  let notifiers = [];
  let __autoTimer = null;
  let __loading = false;

  const defaults = {
    container: 'body',
    html: false,
    noButtons: false,
    showCancelButton: false,
    style: '',
    okText: 'OK',
    cancelText: 'Cancel',
    overlayTpl: '<div class="bora-overlay"></div>',
    modalTpl:
      '<form class="bora-alert bora-alert-v2">' +
        '<div class="bora-message"></div>' +
        '<div class="bora-prompt"></div>' +
        '<div class="bora-buttons"></div>' +
      '</form>',
    promptTpl: '<input class="bora-input" type="text" name="value">',
    notifierDelay: 3,
    notifierPosition: 'bottom-right',
    notifierAutoDismiss: true,
    notifierAnimate: 'fade',
    notifierContainerTpl: '<div class="bora-notifier bora-pos-bottom-right"></div>',
    showModal: function(){ $(this.modal).add(this.overlay).fadeIn(150); },
    hideModal: function(){ $(this.modal).add(this.overlay).fadeOut(150); },
    labels: { ok: 'OK', cancel: 'Cancel', loading: 'Loading...' }
  };

  /* =========================
     NOTIFIER
  ========================= */

  function ensureNotifierContainer(force){
    const posClass = 'bora-pos-' + defaults.notifierPosition.replace(/\s+/g,'-');

    if (notifierContainer && !force) return notifierContainer;

    if (notifierContainer) notifierContainer.remove();

    notifierContainer = $(defaults.notifierContainerTpl);
    notifierContainer
      .removeClass(function(i,c){
        return (c.match(/(^|\s)bora-pos-\S+/g)||[]).join(' ');
      })
      .addClass(posClass);

    $('body').append(notifierContainer);
    return notifierContainer;
  }

  function dismissToast($toast){
    if(!$toast || !$toast.length) return;

    if(defaults.notifierAnimate === 'slide'){
      $toast.slideUp(150, ()=> $toast.remove());
    }else{
      $toast.fadeOut(150, ()=> $toast.remove());
    }
  }

  function notify(message, type='info', delay){
    ensureNotifierContainer();
    delay = (delay === undefined) ? defaults.notifierDelay : delay;

    const toast = $('<div class="bora-toast bora-'+type+' bora-toast-v2"></div>');
    toast.html(message);
    notifierContainer.append(toast);

    toast.hide().fadeIn(180);

    toast.on('click', ()=> dismissToast(toast));

    if(defaults.notifierAutoDismiss && delay>0){
      setTimeout(()=> dismissToast(toast), delay*1000);
    }

    notifiers.push(toast);

    events && events.emit && events.emit('alerts:notify', {message,type});

    return { dismiss: ()=> dismissToast(toast) };
  }

  /* =========================
     MODAL CORE
  ========================= */

  function show(type, message, options={}){

    const defer = $.Deferred();
    const settings = $.extend(true, {}, defaults, options);
    let values = [];

    $(modal).add(overlay).remove();

    activeElement = document.activeElement;
    if(activeElement) activeElement.blur();

    overlay = $(settings.overlayTpl).hide();
    modal = $(settings.modalTpl).hide();

    if(settings.style) modal.addClass(settings.style);

    const msgElem = modal.find('.bora-message');
    settings.html ? msgElem.html(message) : msgElem.text(message);

    if(type==='prompt'){
      modal.find('.bora-prompt')
        .html(options.prompt!==undefined ? options.prompt : settings.promptTpl);
    }

    const buttons = modal.find('.bora-buttons');
    const labels = settings.labels;

    cancelButton = $('<button type="button" class="bora-cancel bora-btn-cancel">')
      .html(options.cancelText || labels.cancel);

    okButton = $('<button type="submit" class="bora-ok bora-btn-ok">')
      .html(options.okText || labels.ok);

    const spinner = $(
      '<span class="bora-loading-inline" style="display:none;">'+
      '<span class="bora-spinner"></span> '+
      '<span class="bora-loading-text">'+labels.loading+'</span>'+
      '</span>'
    );
    okButton.append(spinner);

    if(!settings.noButtons){
      if(type!=='alert') buttons.append(cancelButton);
      buttons.append(okButton);
    }

    $(settings.container).append(overlay).append(modal);
    settings.showModal.call({modal,overlay});

    modal.on('submit.BoraAlertsV2', function(e){
      e.preventDefault();
      if(type==='prompt'){
        modal.serializeArray().forEach(item=>{
          values[item.name]=item.value;
        });
      }else{
        values=null;
      }
      defer.resolve(values);
      hide();
    });

    cancelButton.on('click.BoraAlertsV2', function(){
      hide();
      defer.reject();
    });

    const promise = defer.promise();

    promise.loading = function(on){
      loading(on);
      return promise;
    };

    promise.autoOk = function(sec){
      autoAction('ok',sec);
      return promise;
    };

    promise.autoCancel = function(sec){
      autoAction('cancel',sec);
      return promise;
    };

    return promise;
  }

  function hide(){
    if(!modal) return;
    defaults.hideModal.call({modal,overlay});
    $(document).off('.BoraAlertsV2');
    modal.remove();
    overlay.remove();
    modal=null; overlay=null;
    if(__autoTimer){ clearInterval(__autoTimer); __autoTimer=null; }
    if(activeElement) activeElement.focus();
  }

  /* =========================
     LOADING / AUTO
  ========================= */

  function loading(on){
    if(!okButton) return;
    const spinner = okButton.find('.bora-loading-inline');
    if(on===undefined) on=!__loading;
    __loading=on;
    okButton.prop('disabled',on);
    cancelButton && cancelButton.prop('disabled',on);
    spinner.toggle(on);
  }

  function autoAction(which,seconds){
    if(!seconds || seconds<=0) return;
    let sec=seconds;

    if(__autoTimer){ clearInterval(__autoTimer); }

    const btn = (which==='ok')? okButton : cancelButton;
    const base = btn.text();
    const cd = $('<span class="bora-countdown"> ('+sec+')</span>');
    btn.append(cd);

    __autoTimer=setInterval(()=>{
      sec--;
      if(sec<=0){
        clearInterval(__autoTimer);
        if(which==='ok' && modal) modal.trigger('submit');
        else hide();
      }else{
        cd.text(' ('+sec+')');
      }
    },1000);
  }

  function notifyRich(options = {}) {
    alert('this');
  }

  /* =========================
     PUBLIC API
  ========================= */

  const API = {
    notify,
    notifyRich,
    success:(m,d)=>notify(m,'success',d),
    error:(m,d)=>notify(m,'error',d),
    warning:(m,d)=>notify(m,'warning',d),
    info:(m,d)=>notify(m,'info',d),
    show,
    alert:(m,o)=>show('alert',m,o),
    confirm:(m,o)=>show('confirm',m,o),
    prompt:(m,o)=>show('prompt',m,o),
    hide,
    set:function(k,v){
      if(typeof k==='object') Object.assign(defaults,k);
      else defaults[k]=v;
      return API;
    },
    setLabels:function(obj){
      defaults.labels=Object.assign({},defaults.labels,obj);
      return API;
    }
  };

  return API;
});