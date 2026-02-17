// BoraAlerts.v2.js
// BoraAlerts v2 (side-by-side): spinner, autoOk/autoCancel, i18n labels
// Dominic Karau @ ILEBORA Technologies

// register plugin as separate module so it doesn't override your v1
var BoraAlertsV2 = addPlugin('BoraAlertsV2', {
  pluginName: 'BoraAlertsV2',
  modal: null,
  overlay: null,
  okButton: null,
  cancelButton: null,
  activeElement: null,
  notifierContainer: null,
  notifiers: [],
  // timers for auto actions / loading
  __autoTimer: null,
  __loading: false,
  defaults: {
    // Modal
    container: 'body',
    html: false,
    noButtons: false,
    style: '',
    okText: 'OK',
    cancelText: 'Cancel',
    overlayTpl: '<div class="bora-overlay"></div>',
    modalTpl:
      '<form class="bora-alert bora-alert-v2" enctype="multipart/form-data">' +
        '<div class="bora-message"></div>' +
        '<div class="bora-prompt"></div>' +
        '<div class="bora-buttons"></div>' +
      '</form>',
    promptTpl: '<input class="bora-input" type="text" name="value">',

    // notifier
    notifierDelay: 3,
    notifierPosition: 'bottom-right',
    notifierAutoDismiss: true,
    notifierAnimate: 'fade',
    notifierContainerTpl: '<div class="bora-notifier bora-pos-bottom-right animated bounceIn"></div>',

    // animations / hooks
    showModal: function() { $(this.modal).add(this.overlay).fadeIn(150); },
    hideModal: function() { $(this.modal).add(this.overlay).fadeOut(150); },

    // i18n-ish labels (used as fallback)
    labels: { ok: 'OK', cancel: 'Cancel', loading: 'Loading...' }
  },

  init() {
    // nothing heavy on init; container created lazily.
    // console.log('BoraAlertsV2 ready');
  }
});

BoraAlertsV2.addMethods({
  // simple setter/getter for defaults & labels
  set(keyOrObj, val) {
    if (typeof keyOrObj === 'object') {
      Object.assign(this.defaults, keyOrObj);
    } else {
      this.defaults[keyOrObj] = val;
    }
    // update notifier container if position changed
    if (keyOrObj === 'notifierPosition' || (typeof keyOrObj === 'object' && keyOrObj.notifierPosition)) {
      this._ensureNotifierContainer(true);
    }
    return this;
  },

  // i18n convenience
  setLabels(labels) {
    this.defaults.labels = Object.assign({}, this.defaults.labels, labels);
    return this;
  },

  // INTERNAL: ensure notifier container exists and has correct pos class
  _ensureNotifierContainer(forceRecreate) {
    var d = this.defaults;
    var posClass = 'bora-pos-' + (d.notifierPosition || 'bottom-right').replace(/\s+/g, '-');
    if (this.notifierContainer && !forceRecreate) return this.notifierContainer;
    if (this.notifierContainer) {
      this.notifierContainer.remove();
      this.notifierContainer = null;
    }
    var tpl = d.notifierContainerTpl || '<div class="bora-notifier"></div>';
    this.notifierContainer = $(tpl);
    this.notifierContainer
      .removeClass (function (i, c) {
        return (c.match (/(^|\s)bora-pos-\S+/g) || []).join(' ');
      })
      .addClass(posClass);
    $('body').append(this.notifierContainer);
    return this.notifierContainer;
  },

  // ====== NOTIFIER ======
  notify(message, type = 'info', delay) {
    var self = this, d = this.defaults;
    this._ensureNotifierContainer();
    delay = (typeof delay === 'undefined') ? d.notifierDelay : delay;

    var toast = $('<div class="bora-toast bora-' + type + ' bora-toast-v2"></div>');
    toast.html(message);

    this.notifierContainer.append(toast);

    if (d.notifierAnimate === 'slide') {
      toast.hide().slideDown(180);
    } else {
      toast.hide().fadeIn(180);
    }

    toast.on('click', function () {
      self._dismissToast($(this));
    });

    if (d.notifierAutoDismiss && delay > 0) {
      var t = setTimeout(function () {
        self._dismissToast(toast);
      }, delay * 1000);
      toast.data('timer', t);
    }

    this.notifiers.push(toast);

    return {
      dismiss: function () { self._dismissToast(toast); }
    };
  },

  _dismissToast($toast) {
    if (!$toast || !$toast.length) return;
    var timer = $toast.data('timer');
    if (timer) clearTimeout(timer);
    if (this.defaults.notifierAnimate === 'slide') {
      $toast.slideUp(150, function() { $toast.remove(); });
    } else {
      $toast.fadeOut(150, function() { $toast.remove(); });
    }
  },

  success(msg, delay) { return this.notify(msg, 'success', delay); },
  error(msg, delay)   { return this.notify(msg, 'error', delay); },
  warning(msg, delay) { return this.notify(msg, 'warning', delay); },
  info(msg, delay)    { return this.notify(msg, 'info', delay); },

  // ====== MODAL (alert/confirm/prompt) ======
  show(type, message, options = {}) {
    var defer = $.Deferred();
    var settings = $.extend({}, this.defaults, options);
    var values = [];

    // Remove previous
    $(this.modal).add(this.overlay).remove();

    // Save active element
    this.activeElement = document.activeElement;
    if (this.activeElement) this.activeElement.blur();

    // Create DOM
    this.overlay = $(settings.overlayTpl).hide();
    this.modal = $(settings.modalTpl).hide();

    if (settings.style) this.modal.addClass(settings.style);

    // message area: allow string or HTMLEL
    var msgElem = this.modal.find('.bora-message');
    if (settings.html) msgElem.html(message);
    else msgElem.text(message);

    // prompt area - allow passing `options.prompt` (HTML) or fallback to promptTpl
    if (type === 'prompt') {
      if (options.prompt !== undefined) {
        this.modal.find('.bora-prompt').html(options.prompt);
      } else {
        this.modal.find('.bora-prompt').html(settings.promptTpl);
      }
    } else {
      this.modal.find('.bora-prompt').empty();
    }

    // Buttons
    var buttons = this.modal.find('.bora-buttons');
    var labels = settings.labels || this.defaults.labels;
    this.cancelButton = $('<button type="button" class="bora-cancel bora-btn-cancel">')
        .html(options.cancelText || settings.cancelText || labels.cancel);
    this.okButton = $('<button type="submit" class="bora-ok bora-btn-ok">')
        .html(options.okText || settings.okText || labels.ok);

    // attach spinner container to ok button (hidden by default)
    var spinner = $(
      '<span class="bora-loading-inline" aria-hidden="true" style="display:none;">' +
        '<span class="bora-spinner"></span> <span class="bora-loading-text">' + (labels.loading || 'Loading...') + '</span>' +
      '</span>'
    );
    this.okButton.append(spinner);

    if(!settings.noButtons){
      if (type !== 'alert') buttons.append(this.cancelButton);
      buttons.append(this.okButton);
    }
    // Append
    $(settings.container).append(this.overlay).append(this.modal);
    // Show
    settings.showModal.call({ modal: this.modal, overlay: this.overlay });

    // center if plugin exists
    if ($.fn.center) this.modal.center();

    // Submit = OK
    this.okButton.on('click.BoraAlertsV2', (e) => {
    //this.modal.on('submit.BoraAlertsV2', (e) => {
      // 🔥 If the form has data-bora-skip, do NOT hijack submit
      if ($(e.target).is('[data-bora-skip]')) return; 

      e.preventDefault();
      if (type === 'prompt') {
        var data = this.modal.serializeArray();
        data.forEach(function (item) {
          values[item.name] = item.value;
        });
      } else {
        values = null;
      }
      this.hide(settings);
      defer.resolve(values);
    });

    // Cancel
    this.cancelButton.on('click.BoraAlertsV2', () => {
      this.hide(settings);
      defer.reject();
    });

    // Escape key
    $(document).on('keydown.BoraAlertsV2', (e) => {
      if (e.keyCode === 27) {
        e.preventDefault();
        this.hide(settings);
        defer.reject();
      }
    });

    // Focus trap
    $(document).on('focus.BoraAlertsV2', '*', (e) => {
      if (!$(e.target).closest('.bora-alert').length) {
        e.stopPropagation();
        $(this.modal).find(':input:first').focus();
      }
    });

    // Default focus
    if (type === 'prompt') {
      this.modal.find('.bora-input:first').focus();
    } else {
      // focus OK button (but after spinner appended we ensure it's focusable)
      this.okButton.focus();
    }

    // Provide control methods on the returned promise object
    var self = this;
    var promise = defer.promise();
    // inject helpers directly on promise
    promise.loading = function(on) {
      self.loading(on);
      return promise;
    };
    promise.autoOk = function(sec) {
      self.autoOk(sec, promise);
      return promise;
    };
    promise.autoCancel = function(sec) {
      self.autoCancel(sec, promise);
      return promise;
    };

    return promise;
  },

  update(newHtml, opts = {}) {
    // If modal isn't open, don't explode
    if (!this.modal) return this;

    const msg     = this.modal.find('.bora-message');
    const prompt  = this.modal.find('.bora-prompt');
    const buttons = this.modal.find('.bora-buttons');

    // Choose where to render (full replace, prompt-only, or message-only)
    if (opts.target === 'prompt') {
      prompt.html(newHtml);
    } 
    else if (opts.target === 'message') {
      msg.html(newHtml);
    } 
    else if (opts.target === 'buttons' && !opts.noButtons) {
      buttons.html(newHtml);
    } 
    else {
      // Full content swap (most common case)
      msg.empty();
      prompt.empty();
      msg.html(newHtml);
    }

    // Re-center if needed
    if ($.fn.center) this.modal.center();
    return this;
  },

  hide(options) {
    var settings = $.extend({}, this.defaults, options);
    settings.hideModal.call({ modal: this.modal, overlay: this.overlay });
    $(document).off('.BoraAlertsV2');
    if (this.modal) this.modal.off('.BoraAlertsV2');
    if (this.cancelButton) this.cancelButton.off('.BoraAlertsV2');
    // clear any auto timers
    if (this.__autoTimer) {
      clearInterval(this.__autoTimer);
      this.__autoTimer = null;
    }
    // restore focus
    if (this.activeElement) this.activeElement.focus();
    // remove modal elements references
    this.modal = null;
    this.overlay = null;
    this.okButton = null;
    this.cancelButton = null;
    this.__loading = false;
  },

  alert(message, options) { return this.show('alert', message, options); },
  confirm(message, options) { return this.show('confirm', message, options); },
  prompt(message, options)  { return this.show('prompt', message, options); },

  // ===== Loading indicator helpers =====
  // Toggle loading state on OK button. `on` boolean or toggle when ommitted.
  loading(on) {
    // if no modal open, no-op
    if (!this.okButton) return;
    var labels = (this.defaults && this.defaults.labels) || {};
    var spinnerElem = this.okButton.find('.bora-loading-inline');

    if (typeof on === 'undefined') on = !this.__loading;
    if (on) {
      this.__loading = true;
      // disable both buttons
      this.okButton.prop('disabled', true);
      if (this.cancelButton) this.cancelButton.prop('disabled', true);
      spinnerElem.show();
      // optionally change ok text (we keep text + spinner)
    } else {
      this.__loading = false;
      this.okButton.prop('disabled', false);
      if (this.cancelButton) this.cancelButton.prop('disabled', false);
      spinnerElem.hide();
    }
    return this;
  },

  // ===== autoOk / autoCancel with countdown in button label =====
  autoOk(seconds, promiseObject) {
    if (!this.okButton) return;
    this._startAuto('ok', seconds, promiseObject);
  },
  autoCancel(seconds, promiseObject) {
    if (!this.cancelButton) return;
    this._startAuto('cancel', seconds, promiseObject);
  },

  _startAuto(which, seconds, promiseObject) {
    var self = this;
    var sec = parseInt(seconds, 10);
    if (isNaN(sec) || sec <= 0) return;

    // Clear previous
    if (this.__autoTimer) {
      clearInterval(this.__autoTimer);
      this.__autoTimer = null;
    }

    var button = (which === 'ok') ? this.okButton : this.cancelButton;
    var baseLabel = button.data('baseLabel') || button.clone().children().remove().end().text().trim();
    button.data('baseLabel', baseLabel);

    // show countdown in parentheses
    button.find('.bora-countdown').remove(); // clean old
    var cd = $('<span class="bora-countdown"> (' + sec + ')</span>');
    button.append(cd);

    this.__autoTimer = setInterval(function() {
      sec -= 1;
      if (sec <= 0) {
        clearInterval(self.__autoTimer);
        self.__autoTimer = null;
        // trigger appropriate action
        if (which === 'ok') {
          // emulate submit
          if (self.modal) {
            self.modal.trigger('submit');
          }
          // resolve the promise if provided (handled by submit)
        } else {
          // cancel: hide and reject promise
          self.hide();
          if (promiseObject && typeof promiseObject.reject === 'function') {
            try { promiseObject.reject(); } catch (e) {}
          }
        }
      } else {
        cd.text(' (' + sec + ')');
      }
    }, 1000);
    return this;
  }

});

// expose the API as alertBora (camelCase)
var alertBora = BoraAlertsV2;
if (typeof window !== 'undefined') window.alertBoraV2 = alertBora; // kept separate so you can try side-by-side
// Also keep a short alias in case you want it named 'alertBora' in tests
// do not override existing alertBora if present, use alertBoraV2 instead
if (!window.alertBora) {
  window.alertBora = alertBora;
}

// init
BoraAlertsV2.init();