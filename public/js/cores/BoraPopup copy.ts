// boraPopup plugin (converted from ILEBORA.BoraPopup)
var boraPopup = addPlugin(BoraPlugin, {
    pluginName: 'boraPopup',
    baseObj: null,
    popzIndexBase: 1035,
    openPops: {},          // map of opened popup names -> count
    newPopCount: {},       // map of popupName -> new count
    tabsLoaded: {},
    init() {
        // Call base init
        BoraPlugin.init.call(this);
        this.log('boraPopup initialized', 'init');
    },

    // Factory to create a popup instance (similar to new EPop.Class('myPop'))
    create(targetName) {
        if (!targetName) throw new Error('Popup targetName required');
        const inst = new Popup(this, targetName);
        return inst;
    },

    // helper: get active popcount (number of open popup instances)
    getPopCount() {
        return Object.keys(this.openPops).length;
    },

    // helper: increment openPops
    markOpened(target) {
        this.openPops[target] = (this.openPops[target] || 0) + 1;
    },

    markClosed(target) {
        if (this.openPops[target]) {
            this.openPops[target] = Math.max(0, this.openPops[target] - 1);
            if (this.openPops[target] === 0) delete this.openPops[target];
        }
    },

    // allow adding plugin-level helper methods
    setupLibrary(selector) {
        // Optional helper to attach to a base object
        var self = this;
        $(document).ready(function(){
            self.baseObj = $(selector);
            self.trigger('librarySetup', self.baseObj);
        });
    }
});

// Popup instance class (internal)
class Popup {
    constructor(plugin, target) {
        this.plugin = plugin;           // boraPopup reference
        this.targetName = target;       // string e.g. 'myPop'
        this.targetObj = null;          // jQuery element when created
        this.popParams = { params: null };
        this.openstate = false;
        this.showing = false;
        this.showingState = 0;
        this.tabsAdded = false;
        this.popIndex = 0;
        this.popCount = 0;
        this.zIndex = null;
        this.tabParams = null;

        // behavior flags (defaults copied from legacy)
        this.allowHash = true;
        this.tabParent = 'epop';

        this.enableContentPersistence = true;
        this.forceReload = false;
        this.forceClose = false;
        this.resizeWithWindow = true;
        this.onEscKey = true;
        this.cascadePopups = true;
        this.debug = true;

        // callbacks
        this.onOpenCallback = null;
        this.onCloseCallback = null;

        // init bookkeeping
        this.plugin.newPopCount[this.targetName] = this.plugin.newPopCount[this.targetName] || 0;
        this.plugin.tabsLoaded[this.targetName] = this.plugin.tabsLoaded[this.targetName] || false;
    }

    // ---- markup builder ----
    _template_fullpage(target) {
        return ''
            + '<div id="' + target + '" class="popup pop" data-popup="' + target + '">'
                + '<div class="myTabs popup-inner ">'
                    + '<div class="chat_hd">'
                        + '<div class="chat_tabs_container"><ul class="chat_hd_tbs tabs"></ul></div>'
                        + '<div class="chat_close"></div>'
                    + '</div>'
                    + '<div class="popup-container">'
                        + '<div class="popup-persist-head persist animated fadeIn"></div>'
                        + '<div class="popup-append tabs_cont animated fadeIn"></div>'
                        + '<div id="preload"></div>'
                        + '<div class="popup-persist-foot persist animated fadeIn"></div>'
                    + '</div>'
                + '</div>'
            + '</div>';
    }

    // setup/popParams initializer
    setup(params = {}) {
        this.popParams.params = params;
        this.popParams.url = (typeof params.url === 'undefined') ? params.url : params.url;
        this.popParams.color = params.color || '#ffffff';
        this.popParams.acs = (typeof params.acs === 'undefined') ? 2 : params.acs;
        this.popParams.typ = params.typ || 'default';
        this.popParams.u = params.u || 0;
        this.popParams.v = params.v || 0;
        this.popParams.tab = (typeof params.t === 'undefined') ? 'home' : params.t;
    }

    refresh(params = {}) {
        // refresh is same as setup but with slightly different default for url
        this.popParams.params = params;
        this.popParams.url = params.url == null ? 'inx/def' : params.url ;
        this.popParams.color = params.color || '#ffffff';
        this.popParams.acs = (typeof params.acs === 'undefined') ? 2 : params.acs;
        this.popParams.typ = params.typ || 'default';
        this.popParams.u = params.u || 0;
        this.popParams.v = params.v || 0;
        this.popParams.tab = (typeof params.t === 'undefined') ? 'home' : params.t;
    }

    // create DOM if missing and initialize state
    init() {
        this.plugin.newPopCount[this.targetName] = this.plugin.newPopCount[this.targetName] || 0;
        this.plugin.newPopCount[this.targetName]++;

        if ($('#' + this.targetName).length === 0) {
            $('body').append(this._template_fullpage(this.targetName));
        }
        this.targetObj = $('#' + this.targetName);
        this.openstate = false;
        this.showing = false;
        this.showingState = 0;
        this.tabsAdded = false;
        this.plugin.trigger('instanceInit', this);
        this.plugin.log(`Popup init: ${this.targetName}`, 'Popup.init');
    }

    // Set debug
    setDebug(state) {
        this.debug = !!state;
        this.plugin.log(`Popup ${this.targetName} debug: ${this.debug}`, 'setDebug');
    }

    log(...args) {
        if (this.debug) {
            console.log.apply(console, args);
        }
    }

    // Open popup --- params like { url, color, t, u, v, acs, typ }
    open(params = {}) {
        var self = this;

        // ensure DOM exists
        if (!this.targetObj || this.targetObj.length === 0) {
            this.init();
        }

        // Mark opened map for z-index computation
        this.plugin.markOpened(this.targetName);

        this.popCount = this.plugin.getPopCount();
        this.popIndex = Number(this.plugin.popzIndexBase + this.popCount);
        this.targetObj.css({ "z-index": this.popIndex }).addClass('popIndex' + this.popIndex);

        // Call onOpen callback if set (once)
        if (this.onOpenCallback) {
            try { this.onOpenCallback(); } catch (err) { this.log(err); }
            this.onOpenCallback = null;
        }

        // reset state markers
        this.showingState = 0;
        this.openstate = false;

        // increment newPopCount tracker
        this.plugin.newPopCount[this.targetName] = (this.plugin.newPopCount[this.targetName] || 0) + 1;

        // apply setup/refresh depending on previous type of params object
        if (typeof this.popParams.params !== 'object') {
            this.setup(params);
        } else {
            this.refresh(params);
        }

        // ensure target name present on params
        this.popParams.target = this.targetName;

        // update hash if allowed
        if (this.allowHash && typeof this.popParams.target !== 'undefined') {
            this.changeHash(this.popParams.target);
        }

        // set content container background
        this.targetObj.find('.popup-inner').css('background', this.popParams.color);

        // show popup and prepare content area
        this.targetObj.show();
        this.targetObj.find('#preload').hide();

        // if first open, set close button markup
        if (!this.showing) {
            this.targetObj.find(".chat_close").html('<div class="bck animated fadeIn" onclick="' + this.targetName + '.close()"></div>');
            // The onclick string above is a simple fallback — prefer programmatic handling below
        }

        // position (center)
        this.positionPop();

        // on mobile hook (legacy)
        if (window.Android && typeof window.Android.regPop === 'function') {
            try { Android.regPop(); } catch (e) { /* noop */ }
        }

        // bind global behaviors (click-away, hashchange, esc, resize)
        this._bindBehaviors();

        // mark showing
        this.openstate = true;
        this.showing = true;
        this.plugin.tabsLoaded[this.targetName] = true;

        // trigger event
        this.plugin.trigger('open', this);

        return false;
    }

    // Close popup
    close() {
        // onClose callback may cancel close (if returns 0)
        if (this.onCloseCallback) {
            try {
                if (this.onCloseCallback() === 0) {
                    this.log('Close cancelled by callback');
                    return;
                }
            } catch (err) { this.log(err); }
        }

        // reset some things
        this.popParams = { params: null };
        this.showingState = 0;

        var target = this.targetName;
        var targeted = $('.popIndex' + this.popIndex + '[data-popup="' + target + '"]');

        targeted.find(".chat_hd_tbs").html("");
        targeted.find('.popup-append').html('');
        targeted.removeClass('popIndex' + this.popIndex).css({ "z-index": this.plugin.popzIndexBase });
        targeted.hide();

        // unbind body click and window hashchange for this popup
        $('body').unbind('click.' + target);
        $(window).unbind('hashchange.' + target);

        // update hash
        if (this.allowHash) {
            this.changeHash(''); // remove or reset entry
        }

        // bookkeeping
        this.plugin.newPopCount[target] = 0;
        this.openstate = false;
        this.showing = false;
        this.tabsAdded = false;
        this.plugin.tabsLoaded[target] = false;
        this.plugin.markClosed(target);

        this.plugin.trigger('close', this);
        this.log('Popup closed: ' + target, 'close');
    }

    // Position method (simple: fill screen / reset offsets)
    positionPop() {
        $('.popup').css({ 'margin-top': '0px', 'top': '0px', 'margin-left': '0', 'left': '0' });
    }

    // Bind behaviors based on flags (click-away, esc, resize, hash change)
    _bindBehaviors() {
        var self = this;
        var target = this.targetName;

        // click-away
        if (self.forceClose) {
            $('body').bind('click.' + target, function (e) {
                var targetEl = $(e.target);
                var popInner = $("#" + self.targetName + " .myTabs");
                if (!targetEl.parents().is(popInner) && !targetEl.is(popInner)) {
                    // clicking outside
                    if (self.showing && self.showingState >= 1) {
                        self.showingState = 0;
                        self.close();
                    }
                    self.showingState++;
                }
            });
        }

        // hash change (cascade)
        if (self.cascadePopups) {
            $(window).bind('hashchange.' + target, function (e) {
                // if the hash was cleared, optionally close
                if (window.location.hash === "" && self.openstate && self.plugin.newPopCount[self.targetName] > 1) {
                    // legacy code did nothing decisive here; leaving a hook
                    // self.close();
                }
            });
        }

        // esc key
        if (self.onEscKey) {
            $('body').on('keyup.' + target, function (e) {
                if (e.which === 27) {
                    self.close();
                }
            });
        }

        // resize handler
        if (self.resizeWithWindow) {
            $(window).on('resize.' + target, function () {
                self.positionPop();
            });
        }
    }

    // changeHash behavior - tries to preserve multiple '|' segments and add/replace epop-N entries
    changeHash(newtab) {
        var str = '';
        var start, end, newend;

        if (window.location.hash) {
            str = window.location.hash.substring(1);

            if (str.indexOf(this.tabParent) !== -1) {
                // handle already contains parent
                if (str.indexOf(this.tabParent + "-") !== -1) {
                    start = str.indexOf(this.tabParent + "-") + 1 + this.tabParent.length;
                    end = (canSplit(str, "|")) ? str.lastIndexOf("|") : str.length;
                    newend = (start > end) ? (start + end) : end;
                } else {
                    start = str.indexOf(this.tabParent) + 1 + this.tabParent.length;
                    end = (canSplit(str, "|")) ? str.lastIndexOf("|") : str.length;
                    newend = (start > end) ? (start + end) : end;
                    newtab = '-' + newtab;
                }
                // replaceBetween is assumed to exist in your environment (legacy helper). If not present, do a simpler replace:
                if (typeof replaceBetween === 'function') {
                    str = replaceBetween(str, start, newend, newtab);
                } else {
                    // fallback: naive replace of last occurrence
                    var idx = str.lastIndexOf(this.tabParent);
                    if (idx !== -1) {
                        var prefix = str.substring(0, idx);
                        str = prefix + this.tabParent + "-" + newtab;
                    } else {
                        if (str.length) str = str + "|" + this.tabParent + "-" + newtab;
                        else str = this.tabParent + "-" + newtab;
                    }
                }
            } else {
                if (str.length) str = str + "|" + this.tabParent + "-" + newtab;
                else str = this.tabParent + "-" + newtab;
            }
        } else {
            if (str.length) str = str + "|" + this.tabParent + "-" + newtab;
            else str = this.tabParent + "-" + newtab;
        }

        window.location.hash = str;
    }

    // hashSetup: parse current hash and optionally call eTabs open functions
    hashSetup() {
        if (!window.location.hash) return;
        var hash = window.location.hash.substring(1);
        var allTbs = [];

        if (allTbs = getSplit(hash, '|')) {
            allTbs.forEach(tHash => {
                var tbs = tHash.split('-');
                if (typeof eTabs !== 'undefined' && typeof eTabs[tbs[0]] !== 'undefined' && typeof eTabs[tbs[0]].openTab === 'function') {
                    eTabs[tbs[0]].openTab(tbs[1]);
                }
            });
        } else {
            if (tbs = getSplit(hash, '-')) {
                if (typeof eTabs !== 'undefined' && typeof eTabs[tbs[0]] !== 'undefined' && typeof eTabs[tbs[0]].openTab === 'function') {
                    eTabs[tbs[0]].openTab(tbs[1]);
                }
            }
        }
    }

    // add tabs (items: array of {name, tab, url, active, link})
    addTabs(items) {
        if (!items || this.tabsAdded) return;
        var ulCont = $('#' + this.targetName).find(".chat_hd_tbs");
        ulCont.css('left', '0px');

        items.forEach(item => {
            var name = item.name || '';
            var tabname = item.tab ? ucfirst(item.tab) : '';
            var clss = item.active ? 'active' : '';
            var url = item.url ? 'data-u="' + item.url + '"' : '';
            var tab = item.tab ? 'data-t="' + item.tab + '"' : '';
            var link = item.link ? 'onclick="' + item.link + '"' : '';
            ulCont.append('<li><a class="etab tab' + tabname + ' ' + clss + '" ' + tab + ' ' + url + ' href="javascript:void(0)" ' + link + '>' + name + '</a></li>');
        });

        this.tabsAdded = true;

        // if overflow -> make draggable (requires jquery-ui draggable)
        if (this.isOverflown(ulCont) && typeof ulCont.draggable === 'function') {
            ulCont.draggable({
                axis: 'x',
                start: function (event, ui) {
                    $(this).data('dragging', true);
                },
                stop: function (event, ui) {
                    setTimeout(function () {
                        $(event.target).data('dragging', false);
                    }, 100);
                },
                drag: function (event, ui) {
                    if (ui.position.left > 0) ui.position.left = 0;
                }
            });
        }

        // bind click events for tabs
        var self = this;
        $('#' + this.targetName).find('.chat_hd_tbs li a.etab').on('click', function () {
            if ($('#' + self.targetName).find(".chat_hd_tbs").data('dragging')) {
                self.log('dragging, ignore click');
                return; // dragging
            }
            self.openTab($(this));
        });
    }

    // helper: basic overflow detection
    isOverflown(element) {
        return element.prop('scrollHeight') > element.prop('clientHeight') || element.prop('scrollWidth') > element.prop('clientWidth');
    }

    // open tab by jQuery element or selector
    openTab(obj, force) {
        var force = (typeof force !== 'undefined') ? force : false;
        var tab = $(obj);
        if (!tab || tab.length === 0) return;
        var tabParams = {
            tab: tab.attr('data-t'),
            url: tab.attr('data-u')
        };

        if (this.popParams.tab == tabParams.tab && !force) {
            this.log('Tab already open!');
            return;
        }

        $('#' + this.popParams.target).find(".chat_hd_tbs li a").removeClass('active');
        $('#' + this.popParams.target).find('.chat_hd_tbs li a[data-t="' + tabParams.tab + '"]').addClass('active');

        // populate loader & load url
        var loader = '<div class="lds-ripple"><div></div><div></div></div>';
        $('#' + this.popParams.target).find('.popup-append').html('<div align="center" class="loadercont">' + loader + '</div>').load(tabParams.url, this.popParams.params);

        this.popParams.tab = tabParams.tab;
    }

    // find & open named tab
    findTab(tab) {
        var prnt = $('#' + this.popParams.target + ' .chat_hd_tbs');
        var elem = prnt.find('.tab' + ucfirst(tab));
        if (elem.length) {
            this.openTab(elem);
        } else {
            this.log('tab not found: ' + tab);
        }
    }

    // set onOpen/onClose callbacks
    setOnOpen(callback) { this.onOpenCallback = callback; }
    setOnClose(callback) { this.onCloseCallback = callback; }

    // utility: simple getter for modal state
    isOpen() { return this.openstate; }
}

// small helpers used by legacy code: ucfirst, canSplit, getSplit, replaceBetween, getSplit fallback
function ucfirst(str) {
    if (!str) return '';
    return str.charAt(0).toUpperCase() + str.slice(1);
}

// legacy helper canSplit
function canSplit(str, sep) {
    return (typeof str === 'string' && str.indexOf(sep) !== -1);
}

// getSplit wrapper: returns array if sep found else false
function getSplit(str, sep) {
    if (!str || typeof str !== 'string') return false;
    if (str.indexOf(sep) !== -1) return str.split(sep);
    return false;
}

// replaceBetween fallback: try to emulate old behavior
function replaceBetween(str, start, end, repl) {
    if (typeof str !== 'string') return str;
    start = parseInt(start, 10) || 0;
    end = parseInt(end, 10) || str.length;
    if (start >= str.length) return str + repl;
    return str.substring(0, start) + repl + str.substring(end);
}

// --- expose a small convenience: create & store instance on window by conventional name ---
// example: var myPop = boraPopup.create('myPop'); myPop.init(); myPop.open({url: '...'});

// Example usage (after loading plugin):
// var myPop = boraPopup.create('myPop');
// myPop.init();
// myPop.open({ url: '/path/to/content', color: '#fff', t: 'home' });



