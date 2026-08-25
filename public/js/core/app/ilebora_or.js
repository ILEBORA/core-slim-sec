console.log('ILEBORA');
var _exportsCache = [];
let ILEBORA = (function () {
    var _listeners = {};
    var _includedIdentifiers = [];
    var _toArray = function (obj) {
        // checks if it's an array
        if (typeof obj == "object" && obj.sort) {
        return obj;
        }
        return Array(obj);
    };
    var _createXmlHttpRequest = function () {
        var xhr;
        try {
        xhr = new XMLHttpRequest();
        } catch (e) {
        try {
            xhr = new ActiveXObject("Msxml2.XMLHTTP.6.0");
        } catch (e2) {
            try {
            xhr = new ActiveXObject("Msxml2.XMLHTTP.3.0");
            } catch (e3) {
            try {
                xhr = new ActiveXObject("Msxml2.XMLHTTP");
            } catch (e4) {
                try {
                xhr = new ActiveXObject("Microsoft.XMLHTTP");
                } catch (e5) {
                throw new Error("This browser does not support XMLHttpRequest.");
                }
            }
            }
        }
        }
        return xhr;
    };
    var _isHttpRequestSuccessful = function (status) {
        return (
        (status >= 200 && status < 300) || // Boolean
        status == 304 || // allow any 2XX response code
        status == 1223 || // get it out of the cache
        (!status &&
            (window.location.protocol == "file:" ||
            window.location.protocol == "chrome:"))
        ); // Internet Explorer mangled the status code
    };
    var _createScript = function (data) {
        var script = document.createElement("script");
        script.type = "text/javascript";
        script.class = "scj";
        script.text = data;

        if (typeof window.execScript === "object") {
            // According to IE
            window.execScript(data);
        } else {
        try {
            // Attempt body insertion
            document.body.appendChild(script);
        } catch (e) {
            // Fall back on eval
            window["eval"](data);
        }
        }
    };
    var _dispatchEvent = function (eventName, properties) {
        if (!_listeners[eventName]) {
            return;
        }
        properties.event = eventName;
        for (var i = 0; i < _listeners[eventName].length; i++) {
            _listeners[eventName][i](properties);
        }
    };
    var _ilebora = function (identifier) {
        var klasses = arguments[1] || false;
        var ns = window;

        if (identifier !== "") {
            var parts = identifier.split(ILEBORA.separator);
            for (var i = 0; i < parts.length; i++) {
                if (!ns[parts[i]]) {
                ns[parts[i]] = {};
                }
                ns = ns[parts[i]];
            }
        }

        if (klasses) {
            for (var klass in klasses) {
                if (klasses.hasOwnProperty(klass)) {
                ns[klass] = klasses[klass];
                }
            }
        }

        _dispatchEvent("create", { identifier: identifier });
        return ns;
    };
    _ilebora.exist = function (identifier) {
        if (identifier === "") {
        return true;
        }

        var parts = identifier.split(ILEBORA.separator);
        var ns = window;
        for (var i = 0; i < parts.length; i++) {
        if (!ns[parts[i]]) {
            return false;
        }
        ns = ns[parts[i]];
        }

        return true;
    };
    _ilebora.mapIdentifierToUri = function (identifier) {
        var regexp = new RegExp("\\" + ILEBORA.separator, "g");
        return ILEBORA.baseUri + identifier.replace(regexp, "/");
    };
    var _loadScript = function (identifier) {
        var successCallback = arguments[1];
        var errorCallback = arguments[2];
        var scriptType = arguments[3];
        var async = typeof successCallback === "function";
        var uri = _ilebora.mapIdentifierToUri(identifier) + scriptType; //alert(uri);
        var uriN = uri; //New refresh cache
        if (!engineSettings.cachescripts) {
            //if bust caching of external page
            uriN = uri + "?" + new Date().getTime();
        }
        var event = {
            id: md5(uri),
            uri: uriN,
            async: async,
            version: (typeof rd === "function") ? rd("jsVersion") : "1.0.0",
            callback: successCallback,
            scripttype: scriptType,
        };
        requireScript(event);
    };
    var _cacheScript = function (c, d, e) {
        var a = new XMLHttpRequest();
        a.onreadystatechange = function () {
        4 == a.readyState &&
            (200 == a.status
            ? localStorage.setItem(
                c,
                JSON.stringify({
                    content: a.responseText,
                    version: d,
                })
                )
            : console.warn("error loading " + e));
        };
        a.open("GET", e, !0);
        a.send();
    };
    _ilebora.include = function (identifier) {
        var callback = arguments[1] || false;
        var autoInclude = arguments.length > 2 ? arguments[2] : ILEBORA.autoInclude;

        var isUrl = /^https?:\/\//i.test(identifier);

        if (isUrl) {
            // Remote asset case
            if (document.querySelector(`script[src="${identifier}"]`)) {
                // Already loaded
                if (typeof callback === "function") callback();
                return;
            }

            var script = document.createElement("script");
            script.src = identifier;
            script.async = true;

            script.onload = function () {
                if (typeof callback === "function") callback();
            };
            script.onerror = function () {
                console.error("Failed to load script:", identifier);
            };

            document.head.appendChild(script);
        } else {
            var successCallback = arguments[1] || false;
            var errorCallback = arguments[2] || false;
            var scriptType = arguments[3] || "js";
            scriptType = "." + scriptType;

            // Keep snapshot of globals before loading
            var beforeKeys = Object.keys(window);

            if (_includedIdentifiers[identifier]) {
                if (typeof successCallback === "function") {
                    successCallback();
                }
                return _exportsCache[identifier] || true; // return cached exports if available
            }

            function done() {
                _includedIdentifiers[identifier] = true;

                // Find new globals
                var afterKeys = Object.keys(window);
                var newKeys = afterKeys.filter(k => !beforeKeys.includes(k));

                // Collect exports
                var exports = {};
                newKeys.forEach(k => {
                    exports[k] = window[k];
                });

                _exportsCache[identifier] = exports; // cache them for reuse

                if (typeof successCallback === "function") {
                    successCallback(exports);
                }
            }

            if (successCallback) {
                _loadScript(identifier, done, errorCallback, scriptType);
            } else {
                if (_loadScript(identifier, null, null, scriptType)) {
                    done();
                    return _exportsCache[identifier];
                }
                return false;
            }
        }
    };

    _ilebora.includeO = function (identifier) {
        var successCallback = arguments[1] || false;
        var errorCallback = arguments[2] || false;
        var scriptType = arguments[3] || "js";
        scriptType = "." + scriptType;
        if (_includedIdentifiers[identifier]) {
        if (typeof successCallback === "function") {
            successCallback();
        }
        return true;
        }
        if (successCallback) {
            _loadScript(
                identifier,
                function () {
                _includedIdentifiers[identifier] = true;
                successCallback();
                },
                errorCallback,
                scriptType
            );
        } else {
        if (_loadScript(identifier, null, null, scriptType)) {
            _includedIdentifiers[identifier] = true;
            return true;
        }
        return false;
        }
    };
    _ilebora.use = function (identifier) {
    var callback = arguments[1] || false;
    var autoInclude = arguments.length > 2 ? arguments[2] : ILEBORA.autoInclude;

    var isUrl = /^https?:\/\//i.test(identifier);

    if (isUrl) {
        // Remote asset case
        if (document.querySelector(`script[src="${identifier}"]`)) {
            // Already loaded
            if (typeof callback === "function") callback();
            return;
        }

        var script = document.createElement("script");
        script.src = identifier;
        script.async = true;

        script.onload = function () {
            if (typeof callback === "function") callback();
        };
        script.onerror = function () {
            console.error("Failed to load script:", identifier);
        };

        document.head.appendChild(script);
    } else {
        // Existing namespace logic
        var identifiers = _toArray(identifier);
        var event = { identifier: identifier };
        var parts, target, ns;

        for (var i = 0; i < identifiers.length; i++) {
            identifier = identifiers[i];

            parts = identifier.split(ILEBORA.separator);
            target = parts.pop();
            ns = _ilebora(parts.join(ILEBORA.separator));

            if (target == "*") {
                for (var objectName in ns) {
                    if (ns.hasOwnProperty(objectName)) {
                        window[objectName] = ns[objectName];
                    }
                }
            } else {
                if (ns[target]) {
                    window[target] = ns[target];
                } else if (autoInclude) {
                    if (callback) {
                        _ilebora.include(identifier, function () {
                            window[target] = ns[target];
                            if (i + 1 < identifiers.length) {
                                _ilebora.unpack(
                                    identifiers.slice(i + 1),
                                    callback,
                                    autoInclude
                                );
                            } else {
                                _dispatchEvent("use", event);
                                if (typeof callback === "function") callback();
                            }
                        });
                        return;
                    } else {
                        _ilebora.include(identifier);
                        window[target] = ns[target];
                    }
                }
            }
        }

        _dispatchEvent("use", event);
        if (typeof callback === "function") callback();
    }
};

    _ilebora.from = function (identifier) {
        return {
        include: function () {
            var callback = arguments[0] || false;
            _ilebora.include(identifier, callback);
        },
        use: function (_identifier) {
            var callback = arguments[1] || false;
            if (_identifier.charAt(0) == ".") {
                _identifier = identifier + _identifier;
            }

            if (callback) {
                _ilebora.include(identifier, function () {
                    _ilebora.use(_identifier, callback, false);
                });
            } else {
                _ilebora.include(identifier);
                _ilebora.use(_identifier, callback, false);
            }
        },
        };
    };
    _ilebora.provide = function (identifier) {
        var identifiers = _toArray(identifier);

        for (var i = 0; i < identifiers.length; i++) {
            if (!(identifier in _includedIdentifiers)) {
                _dispatchEvent("provide", { identifier: identifier });
                _includedIdentifiers[identifier] = true;
            }
        }
    };
    _ilebora.addEventListener = function (eventName, callback) {
        if (!_listeners[eventName]) {
        _listeners[eventName] = [];
        }
        _listeners[eventName].push(callback);
    };
    _ilebora.removeEventListener = function (eventName, callback) {
        if (!_listeners[eventName]) {
        return;
        }
        for (var i = 0; i < _listeners[eventName].length; i++) {
        if (_listeners[eventName][i] == callback) {
            delete _listeners[eventName][i];
            return;
        }
        }
    };
    _ilebora.registerNativeExtensions = function () {
        /**
         * @see ILEBORA()
         */
        String.prototype.namespace = function () {
            var klasses = arguments[0] || {};
            return _ilebora(this.valueOf(), klasses);
        };
        /**
         * @see ILEBORA.include()
         */
        String.prototype.include = function () {
            var callback = arguments[0] || false;
            return _ilebora.include(this.valueOf(), callback);
        };
        /**
         * @see ILEBORA.use()
         */
        String.prototype.use = function () {
            var callback = arguments[0] || false;
            return _ilebora.use(this.valueOf(), callback);
        };
        /**
         * @see ILEBORA.from()
         */
        String.prototype.from = function () {
            return _ilebora.from(this.valueOf());
        };
        /**
         * @see ILEBORA.provide()
         * Idea and code submitted by Nathan Smith (http://github.com/smith)
         */
        String.prototype.provide = function () {
            return _ilebora.provide(this.valueOf());
        };
        /**
         * @see ILEBORA.use()
         */
        Array.prototype.use = function () {
            var callback = arguments[0] || false;
            return _ilebora.use(this, callback);
        };
        /**
         * @see ILEBORA.provide()
         */
        Array.prototype.provide = function () {
            return _ilebora.provide(this);
        };
    };

  return _ilebora;
})();

ILEBORA.separator = ".";
ILEBORA.baseUri = "./";
ILEBORA.autoInclude = true;
function rd(y, d = ''){
	return (typeof window.settings[y] === "undefined") ? d : window.settings[y];
}
	
function st(y,v){
	if(v){
		window.settings[y] = v;
	}
} 
function md5(input) {
    const r = new Uint8Array([
      7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
      5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
      4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
      6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
    ]);
  
    const k = new Int32Array([
      -680876936, -389564586, 606105819, -1044525330, -176418897, 1200080426, -1473231341, -45705983,
      1770035416, -1958414417, -42063, -1990404162, 1804603682, -40341101, -1502002290, 1236535329,
      -165796510, -1069501632, 643717713, -373897302, -701558691, 38016083, -660478335, -405537848,
      568446438, -1019803690, -187363961, 1163531501, -1444681467, -51403784, 1735328473, -1926607734,
      -378558, -2022574463, 1839030562, -35309556, -1530992060, 1272893353, -155497632, -1094730640,
      681279174, -358537222, -722521979, 76029189, -640364487, -421815835, 530742520, -995338651,
      -198630844, 1126891415, -1416354905, -57434055, 1700485571, -1894986606, -1051523, -2054922799,
      1873313359, -30611744, -1560198380, 1309151649, -145523070, -1120210379, 718787259, -343485551
    ]);
  
    function hash(data) {
      let h0 = 1732584193,
        h1 = -271733879,
        h2 = -1732584194,
        h3 = 271733878;
  
      const paddedLength = (data.length + 72) & ~63;
      const padded = new Uint8Array(paddedLength);
      let i, j;
  
      for (i = 0; i < data.length; i++) {
        padded[i] = data[i];
      }
  
      padded[i++] = 0x80;
      const n = paddedLength - 8;
  
      while (i < n) {
        padded[i++] = 0;
      }
  
      const lengthBits = data.length * 8;
      for (let shift = 0; shift < 8; shift++) {
        padded[i++] = (lengthBits >> (shift * 8)) & 0xff;
      }
  
      const w = new Int32Array(16);
  
      for (i = 0; i < paddedLength;) {
        for (j = 0; j < 16; j++, i += 4) {
          w[j] =
            padded[i] |
            (padded[i + 1] << 8) |
            (padded[i + 2] << 16) |
            (padded[i + 3] << 24);
        }
  
        let a = h0, b = h1, c = h2, d = h3;
  
        for (j = 0; j < 64; j++) {
          let f, g;
  
          if (j < 16) {
            f = (b & c) | (~b & d);
            g = j;
          } else if (j < 32) {
            f = (d & b) | (~d & c);
            g = (5 * j + 1) & 15;
          } else if (j < 48) {
            f = b ^ c ^ d;
            g = (3 * j + 5) & 15;
          } else {
            f = c ^ (b | ~d);
            g = (7 * j) & 15;
          }
  
          const temp = d;
          d = c;
          c = b;
          b = b + ((a + f + k[j] + w[g]) << r[j] | (a + f + k[j] + w[g]) >>> (32 - r[j]));
          a = temp;
        }
  
        h0 = (h0 + a) | 0;
        h1 = (h1 + b) | 0;
        h2 = (h2 + c) | 0;
        h3 = (h3 + d) | 0;
      }
  
      const hashBytes = new Uint8Array([
        h0 & 0xff, (h0 >> 8) & 0xff, (h0 >> 16) & 0xff, (h0 >> 24) & 0xff,
        h1 & 0xff, (h1 >> 8) & 0xff, (h1 >> 16) & 0xff, (h1 >> 24) & 0xff,
        h2 & 0xff, (h2 >> 8) & 0xff, (h2 >> 16) & 0xff, (h2 >> 24) & 0xff,
        h3 & 0xff, (h3 >> 8) & 0xff, (h3 >> 16) & 0xff, (h3 >> 24) & 0xff
      ]);
  
      return hashBytes;
    }
  
    function toHexString(bytes) {
      return Array.from(bytes)
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");
    }
  
    const encoder = new TextEncoder();
    const data = encoder.encode(input);
    return toHexString(hash(data));
  }
  
  