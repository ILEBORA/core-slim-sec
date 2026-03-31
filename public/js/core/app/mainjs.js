// Log messages will be written to the window's console.
Logger.useDefaults();

// hook.callHook("alt", "this now");

var searchRequest = null;        
var minlength = 2;
var sessionTimeout = 1 * 60 * 1000; //1 * 60 * 1000; //;
var logoutTimer;

function resetLogoutTimer() {
// 	console.log('resetLogoutTimer');
	clearTimeout(logoutTimer);
	logoutTimer = setTimeout(logout, sessionTimeout);
}

function logout() {
	// Redirect to the logout page or trigger the logout API call
	doLogout('');
}

(function(console){

	console.save = function(data, filename){
	
		if(!data) {
			console.error('Console.save: No data');
			return;
		}
	
		if(!filename) filename = 'console.json';
	
		if(typeof data === "object"){
			data = JSON.stringify(data, undefined, 4)
		}
	
		var blob = new Blob([data], {type: 'text/json'}),
			e    = document.createEvent('MouseEvents'),
			a    = document.createElement('a');
	
		a.download = filename;
		a.href = window.URL.createObjectURL(blob);
		a.dataset.downloadurl =  ['text/json', a.download, a.href].join(':');
		e.initMouseEvent('click', true, false, window, 0, 0, 0, 0, 0, false, false, false, false, 0, null);
		a.dispatchEvent(e);
	 }
})(console);

// function replaceMe(template, data) {
// 	var pattern = /{(\w+?)}/g;
// 	return template.replace(pattern, (_, token) => data[token] || '');
// }

function replaceMe(template, data) {
    var pattern = /{(\w+?)}/g;
    return template.replace(pattern, function(_, token) {
        return data[token] || '';
    });
}

function myEventHandler(e){
    if (!e){
      e = window.event;
    }

    if (e.stopPropagation) {
      e.stopPropagation();
    }else {
      e.cancelBubble = true;
    }
}
$.fn.hasAttr = function(name) {  
	return this.attr(name) !== undefined;
};
$.fn.itemFX = function() {
	// $(this).each(function(i){
	// 	$(this).delay(150*i).queue(function(nxt){
	// 		$(this).removeClass('animated fadeIn').addClass('animated fadeIn').show();
	// 		nxt();   
	// 	});
	// });
	
	// this.css({
	// 	'position': 'fixed',
	// 	'left': '45%',
	// 	'top': '35%'
	// });
	// this.css({
	// 	'margin-left': -this.outerWidth() / 2 + 'px',
	// 	'margin-top': -this.outerHeight() / 2 + 'px'
	// });

	// return this;
};
$.fn.menuFX = function() { 
  $(this).each(function(i){
      $(this).delay(150*i).queue(function(nxt){
          $(this).removeClass('animated fadeIn').addClass('animated fadeIn').show();
          nxt();   
      });
  });
	
  this.css({
      'position': 'fixed',
      'left': '45%',
      'top': '35%'
  });
  this.css({
      'margin-left': -this.outerWidth() / 2 + 'px',
      'margin-top': -this.outerHeight() / 2 + 'px'
  });

	return this;
};
$.fn.hasAttr = function(name) {  
	return this.attr(name) !== undefined;
};
$.fn.longPressed = function(duration, callback) {
	var pressTimer;
	var longPressTriggered = false;

	return this.each(function() {
		var $this = $(this);

		$this.mousedown(function(e) {
			longPressTriggered = false;
			pressTimer = window.setTimeout(function() { 
				longPressTriggered = true;
				callback.call($this); 
			}, duration);
			return false;
		}).mouseup(function(e) {
			clearTimeout(pressTimer);
			if (longPressTriggered) {
				e.stopPropagation();
				e.preventDefault();
			}
			return false;
		}).mouseleave(function() {
			clearTimeout(pressTimer);
			return false;
		}).click(function(e) {
			if (longPressTriggered) {
				e.stopPropagation();
				e.preventDefault();
				return false;
			}
		});
	});
};


function menuFX(obj,fx){
  $(obj).each(function(i){
      $(this).delay(100*i).queue(function(nxt){
          $(this).removeClass('animated '+fx).addClass('animated '+fx)
		  		// .show()
				.one('webkitAnimationEnd', function(){
					$(this).removeClass(fx);
				});

          nxt(); 
      });
		
  });
}

// var b64toBlob = (b64Data, contentType='', sliceSize=512) => {
// 	var byteCharacters = atob(b64Data);
// 	var byteArrays = [];
  
// 	for (var offset = 0; offset < byteCharacters.length; offset += sliceSize) {
// 	  var slice = byteCharacters.slice(offset, offset + sliceSize);
  
// 	  var byteNumbers = new Array(slice.length);
// 	  for (var i = 0; i < slice.length; i++) {
// 		byteNumbers[i] = slice.charCodeAt(i);
// 	  }
  
// 	  var byteArray = new Uint8Array(byteNumbers);
// 	  byteArrays.push(byteArray);
// 	}
  
// 	var blob = new Blob(byteArrays, {type: contentType});
// 	return blob;
// };

var b64toBlob = function(b64Data, contentType, sliceSize) {
	contentType = contentType || '';
	sliceSize = sliceSize || 512;
	
	var byteCharacters = atob(b64Data);
	var byteArrays = [];
	
	for (var offset = 0; offset < byteCharacters.length; offset += sliceSize) {
	  var slice = byteCharacters.slice(offset, offset + sliceSize);
	
	  var byteNumbers = new Array(slice.length);
	  for (var i = 0; i < slice.length; i++) {
		byteNumbers[i] = slice.charCodeAt(i);
	  }
	
	  var byteArray = new Uint8Array(byteNumbers);
	  byteArrays.push(byteArray);
	}
	
	var blob = new Blob(byteArrays, { type: contentType });
	return blob;
  };
  

//Fix
if (!String.prototype.startsWith) {
	Object.defineProperty(String.prototype, 'startsWith', {
		value: function(search, rawPos) {
			var pos = rawPos > 0 ? rawPos|0 : 0;
			return this.substring(pos, pos + search.length) === search;
		}
	});
};
// var getGlobal = function () {
//   if (typeof self !== 'undefined') { return self; }
//   if (typeof window !== 'undefined') { return window; }
//   if (typeof global !== 'undefined') { return global; }
//   throw new Error('unable to locate global object');
// };
// var globals = getGlobal();
// if (typeof globals.setTimeout !== 'function') {
	// no setTimeout in this environment!
// }

function getParameter(_0xe264x5) {
	var _0xe264x6 = window['location']['search']['substring'](1),
		_0xe264x7, _0xe264x8, _0xe264x9 = _0xe264x6['split']('&');
	for (_0xe264x7 = 0; _0xe264x7 < _0xe264x9['length']; _0xe264x7++) {
		_0xe264x8 = _0xe264x9[_0xe264x7]['split']('=');
		if (_0xe264x8[0] == _0xe264x5) {
			return _0xe264x8[1];
		}
	};
	return '';
}

function getHtml(elem){
	if($(elem).length){
		return $(elem).html();
	}
	return '';
}
function hmsToSecondsOnly(str) {
	var p = str.split(':'),
		s = 0, m = 1;
	while (p.length > 0) {
		s += m * parseInt(p.pop(), 10);
		m *= 60;
	}
	return s;
}
function redirectTo(url, force = false) {
    if (force) {
        // Replace current history entry (Back won't return here)
        window.location.replace(url);
    } else {
        // Normal navigation (Back will still work)
        window.location.href = url;
    }
    return false;
}
var replaceBetween = function(str, start, end, what) {
	return str.substring(0, start) + what + str.substring(end);
};
function _classCallCheck(instance, varructor) { if (!(instance instanceof varructor)) { throw new TypeError("Cannot call a class as a function"); } }

function getNs(ns,fn,frc){
	waitFor(ns,1000*60,function(){
		if(typeof fn === 'function'){
			fn();
		}else{
			if(frc){
				logTest('getNs:: "'+fn+'" was not found!','warn');
				// tryLoad if alias get name

			}
		}
		
	});
}
    
function getNsD(f,ns,fn){
	// logTest('NsD:: f: '+f);
	// logTest('NsD:: ns: '+'mPGs.'+ns);
	waitForD(f,ns,1000*5,function(){
			if(fn){
				// logTest('NsD:: '+'mPGs.'+ns+'found');
			fn();
		}else{
		//   logTest('NsD:: "'+fn+'" was not found!','warn');
		//   include('private.routes.special.ClientBooking.test',function(){
	//             alert('Test Loaded'); 
	//         });
			use(f+'.'+ns,function(){
				logTest(ns+' Loaded!');
				fn();
			});
		}
		
	});
}

function getNsDFl(f,fl,ns,fn){
	// logTest('NsD FDl:: f: '+f);
	// logTest('NsD FDl:: fl: '+fl);
	// logTest('NsD FDl:: ns: '+'mPGs.'+ns);
	waitForDFl(f,fl,ns,1000*5,function(){
			
			fn();
		
	});
}

function getNsCdn(ns,fn){
	waitForCdn(ns,1000*60,function(){
			if(fn){
			fn();
		}else{
			logTest('CDN:: "'+fn+'" was not found!','warn');
		}
		
	});
}
function getScriptDirectory() {
    // Get the current script element
    var script = document.currentScript || (function() {
        // For older browsers that don't support document.currentScript
        var scripts = document.getElementsByTagName('script');
        return scripts[scripts.length - 1];
    })();

    // Get the script source URL
    var scriptSrc = script.src;

    // Extract the directory from the URL
    var scriptDir = scriptSrc.substring(0, scriptSrc.lastIndexOf('/'));

    return scriptDir;
}

// Cache to store loaded scripts
var scriptCache = {};
function rinclude(file, callback) {
    if (scriptCache[file]) {
        // If cached, execute the callback immediately
        callback();
        return;
    }

    var script = document.createElement('script');
    script.src = file;

    script.onload = function() {
        scriptCache[file] = true;
        if (callback && typeof callback === 'function') {
            callback();
        }
    };

    document.head.appendChild(script);
}

function itemFX(obj,fx){
	console.log('ItemFX');
	// $(obj).hide();
	$(obj).each(function(i){
		$(this).delay(100*i).queue(function(nxt){
			$(this).removeClass('animated '+fx).addClass('animated '+fx).show()
				.one('webkitAnimationEnd', function(){
					$(this).removeClass(fx);
				});
			nxt(); 
		});
		
	});
	// if(ERMnu!=null){
	//     ERMnu.menuSetup();
	// }
}

function exists(namespace) {    
	var tokens = namespace.split('.');
	return tokens.reduce(function(prev, curr) {
		return (typeof prev == "undefined") ? prev : prev[curr];
	}, window);
}

function getModules(data){
	if(data){
	localStorage.setItem('EvarModules',JSON.stringify(data));
	data.forEach(function(data, index) {
		$('.loader').append('Loading '+data.name+'<br>').fadeOut();
		loadModule(data.name,data.version,function(){
			st(data.alias,JSON.stringify(data));
			var fn = (data.alias != null) ? data.alias : null;
			if(fn){
				fn = eval(fn);
				if(typeof fn.getVer === 'function'){
				//fn.getVer(); //test
				}
			}
		});
	});
	}
}

// function getModulesPromise(data,callback){
// 	if(data){
// 		// console.log(data);
// 		localStorage.setItem('EvarModules',JSON.stringify(data));
// 		var promises = [];
// 		data.forEach(function(data, index) {
// 			$('.loader').append('Loading '+data.name+'<br>').fadeOut();
// 			promises.push(
// 				loadModule(data.name,data.version,function(){
// 					st(data.alias,JSON.stringify(data));
// 					var fn = (data.alias != null) ? data.alias : null;
// 					if(fn){
// 						fn = eval(fn);
// 						if(typeof fn.getVer === 'function'){
// 							fn.getVer(); //test
// 						}
// 						// resolve('Module ' + data.name + ' Loaded!');
// 					}else{
// 						// reject('Module ' + data.name + ' Loaded!');
// 					}
// 				})
// 			);
// 		});

// 		Promise.all(promises).then(()=>{
// 			logTest('Success in getModulesPromise!');
// 			if(typeof callback === 'function'){
// 				callback();
// 			}
// 		}).catch((err)=>{
// 			logTest('Error in getModulesPromise '+err);
// 		})
// 	}
// }

function getModulesPromise(data, callback) {
	if (data) {
	  // console.log(data);
	  localStorage.setItem('EvarModules', JSON.stringify(data));
	  var promises = [];
  
	  data.forEach(function (data, index) {
		$('.loader').append('Loading ' + data.name + '<br>').fadeOut();
		promises.push(
		  loadModule(data.name, data.version, function () {
			st(data.alias, JSON.stringify(data));
			var fn = (data.alias !== null) ? data.alias : null;
			if (fn) {
			  fn = eval(fn);
			  if (typeof fn.getVer === 'function') {
				fn.getVer(); //test
			  }
			  // resolve('Module ' + data.name + ' Loaded!');
			} else {
			  // reject('Module ' + data.name + ' Loaded!');
			}
		  })
		);
	  });
  
	  Promise.all(promises).then(function () {
		logTest('Success in getModulesPromise!');
		if (typeof callback === 'function') {
		  callback();
		}
	  }).catch(function (err) {
		logTest('Error in getModulesPromise ' + err);
	  });
	}
  }
  

function forceNs(ns,fn){
	logTest('forceNs');
	waitForNS(ns,1000*60,function(){
		if(typeof fn === 'function'){
			return fn();
		}		
	});
}

/**
 * A function to wait for a namespace to be available
 * @param {*} namespace the namespace to wait for
 * @param {*} timeout The timout in milliseconds
 * @param {*} callback The callback to perform once the namespace is available
 * @param {*} interval time (in milisecponds) between each call. Default 100.
 */
function waitFor(namespace, timeout, callback, interval) {
	//  logTest('NsD:: waitfor:: '+namespace);
	var defaultInterval = interval>=0 ? interval : 100; // try every 100 milliseconds (10 times per second) number chosen to enhance performance;
	if (window[namespace]) { // namespace exists
		callback();
	} else if (timeout <= 0) { // check if we reached the timeout
		return;
	} else {
		setTimeout(function() { // namespace does not exist, wait interval amount then try again;
			waitFor(namespace, timeout - defaultInterval, callback, interval);
		}, defaultInterval);
	}
}

function waitForNS(namespace, timeout, callback, interval) {
	 console.log('NsD:: waitfor:: '+namespace);
	var defaultInterval = interval>=0 ? interval : 100; // try every 100 milliseconds (10 times per second) number chosen to enhance performance;
	if (window[namespace]) { // namespace exists
		console.log(namespace + ' Namespace exists');
		timeout = 0;
		return callback();
	} else if (timeout <= 0) { // check if we reached the timeout
		return;
	} else {
		//Fetch NS
		if(mdl = (searchArray(rd('modulez'),'alias',namespace)) ){
			console.log(namespace +' Found loading!');
			loadModule(mdl.name,mdl.version,function(){
				
				st(mdl.alias,JSON.stringify(mdl));

				var fn = (mdl.alias != null) ? mdl.alias : null;
				if(fn){
					fn = eval(fn);					
					console.log('Ultimate:: '+mdl.alias);
					console.log(fn);
					if(typeof fn.getVer === 'function'){
					//fn.getVer(); //test
					}
					callback();
				}	
				
			});
		}else{
			console.log(namespace + ' Module not defined!');
		}

		setTimeout(function() { // namespace does not exist, wait interval amount then try again;
			waitFor(namespace, timeout - defaultInterval, callback, interval);
		}, defaultInterval);
	}
}

function waitForD(f,namespace, timeout, callback, interval) {
	//  logTest('NsD:: waitfor:: '+namespace);
	var defaultInterval = interval>=0 ? interval : 100; // try every 100 milliseconds (10 times per second) number chosen to enhance performance;
	if (window['mPGs.'+namespace]) { // namespace exists
		callback();
	} else if (timeout <= 0) { // check if we reached the timeout
		return;
	} else {
		use(f+'.'+namespace,function(){
			callback;
		});
		
	//   logTest('Nsd:: Loop!');
	//   setTimeout(function() { // namespace does not exist, wait interval amount then try again;
	//       waitForD(namespace, timeout - defaultInterval, callback, interval);
	//   }, defaultInterval);
	}
}

function waitForDFl(f,fl,namespace, timeout, callback, interval) {
	//  logTest('NsD FDL:: waitfor:: '+namespace);
	var defaultInterval = interval>=0 ? interval : 100; // try every 100 milliseconds (10 times per second) number chosen to enhance performance;
	if (window['mPGs.'+namespace]) { // namespace exists
		callback();
	} else if (timeout <= 0) { // check if we reached the timeout
		return;
	} else {
	//   logTest('Nsd FDL:: t '+f+'.'+fl);
	//   use(f+'.'+fl,function(){
		//   callback();
	//   });
		
	//   logTest('Nsd FDL:: Loop!');
	//   setTimeout(function() { // namespace does not exist, wait interval amount then try again;
	//       waitForD(namespace, timeout - defaultInterval, callback, interval);
	//   }, defaultInterval);
	}
}

// Will be filled with canvas
var ChartJSPHP = new Array();

// You must call this function after document.ready
// function loadChartJsPhp() {
// 	// Getting all chart.js canvas
// 	var elements = document.querySelectorAll("[data-chartjs]");

// 	// Looping every canvas
// 	for (var canvas of elements) {
// 		var id = canvas.id;

// 		// Getting ctx from canvas
// 		var ctx = canvas.getContext('2d');

// 		// Getting values in data attributes
// 		var htmldata = canvas.dataset;
// 		var type = htmldata.chartjs;
// 		var data = JSON.parse(htmldata.data);
// 		var options = JSON.parse(htmldata.options);
// 		evalFunctions(options);
// 		var config = {type:type, data:data, options:options};

// 		// Creating chart and saving for later use
// 		ChartJSPHP[id] = new Chart(ctx, config);
// 	}
// };

// //Converts functions in json from strings to actual functions
// function evalFunctions(chartArray) {
// 	for (var key in chartArray) {
// 		var value = chartArray[key];
// 		if (value instanceof Array || value instanceof Object ) {
// 			evalFunctions(value);
// 		} else if (typeof value === "string" && value.indexOf('function(') == 0) {
// 			chartArray[key] = eval("(" + value + ")");
// 		}
// 	}
// }

function loadChartJsPhp() {
	// Getting all chart.js canvas
	var elements = document.querySelectorAll("[data-chartjs]");
  
	// Looping every canvas
	for (var i = 0; i < elements.length; i++) {
	  var canvas = elements[i];
	  var id = canvas.id;
  
	  // Getting ctx from canvas
	  var ctx = canvas.getContext('2d');
  
	  // Getting values in data attributes
	  var htmldata = canvas.dataset;
	  var type = htmldata.chartjs;
	  var data = JSON.parse(htmldata.data);
	  var options = JSON.parse(htmldata.options);
	  evalFunctions(options);
	  var config = { type: type, data: data, options: options };
  
	  // Creating chart and saving for later use
	  ChartJSPHP[id] = new Chart(ctx, config);
	}
  }
  
  function evalFunctions(obj) {
	for (var prop in obj) {
	  if (obj.hasOwnProperty(prop) && typeof obj[prop] === 'string' && obj[prop].indexOf('function') !== -1) {
		obj[prop] = eval('(' + obj[prop] + ')');
	  } else if (typeof obj[prop] === 'object') {
		evalFunctions(obj[prop]);
	  }
	}
  }
  

function waitForCdn(namespace, timeout, callback, interval) {
	var defaultInterval = interval>=0 ? interval : 100; // try every 100 milliseconds (10 times per second) number chosen to enhance performance;
		if (exists(namespace)) { // namespace exists
		// logTest("CDN:: namespace "+namespace+" found!");  
		callback();
		} else if (timeout <= 0) { // check if we reached the timeout
			// logTest("CDN:: timeout ended!");
			return;
		} else {
			logTest('CDN:: Namespace '+namespace+' not found!');

			//Try load from CDN
		var data = rd(namespace);
		
		if(data != ''){
		// logTest('CDN:: Module name found in memory');
		// logTest('CDN:: Content: '+JSON.stringify(data));
		// loadModule(data.name,data.version,function(){
		//   console.log(data.name + ' module loaded!');
		//   localStorage.setItem(data.alias,JSON.stringify(data));
		//   var fn = (data.alias != null) ? data.alias : null;
		//   if(fn){
		//     fn = eval(fn);
		//     if(typeof fn.getVer === 'function'){
		//       fn.getVer();
		//     }
		//   }
		// });
		}
		setTimeout(function() { // namespace does not exist, wait interval amount then try again;
			waitForCdn(namespace, timeout - defaultInterval, callback, interval);
		}, defaultInterval);
	}
}
  
function encrypt(message, key){
	var message = CryptoJS.AES.encrypt(message, key);
	return message.toString();
}
function decrypt(message, key){
	var code = CryptoJS.AES.decrypt(message, key);
	var decryptedMessage = code.toString(CryptoJS.enc.Utf8);

	return decryptedMessage;
}

function loadPaymentMethod2(method,amount,phone,u,orderID){
	// alert(orderID);
	var options = $('.pmethodoption');
	if(typeof method != 'function'){
		options.html('<img src="assets/images/icons/ajax.gif" />');
		getNs('EInit', function(){
			EInit.ajxw('/wallet/topup/method/'+method,{amount:amount,phone:phone,userID:u,orderID:orderID},function(data){
				logTest(data);
				if(data.response=="success"){
					options.html(data.data);
				}else{
					$.alertable.alert("Opps: Message not sent!");
				}
			});
		});
	}
}

var totalPlugins = (typeof activeplugins != 'undefined' && activeplugins.length) ? activeplugins.length : 10;
var numberOfLoadedPlugins = 0;
// logTest("Total Plugings:: "+totalPlugins);

function pluginLoaded(plugin){
	//Notify Loaded
	// logTest("Plugin:: "+plugin);
	numberOfLoadedPlugins += 1;
	if(numberOfLoadedPlugins == totalPlugins){
		// logTest('Plugins:: All plugins loaded');
	}
}
function rTF(url, callback) {
	getNs("EInit",function(){
		// alert('Check init here');
		EInit.ajx(url,{},function(resp){
			if(typeof callback !== 'undefined'){
			callback(resp);
			}
		});
	});
}


(function($) {
	
	"use strict";  

	

	$(window).on('load', function() {

	/* 
	MixitUp
	========================================================================== */
	// $('#portfolio').mixItUp();

	/* 
	One Page Navigation & wow js
	========================================================================== */
	// var OnePNav = $('.onepage-nev');
	// var top_offset = OnePNav.height() - -0;
	// OnePNav.onePageNav({
	//   currentClass: 'active',
	//   scrollOffset: top_offset,
	// });
	
	/*Page Loader active
	========================================================*/
	$('#preloader').fadeOut();

	// Sticky Nav
	$(window).on('scroll', function() {
		if ($(window).scrollTop() > 200) {
			$('.scrolling-navbar').addClass('top-nav-collapse');
		} else {
			$('.scrolling-navbar').removeClass('top-nav-collapse');
		}
	});

	/* slicknav mobile menu active  */
	// $('.mobile-menu').slicknav({
	//     prependTo: '.navbar-header',
	//     parentTag: 'liner',
	//     allowParentLinks: true,
	//     closeOnClick:true,
	//     duplicate: true,
	//     label: '',
	//     closedSymbol: '<i class="icon-arrow-right"></i>',
	//     openedSymbol: '<i class="icon-arrow-down"></i>',
	//     easingOpen: 'easeOutBounce',
	//     // duration:1000
	//   });

		/* WOW Scroll Spy
	========================================================*/
	//  var wow = new WOW({
	//   //disabled for mobile
	//     mobile: false
	// });

	// wow.init();

	/* Nivo Lightbox 
	========================================================*/
	// $('.lightbox').nivoLightbox({
	//     effect: 'fadeScale',
	//     keyboardNav: true,
	//   });

	/* Counter
	========================================================*/
	// if(typeof counterUp === 'function'){
	//   $('.counterUp').counterUp({
	//   delay: 10,
	//   time: 1000
	//   });
	// }


	/* Back Top Link active
	========================================================*/
		var offset = 200;
		var duration = 500;
		$(window).scroll(function() {
			if ($(this).scrollTop() > offset) {
				$('.back-to-top').fadeIn(400);
			} else {
				$('.back-to-top').fadeOut(400);
			}
		});

		$('.back-to-top').on('click',function(event) {
			event.preventDefault();
			$('html, body').animate({
				scrollTop: 0
			}, 600);
			return false;
		});

		



	});      

}(jQuery));

!function(t){"use strict";function r(t){if(t)c[0]=c[16]=c[1]=c[2]=c[3]=c[4]=c[5]=c[6]=c[7]=c[8]=c[9]=c[10]=c[11]=c[12]=c[13]=c[14]=c[15]=0,this.blocks=c,this.buffer8=i;else if(n){var r=new ArrayBuffer(68);this.buffer8=new Uint8Array(r),this.blocks=new Uint32Array(r)}else this.blocks=[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0];this.h0=this.h1=this.h2=this.h3=this.start=this.bytes=0,this.finalized=this.hashed=!1,this.first=!0}var e="object"==typeof process&&process.versions&&process.versions.node;e&&(t=global);var i,h=!t.JS_MD5_TEST&&"object"==typeof module&&module.exports,s="function"==typeof define&&define.amd,n=!t.JS_MD5_TEST&&"undefined"!=typeof ArrayBuffer,f="0123456789abcdef".split(""),a=[128,32768,8388608,-2147483648],o=[0,8,16,24],u=["hex","array","digest","buffer","arrayBuffer"],c=[];if(n){var p=new ArrayBuffer(68);i=new Uint8Array(p),c=new Uint32Array(p)};var y=function(t){return function(e){return new r(!0).update(e)[t]()}},d=function(){var t=y("hex");e&&(t=l(t)),t.create=function(){return new r},t.update=function(r){return t.create().update(r)};for(var i=0;i<u.length;++i){var h=u[i];t[h]=y(h)}return t},l=function(r){var e,i;try{if(t.JS_MD5_TEST)throw"JS_MD5_TEST";e=require("crypto"),i=require("buffer").Buffer}catch(h){returnlogTest(h),r}var s=function(t){if("string"==typeof t)return e.createHash("md5").update(t,"utf8").digest("hex");if(t.varructor==ArrayBuffer)t=new Uint8Array(t);else if(void 0===t.length)return r(t);return e.createHash("md5").update(new i(t)).digest("hex")};return s};r.prototype.update=function(r){if(!this.finalized){var e="string"!=typeof r;e&&r.varructor==t.ArrayBuffer&&(r=new Uint8Array(r));for(var i,h,s=0,f=r.length||0,a=this.blocks,u=this.buffer8;f>s;){if(this.hashed&&(this.hashed=!1,a[0]=a[16],a[16]=a[1]=a[2]=a[3]=a[4]=a[5]=a[6]=a[7]=a[8]=a[9]=a[10]=a[11]=a[12]=a[13]=a[14]=a[15]=0),e)if(n)for(h=this.start;f>s&&64>h;++s)u[h++]=r[s];else for(h=this.start;f>s&&64>h;++s)a[h>>2]|=r[s]<<o[3&h++];else if(n)for(h=this.start;f>s&&64>h;++s)i=r.charCodeAt(s),128>i?u[h++]=i:2048>i?(u[h++]=192|i>>6,u[h++]=128|63&i):55296>i||i>=57344?(u[h++]=224|i>>12,u[h++]=128|i>>6&63,u[h++]=128|63&i):(i=65536+((1023&i)<<10|1023&r.charCodeAt(++s)),u[h++]=240|i>>18,u[h++]=128|i>>12&63,u[h++]=128|i>>6&63,u[h++]=128|63&i);else for(h=this.start;f>s&&64>h;++s)i=r.charCodeAt(s),128>i?a[h>>2]|=i<<o[3&h++]:2048>i?(a[h>>2]|=(192|i>>6)<<o[3&h++],a[h>>2]|=(128|63&i)<<o[3&h++]):55296>i||i>=57344?(a[h>>2]|=(224|i>>12)<<o[3&h++],a[h>>2]|=(128|i>>6&63)<<o[3&h++],a[h>>2]|=(128|63&i)<<o[3&h++]):(i=65536+((1023&i)<<10|1023&r.charCodeAt(++s)),a[h>>2]|=(240|i>>18)<<o[3&h++],a[h>>2]|=(128|i>>12&63)<<o[3&h++],a[h>>2]|=(128|i>>6&63)<<o[3&h++],a[h>>2]|=(128|63&i)<<o[3&h++]);this.lastByteIndex=h,this.bytes+=h-this.start,h>=64?(this.start=h-64,this.hash(),this.hashed=!0):this.start=h}return this;};},r.prototype.finalize=function(){if(!this.finalized){this.finalized=!0;var t=this.blocks,r=this.lastByteIndex;t[r>>2]|=a[3&r],r>=56&&(this.hashed||this.hash(),t[0]=t[16],t[16]=t[1]=t[2]=t[3]=t[4]=t[5]=t[6]=t[7]=t[8]=t[9]=t[10]=t[11]=t[12]=t[13]=t[14]=t[15]=0),t[14]=this.bytes<<3,this.hash()}},r.prototype.hash=function(){var t,r,e,i,h,s,n=this.blocks;this.first?(t=n[0]-680876937,t=(t<<7|t>>>25)-271733879<<0,i=(-1732584194^2004318071&t)+n[1]-117830708,i=(i<<12|i>>>20)+t<<0,e=(-271733879^i&(-271733879^t))+n[2]-1126478375,e=(e<<17|e>>>15)+i<<0,r=(t^e&(i^t))+n[3]-1316259209,r=(r<<22|r>>>10)+e<<0):(t=this.h0,r=this.h1,e=this.h2,i=this.h3,t+=(i^r&(e^i))+n[0]-680876936,t=(t<<7|t>>>25)+r<<0,i+=(e^t&(r^e))+n[1]-389564586,i=(i<<12|i>>>20)+t<<0,e+=(r^i&(t^r))+n[2]+606105819,e=(e<<17|e>>>15)+i<<0,r+=(t^e&(i^t))+n[3]-1044525330,r=(r<<22|r>>>10)+e<<0),t+=(i^r&(e^i))+n[4]-176418897,t=(t<<7|t>>>25)+r<<0,i+=(e^t&(r^e))+n[5]+1200080426,i=(i<<12|i>>>20)+t<<0,e+=(r^i&(t^r))+n[6]-1473231341,e=(e<<17|e>>>15)+i<<0,r+=(t^e&(i^t))+n[7]-45705983,r=(r<<22|r>>>10)+e<<0,t+=(i^r&(e^i))+n[8]+1770035416,t=(t<<7|t>>>25)+r<<0,i+=(e^t&(r^e))+n[9]-1958414417,i=(i<<12|i>>>20)+t<<0,e+=(r^i&(t^r))+n[10]-42063,e=(e<<17|e>>>15)+i<<0,r+=(t^e&(i^t))+n[11]-1990404162,r=(r<<22|r>>>10)+e<<0,t+=(i^r&(e^i))+n[12]+1804603682,t=(t<<7|t>>>25)+r<<0,i+=(e^t&(r^e))+n[13]-40341101,i=(i<<12|i>>>20)+t<<0,e+=(r^i&(t^r))+n[14]-1502002290,e=(e<<17|e>>>15)+i<<0,r+=(t^e&(i^t))+n[15]+1236535329,r=(r<<22|r>>>10)+e<<0,t+=(e^i&(r^e))+n[1]-165796510,t=(t<<5|t>>>27)+r<<0,i+=(r^e&(t^r))+n[6]-1069501632,i=(i<<9|i>>>23)+t<<0,e+=(t^r&(i^t))+n[11]+643717713,e=(e<<14|e>>>18)+i<<0,r+=(i^t&(e^i))+n[0]-373897302,r=(r<<20|r>>>12)+e<<0,t+=(e^i&(r^e))+n[5]-701558691,t=(t<<5|t>>>27)+r<<0,i+=(r^e&(t^r))+n[10]+38016083,i=(i<<9|i>>>23)+t<<0,e+=(t^r&(i^t))+n[15]-660478335,e=(e<<14|e>>>18)+i<<0,r+=(i^t&(e^i))+n[4]-405537848,r=(r<<20|r>>>12)+e<<0,t+=(e^i&(r^e))+n[9]+568446438,t=(t<<5|t>>>27)+r<<0,i+=(r^e&(t^r))+n[14]-1019803690,i=(i<<9|i>>>23)+t<<0,e+=(t^r&(i^t))+n[3]-187363961,e=(e<<14|e>>>18)+i<<0,r+=(i^t&(e^i))+n[8]+1163531501,r=(r<<20|r>>>12)+e<<0,t+=(e^i&(r^e))+n[13]-1444681467,t=(t<<5|t>>>27)+r<<0,i+=(r^e&(t^r))+n[2]-51403784,i=(i<<9|i>>>23)+t<<0,e+=(t^r&(i^t))+n[7]+1735328473,e=(e<<14|e>>>18)+i<<0,r+=(i^t&(e^i))+n[12]-1926607734,r=(r<<20|r>>>12)+e<<0,h=r^e,t+=(h^i)+n[5]-378558,t=(t<<4|t>>>28)+r<<0,i+=(h^t)+n[8]-2022574463,i=(i<<11|i>>>21)+t<<0,s=i^t,e+=(s^r)+n[11]+1839030562,e=(e<<16|e>>>16)+i<<0,r+=(s^e)+n[14]-35309556,r=(r<<23|r>>>9)+e<<0,h=r^e,t+=(h^i)+n[1]-1530992060,t=(t<<4|t>>>28)+r<<0,i+=(h^t)+n[4]+1272893353,i=(i<<11|i>>>21)+t<<0,s=i^t,e+=(s^r)+n[7]-155497632,e=(e<<16|e>>>16)+i<<0,r+=(s^e)+n[10]-1094730640,r=(r<<23|r>>>9)+e<<0,h=r^e,t+=(h^i)+n[13]+681279174,t=(t<<4|t>>>28)+r<<0,i+=(h^t)+n[0]-358537222,i=(i<<11|i>>>21)+t<<0,s=i^t,e+=(s^r)+n[3]-722521979,e=(e<<16|e>>>16)+i<<0,r+=(s^e)+n[6]+76029189,r=(r<<23|r>>>9)+e<<0,h=r^e,t+=(h^i)+n[9]-640364487,t=(t<<4|t>>>28)+r<<0,i+=(h^t)+n[12]-421815835,i=(i<<11|i>>>21)+t<<0,s=i^t,e+=(s^r)+n[15]+530742520,e=(e<<16|e>>>16)+i<<0,r+=(s^e)+n[2]-995338651,r=(r<<23|r>>>9)+e<<0,t+=(e^(r|~i))+n[0]-198630844,t=(t<<6|t>>>26)+r<<0,i+=(r^(t|~e))+n[7]+1126891415,i=(i<<10|i>>>22)+t<<0,e+=(t^(i|~r))+n[14]-1416354905,e=(e<<15|e>>>17)+i<<0,r+=(i^(e|~t))+n[5]-57434055,r=(r<<21|r>>>11)+e<<0,t+=(e^(r|~i))+n[12]+1700485571,t=(t<<6|t>>>26)+r<<0,i+=(r^(t|~e))+n[3]-1894986606,i=(i<<10|i>>>22)+t<<0,e+=(t^(i|~r))+n[10]-1051523,e=(e<<15|e>>>17)+i<<0,r+=(i^(e|~t))+n[1]-2054922799,r=(r<<21|r>>>11)+e<<0,t+=(e^(r|~i))+n[8]+1873313359,t=(t<<6|t>>>26)+r<<0,i+=(r^(t|~e))+n[15]-30611744,i=(i<<10|i>>>22)+t<<0,e+=(t^(i|~r))+n[6]-1560198380,e=(e<<15|e>>>17)+i<<0,r+=(i^(e|~t))+n[13]+1309151649,r=(r<<21|r>>>11)+e<<0,t+=(e^(r|~i))+n[4]-145523070,t=(t<<6|t>>>26)+r<<0,i+=(r^(t|~e))+n[11]-1120210379,i=(i<<10|i>>>22)+t<<0,e+=(t^(i|~r))+n[2]+718787259,e=(e<<15|e>>>17)+i<<0,r+=(i^(e|~t))+n[9]-343485551,r=(r<<21|r>>>11)+e<<0,this.first?(this.h0=t+1732584193<<0,this.h1=r-271733879<<0,this.h2=e-1732584194<<0,this.h3=i+271733878<<0,this.first=!1):(this.h0=this.h0+t<<0,this.h1=this.h1+r<<0,this.h2=this.h2+e<<0,this.h3=this.h3+i<<0)},r.prototype.hex=function(){this.finalize();var t=this.h0,r=this.h1,e=this.h2,i=this.h3;return f[t>>4&15]+f[15&t]+f[t>>12&15]+f[t>>8&15]+f[t>>20&15]+f[t>>16&15]+f[t>>28&15]+f[t>>24&15]+f[r>>4&15]+f[15&r]+f[r>>12&15]+f[r>>8&15]+f[r>>20&15]+f[r>>16&15]+f[r>>28&15]+f[r>>24&15]+f[e>>4&15]+f[15&e]+f[e>>12&15]+f[e>>8&15]+f[e>>20&15]+f[e>>16&15]+f[e>>28&15]+f[e>>24&15]+f[i>>4&15]+f[15&i]+f[i>>12&15]+f[i>>8&15]+f[i>>20&15]+f[i>>16&15]+f[i>>28&15]+f[i>>24&15]},r.prototype.toString=r.prototype.hex,r.prototype.digest=function(){this.finalize();var t=this.h0,r=this.h1,e=this.h2,i=this.h3;return[255&t,t>>8&255,t>>16&255,t>>24&255,255&r,r>>8&255,r>>16&255,r>>24&255,255&e,e>>8&255,e>>16&255,e>>24&255,255&i,i>>8&255,i>>16&255,i>>24&255]},r.prototype.array=r.prototype.digest,r.prototype.arrayBuffer=function(){this.finalize();var t=new ArrayBuffer(16),r=new Uint32Array(t);return r[0]=this.h0,r[1]=this.h1,r[2]=this.h2,r[3]=this.h3,t},r.prototype.buffer=r.prototype.arrayBuffer;var v=d();h?module.exports=v:(t.md5=v,s&&define(function(){return v}))}(this);
function getNS(ns) {
	var parts = ns.split(".");
	for (var i = 0, len = parts.length, obj = window; i < len; ++i) {
		if(typeof obj[parts[i]] != 'undefined'){
			// console.log('found');
			obj = obj[parts[i]];
		}else{
			// console.log('hana');
			return;
		}
		// console.log(parts[i]);
	}
	return obj;
}
function searchArray(array,item, valuetofind) {
    for (i = 0; i < array.length; i++) {
        if (array[i][item] === valuetofind) {
            return array[i];
        }
    }
    return -1;
}
function _cacheScript(c,d,e){
var a=new XMLHttpRequest;
	a.onreadystatechange=function(){
		4==a.readyState&&(200==a.status?localStorage.setItem(c,JSON.stringify({content:a.responseText,version:d})):console.warn("error loading "+e));
	};
	a.open("GET",e,!0);
	a.send();
}
function getVarName(what){
	for(var name in window){
		if(window[name]==what){
			return name;
		}
	}
	return '';
}

function updateCe(cE){
	var obj_json = JSON.parse(cE);
	var encrypted = obj_json.ciphertext;
	var salt = CryptoJS.enc.Hex.parse(obj_json.salt);
	var iv = CryptoJS.enc.Hex.parse(obj_json.iv);   
	var passphrase = engineSettings.c;
	// console.log('this');
	var key = CryptoJS.PBKDF2(passphrase, salt, { hasher: CryptoJS.algo.SHA512, keySize: 64/8, iterations: 999});
	// console.log('this');

	var decrypted = CryptoJS.AES.decrypt(encrypted, key, { iv: iv});
	// console.log('this');
	// console.log(decrypted);
	window.settings = Object.assign({}, JSON.parse(decrypted.toString(CryptoJS.enc.Utf8)),  window.settings); //decrypted.toString(CryptoJS.enc.Utf8)
	// console.log('this');
}

function rd(y, d = ''){
	return (typeof window.settings[y] === "undefined") ? d : window.settings[y];
}
	
function st(y,v){
	if(v){
		window.settings[y] = v;
	}
}
function Debuger(){
	this._debug = false;
	this.log = function(msg) {
		if (this._debug) {
			logTest('Debug: ' + msg);
			// waitForElementToDisplayE('#console',function(){
			// 	var element = $('#console .terminal');
			// 	if(element.length)element.append(msg + '<br />');
			// });
		}
	};
}
var Debug = new Debuger();
function isIE(userAgent){
	userAgent = userAgent || navigator.userAgent;
	return userAgent.indexOf("MSIE") > -1 || userAgent.indexOf("Trident") > -1 || userAgent.indexOf("Edge") > -1 ;
}
var Debugger = function(gState, klass){
this.debug = {};
	if(gState && klass.isDebug){
		for(var m in console){
			if(typeof console[m] == 'function'){
			this.debug[m] = console[m].bind(window.console, klass.toString()+ " :");
			}
		}
	}else{
		for(var m in console){
			if(typeof console[m] == 'function'){
			this.debug[m] = function(){};
			}
		}
	}
	return this.debug;
};

var _log = function(){
	args = [].slice.call(arguments);
	args.unshift(console);
	return console.log.bind.apply(console.log, args) ;
};

// // no debug mode
// _log('this should not appear');

// // turn it on
// DEBUGMODE = true;

// _log('you should', 'see this', {a:1, b:2, c:3});
// console.log('--- regular log ---');
// _log('you should', 'also see this', {a:4, b:8, c:16});

// // turn it off
// DEBUGMODE = false;

// _log('disabled, should not appear');
// console.log('--- regular log2 ---');

function logTest(msg){
	// console.log('ENV::'+rd('env'));
	if(rd('env') == 0){
		// DEBUGMODE = true;
		Logger.info(msg);
		// turn it off
		// DEBUGMODE = false;
	}
}
function isDefined(itm){
	if(typeof itm != 'undefined'){
		return true;
	}
	return false;
}
var canSplit = function(str, token){
	return (str || '').split(token).length > 1;         
};
function getSplit(str, token){
	var splt = (str || '').split(token);
	if(splt.length > 1){
		return splt;
	}
	return false;
}

function scrollToSection(id,fset) {
	var hoffset = (fset == null) ? -165 : fset;

	var navHeight = $('#header').height() + $('.navbar ').height()+hoffset;
	if($('#' + id).length){
		var scrollTo = $('#' + id).offset().top + navHeight;
		// alert(scrollTo);
		$('html,body').animate({
		'scrollTop': scrollTo
		}, 500);    
	}
}

function scrollToItem(parent,id,fset) {
	var hoffset = (hoffset == null) ? -165 : fset;
	var parent = (parent) ? parent : null;
	if(parent){
	if($('#' + id).length){
		var scrollTo = $('#' + id).offset().top + hoffset;
		$(parent).animate({	'scrollTop': scrollTo }, 500);    
	}
	}
}

function ucfirst(str) {
    if (typeof str !== 'string') {
        console.warn('ucfirst called with non-string:', str);
        return '';
    }
    return str.charAt(0).toUpperCase() + str.slice(1);
}

// function longpressed() {
    // console.log('longpress');
    
	
    // window.addEventListener(
        // 'click',
		// function (){
			// alert('this');
		// },
        // captureClick,
        // true // <-- This registers this listener for the capture
             //     phase instead of the bubbling phase!
    // );
// }

var i = 0;
function loadBind(container) {
    container = container || document;

    var unboundForEach = Array.prototype.forEach,
        forEach = Function.prototype.call.bind(unboundForEach);

    // Bind submit fns
    forEach(container.querySelectorAll('[fns]'), function (el) {
        el.removeEventListener('submit', handlerBestS);
        el.addEventListener('submit', handlerBestS);
    });

    // Long press + click
    forEach(container.querySelectorAll('[fnl]'), function (el) {
        el.removeEventListener('long-press', handlerLdrLong);
        el.addEventListener('long-press', handlerLdrLong);

        el.removeEventListener('click', handlerLdr);
        el.addEventListener('click', handlerLdr);
    });

    // Live UI
    forEach(container.querySelectorAll('[lvui]'), function (el) {
        addToLive.call(el);
    });

    forEach(container.querySelectorAll('[pitm]'), function (el) {
        addToLiveTr.call(el);
    });

    // Lazy loader (now works for AJAX content!)
    lazyLoad(container);
}
function loadBindO(){
	// console.warn('loadBind','Test');
	var unboundForEach = Array.prototype.forEach,
			forEach = Function.prototype.call.bind(unboundForEach);
	// forEach(document.querySelectorAll('[fn]'), function (el) {
	// 	el.addEventListener('click', handlerBest);
	// });
	forEach(document.querySelectorAll('[fns]'), function (el) {
			el.removeEventListener('submit', handlerBestS);
			el.addEventListener('submit', handlerBestS);
		});
		var vi = 1;
	forEach(document.querySelectorAll('[fnf]'), function (el) {
// 
	});
	forEach(document.querySelectorAll('[fnl]'), function (el) {
// 			console.log('Here... log '+vi );vi++;
			el.removeEventListener('long-press', function(e) {
				// stop the event from bubbling up
				e.preventDefault();
				handlerLdrLong(e);
				
			});
			el.addEventListener('long-press', function(e) {
				// stop the event from bubbling up
				e.preventDefault();
				handlerLdrLong(e);
				
			});

			el.removeEventListener('click', handlerLdr);
			el.addEventListener('click', handlerLdr);
		});
	
	forEach(document.querySelectorAll('[lvui]'), function (el) {
			addToLive.call(el);
		});

	forEach(document.querySelectorAll('[pitm]'), function (el) {
		addToLiveTr.call(el);
	});

	container = container || document;
	lazyLoad(container); 
	
}

function supportsSpread() {
	try {
	new Function('foo(...params);');
	return true;
	} catch(e) {
	return false;
	}
}
var v =0;
function handlerLoadModules(e){
	e.target.removeEventListener(e.type, arguments.callee);
	logTest(v);v++;
	var f = this.getAttribute("f");
	var fn = this.getAttribute("fn");
	var args = this.getAttribute("prms");
	
	if(fn){
		var funct = window['mPGs'][fn];
		if(typeof funct != 'function'){
			getNsD(rd('myNsRts')+f,fn,function(){
				logTest('Preloader: '+fn+' ready!');
			});
		}
	}
}

// logTest('Supports Spread:: '+supportsSpread());
function handlerBestS(){
	var f = this.getAttribute("f");
	var fn = this.getAttribute("fns");
	var args = this.getAttribute("prms");
	if(fn){
		var funct = window['mPGs'][fn];
		if(typeof funct === 'function'){
			if(args){
				args = args.split(',');
				// if(supportsSpread()){
				//     funct.call(this, ...args);
				// }else{
					funct.call.apply(funct, [this].concat(_toConsumableArray(args)));
				// }

			}else{
				funct.call(this);
			}
		}else{
			getNsD(rd('myNsRts')+f,fn,function(){
				var funct = window['mPGs'][fn];
				if(typeof funct === 'function'){
					if(args){
							args = args.split(',');
							// if(supportsSpread()){
							//     funct.call(this, ...args);
							// }else{
								funct.call.apply(funct, [this].concat(_toConsumableArray(args)));
							// }
			
					}else{
							funct.call(this);
					}
				}
			});
		logTest('handlerBestS:: "'+fn+'" was not found!','warn');
		}
	}
}

function _toConsumableArray(arr) {
	return (
	_arrayWithoutHoles(arr) ||
	_iterableToArray(arr) ||
	_unsupportedIterableToArray(arr) ||
	_nonIterableSpread()
	);
}

function _nonIterableSpread() {
	throw new TypeError(
	"Invalid attempt to spread non-iterable instance.\nIn order to be iterable, non-array objects must have a [Symbol.iterator]() method."
	);
}

function _unsupportedIterableToArray(o, minLen) {
	if (!o){return;}
	if (typeof o === "string"){return _arrayLikeToArray(o, minLen);}
	var n = Object.prototype.toString.call(o).slice(8, -1);
	if (n === "Object" && o.varructor){ n = o.varructor.name;}
	if (n === "Map" || n === "Set"){return Array.from(o);}
	if (n === "Arguments" || /^(?:Ui|I)nt(?:8|16|32)(?:Clamped)?Array$/.test(n)){
	return _arrayLikeToArray(o, minLen);
	}
}

function _iterableToArray(iter) {
	if (
	(typeof Symbol !== "undefined" && iter[Symbol.iterator] != null) ||
	iter["@@iterator"] != null
	)
	return Array.from(iter);
}

function _arrayWithoutHoles(arr) {
	if (Array.isArray(arr)) return _arrayLikeToArray(arr);
}

function _arrayLikeToArray(arr, len) {
	if (len == null || len > arr.length) len = arr.length;
	for (var i = 0, arr2 = new Array(len); i < len; i++) {
	arr2[i] = arr[i];
	}
	return arr2;
}
function handlerBest(){
	var f = (typeof this.getAttribute("f") == 'undefined') ? this.getAttribute("f") : 'mPGs';
	// logTest('Check Loaded wait');
	var ths = this;
	getNs('mPGs',function(){
		var f = ths.getAttribute("f");
		var fl = ths.getAttribute("fl");
		var fn = ths.getAttribute("fn");
		var args = ths.getAttribute("prms");
		if(fn){
			var funct = window['mPGs'][fn];
			if(typeof funct === 'function'){
			// alert('found');
				if(args){
					args = args.split(',');
					funct.call.apply(funct, [ths].concat(_toConsumableArray(args)));
				}else{
					funct.call(this);
				}
			}else{
				// logTest('handlerBest:: "'+fn+'" was not found!','warn');
				getNsDFl(rd('myNsRts')+f,fl,fn,function(){
					var funct = window['mPGs'][fn];
					if(typeof funct === 'function'){
						if(args){
							args = args.split(',');
							funct.call.apply(funct, [this].concat(_toConsumableArray(args)));
						}else{
							funct.call(this);
						}
					}
				});
				
			}
		}
	});
}

function handlerBestD(){
	var f = (typeof this.getAttribute("f") == 'undefined') ? this.getAttribute("f") : 'mPGs';
	// logTest('Check Loaded wait');
	var ths = this;
	getNs('mPGs',function(){
		var f = ths.getAttribute("f");
		var fl = ths.getAttribute("fl");
		var fn = ths.getAttribute("fn");
		var args = ths.getAttribute("prms");
		if(fn){
			var funct = window['mPGs'][fn];
			if(typeof funct === 'function'){
			logTest('found');
				if(args){
					args = args.split(',');
					funct.call.apply(funct, [ths].concat(_toConsumableArray(args)));
				}else{
					funct.call(this);
				}
			}else{
			logTest('not found');
				getNsD(rd('myNsRts')+f+fl,fn,function(){
				var funct = window['mPGs'][fn];
				if(typeof funct === 'function'){
					if(args){
							args = args.split(',');
							// if(supportsSpread()){
							//     funct.call(this, ...args);
							// }else{
								funct.call.apply(funct, [this].concat(_toConsumableArray(args)));
							// }
			
					}else{
							funct.call(this);
					}
				}
			});
			logTest('handlerBestD:: "'+fn+'" was not found!','warn');
			}
		}
	});
}

function handlerLdr(){
	// console.log('Eloader');
	var fn = this.getAttribute("fnl");
	if(fn){
		lnk(fn);
		// ELoader.openPage(params);
	}
}

function handlerLdrLong(e){
	console.log('Handler Long click');
	console.log(e.target);
}




// Ensure the UI object is initialized
var UI = window.UI || {};
UI.update = UI.update || [];
UI.updatetr = UI.updatetr || [];
UI.toupdate = UI.toupdate || [];

//setOnce per page
var cookiesInit = false;

//Update UI
function liveUpdate(item, value){
	if(typeof UI === 'object'){
		if(UI.update[item]){
			UI.update[item].val = value;		}
	}
}

function liveUiUpdates(updates,broadcast){
	var broadcast = (typeof broadcast !== 'undefined') ? broadcast : false;
	console.warn("liveUiUpdates:: ", updates);

	if(typeof updates === 'object'){
		liveUpdate(updates['widget'], updates['data']);
		// $.each(updates, function(item,value) {
		// 	console.log('Item',item,' value',value);
		// 	liveUpdate(item, value);
		// });
		if(broadcast){
			authNotify('update',rd('bID'),updates);
		}	
	}else{
		alert('Updates not configured correctly!');
	}
}

//End Edits september 2024


	//TODO:: Remove redundant code
	/*Redundant*/
	var update = [];
	function addToLive(){
		
		var tag = this.getAttribute("lvui");
		
		
		if(!UI.update.hasOwnProperty(tag)){
			// console.log("Add to live "+tag);
			
			// addToCookies(tag);

			var cookies = getCookie('lvui');
			var widgets = getCookie('lvui_widgets');
				
			// console.log("COOKIE::", cookies);
			// console.log("WIDGETS::", widgets);

			// UI.toupdate.push(tag);
			UI.update[tag] = (function(el){
				return {
				set val(v){
					el.textContent = v;
					$('[lvui='+tag+']').html(v)//.addClass('edited');
				},
				get val(){
					return el.textContent;
				}
				};
				})(this);
		}
	
		
	}
	

	/*Confirm Redundant*/
	function addItemsToLive(tag,elem){
		if(!UI.update.hasOwnProperty(tag)){
			UI.update[tag] = (function(el){
				return {
					set val(v){
						el.textContent = v;
					},
					get val(){
						return el.textContent;
					}
				};
			})(this);
		}
	}

	
//Interval test
// i = 0;
// setInterval(function() {
// // 	console.log('this'+i);
// // 	console.log(UI.update);
// 	liveUpdate('support-timer',++i);
// 	liveUpdate('support-tickets',++i);
// }, 1000);




//Edit September 2024
// Utility to add an instance if not already present
function addInstance(tag, element) {
    if (!UI.updatetr[tag]) {
        UI.updatetr[tag] = [];
    }

    // Check if this element is already registered
    var isAlreadyAdded = UI.updatetr[tag].some(instance => instance.el === element);

    if (!isAlreadyAdded) {
        UI.updatetr[tag].push(createInstance(element));
    }
}

// Create an instance object for managing updates
function createInstance(element) {
    return {
        el: element,
        updateContent: function (itm, val) {
            var target = $(this.el).find('[chl=' + itm + ']');
            if (target.html() !== val) { // Only update if content has changed
                target.html(val);
                // target.addClass('edited');
            }
        }
    };
}

// Function to add an element to UI.updatetr
function addToLiveTr() {
    var tag = this.getAttribute("pitm");
	// console.log('ADDED PITM TAG :: '+tag);
    addInstance(tag, this);
}

// Function to update elements based on pitm and values
function liveUpdateTr(item, values) {
    if (UI.updatetr.hasOwnProperty(item)) {
        UI.updatetr[item].forEach(instance => {
            $.each(values, function (itm, val) {
                instance.updateContent(itm, val);
            });
        });
    }
}

function liveUpdateTrOW(item, values, edited) {
    edited = (typeof edited !== 'undefined') ? edited : false;

    if (typeof UI === 'object' && UI.updatetr.hasOwnProperty(item)) {
        // Iterate over each instance of elements with the same pitm
        $.each(UI.updatetr[item], function (index, instance) {
            $.each(values, function (itm, val) {
                // console.log('Updating instance', index, 'of', item, 'with', itm, '::', val);
                instance.update(itm, val);
            });
        });
    }
}


function addToLiveTrOW() {
    var tag = this.getAttribute("pitm");

    // Initialize the array if it doesn't exist
    if (!UI.updatetr.hasOwnProperty(tag)) {
        UI.updatetr[tag] = [];
    }

    // Check if this element is already stored to avoid duplicate entries
    var isAlreadyAdded = UI.updatetr[tag].some(function(instance) {
        return instance.el === this;
    }, this);

    if (!isAlreadyAdded) {
        UI.updatetr[tag].push({
            el: this,
            update: function (itm, val) {
                var elem = $(this.el).find('[chl=' + itm + ']');
                // Check if the content is different
                if (elem.html() !== val) {
                    elem.html(val);
                    // elem.addClass('edited'); // Add class only if the content has changed
                }
            }
        });
    }
}

function addToLiveTrO1() {
    var tag = this.getAttribute("pitm");

    // Loop through all elements with the matching pitm value
    $('[pitm="' + tag + '"]').each(function () {
		console.log('ADDED Pitm '+tag);
        var el = this;

        UI.updatetr[tag] = (function (el) {
            return {
                set val(v) {
                    console.log('Updating ' + v[0] + '...' + $(el).find('[chl=' + v[0] + ']').length);
                    console.log($(el).find('[chl=' + v[0] + ']').html() + ' :: ' + v[1]);
                    var elem = $(el).find('[chl=' + v[0] + ']');
                    elem.html(v[1]);
                    // elem.addClass('edited');
                },
                set styl(v) {
                    var elem = $(el).find('[chl=' + v[0] + ']');
                    elem.html(v[1]);
                    // elem.addClass('edited');
                },
                get val() {
                    return $(el).html();
                }
            };
        })(el);
    });
}


function addToLiveTrO(){
	var tag = this.getAttribute("pitm");
	
	// if(!UI.updatetr.hasOwnProperty(tag)){
		// console.log(tag);
		UI.updatetr[tag] = (function(el){
			return {
				set val(v){
					console.log('Updating '+v[0]+'...'+$(el).find('[chl='+v[0]+']').length);
					console.log($(el).find('[chl='+v[0]+']').html() +' :: '+v[1]);
					var elem = $(el).find('[chl='+v[0]+']'); 
						elem.html(v[1]);
						// elem.addClass('edited');
				},
				set styl(v){
					var elem = $(el).find('[chl='+v[0]+']'); 
					elem.html(v[1]);
					// elem.addClass('edited');
				},
				get val(){
					return $(el).html();
				}
			};
		})(this);
	// }
	
}




function liveUpdateTrO(item, values, edited){
	// console.log(UI.updatetr);
	// console.log(UI.updatetr.hasOwnProperty(item));
	// logTest(item+' :: '+values);
	var edited = (typeof edited !== 'undefined') ? edited : false;
	if(typeof UI === 'object'){
		// var values = JSON.parse(values);
		$.each(values, function (itm, val) {
			// console.log('Update-> '+item+' with '+itm+' :: '+val);
			if(UI.updatetr.hasOwnProperty(item)){
				// console.log('Found... update '+' with '+itm+' :: '+val);
				UI.updatetr[item].styl = [itm,val];
			}
		});
	}
}



function liveUpdateTable(table, items, funct, broadcast){
	// if($(table).length == 0){
	// 	return;
	// }

	var broadcast = (typeof broadcast !== 'undefined') ? broadcast : false;

	if(typeof items === 'object'){		
		$.each(items, function (item, values) {
			// console.log('tbody tr.'+item);
			// console.log(values);
			if($(table).has('tbody tr.'+item).length > 0){
				liveUpdateTr(item, values, false);
			}else{
				if($('#tsUpdate').length == 0){
					return;
				}
				//get template
				var markup = $('#tsUpdate').html();

				var i = $(table+' > tbody >tr').length +1;
				values.i = i;
				if(values.product_name){
					//replace literals
					var result = processTemplate(markup,values);

					//TODO:: only add if not 0
					//create tr
					$(table).find("tbody").append(result);
				}
			}
			
			//run funct
			// if(typeof window[funct] === 'function'){
				window[funct](item,values);
			// }
			
		});

		if(broadcast){
			// alert('update tr');
			authNotify('updatetr',rd('bID'),{table:table,items:items,funct:funct});
		}
	}
}

function liveUpdatePitm(items, funct, broadcast) {
    broadcast = (typeof broadcast !== 'undefined') ? broadcast : false;

    if (typeof items === 'object') {
        $.each(items, function (item, values) {
            // console.log('Processing pitm:', item);
            // console.log('Values:', values);

            // Find all instances of elements with the pitm attribute
            var elements = $('*[pitm="' + item + '"]');

            if (elements.length > 0) {
                elements.each(function () {
                    liveUpdateTr(item, values, false);
                });
            }

            // Run the custom function if defined
            if (typeof window[funct] === 'function') {
                window[funct](item, values);
            }
        });

        if (broadcast) {
            // TODO: Implement the broadcasting logic if needed
            // authNotify('updatetr', rd('bID'), { table: table, items: items, funct: funct });
        }
    }
}


function liveUpdatePitmO(items, funct, broadcast){
	// if($(table).length == 0){
	// 	return;
	// }

	var broadcast = (typeof broadcast !== 'undefined') ? broadcast : false;

	if(typeof items === 'object'){		
		$.each(items, function (item, values) {
			// console.log('*[pitm="'+item+'"]');
			// console.log(values);
			if($('*[pitm="'+item+'"]').length > 0){
				liveUpdateTr(item, values, false);
			}
			
			//run funct
			// if(typeof window[funct] === 'function'){
				window[funct](item,values);
			// }
			
		});

		if(broadcast){
			// alert('update tr');
			//TODO:: boradcast pitm
			// authNotify('updatetr',rd('bID'),{table:table,items:items,funct:funct});
		}
	}
}


function processTr(item,values){
    if(values.product_quantity <=0){
        // console.log('tr.'+item);
        $("tr."+item).remove();
    }
}

function processTemplate(markup,values){
	//standard literals
	return markup.replace(/\@\(\$([^)]+)\)/g, function(matched){
		var matched = matched.replace(/[^a-zA-Z _]/g, "");
		return values[matched];
	});
}

function sendToUI(itm){
    if(typeof itm === 'object'){
      $.each(itm, function(key, value) {
          liveUpdate(key,value);
      });
    }
  }

function loadModule(module,version,callback,async){
	var module = (typeof module != 'undefined') ? module : null;
	var version = (typeof version != 'undefined') ? version : '1.0';
	var callback = (typeof callback != 'undefined') ? callback : null;
	var async = (typeof async != 'undefined') ? async : true;
	var cdn = rd('cdn');

	if(module){
		// logTest('require '+module);
		var file = cdn+'/assets/plugins/ilebora/'+module+'/js/'+version;
		// alert(file);
		requireScript({
			'id': md5(file),//md5(cdn+'/assets/plugins/ilebora/'+module+'/'+version+'/'+module), 
			'uri': file,// cdn+'/assets/plugins/ilebora/'+module+'/'+version+'/'+module+'.js', 
			'async': async, 
			'version': version, 
			'callback': callback
		});
	}
}


    
function in_array(value, array) {
	return array.indexOf(value) > -1;
}
function containsString(str,find){
	if(str){
		if ( str.indexOf(find) > -1 ) {
			return true;
		} 
	}
	return false;
}
function stringToBoolean(string){
	// var string = string.toString();
	var string = string+"";
	switch(string.toLowerCase().trim()){
		case "true": 
		case "yes": 
		case "1": 
		return true;

		case "false": 
		case "no": 
		case "0": 
		case null: 
		return false;

		default: 
		return Boolean(string);
	}
}
function showOverlay(){
	// forceNs('ELoader', function(){
	// 	if(typeof ELoader.showOverlay == 'function'){
	// 		ELoader.showOverlay();
	// 	}
	// });
	// overlayLoader.show('Saving...');
}

function hideOverlay(){
	// forceNs('ELoader', function(){
	// 	if(typeof ELoader.showOverlay == 'function'){
	// 		ELoader.hideOverlay();
	// 	}
	// });
	overlayLoader.hide();
}
function doLogout(url){
	// console.log('Logout');
	showOverlay();
	// window.location.replace('?r=logout');

	var url = (typeof url !== 'undefined') ? url : '';
	redirectTo(url, true);
}
function doLogin(lnk){
	// console.log('Login');
	showOverlay();
	
	if(typeof lnk !== 'undefined'){
		return redirectTo(lnk, true);
	}

	window.location.reload(true);
}

function doSync(lnk){
	// $('.mn-overlay').show();
	showOverlay();
	ELoader.openPage(lnk);
	//TODO:: openPage logic
	alert('TODO:: openPage logic');
}

function authNotify(command,user,data){
	if(typeof authChannel !== 'undefined'){
		// alert(command+' '+user);
		authChannel.postMessage({cmd:command,usr:user,update:data});
	}else{
		logTest('authChannel not configured');
	}
}

function authChannelInit(channelName) {
    if (!('BroadcastChannel' in window)) {
        console.warn("BroadcastChannel not supported in this browser");
        return;
    }

	if(!channelName){
		channelName = 'auth_'+rd('prjName')+rd('prjVersion');
	}

    if (!channelName) {
        console.error("authChannelInit: channelName required");
        return;
    }

    window.authChannel = new BroadcastChannel(channelName);

    window.authChannel.onmessage = function(e) {
        const { cmd, usr, lnk, update } = e.data || {};

        if (cmd === 'logout' && usr === rd('bID')) {
            doLogout();
        }

        if (cmd === 'login' && usr === rd('bID')) {
            // alert('doLogin');
            doLogin(lnk);
        }

        if (cmd === 'sync') {
            doSync(lnk);
        }

        if (cmd === 'update' && usr === rd('bID')) {
			console.log(cmd, update);
            liveUiUpdates(update);
        }

        if (cmd === 'updatetr' && usr === rd('bID')) {
            liveUpdateTable(update.table, update.items, update.funct);
        }

		//New 
		if (cmd === 'fact' && usr === rd('bID')) {
			console.log('Broadcast Received... ', update)
			FactBus.dispatch(update, {
				source: 'broadcast'
			});
		}

    };
}

function redirectToDefault(role){
	let url = '';
	switch(role){
		case 'guest': url = '/'; break;
		case 'client': url = '/portal'; break;
		case 'admin':
		case 'developer': url = '/bo'; break;
		default: url = '/'; break;
	}
	
	return url;
}

function encMenu(str){
	var enc = md5(str);
	return enc;
}
function lnk(str, options = {}) {
    if (!str) return;

    const encryptedKeys = []; // reserved for encryption (optional)
    const parts = str.split('-');
    const params = {};
    let pathParts = [];

    // basic encryption stub (can be replaced later)
    // const encMenu = val => btoa(val); // base64 as placeholder

    parts.forEach(pair => {
        const [key, val] = pair.split(':');
        if (!key || val === undefined) return;

        const enc = encryptedKeys.includes(key) ? encMenu(val) : val;
        params[key] = enc;

        // convert to route path order: p = prefix, r = route, sb = sub, sbc = child
        if (['p', 'r', 'sb', 'sbc'].includes(key)) {
            pathParts.push(enc);
        }
    });

    // build clean path
    let url = pathParts.filter(Boolean).join('/');

    // handle query string if `req` exists
    if (params.req) {
        const q = typeof params.req === 'object' ? new URLSearchParams(params.req).toString() : params.req;
        url += '?' + q;
    }

    if (options.returnOnly) {
        return url;
    }

    // choose how to navigate
    if (options.newTab) {
        window.open(url, '_blank');
    } else {
        window.location.href = url;
    }
}
function lnkO(str){
	var params = {};
	var encripted = ['r','sb','sbc'];
	forceNs("ELoader", function(){
    	if(str){
			if(str == 'close'){
				$.alertable.confirm("Close this?", {
					html: true
				}).then(function() {
					window.close();
				}, function() {
					logTest('Confirmation canceled');
				});
			}

    		var links = str.split('-');
			// console.log(links);
    		links.forEach(function (link) {
    			var parsedlink = link.split(":");
    			var enc = in_array(parsedlink[0], encripted)
    			? encMenu(parsedlink[1])
    			: parsedlink[1];
				if(parsedlink[0] == 'req'){
					if(Array.isArray(parsedlink[1])){
						var data = parsedlink[1];
						querystring = encodeQueryData(data);
						params[parsedlink[0]] = querystring;
					}else{
						params[parsedlink[0]] = enc;
					}
		
				}
    			params[parsedlink[0]] = enc;
    		});
			
		// console.log('here');
    	// console.log(params);
		//TODO::include GET params
    	    return ELoader.openPage(params);
    	}
	});
}

function encodeQueryData(data) {
	var ret = [];
	for (let d in data)
	  ret.push(encodeURIComponent(d) + '=' + encodeURIComponent(data[d]));
	return ret.join('&');
 }

function getSetStyleRule(sheetName, selector, rule) {
    var stylesheet = document.querySelector('link[href*=' + sheetName + ']');

    if( stylesheet ){
        stylesheet = stylesheet.sheet;
        stylesheet.insertRule(selector + '{ ' + rule + '}', stylesheet.cssRules.length);
    }

    return stylesheet;
}
// console.log(getSetStyleRule('main', 'body', 'background:red'));
  


$(document).ready(function(){
    $('body').on('click', '[f]', function(e){
        myEventHandler(e);
        var ths = this;
        var target = e.target;
        if(!target.getAttribute('f')){
            e.stopPropagation();
            target = e.target.parentElement;
        }
        var fnparams = target.getAttribute('prms');
            var fn;
			var el = target.getAttribute('f');
			if(el){
				if(el.startsWith("Client")){
					var fnstring = target.getAttribute('fn');
					var levels = getNS('mPGs.'+fnstring);
					
					if (typeof levels === "function"){
						fnparams = fnparams.split(',');
						levels.call.apply(levels, [ths].concat(_toConsumableArray(fnparams)));
					}else{
						alert(el+' Function not found!');
					}
				}else{
					var fnstring = target.getAttribute('fn');
					// console.log('mPGs.' + el + '.' +fnstring);
					var levels = getNS('mPGs.' + el + '.' +fnstring);
					// console.log(levels);

					// if (typeof levels === "function"){
					// 	fnparams = fnparams.split(',');
					// 	levels.call.apply(levels, [ths].concat(_toConsumableArray(fnparams)));
					// }else{
					// 	alert('Function not found!');
					// }
				}  
			}
        
    });
    
    
    $("input").keyup(function(event) { //TODO fix onkeyup
      	logTest("Hello from the other side");
		var btn = $(this);
		var form = btn.closest('form');
		var mfd = form.serializeArray();
		forceNs("EInput",function(){
			if(EInput.setFocus(false).validValsF(mfd,form,false)){
				logTest('valid');
			}
		});
    });
});
    // var lbctn = 0;
// $(document).bind('DOMNodeInserted', function(e) {
//     loadBind();
	// logTest('Load Bind '+lbctn); lbctn++;
	// window.addEventListener('mouseover', function (e) {
	// 	updateMask(e.target); //TODO create mask for edit
	// });
	// $(".albart").each(function() {
	// 	$(this).on("error", function(){
	// 		var ref = (typeof $(this).attr('data-ref') != 'undefined') ? $(this).data('ref') : 'work';
	// 		//TODO:: fix numerous loads
	// 		//console.warn('IMAGE: not found!');
	// 		$(this).attr('src', 'assets/images/icons/noavatar_'+ref+'.png');
	// 	});
	// });
// });

window._lazyCache = window._lazyCache || new Set();

$(function(){
	lazyLoad(document);
})

function lazyLoad(container = document) {
    let imgs = container.querySelectorAll('img.lazy[data-src]');

    imgs.forEach(function (img) {
        let real = img.dataset.src;
        if (!real) return;

        // Wrap automatically if not wrapped
        let wrap = img.closest('.lazy-wrap');
        if (!wrap) {
            wrap = document.createElement('div');
            wrap.className = 'lazy-wrap loading';
            img.parentNode.insertBefore(wrap, img);
            wrap.appendChild(img);
        } else {
            wrap.classList.add('loading');
        }

        // Preserve placeholder size (only if provided)
        if (!img.style.width && img.width) img.style.width = img.width + 'px';
        if (!img.style.height && img.height) img.style.height = img.height + 'px';

        // ALREADY LOADED? Use cache
        if (window._lazyCache.has(real)) {
            img.src = real;
            wrap.classList.remove('loading');
            wrap.classList.add('loaded');
            return;
        }

        let pre = new Image();
        pre.onload = function () {
            img.src = real;
            window._lazyCache.add(real);
            wrap.classList.remove('loading');
            wrap.classList.add('loaded');
        };

        pre.onerror = function () {
            wrap.classList.remove('loading'); // keep placeholder
        };

        pre.src = real;
        img.removeAttribute('data-src');
    });
}


$(document).ready(function () {
    const observerCallback = function(mutationsList) {
        for (let mutation of mutationsList) {
            if (mutation.type === 'childList' && mutation.addedNodes.length > 0) {
                mutation.addedNodes.forEach(node => {
                    if (node.nodeType === 1) {
                        loadBind(node);   // Only process new node
                    }
                });
            }
        }
    };

    const observer = new MutationObserver(observerCallback);

    observer.observe(document.body, {
        childList: true,
        subtree: true
    });
});

function onElementInserted(containerSelector, elementSelector, callback) {

    var onMutationsObserved = function(mutations) {
        mutations.forEach(function(mutation) {
            if (mutation.addedNodes.length) {
                var elements = $(mutation.addedNodes).find(elementSelector);
                for (var i = 0, len = elements.length; i < len; i++) {
                    callback(elements[i]);
                }
            }
        });
    };

    var target = $(containerSelector)[0];
    var config = { childList: true, subtree: true };
    // var MutationObserver = window.MutationObserver || window.WebKitMutationObserver;
    // var observer = new MutationObserver(onMutationsObserved);    
	var MutationObserver = window.MutationObserver || window.WebKitMutationObserver || window.MozMutationObserver;

	if (MutationObserver) {
		var observer = new MutationObserver(onMutationsObserved);
		// Continue using the observer as needed
		try{
			observer.observe(target, config);
		}catch(e){
			console.warn(e);
		}
	} else {
		// MutationObserver is not supported, handle accordingly
		logTest("MutationObserver is not supported in this browser");
	}
    

}

$(document).ready(function(){
	onElementInserted('body', '.livedt', function(element) {
		// console.log(element);
		var tag = element.getAttribute("lvui");
		if(!UI.toupdate.hasOwnProperty(tag)){
			// logTest("Add to live "+tag);
			UI.toupdate.push(tag);
		}
		// alert('found '+tag);
		
	});

});

function updateMask(target) {
    var elements = document.getElementsByClassName("highlight-wrap");
    var hObj;
    if (elements.length !== 0) {
        hObj = elements[0];
    } else {
        hObj = document.createElement("div");
        hObj.className = 'highlight-wrap';
        hObj.style.position = 'absolute';
        hObj.style.backgroundColor = '#205081';
        hObj.style.opacity = '0.5';
        hObj.style.cursor = 'default';
        hObj.style.pointerEvents = 'none';
        document.body.appendChild(hObj);
    }
    var rect = target.getBoundingClientRect();
    hObj.style.left = (rect.left + window.scrollX) + "px";
    hObj.style.top = (rect.top + window.scrollY) + "px";
    hObj.style.width = rect.width + "px";
    hObj.style.height = rect.height + "px";

}

//Addons 10Nov2022
function isOverflown(element) {
	return element.scrollHeight > element.clientHeight || element.scrollWidth > element.clientWidth;
}

function clearConsole(){
	console.API;
	if (typeof console._commandLineAPI !== 'undefined') {
		console.API = console._commandLineAPI; //chrome
	} else if (typeof console._inspectorCommandLineAPI !== 'undefined') {
		console.API = console._inspectorCommandLineAPI; //Safari
	} else if (typeof console.clear !== 'undefined') {
		console.API = console;
	}

	console.API.clear();
	logTest('Clean start...');
}

$.fn.moveUp = function() {
	before = $(this).prev();
	$(this).insertBefore(before);
};

$.fn.moveDown = function() {
	after=$(this).next();
	$(this).insertAfter(after);
};

function myRound(value, decimals) {
	return Number(Math.round(value + 'e' + decimals) + 'e-' + decimals);
}

function setCookie(name,value,days) {
    var expires = "";
    if (days) {
        var date = new Date();
        date.setTime(date.getTime() + (days*24*60*60*1000));
        expires = "; expires=" + date.toUTCString();
    }
    document.cookie = name + "=" + (value || "")  + expires + "; path=/";
}
function getCookie(name) {
    var nameEQ = name + "=";
    var ca = document.cookie.split(';');
    for(var i=0;i < ca.length;i++) {
        var c = ca[i];
        while (c.charAt(0)==' ') c = c.substring(1,c.length);
        if (c.indexOf(nameEQ) == 0) return c.substring(nameEQ.length,c.length);
    }
    return null;
}
function eraseCookie(name) {   
    document.cookie = name +'=; Path=/; Expires=Thu, 01 Jan 1970 00:00:01 GMT;';
}

// var encodeGetParams = p => 
//   Object.entries(p).map(kv => kv.map(encodeURIComponent).join("=")).join("&");

function encodeGetParams(p) {
	return 'req='+btoa(p);

	// return Object.entries(p)
	//   .map(function (kv) {
	// 	return kv.map(encodeURIComponent).join("=");
	//   })
	//   .join("&");
}

function isLoggedIn(){
	var auth = getCookie('authSessID');
	console.log(auth);
	// alert(typeof auth);
	
	if(auth != null){
		alert('isLoggedIn');
		return true;
	}

	alert('Not logged in');

	return false;
}

// isLoggedIn();

var cookieRegistry = [];

//TODO:: get js to know authSess change
function listenCookieChange(cookieName, callback) {
    setInterval(function() {
        if (cookieRegistry[cookieName]) {
            if (getCookie(cookieName) != cookieRegistry[cookieName]) { 
                // update registry so we dont get triggered again
                cookieRegistry[cookieName] = getCookie(cookieName); 
                return callback();
            } 
        } else {
            cookieRegistry[cookieName] = readCookie(cookieName);
        }
    }, 1000);
}

function readCookie(name) {
    const match = document.cookie.match(new RegExp('(?:^|; )' + name + '=([^;]*)'));
    return match ? decodeURIComponent(match[1]) : null;
}

//Popups
var codeEditorWindow = null;

function openOrFocusCodeEditor2(url) {
    // Check if the code editor window is already open
    if (codeEditorWindow === null || codeEditorWindow.closed) {
        // Open a new tab for the code editor
        codeEditorWindow = window.open(url, '_blank');
    } else {
        // If the code editor window is already open, focus on it
        codeEditorWindow.focus();
    }
}

function openOrFocusCodeEditor(url, hash) {
    // Construct the full URL with the dynamic hash value
    const fullURL = url + hash;

    // Check if the code editor window is already open
    if (codeEditorWindow === null || codeEditorWindow.closed) {
        // Open a new tab for the code editor
        // codeEditorWindow = window.open(fullURL, '_blank');
		codeEditorWindow = window.open(url, '_blank', 'width=800,height=600');
    } else {
        // If the code editor window is already open, focus on it
        codeEditorWindow.location.href = fullURL;
        codeEditorWindow.focus();
    }
}

//Generic
function closeAll(){
	if(typeof EPop != 'undefined'){
		EPop.closePop();
	}
	return;
}

function vibrate(duration = 200) {
    if (!('vibrate' in navigator)) {
        console.warn('Vibration API not supported on this device.');
        return false;
    }

    try {
        // Allow single value or pattern (array)
        if (Array.isArray(duration) || typeof duration === 'number') {
            navigator.vibrate(duration);
            return true;
        } else {
            console.error('Invalid vibration pattern:', duration);
            return false;
        }
    } catch (e) {
        console.error('Vibration failed:', e);
        return false;
    }
}
//
function showAlert(content, style = 'info', duration = 10) {
	var cls = (typeof content.class !== 'undefined') ? content.class : null;

    if(!localStorage.getItem('notifyID_'+cls)){
        localStorage.setItem('notifyID_'+cls, 1);
    }

    var getPrev = localStorage.getItem('notifyID_'+cls);
    var newId = (typeof content.id !== 'undefined') ? content.id : null;
    
    if(newId){
        console.log(getPrev + '::' + newId);
        if (parseInt(getPrev) < parseInt(newId) && typeof content !== 'undefined') {
            localStorage.setItem('notifyID_'+cls, newId);
            var stt = {};
            if (typeof content.title !== 'undefined') {
                stt.title = content.title;
            }
            if (typeof content.info !== 'undefined') {
                stt.text = content.info;
            }
            if (typeof content.image !== 'undefined') {
                stt.image = "<img src='" + content.image + "' width='40' '/>";
            }

            // Play sound
            var audio = new Audio('assets/sound/doink.mp3');
            audio.play();

			alertBora.set('notifierPosition', 'top-right').set('notifierDelay', 4);

            var notification = alertBora.notify(stt, style, duration);
		
			return notification || null;
        }
    }
}


//FormJourney Handler
// Register the plugin
var formJourney = addPlugin(
    BoraPlugin,
    {
        pluginName: 'formJourney',
        journeys: {}, // store the registered journeys
        init: function() {
            BoraPlugin.init.call(this); // call base init
            console.log('formJourney plugin initialized.');

            // Attach a global submit listener for forms with data-ajax="true"
            var self = this;
            $(document).on('submit', 'form[data-ajax="true"]', function(e) {
                e.preventDefault();
                var $form = $(this);
                var journey = $form.data('handler') || 'default';

                // Trigger pre-submit hooks if they exist
                if (typeof appHooks !== 'undefined') {
                    let result = appHooks.callHook('form:beforeSubmit', $form);

					if (result === false) {
						console.warn("Submission cancelled by beforeSubmit hook.");
						return; // IMPORTANT: stop here!
					}
                }

                // Execute registered journey or default
                let handler = self.journeys[journey] || self.default;
				handler($form, function(resp) {
					self._afterSubmit($form, resp);
				});
            });
        }
    }
);

// Add methods
formJourney.addMethods({
    registerJourney: function(name, callback) {
        if (!this.journeys[name]) {
            this.journeys[name] = callback;
        }
    },

    default: function($form, done) {
        var url = $form.attr('action');
        var method = $form.attr('method') || 'POST';
        var data = $form.serialize();

        $.ajax({
            url: url,
            method: method,
            data: data,
            success: function(resp) {
                console.log('Default form saved', resp);
                if (typeof done === 'function') done(resp);
            },
            error: function(err) {
                console.error('Form error', err);
                if (typeof done === 'function') done(err);
            }
        });
    },

    _afterSubmit: function($form, resp) {
        if (typeof appHooks !== 'undefined') {
            appHooks.callHook('form:afterSubmit', $form, resp);
        }
    },
	// Add this inside `formJourney.addMethods({...})`
	run: function(journeyName, $form, done) {
		if (typeof this.journeys[journeyName] !== 'function') {
			console.warn(`Journey "${journeyName}" not found.`);
			return false;
		}

		// Pre-submit hooks (just like auto mode)
		if (typeof appHooks !== 'undefined') {
			let result = appHooks?.call('form:beforeSubmit', $form);
			if (result === false) {
				console.warn("Manual journey cancelled by beforeSubmit hook.");
				return false;
			}
		}

		// Execute it
		this.journeys[journeyName]($form, (resp) => {
			this._afterSubmit($form, resp);
			if (typeof done === 'function') done(resp);
		});

		return true;
	},
	
});

// Debug & initialize
formJourney.setDebug(true);
formJourney.init();


$.fn.attachDragger = (function(){
    var attachment = false, lastPosition, position, difference;
    $( $(this).selector ).on("mousedown mouseup mousemove",function(e){
        if( e.type == "mousedown" ) attachment = true, lastPosition = [e.clientX, e.clientY];
        if( e.type == "mouseup" ) attachment = false;
        if( e.type == "mousemove" && attachment == true ){
            position = [e.clientX, e.clientY];
            difference = [ (position[0]-lastPosition[0]), (position[1]-lastPosition[1]) ];
            $(this).scrollLeft( $(this).scrollLeft() - difference[0] );
            $(this).scrollTop( $(this).scrollTop() - difference[1] );
            lastPosition = [e.clientX, e.clientY];
        }
    });
    $(window).on("mouseup", function(){
        attachment = false;
    });
});