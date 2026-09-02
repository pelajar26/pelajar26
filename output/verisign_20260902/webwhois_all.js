/**-------------------------------------------------------------------------------
*    The information in this document is proprietary
*    to VeriSign and the VeriSign Registry Business.
*    It may not be used, reproduced or disclosed without
*    the written approval of the General Manager of
*    VeriSign Global Registry Services.
*
*    PRIVILEDGED AND CONFIDENTIAL
*    VERISIGN PROPRIETARY INFORMATION
*    REGISTRY SENSITIVE INFORMATION
*
*    Copyright (c) 2013 VeriSign, Inc.  All rights reserved.
*-------------------------------------------------------------------------------*/

/* Plugin makeMenu */
// the semi-colon before function invocation is a safety net against concatenated
// scripts and/or other plugins which may not be closed properly.
;(function ( $, win, doc, UND/*undefined*/ ) {
    $.fn.fireIt = function(fn){
        return fn.apply(this, arguments);
    };
    $.fn.chainIt = function(fn){
        fn.apply(this, arguments);
        return this;
    };

        // Create the defaults once
        var pluginName = "makeMenu",
            defaults = {
              action: 'click',
              sMenuEle: '.sbOptions', 
              cEle: 'a', 
              pEle: 'li', 
              toggleIcon: false,
              afterLoad: function(){ }, 
              beforeShow: function(){ }, 
              afterShow: function() { }, 
              beforeHide: function(){ }, 
              afterHide: function() { }
        };

        // The actual plugin constructor
        function Plugin ( element, options ) {
            var that = this;
                that.element = element;
                that.$el = $(element);                
                that.settings = $.extend( {}, defaults, options );
                that._defaults = defaults;
                that._name = pluginName;
                that._initialized = false;
                that._visible = false;
                //that.init(); //initialize when you are sure the document is ready for accessing the DOM elements
                that.docEvent = function () {
                  that.hideMenu();
                };
        }

        Plugin.prototype = {
                init: function () {                       
                        var that = this;
                        // this.showMenu(this.element, this.settings); 
                        if(that._initialized === true)
                        {
                          return this;//chaining
                        }                        
                        that.$el
                        .on("click", function (event) {                            
                            that.toggleIt();
                            event.stopPropagation();
                        })
                        .find(that.settings.sMenuEle)
                        .chainIt(function () {
                            that._visible = $(this).is(":visible");
                        })
                        .click(function (e) {
                            e.stopPropagation();
                        });

                        if ($.isFunction(that.settings.afterLoad))
                            that.settings.afterLoad.call(that);
                        that._initialized = true;
                        return this; //chaining
                },

                showMenu: function (ele, settings) {                  
                  var that = this;
                  that.settings.beforeShow.call(that);                  
                  that.$el.find(that.settings.sMenuEle).show();
                  if(that.settings.toggleIcon){                                               
                     that.$el.addClass("active");
                  }
                  //Add a event to hide the menu when document is clicked anywhere
                  $(doc).bind('click', that.docEvent);
                  that.settings.afterShow.call(that);
                  return that;//chaining
                },

                hideMenu: function() {
                  var that = this;
                    that.settings.beforeHide.call(that);
                    that.$el.find(that.settings.sMenuEle).hide();
                    if(that.settings.toggleIcon){
                        that.$el.removeClass("active");
                    }
                    //unbind the event to hide the menu from document object
                    $(doc).unbind('click', that.docEvent);
                    that.settings.afterHide.call(that);
                    return that;//chaining
                },

                toggleIt: function() {
                    var that = this;
                    var $mEl = that.$el.find(that.settings.sMenuEle);
                    if($mEl.is(":visible")) {
                        that.hideMenu();
                    }else{
                        that.showMenu();
                    }
                    return that;//chaining
                }
        };

        // A really lightweight plugin wrapper around the constructor,
        // preventing against multiple instantiations
        $.fn[ pluginName ] = function ( options, fnName ) {
                return this.each(function() {
                        var plugin = $.data( this, "plugin_" + pluginName ) ;
                        if ( !plugin) {
                            plugin = new Plugin( this, options );
                            $.data( this, "plugin_" + pluginName, plugin );

                            $(function(){//when document is loaded...
                              plugin.init();//initialize the plugin
                              if($.isFunction(plugin[fnName]))
                                plugin[fnName]();
                            });
                        }else{
                                plugin.init();//initialize the plugin.
                                if($.isFunction(plugin[fnName]))
                                        plugin[fnName]();
                        }
                });
        };

})( jQuery, window, document );


/* Defining startsWith function */
if (typeof String.prototype.startsWith !== 'function') {
  String.prototype.startsWith = function (str) {
    return this.slice(0, str.length) === str;
  };
}

//load I18 bundles
function localize_page(language){
   var setpath = "lang/";  
    jQuery.i18n.properties({
        name: 'Whois',
        path: setpath, 
        mode: 'map',
        language: language,
        async: true,
        callback: function(){
            $("[data-localize]").each(function() {
                $(this).html(jQuery.i18n.prop($(this).attr('data-localize')));                
            });
            var normalQueryHelpMsg = getI18Message('normal.query.help');                      
            $(".query-help").html(normalQueryHelpMsg);
            $(".query-help").find(".accordion").on("click", function() {
                $(this).next().toggle();
                $(this).toggleClass("arrowDown arrowUp");
            });
            if (typeof window.cookieconsent != "undefined") {
                window.cookieconsent.initialise({
                    "palette": {
                        "popup": {
                            "background": "#237afc"
                        },
                        "button": {
                            "background": "#fff",
                            "text": "#237afc"
                        }
                    },
                    "theme": "classic",
                    "position": "top",
                    "static": true,
                    "showLink": false,
                    "content": {
                        "message": jQuery.i18n.prop('cookie.headertext'),
                        "dismiss": "X"
                    }
                });
            }
        }
    });
}

function getI18Message(key, value) {
  if (key == "" || ((key === "webwhois.error.InvalidInput" ||
    key === "webwhois.success.echo.query") && (value == null || typeof value == undefined))) {
    return "";
  } else {
    //encode html characters in the user query string
    value = $('<div/>').text(value).html();
    if (key === "webwhois.success.echo.query") {
      value = ("<b>" + value + "</b>");
    }
    return jQuery.i18n.prop(key, value);
  }
}

function getParameterByName(name) {
  name = name.replace(/[\[]/, "\\\[").replace(/[\]]/, "\\\]");
  var regexS = "[\\?&]" + name + "=([^&#]*)";
  var regex = new RegExp(regexS);
  var results = regex.exec(window.location.search);
  if(results == null)
    return null;
  else
    return decodeURIComponent(results[1].replace(/\+/g, " "));
}

getLang =  getParameterByName('language');
localize_page(getLang);

/* Plugin - Tabs */
$.fn.tabIt = function(fn) {
    return this.each(function(){
      var p = $(this);       
          p.find('.tab_nav a')                   
            .filter(":first-child")
              .addClass("active")
              .end()
          .end()
          .find('.tab_block')
            .hide()
          .end()
          .find(".tab_nav + .tab_block")
            .show()          
          .end() 
          .find('.tab_nav a')
            .click(function () {
              var link = $(this);
              var a = link.index();
              link.addClass("active")
                  .siblings()
                  .removeClass("active");
              clearResultsAndAbortPending();
              p.find(".tab_block")
                  .hide()
                  .removeClass('selected')
                  .find("ul.tldmenu")
                    .removeClass("cmenu")
                  .end()            
                  .eq(a)
                    .show()
                    .addClass('selected') 
                    .find("ul.tldmenu")
                      .addClass("cmenu")
                        .end()                
                    .find(".searchbox")
                      .focus();
            }); 

            fn();
    });
};//$.fn.tabIt

// Tooltip Plugin

$.fn.tootTip = function(msg) {
  
  var changeTooltipPosition = function(event) {
    var tooltipX = event.pageX - 8;
    var tooltipY = event.pageY + 8;
    $('div.tooltip').css({
      top: tooltipY,
      left: tooltipX
    });
  };

  var clz = 'tooltip';
  var showTooltip = function(msg){
    return function(event) {
      $('div.'+clz).remove();
      $('<div class="'+clz+'">' + msg + '</div>')
        .appendTo('body');
      changeTooltipPosition(event);
    };
  };

  var hideTooltip = function() {
    $('div.tooltip').remove();
  };

  return this.each(function(){
    $(this).on({
      mousemove: changeTooltipPosition,
      mouseenter: showTooltip(msg),
      mouseleave: hideTooltip
    });
  }); //return this;
}; //tooltip

   
$("#awhoistab").tabIt(function(){
    var cTldMenu = $(".sbHolder"),
    cTldMenuCopy = cTldMenu.clone();
    cTldMenuCopy.find("ul.tldmenu").removeClass("cmenu");      
    cTldMenuCopy.insertBefore($(".fluid-textbox").not(":first"));
    $(".help-panel").show();
});


jQuery.fn.relToTitle = function() {
  return this.each(function() {
    var _ = $(this);
    var value = $.trim(_.text());
    _.attr("title", value);
    if (_.hasClass('disabled')) {
      _.attr("title", "");
      _.tootTip(getI18Message('webwhois.NoAdvanceOptions'));
      _.off("click");
    }
  });
};

jQuery.fn.ellipsis = function(len) {
  len = len || 10;
  return this.each(function() {
    $(this).text(function(i, text) {
      var t = $.trim($(this).text());
      if (t.length > len) {
        return t.substring(0, len - 1) + "...";
      }
      return t;
    });
  });
};



$(function() {  

  $(document).ajaxStart(function() {
    $('#loading').show();
  }).ajaxComplete(function() {
    $('#loading').hide();
  });

  $(document).on('click', 'div.collapsible h3', function(e){  
    var _icon = $(this).find(".ui-icon");    
    $(this).next("div.ui-accordion-content").toggle("fast", function(){         
       _icon.toggleClass("ui-icon-triangle-1-e ui-icon-triangle-1-s");     
    });    
  }); 

  var justOneTLD = $("ul.tldmenu:first li a").length <= 1,
    formH = $("form").height(),
    wrapperH = $("#wrapper").height(),
    tldMenuH = $(".sbOptions").height(),
    language = getParameterByName("language");

    if (language === null || language === "") {
      language = "en_US";
    }

  if(justOneTLD) {  
  var _ibox = $(".sbHolder");           
      _ibox.off("click");
      _ibox.find("a.sbSelector").addClass("defaultmouse").text($.trim($("ul.cmenu li a[rel=checked]").attr("title")) || $.trim($("ul.cmenu li a").not(".disabled").first().attr("title")));
      _ibox.find(".sbToggle").remove();        
  }
  else {
      var menu = $(".sbHolder").makeMenu({
      toggleIcon: true,
      beforeShow: function() {
        $(".locales_wrapper").hide();
      }
    });
  }

    
  var hrefLink = $(".ad-search a").attr("href"),
      nameURL = "http://whois.nic.name",
      errorMsgWrap = $("<h2 style='margin-bottom:0'>"+getI18Message('webwhois.Redirecting')+"</h2><p>" + nameURL + "</p>"),
      $formValues = $("#aWhoisearchform .searchbox, #aWhoisearchform .searchbtn");
  $('#awhoistab ul li a').each(function() {
    var _link = $(this);        

    _link.attr("title", $.trim(_link.text()));
    _link.on("click", function(e) {
      e.stopPropagation();
      var tld = $(this).attr("title");
      if (tld === ".name") {
        $formValues.attr('disabled', true);
        $("#whois_results").prepend(errorMsgWrap).addClass("ui-message-error");
        window.parent.location = nameURL;
      } else {
        $formValues.attr('disabled', false);
        clearResultsAndAbortPending();
      }
      $(".sbSelector")
        .attr("title", tld)
        .text(tld).ellipsis(12);   

      var pageHref = $(".ad-search a");
      pageHref.attr("href", hrefLink + "?" + "currenttld=" + tld);

      $(".sbHolder").removeClass("active");
      menu.makeMenu({}, 'hideMenu');      

    });

    _link.relToTitle().ellipsis(12);

  });

  $("#awhoistab a.sbSelector").each(function(){    
    var _ = $(this),
    checkedTitle = $.trim($("ul.cmenu li a[rel=checked]").attr("title")),
    checkedText  = $.trim($("ul.cmenu li a[rel=checked]").text()),
    title        = $.trim($("ul.cmenu li a").not(".disabled").first().attr("title")),
    text         = $.trim($("ul.cmenu li a").not(".disabled").first().text());
    _.attr("title", checkedTitle || title).text(checkedText || text).ellipsis(12); 
      if(text === "" && title === "") {      
        $("a,div,h3").not(".accordion").off("click");
        $(".tab_nav a").not(".active").hover(function(){
           $(this).css( "background-position", "-2px -37px" );
        })
        $(".searchbox, .searchbtn").attr('disabled', true);
        $("#whois_results").html(getI18Message('webwhois.error.NoApprovedTLDS')).addClass("ui-message-error");
        showResult();
      }
  }); 

  var getTld= $.trim(getParameterByName("currenttld")),
      lang = $.trim(getParameterByName("language")),
      queryParam = (lang) ? "&" : "?",
      findMatchingTld = $("ul.tldmenu:first li a").filter(function (index, value) {             
        if(getTld !== "" && !$(this).hasClass("disabled")) {
          return $.trim($(this).text()) === getTld;
        }
      }), 
      pageHref = $(".ad-search a");       
      if(getTld !== "" && findMatchingTld.eq(0).text() === getTld) {
        $(".sbSelector").attr("title", getTld).text(getTld).ellipsis(12);
      }
      (lang !== "") ? pageHref.attr("href", pageHref.attr("href") 
                + "?" + "currenttld=" + getTld 
                + "&language=" + lang) 
                    : pageHref.attr("href", pageHref.attr("href") 
                + "?" + "currenttld=" + getTld)      

  
  $('.tab_nav a').wrapInner("<div />");

  $(".selector").on("click", function(h) {
    h.stopPropagation();
    $(".locales_wrapper").show();
    if (menu) {
      menu.makeMenu({}, 'hideMenu');
    }
  });

  $(".locale_name").text($.trim($("#" + language).text()));

  $(".locale .close").click(function() {
    $(".locales_wrapper").hide();
  });

  $(".locales_wrapper").click(function(h) {
    h.stopPropagation()
  });

  $("body").click(function() {
    $(".locales_wrapper").hide()
  });  

 
});
 

function splitResponse(textMsg,query,idnQuery){
    var result = new Object();
    var lines = textMsg.split('\n');
    var range = getResultRange(lines);
    var queryString = query;
    if (query != idnQuery) {
        queryString = query + " (" + idnQuery + ")";
    }
    result['query_string'] = (getI18Message("webwhois.success.echo.query",queryString) + '\n');
    result['header'] = ((lines.slice(0, range['start'])).join('\n'));   
    result['result_main'] = splitResultMain(lines.slice(range['start'], range['end']));    
    if (range['end'] < lines.length) {
        result['result_db'] = (lines[range['end']]);
        if (range['end'] < lines.length - 1) {
            result['footer'] = ((lines.slice(range['end'] + 1)).join('\n'));
        }
    } 
    return result;
}

function splitResultMain(lines) {
  var result = []
  for (var i = 0; i < lines.length; i++) {
    var domain = {line: lines[i].replace(/^[ ]+/g,'')};
    var eppStatus = getEppStatus(domain.line);
    if (eppStatus) {
      domain.eppStatus = eppStatus;
      domain.eppStatusCode = getEppStatusCode(lines[i]);
    }
    result.push(domain);
    }  
    return result;
}

function getEppStatus(line) {
  return (line.startsWith('Domain Status:') || line.startsWith('Status:') || line.startsWith('Name Server Status:'));
};

function getEppStatusCode(line) {
    var start = line.indexOf(":") + 2;
    var end = line.indexOf(" http");
    if (end == -1) { // For backward compatibility till AWIP+CNRA changes are deployed in CTLD & CORE DB
        end = line.length;
    }
  return line.slice(start, end);
}

function getResultRange(lines) {
    var result = new Object();
    var resultPattern = new RegExp("^[\\w ]+: .*");
    var start = -1;

    for (var i = 0; i < lines.length; i++) {
        if (start === -1 && ((lines[i].indexOf('No match for ') === 0) || resultPattern.test(lines[i]))) {
            start = i;
        }
        if (lines[i].indexOf('>>>') === 0) {
            return {start: start, end: i};
        }
    }
    return {start: start, end: lines.length};
}

function showResult() {
  $("#whois_results").show();
  $("#captcha_msg").hide();
  $("#captcha_container").hide();
}
function showCaptcha() {
  $("#whois_results").hide();
  $("#captcha_msg").show();    
  $("#captcha_container").show();
}

function showLoading() {
  $("#whois_results").hide();
  $("#captcha_msg").hide();  
}

var pendingAjaxRequest;

function clearResultsAndAbortPending() {
    $("#whois_results").removeClass("ui-message-error").empty();
    $("#pagination, #result_abort,#version, #status, #footer").hide();
    if (pendingAjaxRequest) {
        pendingAjaxRequest.abort();
    }
}

function collapseHelpMenu() {    
    $("#normal-help .ui-accordion-content").hide("fast", function() {
        $("#normal-help .ui-icon").removeClass("ui-icon-triangle-1-s").addClass("ui-icon-triangle-1-e");
    });  
}


function getWhoIs() {   

    var query = $('div.selected input[name="userInput"]').val();
    var radioValue = $('div.tab_nav a.active').attr('id');
    var verifyAuth = $('input[name="authpage"]').val();

    var tldValue = '';
    var errorMsgWrap = $("<h2 style='margin-bottom:0'>"+getI18Message('webwhois.error.WeAreSorry')+"</h2>");
    var restPath = "rest/whois";
    if (verifyAuth) {
        restPath = "../rest/whois"
    }

    tldValue = $(".sbSelector").attr("title");
    tldValue = tldValue.replace(".", "");
    tldValue = $.trim(tldValue);

    var data = {
      q: query,
      tld: tldValue,
      type: radioValue
    }

    if ($('#captcha_container').find('#g-recaptcha-response').length > 0) {
        data['grecaptcha_response_field'] = grecaptcha.getResponse();
    }   
 
    clearResultsAndAbortPending();
    showLoading();
   
    pendingAjaxRequest = $.get(restPath, data)
      .done(function(result) {
      pendingAjaxRequest = null;
      var textMsg = result['message'],
        whois_response = splitResponse(textMsg,result['query'],result['idnQuery']),
        resultTemplate = $('#result-template').html(),
        compiledResultTemplate = Handlebars.compile(resultTemplate);
      whois_response['eppStatusDescEnabledTld'] = result ['eppStatusDescEnabledTld'] === 'true';
      $("#whois_results").html(compiledResultTemplate({
        result: whois_response
      }));
      showResult();
    }).fail(function(eventObject, status, error) {
      pendingAjaxRequest = null;
      showErrorMessage(eventObject, status, error);
    });
}

/***** Show EPP Status Reference Modal dialog *****/

function getEppStatRef(eppStatusCode, curPos) {

  var restPath = "rest/epp/statuscode/" + eppStatusCode;

  pendingAjaxRequest = $.get(restPath)
    .done(function(result) {
      pendingAjaxRequest = null;
      result['whatDoesItMean'] = result['whatDoesItMean'].split('\n');
      result['shouldYouDoSomething'] = result['shouldYouDoSomething'].split('\n');
      var modalSource = $("#epp-stat-ref").html(),
          compiledModalTemplate = Handlebars.compile(modalSource);
      $("#epp-stat-data").html(compiledModalTemplate(result));
      $('#eppStatusReference').modal({show:true});
      rePos(curPos);
    })
    .fail(function() {
      $("#epp-stat-data").html(getI18Message('webwhois.error.system.unavailable'));
      $('#eppStatusReference').modal({show:true});
      rePos(curPos);
    });
    $(window).resize(rePos(curPos));
}


function captchaCallback () {
	disableBtn();
	grecaptcha.render('captcha_container', 
	{   'sitekey' : '6Lf0pl0UAAAAAJUaYqK39DAMJ-CVvvm1a_diwabi', 
	    'theme' : 'light' , 
        'callback' : enableBtn  
    } )
}

function disableBtn() {
	$(".searchbtn").attr('disabled', 'disabled').css('opacity', 0.5);
}

function enableBtn() {
	$(".searchbtn").removeAttr('disabled').css('opacity' , 1.0);
}

function showErrorMessage(jqXHR, status, error) {
   var errorMesg = "",
     errorMsgWrap = $("<h2 style='margin-bottom:0'>" + getI18Message('webwhois.error.WeAreSorry') + "</h2>");

   if (typeof error === "string" && error === "Internal Server Error") {
     errorMesg = getI18Message('webwhois.error.system.unavailable');
     $("#whois_results").html(errorMesg).addClass("ui-message-error");
     showResult();
   } else if (jqXHR.status === 429) {
        try {
		    grecaptcha.reset();
		    disableBtn();
	    }
	    catch(err) {
		    captchaCallback();
	    }
        showCaptcha();
   } else if (jqXHR.status === 400 || jqXHR.status === 500) {
        result = jQuery.parseJSON(jqXHR.responseText);
        var responseCode = result['message'];
        var queryString = result['query'];
        if (responseCode === "webwhois.error.Port43.RateLimit" || responseCode === "webwhois.error.Port43.FilteredOut") {
            errorMsgWrap.append(getI18Message(responseCode));
            $("#whois_results").html(errorMsgWrap).addClass("ui-message-error");
      } else {
            errorMesg = getI18Message(responseCode,queryString);
            $("#whois_results").html(errorMesg).addClass("ui-message-error");
        }  
        showResult();
   } else if (jqXHR.status === 414) {
        errorMesg = getI18Message('webwhois.error.RequestLengthExceeded');
        $("#whois_results").html(errorMesg).addClass("ui-message-error");
        showResult();
   } else if (jqXHR.status === 401) {
        window.location = window.location.href;
   } else if (jqXHR.status === 403) {
        errorMsgWrap.after(getI18Message('webwhois.error.RateLimitedByApache'));
        $("#whois_results").html(errorMsgWrap).addClass("ui-message-error");
        showResult();
   } else if (error !== 'abort') {
        errorMesg = getI18Message('webwhois.error.system.unavailable');
        $("#whois_results").html(errorMesg).addClass("ui-message-error");
        showResult();
   }
}


function createResult(textMsg) {
  var qresult = {};

  qresult['records'] = $.map(textMsg.domainResultsStr, function(response) {
    var record = {};
    var lines = response.split("\n");
    lines = removeEmptyLinesAtEnd(lines);
    var pos = 0;
    var basic = []; // details before contact

    while (pos < lines.length && !lines[pos].startsWith("Contact")) {
      var details = {line: lines[pos]};
      var eppStatus = getEppStatus(lines[pos]);
      if (eppStatus) {
        details.eppStatus = eppStatus;
        details.eppStatusCode = getEppStatusCode(lines[pos]);
      }
      basic.push(details);
      pos++;
    };
    record.basic = basic;

    var contacts = []
    while (pos < lines.length && !lines[pos].startsWith("Name Server")) {
        var result = processContact(lines, pos)
        contacts.push(result.contact);
        pos = result.pos;
    }
    record.contacts = contacts;
    var startPos = pos;
    while (pos < lines.length && !lines[pos].startsWith("Contact")) {
      pos++;
    };
    record.remaining = lines.slice(startPos, pos)

    var billingContacts = []
    while (pos < lines.length) {
        var contact;
        var result = processContact(lines, pos)
        billingContacts.push(result.contact);
        pos = result.pos;
    }
    record.billingContacts = billingContacts;
    return record;
  });
  qresult["lastUpdatedDate"] = getI18Message('webwhois.message.LastUpdatedDate');
  qresult["timestamp"] = textMsg.lastUpdatedTime;
  return qresult;
}

function removeEmptyLinesAtEnd(lines) {
    var index;
    for (index = lines.length; index > 0 && lines[index - 1].trim() === ""; index--);
    return lines.slice(0, index)
}

function processContact(lines, pos) {
      var startPos = pos;
    var len = lines[pos].length;
    var contactType = lines[pos].slice(14, len);

      pos++;
      var contactName = "";
      while (pos < lines.length && !lines[pos].startsWith("Contact Type:") && !lines[pos].startsWith("Name Server")) {
        if (lines[pos].startsWith(contactType+" Name:")) {
          contactName = lines[pos];
        }
        pos++;
      };
      var contact = {
        name: contactName,
        details: lines.slice(startPos+1, pos)
      }
      return {contact: contact, pos: pos};
}


$(function(){  

  $("#captcha_msg").append(getI18Message('webwhois.error.CaptchaMessage'));
  $("#errorMessageHeader").append(getI18Message('webwhois.error.WeAreSorry'));  

  /* Submitting the form */

  var $awhoisform = $("#aWhoisearchform");
  
  $awhoisform.on("submit", function(e) {
    $("#awhoistab .sbHolder").removeClass("active");
    collapseHelpMenu();    
    var isIndexPage = $('input[name="thinlookup"]').val() === "yesthinlookup",
      checkSearchType = $.trim($('#awhoistab .tab_nav a.active').attr('id'));
    $("#pagination,#result_abort, #version, #status, #footer").hide();
    getWhoIs();
    return false;
  });

  $awhoisform.find("input:text").keydown(function(e) {
    if (e.key === 'Enter') {
      e.preventDefault();
    }
    return true;
  }).end();

  $awhoisform.find("input:text").keyup(function(e) {
    if (e.key === 'Enter')
      $awhoisform.submit();
    return true;
  }).end();

  /* Querying parameters from browser window */
  
  // The tld variable previously got its value from the "tld" parameter, but 
  // has been changed since the "tld" parameter is being used for the new BERS TLD functionality
  var input = getParameterByName("q"),
      tld = getParameterByName("currenttld"), 
      type = getParameterByName("type");
  
  if(type != null && type != ""){
    $("#"+type).addClass("active").siblings().removeClass("active");
    $('.tab_nav a.active').click();
  }

  if(input != null && input != ""){
    $('div.selected input[name="userInput"]').val(input);
  }

  if(tld != null && tld != ""){
    $(".sbSelector").text(tld);
    $("a.sbSelector").attr("title",tld).ellipsis(12);    
  }

  if(input!=null && tld != null && type != null){ 
    getWhoIs();   
  }   
  
  $('input.inputbox-domain').focus();
  var isInIFrame = window.location !== window.parent.location;
  if (isInIFrame) {
    $("#wrapper").css("margin", "0");
  }

  $(".tab_nav a div").each(function() {    
    if ($(this).height() > 21) {
      $(this).parent().addClass('double');
    }
  });

 });  
 

/**-------------------------------------------------------------------------------
Iframe Resizing 
*-------------------------------------------------------------------------------*/
var pipepath = "www.verisigninc.com/products-and-services/domain-name-services/whois";

function getArgs() {
  var args = [];
  var query = location.search.substring(1);
  var pairs = query.split("&");
  for (var i = 0; i < pairs.length; i++)
  {
    var pos = pairs[i].indexOf('=');
    if (pos == -1) continue;
    var argname = pairs[i].substring(0, pos);
    var value = pairs[i].substring(pos + 1);
    args[argname] = unescape(value);
  }
  return args;
}

function loadPage(page,queryString) {
  var args = getArgs();
  var qString = "";
  
  if (args.ppath)
  {
    pipepath = args.ppath;
  }
  
  if (queryString)
  {
    qString = queryString
  }
  
  var language = parseLanguage(window.location.search.substring(1), "language");  
  window.location.href = page + ".html?ppath=" + pipepath + "&language=" + language + "&" + qString;
  
}

function loadExternalPage(page) {
  var args = getArgs();
  var qString = "";
  
  if (args.ppath)
  {
    pipepath = args.ppath;
  }
    
  var language = parseLanguage(window.location.search.substring(1), "language");
  window.open(page + "?ppath=" + pipepath + "&language=" + language + "&" + qString,'mywin', '');
  
}


function rePos(curPos){
     var elePos;
     var args = getArgs();
     if (args.ppath) { // loaded as part of iframe
        elePos = curPos - $(window).scrollTop();
     } else { // loaded in stand-alone page
        var top = $(window).scrollTop();
        var height = $(window).height();
        var modalHeight = $('.modal-dialog').height();
        var view = height - modalHeight;
        elePos = top + (view/2);
     }

     $('#loading').css({
        position:'fixed',
        left: ($(window).width() - $('#loading').outerWidth())/2,
        top: 150
     });
     var resHeight = $('#wrapper').height();
     $('.eppModal').css({'height': resHeight + 'px'});
     $('.modal-dialog').css({'top':elePos});
}


// JavaScript Document
