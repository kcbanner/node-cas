
/*!
 * node-cas
 * Copyright(c) 2011 Casey Banner <kcbanner@gmail.com>
 * MIT Licensed
 */

/**
 * Module dependencies
 */

var http = require('http');
var https = require('https');
var url = require('url');
var jsdom = require('jsdom');



/**
 * Initialize CAS with the given `options`.
 *
 * @param {Object} options
 *     { 
 *       'base_url': 
 *           The full URL to the CAS server, including the base path.
 *       'service': 
 *           The URL of the current page. Optional with authenticate().
 *       'version': 
 *           Either 1.0 or 2.0
 *
 *       'external_pgt_url': 
 *           (optional) The URL of an external proxy's PGT callback.
 *       'proxy_server': 
 *           (optional) Set to TRUE if you want to automatically start 
 *           a proxy callback server locally.
 *           Do not use with `external_pgt_url`.
 *       'proxy_server_port':
 *           (optional) The port to listen on for outgoing requests that are
 *           to be forwarded to an external CAS enabled service.
 *           Disabled by default.
 *       'proxy_callback_host':
 *           The publicly accessible host name of your callback server.
 *           It must be usable by the CAS server.
 *           Required only if you used `proxy_server`.
 *       'proxy_callback_port':
 *           (optional) The port to listen on for incoming connections from
 *           the CAS server. Default is 80443.
 *       'proxy_server_key':
 *           A string value of your SSL private key. 
 *           Required only if you used `proxy_server`.
 *       'proxy_server_cert':
 *           A string value of your SSL certificate. 
 *           Required only if you used `proxy_server`.
 *     }
 * @api public
 */
var CAS = module.exports = function CAS(options) {  
  options = options || {};

  if (!options.version) {
    // Can specify 1.0 or 2.0. Default is 1.0.
    options.version = 1.0;
  }
  this.version = options.version;

  if (!options.base_url) {
    throw new Error('Required CAS option `base_url` missing.');
  } 

  var cas_url = url.parse(options.base_url);
  if (cas_url.protocol != 'https:') {
    throw new Error('Only https CAS servers are supported.');
  } 
  if (!cas_url.hostname) {
    throw new Error('Option `base_url` must be a valid url like: https://example.com/cas');
  } 
  
  
  this.hostname = cas_url.hostname;
  this.port = cas_url.port || 443;
  this.base_path = cas_url.pathname;
  this.service = options.service;
  this.pgtStore = {};

  // User has supplied their own PGT callback URL
  if (options.external_pgt_url) {
    var pgt_url = url.parse(options.external_pgt_url);
    if (pgt_url.protocol != 'https:') {
      throw new Error('Option `pgt_url` must be https');
    }
    if (!pgt_url.hostname) {
      throw new Error('Option `pgt_url` must be a valid url like: https://example.com/callback');
    }
    this.pgt_url = options.external_pgt_url;
  }
  // User is requesting the built-in proxy server
  else if (options.proxy_server) {
    //// Required
    // (openssl genrsa -out privatekey.pem 1024)
    this.proxy_server_key = options.proxy_server_key;
    // (openssl req -new -key privatekey.pem -out csr.pem)
    // (openssl x509 -req -in csr.pem -signkey privatekey.pem -out cert.pem)
    this.proxy_server_cert = options.proxy_server_cert;
    if (!this.proxy_server_key || !this.proxy_server_cert) {
        throw new Error('Options `proxy_server_key` and `proxy_server_cert` are required because you specified `proxy_server`');
    }
    this.proxy_callback_host = options.proxy_callback_host;
    if (!this.proxy_callback_host) {
        throw new Error('Option `proxy_callback_host` is required because you specified `proxy_server`');
    }
    //// Optional
    this.proxy_server_port = options.proxy_server_port || 0;
    this.proxy_callback_port = options.proxy_callback_port || 80443
    
    this.startProxyServer(this.proxy_server_key, this.proxy_server_cert, this.proxy_callback_host, this.proxy_callback_port, this.proxy_server_port);
  }

};


/**
 * Library version.
 */

CAS.version = '0.0.4';



/**
 * Force CAS authentication on a web page. If users are not yet authenticated, 
 * they will be redirected to the CAS server.
 *
 * @param {object} req
 *      HTTP request object
 * @param {object} res
 *      HTTP response object
 * @param {function} callback
 *      callback(err, status, username, extended)
 * @param {String} service
 *      (optional) The URL of the service/page that is requesting 
 *      authentication. Default is to extract this automatically from
 *      the `req` object.
 */
CAS.prototype.authenticate = function(req, res, callback, service)
{
    var casURL = 'https://' + this.hostname + ':' + this.port + this.base_path;
    var reqURL = url.parse(req.url, true);
    
    // Try to extract the CAS ticket from the URL
    var ticket = reqURL.query['ticket'];

    // Set the service URL automatically if it wasn't manually provided
    if (!service) {
        // Get the URL of the current page, minus the 'ticket'
        delete reqURL.query['ticket'];
        service = url.format({
            protocol: req.protocol || 'http',
            host: req.headers['host'],
            pathname: reqURL.pathname,
            query: reqURL.query
        });
        //console.log('authenticate() -- derived service: ' + service);
    }
    
    // No ticket, so we haven't been sent to the CAS server yet
    if (!ticket) {
        // redirect to CAS server now
        var redirectURL = casURL + '/login?service=' + encodeURIComponent(service);
        res.writeHead(307, {'Location': redirectURL});
        res.write('<a href="' + redirectURL + '">CAS login</a>');
        res.end();
    }

    // We have a ticket! 
    else {
        // Validate it with the CAS server now
        this.validate(ticket, callback, service);
    }
};



/**
 * Log the user out of their CAS session. The user will be redirected to
 * the CAS server.
 *
 * @param {Object} req
 *     HTTP request object
 * @param {Object} res
 *     HTTP response object
 * @param {String} returnUrl
 *     (optional) The URL that the user will return to after logging out.
 * @param {Boolean} doRedirect
 *     (optional) Set this to TRUE to have the CAS server redirect the user 
 *      automatically. Default is for the CAS server to only provide a 
 *      hyperlink to be clicked on.
 */
CAS.prototype.logout = function(req, res, returnUrl, doRedirect)
{
    var logout_path;
    if (returnUrl && doRedirect) {
        // Logout with auto redirect
        logout_path += '/logout?service=' + encodeURIComponent(returnUrl);
    } else if (returnUrl) {
        // Logout and provide a hyperlink back
        logout_path += '/logout?url=' + encodeURIComponent(returnUrl);
    } else {
        // Logout with no way back
        logout_path = '/logout';
    }
    
    var redirectURL = 'https://' + this.hostname + ':' + this.port + this.base_path + logout_path;
    res.writeHead(307, {'Location' : redirectURL});
    res.write('<a href="' + redirectURL + '">CAS logout</a>');
    res.end();
}



/**
 * Attempt to validate a given ticket with the CAS server.
 * `callback` is called with (err, auth_status, username, extended)
 *
 * @param {String} ticket
 *     Either a service ticket (ST) or a proxy ticket (PT)
 * @param {Function} callback
 *     callback(err, auth_status, username, extended)
 * @param {String} service
 *     The URL of the service requesting authentication. Optional if
 *     the `service` option was specified during initialization.
 * @param {Boolean} renew 
 *     (optional) Set this to TRUE to force the CAS server to request
 *     credentials from the user even if they had already done so
 *     recently.
 * @api public
 */
CAS.prototype.validate = function(ticket, callback, service, renew) {
  // Use different CAS path depending on version
  var validate_path;
  var pgtURL;
  if (this.version < 2.0) {
    // CAS 1.0
    validate_path = 'validate';
  } else {
    // CAS 2.0
    pgtURL = this.pgt_url;
    if (ticket.indexOf('PT-') == 0) {
      validate_path = 'proxyValidate';
    } else {
      //validate_path = 'serviceValidate';
      validate_path = 'proxyValidate';
    }
  }
  
  // Service URL can be specified in the function call, or during
  // initialization.
  var service_url = service || this.service;
  if (!service_url) {
    throw new Error('Required CAS option `service` missing.');
  }

  var query = {
    'ticket': ticket,
    'service': service_url
  };
  if (renew) {
    query['renew'] = 1;
  }
  if (pgtURL) {
    query['pgtUrl'] = pgtURL;
  }
  
  var queryPath = url.format({
      pathname: this.base_path+'/'+validate_path,
      query: query
    });
  //console.log('CAS validate path: ' + queryPath);

  var req = https.get({
    host: this.hostname,
    port: this.port,
    path: queryPath
  }, function(res) {
    // Handle server errors
    res.on('error', function(e) {
      callback(e);
    });

    // Read result
    res.setEncoding('utf8');
    var response = '';
    res.on('data', function(chunk) {
      response += chunk;
    });

    res.on('end', function() {
      // CAS 1.0
      if (this.version < 2.0) {
        var sections = response.split('\n');
        if (sections.length >= 1) {
          if (sections[0] == 'no') {
            callback(undefined, false);
            return;
          } else if (sections[0] == 'yes' &&  sections.length >= 2) {
            callback(undefined, true, sections[1]);
            return;
          }
        }
        // Format was not correct, error
        callback(new Error('Bad response format.'));
      } 
      
      // CAS 2.0 (XML response, and extended attributes)
      else {
        // Use jsdom to parse the XML repsonse.
        // ( Note:
        //     It seems jsdom currently does not support XML namespaces.
        //     And node names here are case insensitive. Hence attribute
        //     names will also be case insensitive.
        // )
        jsdom.env(response, function(err, window) {
            if (err) {
                callback(new Error('jsdom could not parse response: ' + response));
                return;
            } 
            
            // Check for auth success
            var elemSuccess = window.document.getElementsByTagName('cas:authenticationSuccess')[0];
            if (elemSuccess) {
                var elemUser = elemSuccess.getElementsByTagName('cas:user')[0];
                if (!elemUser) {
                    //  This should never happen
                    callback(new Error("No username?"), false);
                    return;
                }

                // Got username
                var username = elemUser.textContent;
                
                // Look for optional proxy granting ticket
                var pgtIOU;
                var elemPGT = elemSuccess.getElementsByTagName('cas:proxyGrantingTicket')[0];
                if (elemPGT) {
                    pgtIOU = elemPGT.textContent;
                }
                
                // Look for optional proxies
                var proxies = [];
                var elemProxies = elemSuccess.getElementsByTagName('cas:proxies');
                for (var i=0; i<elemProxies.length; i++) {
                    var thisProxy = elemProxies[i].textContent;
                    // trim whitespace
                    thisProxy = thisProxy
                        .replace(/^\s+/, '', thisProxy)
                        .replace(/\s+$/, '', thisProxy);
                    proxies.push(thisProxy);
                }

                // Look for optional attributes
                var attributes = parseAttributes(elemSuccess);
                
                callback(undefined, true, username, {
                    'username': username,
                    'attributes': attributes,
                    'PGTIOU': pgtIOU,
                    'proxies': proxies
                });
                return;
            } // end if auth success

            // Check for correctly formatted auth failure message
            var elemFailure = window.document.getElementsByTagName('cas:authenticationFailure')[0];
            if (elemFailure) {
                var code = elemFailure.getAttribute('code');
                var message = 'Validation failed [' + code +']: ';
                message += elemFailure.textContent;
                callback(new Error(message), false);
                return;
            }

            // The response was not in any expected format, error
            callback(new Error('Bad response format.'));
            console.error(response);
            return;
        });
      };
    });
  });
};


/**
 * Send a PGT to the CAS server, and get a PT in return.
 * Used internally by the proxy server.
 *
 * @param {string} pgt
 *      Proxy granting ticket
 * @param {function} callback
 *      callback(err, pt)
 */
CAS.prototype.getProxyTicket = function(pgt, targetService, callback) {
    var req = https.get({
        host: this.hostname,
        port: this.port,
        path: url.format({
            'pathname': this.base_path + '/proxy',
            'query': { 
                'targetService': targetService,
                'pgt': pgt
            }
        })
    }, function(res) {
        // Handle server errors
        res.on('error', function(e) {
            callback(e);
        });
        
        // Read result
        res.setEncoding('utf8');
        var response = '';
        res.on('data', function(chunk) {
            response += chunk;
        });
        res.on('end', function() {
            // Use jsdom to parse the XML response
            jsdom.env(response, function(err, window) {
                if (err) {
                    callback(new Error("jsdom could not parse response: " + response));
                    return;
                }
                // Got the proxy ticket
                var elemTicket = window.document.getElementsByTagName('cas:proxyTicket')[0];
                if (elemTicket) {
                    var proxyTicket = elemTicket.textContent;
                    callback(undefined, proxyTicket);
                    return;
                }
                // Got a proxy failure
                var elemFailure = window.document.getElementsByTagName('cas:proxyFailure')[0];
                if (elemFailure) {
                    var code = elemFailure.getAttribute('code');
                    var message = 'Proxy failure [' + code + ']: ';
                    message += elemFailure.textContent;
                    callback(new Error(message));
                    return;
                }
                // Unexpected response
                callback(new Error("Bad response format: " + response));
                return;
            });
        });
    });
}


/**
 * Start a local proxy server.
 * 
 * This is a local HTTPS server that listens for incoming connections from 
 * the CAS server. Any PGTs received from the CAS server will be stored
 * in `this.pgtStore`.
 *
 * This is optionally also a proxy server that listens for outgoing proxy 
 * requests from clients that already have a PGTIOU. In addition to the 
 * normal HTTP information, the client must also supply these two headers 
 * in the request:
 *    cas-proxy-pgtiou
 *    cas-proxy-targeturl
 *
 * For this to work, the local machine and the CAS server must be able to 
 * access each other on the network.
 *
 * @param {string/buffer} key
 *    The SSL private key
 * @param {string/buffer} cert
 *    The SSL certificate
 * @param {string} callbackHost
 *    The publicly accessible hostname for the callback server.
 * @param {int} callbackPort
 *    The port number to listen on for incoming CAS PGT messages.
 * @param {int} proxyPort
 *    The port number to listen on for outgoing proxied requests.
 *    Omit this to disable the proxy server and only allow
 *    internal requests via CAS.proxiedRequest().
 */
CAS.prototype.startProxyServer = function(key, cert, callbackHost, callbackPort, proxyPort) {
    var serverOptions = {
        'key': key,
        'cert': cert
    };
    var self = this;
    
    // This is the pgtURL that will be sent to the CAS server during a
    // validation request.
    this.pgt_url = 'https://' + callbackHost + ':' + callbackPort + '/';
    
    // PGT callback server that listens for incoming connections from
    // the CAS server.
    var pgtServer = https.createServer(serverOptions);
    console.log('Starting PGT callback server');
    pgtServer.addListener("request", function(req, res) {
        res.writeHead(200, {'Content-Type': 'text/plain'});
        res.end();
        // Save the PGT ticket into the memory store
        var reqURL = url.parse(req.url, true);
        var pgtIOU = reqURL.query['pgtIou'];
        var pgtID = reqURL.query['pgtId'];
        if (pgtIOU && pgtID) {
            self.pgtStore[ pgtIOU ] = pgtID;
            //console.log('Callback -- got PGT: ' + pgtID);
        } else {
            //console.error('Callback -- Got unrecognized request:' + req.method + ' ' + req.url);
        }
    });
    pgtServer.listen(callbackPort);
    
    // Proxy server that listens for local connections and forwards them to 
    // the target service. Disabled by default.
    if (proxyPort) {
        var proxyServer = https.createServer(serverOptions);
        console.log('Starting CAS proxy server');
        proxyServer.addListener("request", function(req, res) {
            // Use "cas-proxy-..." headers to obtain information about the 
            // requested target service.
            try {
                var pgtIOU = req.headers['cas-proxy-pgtiou'];
                if (!pgtIOU) {
                    throw 'Header "cas-proxy-pgtiou" was not found';
                }
                if (!self.pgtStore[pgtIOU]) {
                    throw 'Invalid "cas-proxy-pgtiou" was given';
                }
                var targetURL = req.headers['cas-proxy-targeturl'];
                if (!targetURL) {
                    throw 'Header "cas-proxy-targeturl" was not found';
                }
                targetOptions = url.parse(targetURL, true);
                if (!targetOptions.hostname) {
                    throw 'Invalid "cas-proxy-targeturl" was given';
                }
            } catch (e) {
                res.writeHead(400, {'Content-Type': 'text/plain'});
                res.write('400 - CAS Proxy Error\n');
                if (typeof e == 'string') {
                    res.write(e);
                } else {
                    res.write(e.message);
                }
                res.end();
                return;
            }
            
            // The headers are okay. Next begin the proxied request.
            targetOptions.method = req.method || 'GET';
            self.proxiedRequest(pgtIOU, targetOptions, function(err, targetReq, targetRes) {
                if (err) {
                    res.writeHead(500, {'Content-Type': 'text/plain'});
                    res.write('500 - CAS Proxy Error\n');
                    res.write(err.message);
                    res.end();
                    return;
                }
            
                // Mirror requester's data to the target
                req.on('data', function(chunk) {
                    targetReq.write(chunk);
                });
                req.on('end', function() {
                    targetReq.end();
                });
            
                // Mirror target's response headers back to requester
                res.writeHead(targetRes.statusCode, targetRes.headers);
            
                // Mirror target's data back to the requester
                targetRes.on('data', function(chunk) {
                    res.write(chunk);
                });
                targetRes.on('end', function() {
                    res.end();
                });
            });
        });
        proxyServer.listen(proxyPort);
    }
}


/**
 * Create a CAS proxied HTTP/HTTPS request.
 * The CAS proxy ticket (PT) will automatically be added to the target 
 * service's query.
 *
 * @param {String} pgtIOU
 *     This should have been obtained during the initial CAS login with
 *     the validate() function.
 * @param {Object} options
 *     Same as the options passed in to http.request(). This is where you 
 *     specify the service URL you are requesting.
 * @param {function} callback
 *     callback(err, req, res)
 */
CAS.prototype.proxiedRequest = function(pgtIOU, options, callback) {
    // Look up the PGT using the PGTIOU
    var pgt = this.pgtStore[pgtIOU];
    if (!pgt) {
        callback(new Error('Invalid PGTIOU supplied'));
    }
    
    var targetService = url.format(options);
    //console.log('Proxied Request -- targetService: ' + targetService);
    
    this.getProxyTicket(pgt, targetService, function(err, pt) {
        if (err) {
            callback(err);
            return;
        }
        //console.log('Proxied Request -- got PT: ' + pt);
        
        // Add the proxy ticket to the target service's query string
        var path = options.path || targetService.replace(/^https?:\/\/[^\/]+/, '');
        if (path.indexOf('&') >= 0) {
            options.path = path + '&ticket=' + pt;
        } else {
            options.path = path + '?ticket=' + pt;
        }
        delete options.pathname;
        delete options.search;
        delete options.href;
        delete options.query;
        options.agent = false;
        
        // Request the target service
        var serviceObj;
        if (options.options == 'https:') {
            serviceObj = https;
        } else {
            serviceObj = http;
        }
        try {
            var req = serviceObj.get(options, function(res) {
                callback(undefined, req, res);
            });
        }
        catch (e) {
            callback(e);
        }
        
    });
}


/**
 * Parse a cas:authenticationSuccess XML node for CAS attributes.
 * Supports Jasig style, RubyCAS style, and Name-Value.
 *
 * @param {object} elemSuccess
 *     DOM node
 * @return {object}
 *     {
 *         attr1: [ attr1-val1, attr1-val2, ... ],
 *         attr2: [ attr2-val1, attr2-val2, ... ],
 *         ...
 *     }
 */
var parseAttributes = function(elemSuccess) {
    var attributes = {};
    var elemAttribute = elemSuccess.getElementsByTagName('cas:attributes')[0];
    if (elemAttribute && elemAttribute.hasChildNodes()) {
        // "Jasig Style" Attributes:
        // 
        //  <cas:serviceResponse xmlns:cas='http://www.yale.edu/tp/cas'>
        //      <cas:authenticationSuccess>
        //          <cas:user>jsmith</cas:user>
        //          <cas:attributes>
        //              <cas:attraStyle>RubyCAS</cas:attraStyle>
        //              <cas:surname>Smith</cas:surname>
        //              <cas:givenName>John</cas:givenName>
        //              <cas:memberOf>CN=Staff,OU=Groups,DC=example,DC=edu</cas:memberOf>
        //              <cas:memberOf>CN=Spanish Department,OU=Departments,...</cas:memberOf>
        //          </cas:attributes>
        //          <cas:proxyGrantingTicket>PGTIOU-84678-8a9d2...</cas:proxyGrantingTicket>
        //      </cas:authenticationSuccess>
        //  </cas:serviceResponse>
        //
        for (var i=0; i<elemAttribute.childNodes.length; i++) {
            var node = elemAttribute.childNodes[i];
            var attrName = node.nodeName.toLowerCase().replace(/cas:/, '');
            if (attrName != '#text') {
                var attrValue = node.textContent;
                if (!attributes[attrName]) {
                    attributes[attrName] = [attrValue];
                } else {
                    attributes[attrName].push(attrValue);
                }
            }
        }
    }
    
    else {
        // "RubyCAS Style" attributes
        // 
        //    <cas:serviceResponse xmlns:cas='http://www.yale.edu/tp/cas'>
        //        <cas:authenticationSuccess>
        //            <cas:user>jsmith</cas:user>
        //                      
        //            <cas:attraStyle>RubyCAS</cas:attraStyle>
        //            <cas:surname>Smith</cas:surname>
        //            <cas:givenName>John</cas:givenName>
        //            <cas:memberOf>CN=Staff,OU=Groups,DC=example,DC=edu</cas:memberOf>
        //            <cas:memberOf>CN=Spanish Department,OU=Departments,...</cas:memberOf>
        //                      
        //            <cas:proxyGrantingTicket>PGTIOU-84678-8a9d2...</cas:proxyGrantingTicket>
        //        </cas:authenticationSuccess>
        //    </cas:serviceResponse>
        // 
        for (var i=0; i<elemSuccess.childNodes.length; i++) {
            var node = elemSuccess.childNodes[i];
            var tagName = node.nodeName.toLowerCase().replace(/cas:/, '');
            switch (tagName) {
                case 'user':
                case 'proxies':
                case 'proxygrantingticket':
                case '#text':
                    // these are not CAS attributes
                    break;
                default:
                    var attrName = tagName;
                    var attrValue = node.textContent;
                    if (attrValue != '') {
                        if (!attributes[attrName]) {
                            attributes[attrName] = [attrValue];
                        } else {
                            attributes[attrName].push(attrValue);
                        }
                    }
                    break;
            }
        }
    }
    
    if (attributes == {}) {
        // "Name-Value" attributes.
        // 
        // Attribute format from this mailing list thread:
        // http://jasig.275507.n4.nabble.com/CAS-attributes-and-how-they-appear-in-the-CAS-response-td264272.html
        // Note: This is a less widely used format, but in use by at least two institutions.
        // 
        //    <cas:serviceResponse xmlns:cas='http://www.yale.edu/tp/cas'>
        //        <cas:authenticationSuccess>
        //            <cas:user>jsmith</cas:user>
        //                      
        //            <cas:attribute name='attraStyle' value='Name-Value' />
        //            <cas:attribute name='surname' value='Smith' />
        //            <cas:attribute name='givenName' value='John' />
        //            <cas:attribute name='memberOf' value='CN=Staff,OU=Groups,DC=example,DC=edu' />
        //            <cas:attribute name='memberOf' value='CN=Spanish Department,OU=Departments,...' />
        //                      
        //            <cas:proxyGrantingTicket>PGTIOU-84678-8a9d2sfa23casd</cas:proxyGrantingTicket>
        //        </cas:authenticationSuccess>
        //    </cas:serviceResponse>
        //
        var nodes = elemSuccess.getElementsByTagName('cas:attribute');
        if (nodes && nodes.length) {
            for (var i=0; i<nodes.length; i++) {
                var attrName = nodes[i].getAttribute('name');
                var attrValue = nodes[i].getAttribute('value');
                if (!attributes[attrName]) {
                    attributes[attrName] = [attrValue];
                } else {
                    attributes[attrName].push(attrValue);
                }
            }
        }
    }
    
    return attributes;
}