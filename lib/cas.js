
/*!
 * node-cas
 * Copyright(c) 2011 Casey Banner <kcbanner@gmail.com>
 * MIT Licensed
 *
 * A Node.js CAS client, implementing the protocol as defined at:
 * http://www.jasig.org/cas/protocol
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
 *           (optional) The URL of the external proxy's PGT callback.
 *           e.g. https://proxy.example.com:8989/
 *           The CAS server will try to contact this host every time a user 
 *           logs in. 
 *           Do not use with the `proxy_server` option.
 *       'external_proxy_url':
 *           (optional) The URL of the external CAS proxy. The protocol, 
 *           hostname, and port number are required. The path will be ignored.
 *           e.g. https://proxy.example.com:8080/
 *           Should be used together with the `external_pgt_url` option.
 *           The CAS client will use this URL to make proxied requests.
 *
 *       'proxy_server': 
 *           (optional) Set to TRUE if you want to automatically start 
 *           a proxy callback server internally.
 *           Do not use with `external_pgt_url`.
 *           The CAS client will use this internal server to make proxied 
 *           requests.
 *       'proxy_server_port':
 *           (optional) The port to listen on for external proxy requests for 
 *           a CAS enabled service.
 *           Disabled by default.
 *       'proxy_callback_host':
 *           The publicly accessible host name of your callback server.
 *           It must be usable by the CAS server. The CAS server will try to
 *           contact this host every time a user logs in.
 *           Required only if you used `proxy_server`.
 *       'proxy_callback_port':
 *           (optional) The port to listen on for incoming connections from
 *           the CAS server. Used with `proxy_callback_host`. Default is 80443.
 *       'proxy_server_key':
 *           A string value of your SSL private key. 
 *           Required only if you used `proxy_server`.
 *       'proxy_server_cert':
 *           A string value of your SSL certificate. 
 *           Required only if you used `proxy_server`.
 *       'proxy_server_ca':
 *           (optional) An array of SSL CA and Intermediate CA certificates.
 *
 *       'sso_servers':
 *           An array of IP addresses of servers that we will accept
 *           single sign out requests from. Default is to accept all
 *           well-formed requests no matter where they are from.
 *           Only relevant if you use handleSingleSignout().
 *     }
 * @api public
 */
var CAS = module.exports = function CAS(options) 
{  
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
  this.pgt_is_external = false;
  
  // Optional single sign out server list
  if (options.sso_servers) {
    this.ssoServers = options.sso_servers;
  }

  // User has supplied an external PGT callback URL
  if (options.external_pgt_url) {
    var pgt_url = url.parse(options.external_pgt_url);
    if (pgt_url.protocol != 'https:') {
      throw new Error('Option `external_pgt_url` must be https');
    }
    if (!pgt_url.hostname) {
      throw new Error('Option `external_pgt_url` must be a valid url like: https://example.com:8989/callback');
    }
    this.is_pgt_external = true;
    this.pgt_url = url.format(pgt_url);
    
    // A PGT callback URL is only useful if you also have a proxy URL to 
    // go with it.
    if (options.external_proxy_url) {
      var proxy_url = url.parse(options.external_proxy_url);
      if (!proxy_url.hostname) {
        throw new Error('Option `external_proxy_url` must be a vald url like: https://example.com:8080/');
      }
      this.external_proxy_url = url.format(proxy_url);
    }
  }

  // User is requesting the internal proxy server
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
    this.proxy_server_ca = options.proxy_server_ca || [];
    
    this.startProxyServer(this.proxy_server_key, this.proxy_server_cert, this.proxy_server_ca, this.proxy_callback_host, this.proxy_callback_port, this.proxy_server_port);
  }

};


/**
 * Library version.
 */

CAS.version = '0.0.4';



/**
 * Force CAS authentication on a web page. If users are not yet authenticated, 
 * they will be redirected to the CAS server to log in there.
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
 * @api public
 */
CAS.prototype.authenticate = function(req, res, callback, service)
{
    var casURL = 'https://' + this.hostname + ':' + this.port + this.base_path;
    var reqURL = url.parse(req.url, true);
    
    // Try to extract the CAS ticket from the URL
    var ticket = reqURL.query['ticket'];

    // Obtain the service URL automatically if it wasn't provided during 
    // initialization.
    if (!service) {
        // Get the URL of the current page, minus the 'ticket'
        delete reqURL.query['ticket'];
        service = url.format({
            protocol: req.protocol || 'http',
            host: req.headers['host'],
            pathname: reqURL.pathname,
            query: reqURL.query
        });
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
 * Handle a single sign-out request from the CAS server. 
 *
 * In CAS 3.x the server keeps track of all the `ticket` and `service` values
 * associated with each user. Then when the user logs out from one site, the
 * server will contact every `service` they have authenticated with and POST
 * a sign-out request containing the original `ticket` used to login.
 *
 * This is optional. But if you do use this, it must come before authenticate().
 * Also, it will only work if the service is accessible on the network by the 
 * CAS server.
 *
 * Unlike the other functions in this module, this one will only work 
 * with Express or something else that pre-processes the body of a POST 
 * request. It is not compatible with basic node.js http req objects.
 *
 * @param {Object} req
 *      Express/Connect HTTP serverRequest.
 * @param {Object} res
 *      HTTP serverResponse.
 * @param {Function} next
        Normal callback if no logout request was made.
 * @param {Function} logoutCallback
 *      function(ticket)
 * @api public
 */
CAS.prototype.handleSingleSignout = function(req, res, next, logoutCallback)
{
    if (req.method == 'POST' && req.body['logoutRequest']) {
        // Check IP address
        var remoteIP = req.connection.remoteAddress;
        if (this.ssoServers && this.ssoServers.indexOf(remoteIP) < 0) {
            // not a recognized single signout server
            return next();
        }
        // This was a signout request. Parse the XML.
        jsdom.env(req.body['logoutRequest'], function(err, window) {
            if (!err) {
                var ticketElem = window.document.getElementsByTagName('samlp:SessionIndex')[0];
                if (ticketElem) {
                    // This is the ticket that was issued by CAS when the user
                    // first logged in. Pass it into the callback so the
                    // framework can use it to delete the user's session.
                    var ticket = ticketElem.textContent.trim();
                    return logoutCallback(ticket);
                }
            }
            // This was not a valid signout request.
            return next();
        });
    }
    else {
        // This was not a signout request. Proceed normally.
        return next();
    }
}



/**
 * Log the user out of their CAS session. The user will be redirected to
 * the CAS server for this.
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
 * @api public
 */
CAS.prototype.logout = function(req, res, returnUrl, doRedirect)
{
    var logout_path;
    if (returnUrl && doRedirect) {
        // Logout with auto redirect
        logout_path = '/logout?service=' + encodeURIComponent(returnUrl);
    } else if (returnUrl) {
        // Logout and provide a hyperlink back
        logout_path = '/logout?url=' + encodeURIComponent(returnUrl);
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
 *     callback(err, auth_status, username, extended).
 *     `extended` is an object containing:
 *       - username
 *       - attributes
 *       - PGTIOU
 *       - ticket
 *       - proxies
 * @param {String} service
 *     The URL of the service requesting authentication. Optional if
 *     the `service` option was already specified during initialization.
 * @param {Boolean} renew 
 *     (optional) Set this to TRUE to force the CAS server to request
 *     credentials from the user even if they had already done so
 *     recently.
 * @api public
 */
CAS.prototype.validate = function(ticket, callback, service, renew) 
{
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
      if (response.length > 1e6) {
        req.connection.destroy();
      }
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
                    var thisProxy = elemProxies[i].textContent.trim();
                    proxies.push(thisProxy);
                }

                // Look for optional attributes
                var attributes = parseAttributes(elemSuccess);
                
                callback(undefined, true, username, {
                    'username': username,
                    'attributes': attributes,
                    'PGTIOU': pgtIOU,
                    'ticket': ticket,
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
 * Fetches the PGT value that matches a given PGTIOU.
 * Used internally by getProxyTicket().
 *
 * @param {String} pgtIOU
 *     This is the PGTIOU that can be found in the validation response of the
 *     CAS server.
 * @param {Function} callback
 *     callback(err, pgt)
 * @return {null|String}
 *     If using an internal PGT callback server, then the PGT will also
 *     be delivered as the return value. Otherwise, NULL.
 */
CAS.prototype.getProxyGrantingTicket = function(pgtIOU, callback)
{
    var pgt = '';
    
    // If configured for external proxy server use, fetch the PT from there
    if (this.is_pgt_external) {
        var urlFetchPGT = url.parse(this.pgt_url + 'getPGT?pgtiou=' + pgtIOU);
        https.get(urlFetchPGT, function(res) {
            res.on('data', function(chunk) {
                pgt += chunk;
            });
            res.on('end', function() {
                callback(null, pgt);
            });
            res.on('error', function(err) {
                callback(err);
            });
        });
        return null;
    }

    // Look up the PGT locally
    else if (this.pgtStore[pgtIOU]) {
        pgt = this.pgtStore[pgtIOU]['pgtID'];
        callback && callback(null, pgt);
        return pgt;
    }
    else {
        callback && callback(new Error('Invalid PGTIOU supplied'));
        return null;
    }
}



/**
 * Obtain a Proxy Ticket (PT) that can be used to access a service on behalf
 * of a user.
 *
 * Used internally by proxiedRequest(), but you may also use it to manually
 * assemble proxied requests by other means.
 *
 * @param {string} pgtIOU
 *      The PGTIOU that was given by the CAS server when the user logged in.
 * @param {function} callback
 *      callback(err, pt)
 */
CAS.prototype.getProxyTicket = function(pgtIOU, targetService, callback) 
{
    var self = this;
    
    // Obtain the PGT
    this.getProxyGrantingTicket(pgtIOU, function(err, pgt) {
        if (err) {
            callback(err);
            return;
        }
        // Query the CAS server
        var req = https.get({
            protocol: 'https:',
            hostname: self.hostname,
            port: self.port,
            path: url.format({
                pathname: self.base_path + '/proxy',
                query: { 
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
                if (response.length > 1e6) {
                    req.connection.destroy();            
                }
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
 * @param {String/Buffer} key
 *    The SSL private key
 * @param {String/Buffer} cert
 *    The SSL certificate
 * @param {Array} ca
 *    The CA Bundle for the SSL certificate
 * @param {String} callbackHost
 *    The publicly accessible hostname for the callback server.
 * @param {Integer} callbackPort
 *    The port number to listen on for incoming CAS PGT messages.
 * @param {Integer} proxyPort
 *    The port number to listen on for outgoing proxied requests.
 *    Omit this to disable the proxy server and only allow
 *    internal requests via CAS.proxiedRequest().
 * @api public
 */
CAS.prototype.startProxyServer = function(key, cert, ca, callbackHost, callbackPort, proxyPort) 
{
    var serverOptions = {
        'key': key,
        'cert': cert,
        'ca': ca
    };
    var self = this;
    
    // This is the pgtURL that will be sent to the CAS server during a
    // validation request. The CAS server will try to connect to it.
    this.pgt_url = 'https://' + callbackHost + ':' + callbackPort + '/';
    
    // PGT callback server that listens for incoming connections from
    // the CAS server.
    var pgtServer = https.createServer(serverOptions);
    console.log('Starting PGT callback server on port ' + callbackPort);
    pgtServer.addListener("request", function(req, res) {
        
        var reqURL = url.parse(req.url, true);

        // Check if this is a request from a CAS _client_ to get a PGT.
        // [ see first part of getProxyTicket() ]
        if (reqURL.pathname == '/getPGT') {
            var pgtIOU = reqURL.query['pgtiou'];
            if (self.pgtStore[pgtIOU]) {
                res.writeHead(200, { 'Content-type': 'text/plain' });
                res.write(self.pgtStore[pgtIOU]['pgtID']);
                res.end();
            }
            else {
                res.writeHead(403, { 'Content-type': 'text/plain' });
                res.write("Invalid PGTIOU supplied");
                res.end();
            }
            return;
        }
    
        // Otherwise this is a connection from the CAS _server_.
        // The incoming connection tells us what the PGTIOU and PGT values
        // are. It expects only a HTTP 200 response in return.
        else {
            res.writeHead(200, {'Content-Type': 'text/plain'});
            res.end();
            // Save the PGT ticket into the memory store
            var pgtIOU = reqURL.query['pgtIou'];
            var pgtID = reqURL.query['pgtId'];
            if (pgtIOU && pgtID) {
                self.pgtStore[ pgtIOU ] = {
                    'pgtID': pgtID,
                    'time': process.uptime()
                };
            }
            return;
        }
    });
    pgtServer.listen(callbackPort);
    
    // Start an interval for garbage collection of the local PGT store.
    if (this.pgtInterval) {
        clearInterval(this.pgtInterval);
    }
    this.pgtInterval = setInterval(function() {
        var now = process.uptime();
        // Delete entries older than an hour
        for (var pgtIOU in self.pgtStore) {
            var timestamp = self.pgtStore[pgtIOU]['time'];
            if (now - timestamp > 60 * 60 * 1) {
                delete self.pgtStore[pgtIOU];
            }
        }
    }, 1000 * 60);
    
    // Proxy server that listens for HTTPS connections from other CAS clients
    // and forwards them to the target service. Disabled by default.
    if (proxyPort) {
        var proxyServer = https.createServer(serverOptions);
        console.log('Starting CAS proxy server on port ' + proxyPort);
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
                var targetOptions = url.parse(targetURL, true);
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
 * @param {Function} callback
 *     callback(err, req, res)
 * @api public
 */
CAS.prototype.proxiedRequest = function(pgtIOU, options, callback) 
{
    if (this.external_proxy_url) {
        this.proxiedRequestExternal(this.external_proxy_url, pgtIOU, options, callback);
        return;
    }

    var targetService = url.format(options);
    
    this.getProxyTicket(pgtIOU, targetService, function(err, pt) {
        if (err) {
            callback(err);
            return;
        }
        
        // Add the proxy ticket to the target service's query string
        var path = options.path || targetService.replace(/^https?:\/\/[^\/]+/, '');
        if (path.match(/[&?]/)) {
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
            switch (options.method.toUpperCase()) {
                default:
                case 'GET':
                case 'HEADER':
                    // get() automatically ends the request.
                    var req = serviceObj.get(options, function(res) {
                        callback(undefined, req, res);
                    });
                    break;
                    
                case 'POST':
                case 'PUT':
                    // Let the calling function end the request manually after
                    // it has finished sending all its data.
                    var res;
                    var req = serviceObj.request(options, function(_res) {
                        res = _res;
                    });
                    callback(undefined, req, res);
                    break;
            }
        }
        catch (err) {
            callback(err);
        }
        
    });
}


/**
 * Create a CAS proxied HTTP/HTTPS request through an external server.
 *
 * @param {String} proxyURL
 *     The URL of the CAS proxy server
 * @param {String} pgtIOU
 *     This should have been obtained during the initial CAS login with
 *     the validate() function.
 * @param {Object} requestOptions
 *     Same as the options passed in to http.request(). This is where you 
 *     specify the service URL you are requesting.
 * @param {Function} callback
 *     callback(err, req, res)
 * @api public
 */
CAS.prototype.proxiedRequestExternal = function(proxyURL, pgtIOU, options, callback) 
{
    var targetService = url.format(options);
    var proxyInfo = url.parse(proxyURL);

    // Add the target's path (and querystring) to the proxy request.
    proxyInfo.path = options.path;

    // Add the custom proxy headers
    var headers = options.headers || {};
    headers['cas-proxy-pgtiou'] = pgtIOU;
    headers['cas-proxy-targeturl'] = targetService;
    proxyInfo.headers = headers;

    var serviceObj;
    if (proxyInfo.protocol.indexOf('https') == 0) {
        serviceObj = https;
    } else {
        serviceObj = http;
    }
    
    try {
        var req = serviceObj.get(proxyInfo, function(res) {
            callback(undefined, req, res);
        });
    } catch(e) {
        callback(e);
    }
}


/**
 * Parse a cas:authenticationSuccess XML node for CAS attributes.
 * Supports Jasig style, RubyCAS style, and Name-Value.
 *
 * @param {Object} elemSuccess
 *     DOM node
 * @return {Object}
 *     {
 *         attr1: [ attr1-val1, attr1-val2, ... ],
 *         attr2: [ attr2-val1, attr2-val2, ... ],
 *         ...
 *     }
 * @attribution http://downloads.jasig.org/cas-clients/php/1.2.0/docs/api/client_8php_source.html#l01589
 */
var parseAttributes = function(elemSuccess) 
{
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
