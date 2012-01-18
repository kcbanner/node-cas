
/*!
 * node-cas
 * Copyright(c) 2011 Casey Banner <kcbanner@gmail.com>
 * MIT Licensed
 */

/**
 * Module dependencies
 */

var https = require('https');
var url = require('url');
var jsdom = require('jsdom');



/**
 * Initialize CAS with the given `options`.
 *
 * @param {Object} options
 *     { 
 *       'base_url': The full URL to the CAS server, including the base path,
 *       'service': The URL of the current page. Optional with authenticate(),
 *       'version': Either 1.0 or 2.0
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
  } else if (!cas_url.hostname) {
    throw new Error('Option `base_url` must be a valid url like: https://example.com/cas');
  } else {
    this.hostname = cas_url.hostname;
    this.port = cas_url.port || 443;
    this.base_path = cas_url.pathname;
  }
  
  this.service = options.service;
  
  
  this.tickets = {
    'ST': null, // service ticket
    'PT': null, // proxy ticket
    'PGT': null, // proxy generating ticket
    'PGTIOU': null // IOU for proxy generating ticket
  };
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
 *      Success callback: function(err, status, username, attributes) { ... }
 */
CAS.prototype.authenticate = function(req, res, callback)
{
    var casURL = 'https://' + this.hostname + ':' + this.port + this.base_path;
    var ticket = req.param('ticket');
    
    // Set the return URL automatically if it wasn't manually provided
    if (!this.service) {
        // Get the URL of the current page
        this.service = 'http://' + req.headers['host'] + req.url;
    }
    
    // No ticket, so we haven't been sent to the CAS server yet
    if (!ticket) {
        // redirect to CAS server now
        res.redirect(casURL + '/login?service=' + encodeURIComponent(this.service));
    }

    // We have a ticket! 
    else {
        this.tickets['ST'] = ticket;
        // Validate it with the CAS server now
        this.validate(ticket, callback);
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
    
    var casURL = 'https://' + this.hostname + ':' + this.port + this.base_path;
    res.redirect(casURL + logout_path);
}



/**
 * Attempt to validate a given ticket with the CAS server.
 * `callback` is called with (err, auth_status, username, attributes)
 *
 * @param {String} ticket
 * @param {Function} callback 
 * @param {Boolean} renew (optional)
 * @api public
 */
CAS.prototype.validate = function(ticket, callback, renew) {
  // Use different CAS path depending on version
  var validate_path;
  if (this.version < 2.0) {
    // CAS 1.0
    validate_path = 'validate';
  } else {
    // CAS 2.0
    validate_path = 'serviceValidate';
  }

  if (!this.service) {
    throw new Error('Required CAS option `service` missing.');
  }

  var req = https.get({
    host: this.hostname,
    port: this.port,
    path: url.format({
      "pathname": this.base_path+'/'+validate_path,
      "query": {ticket: ticket, service: this.service},
      "renew": renew
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
        callback({message: 'Bad response format.'});
      } 
      
      // CAS 2.0 (XML response, and optional attributes)
      else {
        // Use jsdom to parse the XML repsonse.
        // ( Note:
        //     It seems jsdom currently does not support XML namespaces.
        //     And node names here are case insensitive. Hence attribute
        //     names will also be case insensitive.
        // )
        //response = response.replace(/<cas:/, '<').replace(/<\/cas:/, '</');
        jsdom.env(response, function(err, window) {
            if (err) {
                callback({message: 'jsdom could not parse response' + response});
                return;
            } else {
                // Check for auth success
                var elemSuccess = window.document.getElementsByTagName('cas:authenticationSuccess');
                elemSuccess = elemSuccess[0];
                if (elemSuccess) {
                    var elemUser = elemSuccess.getElementsByTagName('cas:user')[0];
                    if (!elemUser) {
                        //  no "user"??
                        callback({'message': "No username?"}, false);
                        return;
                    } else {
                        // Success
                        var username = elemUser.textContent;

                        var attributes = {};
                        // Look for any optional attributes
                        var elemAttribute = window.document.getElementsByTagName('cas:attributes')[0];
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
                                var attrValue = node.textContent;
                                if (!attributes[attrName]) {
                                    attributes[attrName] = [attrValue];
                                } else {
                                    attributes[attrName].push(attrValue);
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
                        
                        //console.log(attributes);
                        callback(undefined, true, username, attributes);
                        return;
                    }
                } // end if auth success

                // Check for correctly formatted auth failure message
                var elemFailure = window.document.getElementsByTagName('cas:authenticationFailure')[0];
                if (elemFailure) {
                    var code = elemFailure.getAttribute('code');
                    var message = 'Login failed: ';
                    message += elemFailure.textContent;
                    callback({ 'code': code, 'message': message }, false);
                    return;
                }

                // The response was not in any expected format, error
                callback({message: 'Bad response format.'});
                return;
            }
        });
        
      };

    });
  });
};
