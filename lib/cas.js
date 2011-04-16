
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

/**
 * Initialize CAS with the given `options`.
 *
 * @param {Object} options
 * @api public
 */
var CAS = module.exports = function CAS(options) {  
  options = options || {};

  if (!options.base_url) {
    throw new Error('Required CAS option `base_url` missing.');
  } 

  if (!options.service) {
    throw new Error('Required CAS option `service` missing.');
  }

  var cas_url = url.parse(options.base_url);
  if (cas_url.protocol != 'https:') {
    throw new Error('Only https CAS servers are supported.');
  } else if (!cas_url.hostname) {
    throw new Error('Option `base_url` must be a valid url like: https://example.com/cas');    
  } else {
    this.hostname = cas_url.host;
    this.port = cas_url.port || 443;
    this.base_path = cas_url.pathname;
  }  
  
  this.service = options.service;
};

/**
 * Library version.
 */

CAS.version = '0.0.1';

/**
 * Attempt to validate a given ticket with the CAS server.
 * `callback` is called with (err, auth_status, username)
 *
 * @param {String} ticket
 * @param {Function} callback 
 * @api public
 */

CAS.prototype.validate = function(ticket, callback) {
  var req = https.get({
    host: this.hostname,
    port: this.port,
    path: url.format({
      pathname: this.base_path+'/validate',
      query: {ticket: ticket, service: this.service}
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
    });
  });
};