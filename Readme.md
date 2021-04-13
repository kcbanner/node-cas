# Node CAS  |  forked from [kcbanner](https://github.com/kcbanner/node-cas) 

  Central Authentication Service (CAS) client for Node.js

  This module handles CAS authentication (with support for proxies and extended attributes), and can also transparently redirect a web page if needed. The ticket validation step is available as its own function for those who wish to handle things manually. Single sign out is also supported with Express/Connect.
  
  To start the login process manually, send your users to: `https://cas_base_url/login?service=url_to_handle_ticket_validation`. In the University of Waterloo example below, this url would be: `https://cas.uwaterloo.ca/cas/login?service='my_service'`.
  
  Or if you are using standard HTTP req/res objects for a web page, you may use the provided `authenticate()` function to handle the redirection automatically.
  
  It is also possible to use this as a standalone CAS PGT callback server that other CAS clients can use.
  
  

## Installation

Clone this project into `node_modules/cas` and then run `npm install` inside it.

## Usage

Setup:

```javascript
    var CAS = require('cas');
    var cas = new CAS({
        base_url: 'https://cas.uwaterloo.ca/cas', 
        service: 'my_service',
        version: 2.0
    });
```

Using it in a login route:

```javascript
    exports.cas_login = function(req, res) {
      var ticket = req.param('ticket');
      if (ticket) {
        cas.validate(ticket, function(err, status, username) {
          if (err) {
            // Handle the error
            res.send({error: err});
          } else {
            // Log the user in
            res.send({status: status, username: username});
          }
        });
      } else {
        res.redirect('/');
      }
    };
```

Using the auto redirect authentication:

```javascript
    exports.cas_login = function(req, res) {
      cas.authenticate(req, res, function(err, status, username, extended) {
        if (err) {
          // Handle the error
          res.send({error: err});
        } else {
          // Log the user in 
          res.send({status: status, username: username, attributes: extended.attributes});
        }
      });    
    }
```

Longer example with CAS proxy (also see the [wiki](https://github.com/joshchan/node-cas/wiki/CAS-Proxy)):

```javascript
    var fs = require('fs');
    var http = require('http');

    // Initialize CAS
    var CAS = require('cas');
    var cas = new CAS({
        base_url: 'https://cas.uwaterloo.ca/cas',
        version: 2.0,
        
        // CAS server will connect to this. It must be accessible on the
        // public internet.
        pgt_server: true,
        ssl_key: fs.readFileSync('/path/to/private_key.pem'),
        ssl_cert: fs.readFileSync('/path/to/ssl_cert.pem'),
        pgt_host: 'my-public-domain.example.com',
        pgt_port: 8989
    });
    
    // Main web server
    var server = http.createServer();
    server.addListener('request', function(req, res) {

        var ip = req.connection.remoteAddress
             || req.socket.remoteAddress 
             || req.connection.socket.remoteAddress;
        
        cas.authenticate(req, res, function(err, status, username, extended) {
            if (err) {
                res.end(err.message);
                return;
            }
            
            // At this point the user has been authenticated. In a real web
            // framework you would want to use sessions to track the info.
            
            res.writeHead(200, {'Content-Type': 'text/html'});
            res.write('<div style="border:solid 1px black; padding:1em; margin:1em;">');
            res.write('<p>Welcome ' + username + '. Your IP address is ' + ip + '.</p>');
            res.write('<p>You are here: <b>http://' + req.headers.host + req.url + '</b></p>');
            
            // CAS server should return a PGTIOU since we specified a PGT callback
            var pgtIOU = extended['PGTIOU'];
            if (pgtIOU) {
                res.write('<p>');
                res.write('Your PGTIOU for this session is: ' + pgtIOU + '<br/>');
                res.write('Your web framework should keep track of this if it wants to use CAS proxied services on your behalf.<br/>');
                res.write('</p>');
                
                // Now you are authorized to fetch a 3rd party service on behalf
                // of the user.
                var url = "http://example.com/user/info";
                cas.getProxyTicket(pgtIOU, url, function(err, ticket) {
                    if (!err) {
                        url += '?ticket=' + ticket;
                        request(url, ... )
                    }
                    res.write('</div>');
                    res.end();
                });
            }
            
            else {
                res.write('</div>');
                res.end();
            }
        
        });
        
    });
    server.listen(8080);
```

## License 

Moved to LICENSE.md
