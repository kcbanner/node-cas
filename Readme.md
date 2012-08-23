# cas

  Central Authentication Service (CAS) client for Node.js

  This module handles CAS authentication (with support for proxies and extended attributes), and can also transparently redirect a web page if needed. The ticket validation step is available as its own function for those who wish to handle things manually. Proxied requests can be made through a function call, or optionally through an HTTP request with custom headers. Single sign out is also supported with Express/Connect.
  
  To start the login process manually, send your users to: `https://cas_base_url/login?service=url_to_handle_ticket_validation`. In the University of Waterloo example below, this url would be: `https://cas.uwaterloo.ca/cas/login?service='my_service'`.
  
  Or if you are using standard HTTP req/res objects for a web page, you may use the provided `authenticate()` function to handle the redirection automatically.
  
  It is also possible to use this as a standalone CAS proxy server.
  
  

## Installation

via npm:

    $ npm install cas

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
        
        proxy_server: true,
        proxy_server_port: 0, // disable inbound external proxy connections
        proxy_server_key: fs.readFileSync('/path/to/private_key.pem'),
        proxy_server_cert: fs.readFileSync('/path/to/ssl_cert.pem'),
        
        // CAS server will connect to this. It must be accessible on the
        // public internet.
        proxy_callback_host: 'my-public-domain.example.com',
        proxy_callback_port: 8989
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
            
            // CAS server should return a PGTIOU since we specified a proxy
            var pgtIOU = extended['PGTIOU'];
            if (pgtIOU) {
                res.write('<p>');
                res.write('Your PGTIOU for this session is: ' + pgtIOU + '<br/>');
                res.write('Your web framework should keep track of this if it wants to use CAS proxied services on your behalf.<br/>');
                res.write('</p>');
            
                // For testing the proxy function at "/proxyDirect"
                if (req.url.match(/proxyDirect/)) {
                    res.write('Starting direct proxy request...<br/>');
                    
                    // Fetch http://localhost:8080/test through the proxy on user's behalf
                    cas.proxiedRequest(pgtIOU, {
                        protocol: 'http:',
                        method: 'GET',
                        hostname: 'localhost',
                        port: 8080,
                        pathname: '/test'
                    }, function(err, proxyReq, proxyRes) {
                        // Just display the proxied results directly
                        proxyRes.on('data', function(chunk) {
                            res.write(chunk);
                        });
                        proxyRes.on('end', function() {
                            res.write('Proxy Done<br/>');
                            res.write('</div>');
                            res.end();
                        });
                    });
                    
                    return;
                } // end of "/proxyDirect"
            }
            
            // Normal requests, such as to "/test"
            res.write('Done<br/>');
            res.write('</div>');
            res.end();
        
        });
        
    });
    server.listen(8080);
```

## License 

(The MIT License)

Copyright (c) 2011 Casey Banner &lt;kcbanner@gmail.com&gt;

Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the
'Software'), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED 'AS IS', WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.