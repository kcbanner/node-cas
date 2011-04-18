
# cas

  Central Authentication Service (CAS) client for Node.js

  This module only handles the ticket validation step of the CAS login process. Planned features include functions to generate the login/logout URLs.

  Generally, to start the login process, send your users to: `https://cas_base_url/login?service=url_to_handle_ticket_validation`. In the University of Waterloo example below, this url would be: `https://cas.uwaterloo.ca/cas/login?service='my_service'`.

## Installation

via npm:

    $ npm install cas

## Usage

Setup:

    var CAS = require('cas');
    var cas = new CAS({base_url: 'https://cas.uwaterloo.ca/cas', service: 'my_service'});

Using it in a login route:

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