
/**
 * Module dependencies.
 */

var CAS = require('../lib/cas')
  , should = require('should')
  , nock = require('nock');

var base_url = 'https://localhost/cas',
    service = 'test_service',
    sso_servers = ['test_remote_address'],
    cas = new CAS({
      base_url: base_url, 
      service: service,
      version: 2.0,
      sso_servers: sso_servers
    });

module.exports = {
  'test .version': function(){
    CAS.version.should.match(/^\d+\.\d+\.\d+$/);
  },
  
  
  'handleSingleSignout - should return valid ticket in logout callback': function() {
      var ticket = 'TICKET';

      var req = {
          method: 'POST',
          body: {
              'logoutRequest': '<samlp:SessionIndex>' + ticket + '</samlp:SessionIndex>'
          },
          connection: {
              remoteAddress: sso_servers[0]
          }
      };
      var res = {};
      var next = function() {
          should.not.exist(true, 'should not call next function');
      };
      var logoutCallback = function(result) {
          ticket.should.equal(result, 'should return valid ticket');
      };

      cas.handleSingleSignout(req, res, next, logoutCallback);
  },
  
  
  'validate - should return valid ': function() {
      var ticket = "TICKET";
      var user = "USERNAME";
      var attributes = { 
          attrastyle: [ 'RubyCAS' ],
          surname: [ 'Smith' ],
          givenname: [ 'John' ],
          memberof: [ 'CN=Staff,OU=Groups,DC=example,DC=edu', 'CN=Spanish Department,OU=Departments,...' ]
      };
      var attributesTag = '<cas:attributes>' +
                     '<cas:attraStyle>' + attributes.attrastyle[0] + '</cas:attraStyle>' +
                     '<cas:surname>' + attributes.surname[0] + '</cas:surname>' +
                     '<cas:givenName>' + attributes.givenname[0] + '</cas:givenName>' +
                     '<cas:memberOf>' + attributes.memberof[0] + '</cas:memberOf>' +
                     '<cas:memberOf>' + attributes.memberof[1] + '</cas:memberOf>' +
                 '</cas:attributes>';
      var proxyGrantingTicket = "PROXY_GRANTING_TICKET";
      var proxies = ['proxy1', 'proxy2'];
      var proxiesTag = '';
      proxies.forEach(function(proxy) {
        proxiesTag += '<cas:proxies>' + proxy + '</cas:proxies>';
      });
 
      nock(base_url)
        .get('/proxyValidate')
        .query({ticket: ticket, service: service})
        .reply(200, 
        '<cas:serviceResponse xmlns:cas="http://www.yale.edu/tp/cas">' +
        '<cas:authenticationSuccess>' +
        '<cas:user>' + user + '</cas:user>' +
        attributesTag+
        '<cas:proxyGrantingTicket>' + proxyGrantingTicket + '</cas:proxyGrantingTicket>' +
        proxiesTag + 
        '</cas:authenticationSuccess>' + 
        '</cas:serviceResponse>');

      var callback = function(err, one, username, ticketInfo) {
          should.not.exist(err, 'should not have any errors');
          
          one.should.equal(true);
          
          should.exist(username, 'username should exist');
          user.should.equal(username, 'username should valid');
          
          should.exist(ticketInfo, 'ticketInfo should exist');
          
          should.exist(ticketInfo.username, 'username property should exist');
          user.should.equal(ticketInfo.username, 'username should valid');
          
          should.exist(ticketInfo.attributes, 'attributes property should exist');
          attributes.should.deepEqual(ticketInfo.attributes, 'attributes should valid');

          should.exist(ticketInfo.PGTIOU, 'PGTIOU property should exist');
          proxyGrantingTicket.should.equal(ticketInfo.PGTIOU, 'PGTIOU property should valid');
        
          should.exist(ticketInfo.ticket, 'ticket property should exist');
          ticket.should.equal(ticketInfo.ticket, 'ticket property should valid');

          should.exist(ticketInfo.proxies, 'proxies property should exist');
          proxies.should.deepEqual(ticketInfo.proxies, 'proxies should valid');
      };

      cas.validate(ticket, callback, service, null); 
  },
    
  
};