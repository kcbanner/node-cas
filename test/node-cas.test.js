
/**
 * Module dependencies.
 */

var CAS = require('../lib/cas')
    , should = require('should')
    , nock = require('nock');

// Initial server infomation
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
    'test .version': function () {
        CAS.version.should.match(/^\d+\.\d+\.\d+$/);
    },


    'handleSingleSignout - should return valid ticket in callback': function () {
        // Assign
        var ticket = 'TICKET';

        var req = {
            method: 'POST',
            body: {
                logoutRequest: '<samlp:LogoutRequest>' + 
                                    '<samlp:SessionIndex>' + 
                                        ticket + 
                                    '</samlp:SessionIndex>' +
                               '</samlp:LogoutRequest>'
            },
            connection: {
                remoteAddress: sso_servers[0]
            }
        };
        var res = {};
        var next = function () {
            // Assert
            should.not.exist(true, 'should not call this function');
        };
        var logoutCallback = function (result) {
            // Assert
            should.equal(result, ticket, 'should return valid ticket');
        };

        // Action
        cas.handleSingleSignout(req, res, next, logoutCallback);
    },


    'handleSingleSignout - should call next method when get invalid request': function() {
        // Assign
        var req = {
            method: 'POST',
            body: {
                logoutRequest: 'INVALID REQUEST'
            },
            connection: {
                remoteAddress: sso_servers[0]
            }
        };
        var res = {};
        var next = function () {
            // Assert
            should.exist(true, 'should call this function');
        };
        var logoutCallback = function (result) {
            // Assert
            should.not.exist(result, 'should not return any tickets');
        };

        // Action
        cas.handleSingleSignout(req, res, next, logoutCallback);
    },


    'validate - should return valid ticket information': function () {
        // Assign
        var ticket = "TEST TICKET";
        var user = "TEST USERNAME";
        var attributes = {
            attrastyle: ['RubyCAS'],
            surname: ['Smith'],
            givenname: ['John'],
            memberof: ['CN=Staff,OU=Groups,DC=example,DC=edu', 'CN=Spanish Department,OU=Departments,...']
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
        proxies.forEach(function (proxy) {
            proxiesTag += '<cas:proxies>' + proxy + '</cas:proxies>';
        });

        // Mock up response 
        nock(base_url)
            .get('/proxyValidate')
            .query({ ticket: ticket, service: service })
            .reply(200,
                '<cas:serviceResponse xmlns:cas="http://www.yale.edu/tp/cas">' +
                    '<cas:authenticationSuccess>' +
                        '<cas:user>' + user + '</cas:user>' +
                        attributesTag +
                        '<cas:proxyGrantingTicket>' + proxyGrantingTicket + '</cas:proxyGrantingTicket>' +
                        proxiesTag +
                    '</cas:authenticationSuccess>' +
                '</cas:serviceResponse>');

        var callback = function (err, one, username, ticketInfo) {
            // Assert
            should.not.exist(err, 'should not have any errors');

            one.should.equal(true);

            should.exist(username, 'should have username');
            should.equal(username, user, 'should return valid username');

            should.exist(ticketInfo, 'should have ticketInfo');

            should.exist(ticketInfo.username, 'should have username property');
            should.equal(ticketInfo.username, user, 'should have username');

            should.exist(ticketInfo.attributes, 'should have attributes property');
            should.deepEqual(ticketInfo.attributes, attributes, 'should have attributes');

            should.exist(ticketInfo.PGTIOU, 'should have PGTIOU property');
            should.equal(ticketInfo.PGTIOU, proxyGrantingTicket, 'should have PGTIOU property');

            should.exist(ticketInfo.ticket, 'should have ticket property');
            should.equal(ticketInfo.ticket, ticket, 'should return valid ticket property');

            should.exist(ticketInfo.proxies, 'should have proxies property');
            should.deepEqual(ticketInfo.proxies, proxies, 'should return valid proxies');
        };

        // Action
        cas.validate(ticket, callback, service, null);
    },


    'validate - should return error when server does not return user info': function () {
        // Assign
        var ticket = "TEST TICKET";

         // Mock up response 
        nock(base_url)
            .get('/proxyValidate')
            .query({ ticket: ticket, service: service })
            .reply(200,
                '<cas:serviceResponse xmlns:cas="http://www.yale.edu/tp/cas">' +
                    '<cas:authenticationSuccess>' +
                        '<cas:proxyGrantingTicket>TEST PROXY GRANTING TICKET</cas:proxyGrantingTicket>' +
                    '</cas:authenticationSuccess>' +
                '</cas:serviceResponse>');

         var callback = function (err, one, username, ticketInfo) {
            // Assert
            should.exist(err, 'should return a error');
            should.equal(err.message, 'No username?', 'should return no username error message');
            
            should.exist(one, 'should return');
            should.equal(one, false, 'should return false');
            
            should.not.exist(username, 'should not return username');
            should.not.exist(ticketInfo, 'should not return ticket info');
         };

        // Action
        cas.validate(ticket, callback, service, null);
    },


    'validate - should return error when server does not return invalid info': function () {
        // Assign
        var ticket = "TEST TICKET";

         // Mock up response 
        nock(base_url)
            .get('/proxyValidate')
            .query({ ticket: ticket, service: service })
            .reply(200, 'INVALID RESPONSE DATA');

         var callback = function (err, one, username, ticketInfo) {
            // Assert
            should.exist(err, 'should return a error');
            should.equal(err.message, 'Bad response format.', 'should return bad request error message');
            
            should.not.exist(one, 'should not return');
            should.not.exist(username, 'should not return username');
            should.not.exist(ticketInfo, 'should not return ticket info');
         };

        // Action
        cas.validate(ticket, callback, service, null);
    },


    'getProxyTicket - should return valid proxy ticket': function () {
        // Assign
        var proxyTicket = 'TEST proxyTicket';
        var pgtID = 'TEST pgtID';
        var pgtIOU = 'TEST pgtIOU';

        cas.pgtStore[pgtIOU] = {
            'pgtID': pgtID,
            'time': process.uptime()
        };

        // Mock up response 
        nock(base_url)
            .get('/proxy')
            .query({ targetService: service, pgt: pgtID })
            .reply(200, '<cas:serviceResponse>' +
                            '<cas:proxySuccess>' +
                                '<cas:proxyTicket>' + proxyTicket + '</cas:proxyTicket>' +
                            '</cas:proxySuccess>' +
                        '</cas:serviceResponse>');

        var callback = function (err, returnProxyTicket) {
            // Assert
            should.not.exist(err, 'should not have any errors');

            should.exist(returnProxyTicket, 'should have proxy ticket');
            should.equal(returnProxyTicket, proxyTicket, 'should return valid proxy ticket');
        };

        // Action
        cas.getProxyTicket(pgtIOU, service, callback);
    },
    
    'getProxyTicket - should return proxy failure error': function () {
        // Assign
        var pgtID = 'TEST pgtID';
        var pgtIOU = 'TEST pgtIOU';

        cas.pgtStore[pgtIOU] = {
            'pgtID': pgtID,
            'time': process.uptime()
        };

        var errorCode = 500;
        var errorMessage = 'TEST Error message';

        // Mock up response
        nock(base_url)
            .get('/proxy')
            .query({ targetService: service, pgt: pgtID })
            .reply(200, '<cas:serviceResponse>' +
                            '<cas:proxyFailure code="' + errorCode + '">' +
                                errorMessage +
                            '</cas:proxyFailure>' +
                        '</cas:serviceResponse>');
                        
        var callback = function(err, returnProxyTicket) {
            // Assert
            should.exist(err, 'should have a error');
            should.equal(err.message, 'Proxy failure [' + errorCode + ']: ' + errorMessage, 'should return valid error message');
            
            should.not.exist(returnProxyTicket, 'should not return any tickets');
        };

        // Action
        cas.getProxyTicket(pgtIOU, service, callback);
    },
    
    
    'getProxyTicket - should return bad request when server return invalid data': function() {
        // Assign
        var pgtID = 'TEST pgtID';
        var pgtIOU = 'TEST pgtIOU';

        cas.pgtStore[pgtIOU] = {
            'pgtID': pgtID,
            'time': process.uptime()
        };

        var invalidResponse = 'INVALID RESPONSE DATA';

        // Mock up response
        nock(base_url)
            .get('/proxy')
            .query({ targetService: service, pgt: pgtID })
            .reply(200, invalidResponse);
                        
        var callback = function(err, returnProxyTicket) {
            // Assert
            should.exist(err, 'should have a error');
            console.log(err.message);
            should.equal(err.message, "Bad response format: " + invalidResponse, 'should return bad request error message');
            
            should.not.exist(returnProxyTicket, 'should not return any tickets');
        };

        // Action
        cas.getProxyTicket(pgtIOU, service, callback);
    }

};