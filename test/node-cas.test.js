
/**
 * Module dependencies.
 */

var cas = require('node-cas')
  , should = require('should');

module.exports = {
  'test .version': function(){
    cas.version.should.match(/^\d+\.\d+\.\d+$/);
  }
};