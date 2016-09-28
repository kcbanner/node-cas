0.0.5 / 2015-09-04
==================

  * Functionality unchanged, but terminology has been revised for correctness and clarity.
      * Disambiguate `PGT callback server` from `proxy server`
      * Disambiguate `CAS proxy` from `HTTP proxy`
      - HTTP proxy functionality unchanged but is now **deprecated**
        - Originally, the HTTP proxy functions were intended to be the way of making authorized requests from 3rd party services. However, it is better to simply obtain a `ticket` via getProxyTicket() to use with a fully featured HTTP client like [request](https://github.com/request/request).

  * Some options have been renamed (old names are **deprecated** but still work):
      * old: `proxy_server` => new: `pgt_server`
      * old: `proxy_callback_host` => new: `pgt_host`
      * old: `proxy_callback_port` => new: `pgt_port`
      * old: `proxy_server_key` => new: `ssl_key`
      * old: `proxy_server_cert` => new: `ssl_cert`
      * old: `proxy_server_ca` => new: `ssl_ca`

  * These options are **deprecated** (but work the same as before):
      - `proxy_server_port`
      - `external_proxy_url`
    
  * These methods are also **deprecated** (but work the same as before):
      - proxiedRequest()
      - proxiedRequestExternal()

0.0.4 / 2012-02-17
==================

  * Support for CAS 2.0 features
      - CAS extended attributes
      - CAS proxies
      
        . provides built-in PGT callback and proxy servers
        . can make proxied requests with internal proxy server
        . can act as a standalone external proxy server for others
        . can make proxied requests with external proxy server
        
  * single sign out support
  * auto redirect with authenticate()
  * logout


0.0.1 / 2010-01-03
==================

  * Initial release
