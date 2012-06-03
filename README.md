galette
=======

Session store/session backup/SSO based on encrypted cookies; implemented as [Connect](http://www.senchalabs.org/connect) middleware for Node.js.

[TL;DR](#api-and-usage-examples)

Rationale
---------

Conventional wisdom states that [session data belongs in server-side storage](http://wonko.com/post/why-you-probably-shouldnt-use-cookies-to-store-session-data)
and that [single sign-on](http://en.wikipedia.org/wiki/Single_sign-on) is best performed by [pushing bits of XML around with page 
forwarding](http://en.wikipedia.org/wiki/SAML_2.0#SAML_2.0_Bindings). Yet the accepted approaches present problems that are sometimes hard to overcome:

* Scalability: every instance of the application server requires access to session store. Unless sessions are sticky (instance-affine), _all_
instances of the application have to talk to the _same_ session store. This is a real bummer if the instances do not sit in the same data center.

* Fault tolerance: session store becomes a single point of failure -- if it crashes, all session information is lost. Modern applications tend to
use in-memory databases such as [memcached](http://memcached.org/) or [Redis](http://redis.io/) as their session stores. In-memory databases are
designed for speed, not fault tolerance: their most effective method of crash recovery is to drop the database and restart. Improvements exist, but
entail performance costs and don't really bring them up to the level of a clustered journaled database.

* Friendliness to frontend-centric (AJAX) applications: page forwarding destroys application state embedded in browser scripts.

This library aims to provide [an alternative to traditional sessions and single sign-on](/MaxMotovilov/galette/wiki/Flame-on!) in an
interoperable manner, perhaps becoming a reference implementation for a new standard in the future.

Prior art
---------

* Sessions in cookies (Node.js): [1](/jxa/Connect-Cookie-Session-Storage), [2](/benadida/node-client-sessions)
* Cookie-based SSO: [3](http://support.ideascale.com/kb/ideascale-setup/single-sign-on-multipass-token-based-cookie-based)

Conventions and interoperability
--------------------------------

### Encoding of cookie content

* Session information contained in the cookie is a [BSON-encoded](http://bsonspec.org/) dictionary. BSON was selected over JSON in part for syntactic compactness but 
mostly because it supports binary data and thus can store secure credentials without additional base-64 bloat. 

* There is exactly one field with predefined meaning: `"exp"` (expiration); if present, it should contain a 64-bit UTC timestamp (BSON type `0x09`) determining 
expiration time of the cookie used in order to guard against a [replay attack](http://en.wikipedia.org/wiki/Replay_attack).

* BSON-encoded binary string is encrypted (see below) and then base-64 encoded.

### Cookie names and HTTP attributes

* The cookies have two-part names separated by dot: the first part is a user-defined prefix (suggested defaults are `"session"` for session store cookies and `"creds"` 
for session backup/single sign-on credentials); the second part identifies the encryption key used to create the cookie and its meaning depends on the _key manager_.

* When used within single application, session store or backup cookies should use the default HTTP domain (equal to host). When used for single sign-on purposes within
a single higher-level DNS domain, the HTTP `Domain` attribute should be set explicitly.

* By default, the `HttpOnly` attribute should be set to minimize the potential of replay attacks via cookie theft. It has to be left off in order to implement
cross-domain single sign-on with a browser script.

* As cookies are encrypted, there is no particular benefit to setting the HTTP `Secure` attribute.

* The `Expires` attribute should be set to the same time as the `"exp"` field in the cookie content. Note that while HTTP expiration should always be specified for a 
cookie, the use of internal timestamp is unnecessary in some cases (e.g. if backup credentials are always verified via an external service before being used to
create the session anew).

### Encryption and key management

* Symmetric encryption is strongly suggested (current implementation uses AES-256-CBC).

* As unencrypted content of the cookie is relatively predictable, encryption keys [should not be reused](http://en.wikipedia.org/wiki/Known-plaintext_attack). The
simple and robust approach is to create a new key for every encryption by combining a strong secret key with a [nonce](http://en.wikipedia.org/wiki/Cryptographic_nonce)
and including the nonce (or enough information to reconstruct it) in the key identifier part of the cookie name. When used for SSO purposes, the secret key must be
shared between all participating application instances.

* This implementation provides a simple key manager that uses random 64-bit number as a nonce. This does not guarantee key uniqueness but should be sufficient
in most cases; enterprise-level single sign-on requires significantly more sophisticated key management strategies that should be implemented by the users of the library.

### Usage scenarios

* Session store for a single application: the application itself handles the sign-on sequence and stores session info in the cookie. Re-encrypting and re-sending the
cookie on every request is relatively expensive even if new key is not generated every time (although it really ought to be) therefore if session data does not change
often, cookie only needs to be re-encrypted to avoid expiration of the active session which can be done relatively infrequently. Current implementation's default is
to refresh the cookie once half of the session lifetime has passed.

* Session backup for a single application: the application uses traditional session data storage (for example, because session data is large or changes frequently) but
would like to be able to recreate the session in the event of failover to a different storage, making the switch transparent to the end user. In this case the application
stores some form of secure credentials (verifiable token is OK, but **not** a plaintext password -- this can come back and bite you in too many ways!) in the cookie and
will only unencrypt and use it if the session data are lost. The backup cookies should still expire but may have a relatively long lifetime.

* Single sign-on: may come in many flavors, but normally one application (identity provider) would store credentials in the cookie and other applications (within the
same domain) would be able to access them and create sessions of their own transparently to the user by reconstructing the encryption key from the shared secret and
the nonce taken from the cookie name. Any of participating applications can then refresh the common session by re-encrypting the cookie with a new timestamp. 
Enterprise-wide single sign on requires sophisticated key management to guard against leakage of shared secrets from compromised application servers.

API and usage examples
----------------------

### Session store

	var galette = require( 'galette' ),
		connect = require('connect'),
		app = connect()
			.use( connect.cookieParser() )
			.use( galette.session( /* options */ ) )
			.use( /* Your application */ );

Installs cookie-based session middleware into the middleware stack. Do not use `galette.session()` together with `connect.session()` -- while they provide identical 
services to the rest of the application, each takes control over `req.session`. Your application is responsible for populating `req.session` as part of its sign-on process
in the same way it would be with [Connect built-in session middleware](http://www.senchalabs.org/connect/session.html).

### Session/credential backup

	var galette = require( 'galette' ),
		connect = require('connect'),
		app = connect()
			.use( connect.cookieParser( "secret" ) )
			.use( connect.session( /* connect.session options */ ) )
			.use( galette.creds( /* options */ ) )
			.use( /* Your application */ );

Installs credential backup middleware into the middleware stack. It does not replace `connect.sesssion()` and does not work with `req.session`. Instead, it uses another 
property of the request object, `req.creds`: your application is expected to populate it as part of the sign-on and can use the information in it  to re-establish 
the session if `req.session` is not available.

### Single sign-on

To implement single sign-on, use either of the approaches above. Your application (service provider, in SSO terms) is responsible for forwarding the browser to the
single sign-on page (identity provider) if either `req.session` or `req.creds` are not available. The sign-on page is responsible for populating either `req.session` or
`req.creds` and forwarding the browser back to the application. This library does not provide any support for page forwarding or implement a key management scheme
to properly deal with shared secrets -- unless you choose to store the shared secret(s) directly in the configuration or code of all applications participating in the
SSO (see the section below).

### Options

Both `galette.session()` and `galette.creds()` understand a common dictionary of options:

* `cookieName`: first part of the cookie name (before the dot). Defaults to `"session"` for `galette.session()`, `"creds"` for `galette.creds()`.

* `expireAfter`: session lifetime in seconds (or lifetime of the credentials backup). Defaults to 3600 (1 hour).

* `refreshAfter`: forces re-encryption of the cookie after so many seconds from its creation or last refresh. If not set, defaults to 1/2 of `expireAfter` 
value; to disable session keep-alive completely set it to a value greater or equal to `expireAfter` (it will still be refreshed if `req.session` or 
`req.creds`, respectively, are modified). Setting it to 0 will force the cookie to refresh on every request no matter what.

* `ignoreChanges`: set to `true` to disable refresh of the cookie when `req.session` or `req.creds` are modified by your application. The session data or credential
backup data will be frozen after initial population; the cookie may still be refreshed as part of the keep-alive logic if so desired (see `refreshAfter`).

* `timestamp`: defaults to `true` which causes the `"exp"` property to be added to the cookie content and checked on every access to guard against possible replay
attacks. Set to `false` when application-controlled checks make the timestamp unnecessary/

* `cipher`: a callback function accepting two arguments (key and plaintext) and returning the ciphertext, all as binary-encoded strings. The library 
provides a default version using AES-256 (expecting 256-bit keys from the key manager).

* `decipher`: a callback function accepting two arguments (key and ciphertext) and returning the plaintext, all as binary-encoded strings. The library 
provides a counterpart to the default implementation of `cipher`.

* `keyManager`: a callback function called with no arguments to generate a new key or with a single string argument, key ID, taken from the cookie name. In
either case, the key manager should return a plain object with 2 properties: `id` and `key`. The key returned should be compatible with `cipher` and
`decipher` implementations in use. The library provides a default key manager that uses a stored (either configured or automatically generated) secret
and combines it with a random nonce to obtain the key.

* `secret`: only used by the default key manager. If not set, the secret is generated automatically so it could not be shared with other instances of the
same application or with other applications and it will not be preserved across the server restart. Set it to a long (192 bit or more) pseudorandom bit string
(in binary encoding); you can obtain one from `crypto.randomBytes()`.

