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

* Sessions in cookies (Node.js): [1](http://www.senchalabs.org/connect/cookieSession.html), [2](/jxa/Connect-Cookie-Session-Storage), [3](/benadida/node-client-sessions)
* Cookie-based SSO: [4](http://support.ideascale.com/kb/ideascale-setup/single-sign-on-multipass-token-based-cookie-based)

Conventions and interoperability
--------------------------------

### Encoding of cookie content

* Session information contained in the cookie is a [BSON-encoded](http://bsonspec.org/) dictionary. BSON was selected over JSON in part for syntactic compactness but 
mostly because it supports binary data and thus can store secure credentials without additional base-64 bloat. 

* There is exactly one field with predefined meaning: `"exp"` (expiration); if present, it should contain a 64-bit UTC timestamp (BSON type `0x09`) determining 
expiration time of the cookie used in order to guard against a [replay attack](http://en.wikipedia.org/wiki/Replay_attack).

* BSON-encoded binary string is encrypted (see below) and then base-64 encoded. In the resulting encoding, characters `"+"` (plus), `"/"` (forward slash) and `"="` (equals) 
are replaced with `"."` (period), `"_"` (underscore) and `"-"`, respectively, in order to avoid potential issues with URL encoding of cookie content performed by some
server-side frameworks.

### Cookie names and HTTP attributes

* The cookies have two-part names separated by dot: the first part is a user-defined prefix (suggested default is `"session"`); the second part identifies the 
encryption key used to create the cookie and its meaning depends on the _key manager_.

* When used within single application, session store or backup cookies should use the default HTTP domain (equal to host). When used for single sign-on purposes within
a single higher-level DNS domain, the HTTP `Domain` attribute should be set explicitly.

* By default, the `HttpOnly` attribute should be set to minimize the potential of replay attacks via cookie theft. It has to be left off in order to implement
cross-domain single sign-on with a browser script.

* As cookies are encrypted, there is no particular benefit to setting the HTTP `Secure` attribute.

* The `Expires` attribute should be set to the same time as the `"exp"` field in the cookie content. Note that while HTTP expiration should always be specified for a 
cookie, the use of internal timestamp is unnecessary in some cases (e.g. if backup credentials are always verified via an external service before being used to
create the session anew).

### Encryption and key management

* Symmetric encryption is strongly suggested.

* As unencrypted content of the cookie is relatively predictable, encryption keys [should not be reused](http://en.wikipedia.org/wiki/Known-plaintext_attack). The
simple and robust approach is to create a new key for every encryption by combining a strong secret key with a [nonce](http://en.wikipedia.org/wiki/Cryptographic_nonce)
and including the nonce (or enough information to reconstruct it) in the key identifier part of the cookie name. When used for SSO purposes, the secret key must be
shared between all participating application instances.

* This implementation provides a simple key manager that uses current timestamp as a nonce. This does not guarantee key uniqueness but should be sufficient
in most cases; enterprise-level single sign-on requires significantly more sophisticated key management strategies that should be implemented by the users of the library.

#### Implementation details

In order for the overall scheme to be interoperable, both key management and encryption should be well defined and supported by all participant. Current implementation
can be interoperable with any other platform supporting AES-256-CBC and SHA1, provided that a shared secret is specified by the user of the library.

The encryption keys are created as follows:

* Lower 48 bits of the current [UNIX time](http://en.wikipedia.org/wiki/Unix_time) expressed in milliseconds, in [little-endian](http://en.wikipedia.org/wiki/Endianness)
encoding are used as a nonce and also stored as the key ID in hexadecimal form;
* The 256-bit AES encryption key is created by computing [HKDF](https://tools.ietf.org/html/rfc5869) using SHA1 as hash function, with the 48-bit value from the 
previous step as input key material and the shared secret as salt.

The cookie content is encrypted as follows:

* AES-256 with cipher-block chaining (`aes-256-cbc` in OpenSSL terms) is applied to the BSON-encoded binary buffer with a random 128-bit initialization vector;
* The resulting binary sequence is prefixed with the initialization vector, resulting in `16*(2+ceil(bson.length/16))` bytes of data before base-64 encoding.

### Usage scenarios

* Session store for a single application: the application itself handles the sign-on sequence and stores session info in the cookie. Re-encrypting and re-sending the
cookie on every request is relatively expensive even if a new key is not generated every time (although it really ought to be) therefore -- if session data does not change
often -- cookie only needs to be re-encrypted to avoid expiration of the active session which can be done relatively infrequently. Current implementation's default is
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

The library API is intentionally kept backward compatible with [Connect sessions](http://www.senchalabs.org/connect/session.html) to the largest possible extent. Note
that `galette` can be used either as a drop-in replacement for `connect.session` or in conjunction with it (to provide session backup and/or single signon capability).

### Session store

	var galette = require( 'galette' ),
		connect = require('connect'),
		app = connect()
			.use( connect.cookieParser() )
			.use( galette( /* options */ ) )
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
			.use( galette({ 
				name: /* something other than "session" */
				/* other options */ 
			}) )
			.use( /* Your application */ );

Installs credential backup middleware into the middleware stack. It does not replace `connect.sesssion()` and does not work with `req.session`. Instead, it uses another 
property of the request object: you specify its name using the `"name"` property of the options dictionary. Your application is expected to populate it as part of the 
sign-on and can use the information in it  to re-establish the session if `req.session` is not available.

### Single sign-on

To implement single sign-on, use either of the approaches above. Your application (service provider, in SSO terms) is responsible for forwarding the browser to the
single sign-on page (identity provider) if either `req.session` or `req.creds` are not available. The sign-on page is responsible for populating either `req.session` or
`req.creds` and forwarding the browser back to the application. This library does not provide any support for page forwarding or implement a key management scheme
to properly deal with shared secrets -- unless you choose to store the shared secret(s) directly in the configuration or code of all applications participating in the
SSO (see the section below).

### Options

* `name`: name of the property of the request object where session information will be stored; also, first part of the cookie name (before the dot). Defaults to 
`"session"`.

* `expireAfter`: session and cookie lifetime in milliseconds. If set to `null`, uses browser-session cookies and does not trake the lifetime; this is also the default
behavior when neither `expireAfter` nor `cookie.maxAge` are specified.

* `refreshAfter`: controls session keep-alive behavior by forcing re-encryption of the cookie after the specified number of milliseconds from its creation or last 
refresh. If not set, defaults to 1/2 of `expireAfter` value; to disable session keep-alive completely set it to a value greater or equal to `expireAfter`. Note that
the cookie is always refreshed if the underlying data are modifed by the application. Setting `refreshAfter` to 0 will force the cookie to refresh on every request 
no matter what.

* `timestamp`: defaults to `true` when `expireAfter` is set. This setting adds the `"exp"` property to cookie content and checks it on every access to guard against 
possible replay attacks. Set to `false` when application-controlled checks make the timestamp unnecessary; the setting is ignored if neither `expireAfter` nor 
`cookie.maxAge` are specified as part of options.

* `cipher`: a callback function accepting three arguments (key, plaintext and callback); the callback is invoked with the resulting ciphertext, or with the error 
object. Key, plaintext and ciphertext are `Buffer`s. The library provides a default version using AES-256 with a random intialization vector.

* `decipher`: a counterpart function to `cipher` with the same parameter types; `cipher` and `decipher` should be provided together or not at all.

* `keyManager`: a callback function called with no arguments to generate a new key or with a single string argument, key ID, taken from the cookie name. In
either case, the key manager should return a plain object with at least 2 properties: `id` (a string suitable to become part of a cookie name) and `value` 
(a `Buffer`). The key returned should be compatible with `cipher` and `decipher` implementations in use. The library provides a default key manager that 
uses stored (either configured or automatically generated) secret and combines it with current timestamp to obtain the key.

* `secret`: only used by the default key manager. If not set, the secret is generated automatically so it could not be shared with other instances of the
same application or with other applications and it will not be preserved across the server restart. Set it to a long (160 bit is good) pseudorandom bit string
(in binary encoding); you can obtain one by calling `crypto.randomBytes( 20 )`.

* `cookie`: initial property settings for the cookie object, as follows:

 * `domain`: if not speficied, will be left blank effectively restricting the cookie to current host;

 * `path`: defaults to `"/"`;

 * `maxAge`: cookie (and session) lifetime in _seconds_; it is recommended to use the `expireAfter` option which overrides `maxAge`;'

 * `httpOnly`: defaults to `true` if `cookie` is not specified at all, otherwise should be specified explicitly;

 * `secure`: set to `true` to transmit the cookie only through HTTPS; the library code ignores this setting.

### Properties and methods of the session object

* `cookie`: can be used to dynamically adjust cookie properties (`domain`, `path`, `httpOnly`, `secure`, `maxAge` or `expires`) on a per-request basis. Note that
a change to any of these properties does not automatically re-encrypt and resend the cookie; you may have to call `save()` method on the session object to force it.

* `regenerate()`: regenerates the session and destroys old content.

* `destroy()`: destroys the session content; will remove the cookie if new content is not added to the session afterwards.

* `reload()`: resets the session object content to the data that were received with the cookie.

* `save()`: forces the library to re-encrypt and resend the session with the response to current request.

### Differences from `Connect.session`

While galette API is generally backwards compatible, there are certain differences due to the nature of its implementation:

* Changes to session made after response headers have been sent will be ignored;

* `destroy()` does not destroy the session object itself, only its user-supplied properties;

* `touch()` is not provided.


