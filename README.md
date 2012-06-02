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

* This implementation provides a simple key manager that uses current UTC timestamp as a nonce. This does not guarantee key uniqueness but should be sufficient
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
