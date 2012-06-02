galette
=======

Session store/session backup/SSO based on encrypted cookies; implemented as [Connect](http://www.senchalabs.org/connect) middleware for Node.js.

Rationale
---------

Conventional wisdom states that [session data belongs in server-side storage](http://wonko.com/post/why-you-probably-shouldnt-use-cookies-to-store-session-data)
and that single sign-on is best performed by [pushing bits of XML around with page forwarding](http://en.wikipedia.org/wiki/SAML_2.0#SAML_2.0_Bindings). Yet the
accepted approaches present problems that are sometimes hard to overcome:

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

API and usage examples
----------------------
