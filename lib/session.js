// Copyright (C) 2014 12 Quarters Consulting
//           (C) 2012 ...Max... & Adstream Holdings
// All rights reserved.
// Redistribution and use are permitted under the modified BSD license
// available at https://github.com/MaxMotovilov/adstream-js-frameworks/wiki/License

var	BSON = require( 'buffalo' ),
	connect = require( 'connect' ),
	promise = require( 'node-promise' ),
	debug = console.log,
	cookie = require( 'cookie' ),
	merge = require( 'utils-merge' ),

	toSafeBase64Regex = /[+\/=]/g,
	fromSafeBase64Regex = /[._\-]/g,
	safeBase64Replace = '+./_=-';

function cleanup( o ) {
	Object.keys( o ).forEach( function( f ){ delete o[f]; } );
}

function shallowCopy( o ) {
	var v = {};
	Object.keys( o ).forEach( function( f ){ v[f] = o[f]; } );
	return v;
}

function Cookie(){}

Cookie.prototype = {

	get maxAge() {
		return this.expires ? Math.round( (this.expires.valueOf() - Date.now()) / 1000 ) : null;
	},

	set maxAge( age ) {
		this.expires = new Date( Date.now() + 1000*age );
	}
};

(module.exports = function galette_SessionState( options, req ) {

	this.$options = options;

	// Mutable session state
	this.$ = { /*
		old: {
			id: 		string,
			data:		BSON,
			seq:		number?,
			expires:	number?
		},
		requireRefresh:	boolean?
	*/ };
	this.$remove = [];

	// Compatibility with connect.session
	this.cookie = merge( new Cookie(), options.cookie );
	if( options.expireAfter ) 
		this.cookie.expires = new Date( Date.now() + options.expireAfter );

}).prototype = {

	makeSession: function() {
		function galette_SessionData(){}
		galette_SessionData.prototype = this;
		return new galette_SessionData();
	},

	// Methods of galette_SessionData

	initialize: function( key_id, base64_ciphertext ) {

		var	p, _this = this;

		function signal( err ) {
			_this.$remove.push( key_id );
			debug( _this.$options.name + '.' + key_id + ':', err );
			if( p )	p.reject( err );
			else throw err;
		}

		try {
			this.$options.keyManager( key_id, 
				function( err, key ) {
					if( err )
						signal( err );
					else try {
						_this.$options.decipher( 
							key.value, 
							new Buffer( 
								base64_ciphertext.replace( fromSafeBase64Regex, function(c){ 
									return safeBase64Replace.charAt( safeBase64Replace.indexOf(c) - 1 );
								} ), 'base64' 
							),
							function( err, plaintext ) {
								if( err )
									signal( err );
								else try {
									_this.$initialize( plaintext, key.id, key.seq );
									if( p )	p.resolve( true );
									else p = true;
								} catch( e ) {
									signal( e );
								}
							}
						);
					} catch( e ) { 
						signal( e ); 
					}
				} 
			);

		} catch( e ) { 
			return e;
		}

		return p || (p = promise.defer());
	},

	$initialize: function( bson, key_id, seq ) {
		if( !this.$.old ||
			seq && this.$.old.seq < seq ) {

			var s = BSON.parse( bson );
			if( s.exp && s.exp.valueOf() < Date.now() )
				throw Error( "Possible replay attack" );

			this.$.old = { id: key_id };

			if( s.exp ) {
				this.$.old.expires = s.exp.valueOf();
			
				var now = Date.now();
				if( now + ( this.$options.expireAfter - this.$options.refreshAfter ) >= this.$.old.expires ) {
					this.cookie.expires = new Date( now + this.$options.expireAfter );
					this.$.requireRefresh = true;
				}

				delete s.exp;
				this.$.old.data = BSON.serialize( s );
			}
			else
				this.$.old.data = bson;

			cleanup( this );
			merge( this, s );

			if( seq )	this.$.old.seq = seq;

		} else
			this.$remove.push( key_id );
	},

	commit: function( res ) {

		var bson, p, key_id, _this = this;

		function signal( err ) {
			debug( _this.$options.name + '.' + ( key_id || '*' ) + ':', err );
			if( p )	p.reject( err );
			else throw err;
		}

		if( this.$.requireRefresh ||
			(bson = BSON.serialize( shallowCopy( this ) )).toString( 'binary' ) !== 
				( this.$.old ? this.$.old.data : BSON.serialize({}) ).toString( 'binary' )
		) {
			if( this.$options.timestamp && this.cookie.expires && (this.exp = this.cookie.expires) || !bson )
				bson = BSON.serialize( shallowCopy( this ) );
			if( this.$.old )	
				this.$remove.push( this.$.old.id );

			try {
				this.$options.keyManager(
					function( err, key ) {

						// For debugging purposes
						if( key )	key_id = key.id;

						if( err )
							signal( err );
						else _this.$options.cipher( key.value, bson,
							function( err, ciphertext ) {
								if( err )
									signal( err );
								else {
									if( _this.$remove.length && _this.$remove[_this.$remove.length-1] ===
										_this.$options.name + '.' + key.id )
										_this.$remove.pop(); // Paranoids have enemies too

									res.setHeader( 'Set-Cookie',
										cookie.serialize(
											_this.$options.name + '.' + key.id, 
											ciphertext.toString( 'base64' )
												.replace( toSafeBase64Regex, function(c){ 
														return safeBase64Replace.charAt( safeBase64Replace.indexOf(c) + 1 );
												} ),
											_this.cookie
										)
									);
									if( p )	p.resolve( true );
									else p = true;
								}
							}
						);
					}
				);
			} catch( e ) { 
				return e;
			}
		} else
			p = true;
		
		var	delete_cookie_options = merge( {}, this.$options.cookie );
		delete_cookie_options.maxAge = 0;
		delete_cookie_options.expires = new Date( 1 );

		res.setHeader( 'Set-Cookie',
			this.$remove.map( function( id ) {
				return cookie.serialize(
					_this.$options.name + '.' + id, '', delete_cookie_options
				);
			} )
		);

		return p || (p = promise.defer());
	},

	// Compatibility with connect.session

	save: function( cb ) {
		if( this.$.old ) {
			this.$remove.push( this.$.old.id );
			this.$.requireRefresh = true;
		}
		if( cb )	cb();
	},

	destroy: function( cb ) {
		if( this.$.old ) {
			this.$remove.push( this.$.old.id );
			delete this.$.old;
		}
		cleanup( this );
		if( cb )	cb();
	},

	reload: function( cb ) {
		if( this.$.old ) {
			cleanup( this );
			merge( this, BSON.parse( this.$.old.data ) );
			if( this.exp )	this.cookie.expires = this.exp;
		}
		if( cb )	cb();
	},

	regenerate: function( cb ) {
		this.destroy();
		if( this.$options.expireAfter ) 
			this.cookie.expires = new Date( Date.now() + this.$options.expireAfter );
		if( cb )	cb();
	}
}
