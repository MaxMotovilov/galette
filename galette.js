// Copyright (C) 2012 ...Max... & Adstream Holdings
// All rights reserved.
// Redistribution and use are permitted under the modified BSD license
// available at https://github.com/MaxMotovilov/adstream-js-frameworks/wiki/License

var	connect = require( 'connect' ),
	SessionState = require( './lib/session' ),
	promise = require( 'node-promise' );

function useDefaults( options ) {
	
	if( (!options.cipher) !== (!options.decipher) )
		throw Error( '"cipher" and "decipher" should be specified together' );

	if( !options.cipher )
		connect.utils.merge( options, require( './lib/cipher' ) );

	if( !options.keyManager )
		options.keyManager = require( './lib/key_manager' )( options.secret );

	if( !('expireAfter' in options) )
		options.expireAfter = options.cookie && options.cookie.maxAge || 0;

	if( options.expireAfter && !('timestamp' in options) )		
		options.timestamp = true;
	else if( !options.expireAfter )
		options.timestamp = false;

	if( !('refreshAfter' in options) )
		options.refreshAfter = options.expireAfter/2;

	if( !options.name )	
		options.name = 'session';

	if( !options.cookie )
		options.cookie = { httpOnly: true, path: '/' };
	else {	
		if( options.cookie.maxAge )
			delete options.cookie.maxAge;
		if( !options.cookie.path )
			options.cookie.path = '/';
	}
}

function patchServerResponse( res, async_update ) {
	var writeHead = res.writeHead,
		_send = res._send,
		queue = [],
		started;

	function bind( self, fn, args ) {
		return function(){
			return fn.apply( self, args );
		}
	}

	res.writeHead = function( status ) {
		this.statusCode = status;
		queue.push( bind( this, writeHead, arguments ) );

		if( !started )
			started = promise.when(
				async_update( res ),
				function() {
					res.writeHead = writeHead;
					res._send = _send;
					queue.forEach( function(c){c();} );
				},
				function( err ) {
					res.writeHead = writeHead;
					res._send = _send;
					res.writeHead( 500, {
						'Content-Type': 'text/plain'
					} );
					res.end( 
						'galette failed to update session cookie(s):\n' +
						err.toString()
					);
				}
			);
	}

	res._send = function() {
		queue.push( bind( this, _send, arguments ) );
	}
}

module.exports = function( options ) {

	useDefaults( options );

	var name = options.name,
		splitter = new RegExp( '^' + name.replace( /[.$]/g, '\\$&' ) + '\\.(.*)$', 'i' );

	return function galette( req, res, next ) {
		// Protect against double usage
		if( req[name] )	return next();

		var	state = new SessionState( options, req );
		req[name] = state.makeSession();

		promise.when(
			promise.all(
				Object.keys( req.cookies )
					.map( function( cname ) {
						var	spl;
						if( spl = splitter.exec( cname ) )	
							return state.initialize.call( req[name], spl[1], req.cookies[cname] );
					} )
			),
			(function() { 
				next();
				this.resume();
			 }).bind( connect.utils.pause( req ) )
		);
		
		patchServerResponse( res, state.commit.bind( req[name] ) );
	}
}
