// Copyright (C) 2014-2019 12 Quarters Consulting
//           (C) 2012 ...Max... & Adstream Holdings
// All rights reserved.
// Redistribution and use are permitted under the modified BSD license
// available at https://github.com/MaxMotovilov/adstream-js-frameworks/wiki/License

var	connect = require( 'connect' ),
	SessionState = require( './lib/session' ),
	merge = require( 'utils-merge' ),
	promise = require( 'node-promise' );

function useDefaults( options ) {

	if( (!options.cipher) !== (!options.decipher) )
		throw Error( '"cipher" and "decipher" should be specified together' );

	if( !options.cipher )
		merge( options, require( './lib/cipher' ) );

	if( !options.keyManager )
		options.keyManager = require( './lib/key_manager' )( options.secret );

	if( !('expireAfter' in options) ) {
		options.expireAfter = options.cookie && options.cookie.maxAge;
		if( options.expireAfter )	options.expireAfter *= 1000;
		else	options.expireAfter = null;
	}

	if( options.expireAfter && !('timestamp' in options) )
		options.timestamp = true;
	else if( !options.expireAfter )
		options.timestamp = false;

	if( !('refreshAfter' in options) && options.expireAfter )
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

var proxies = [ 'writeHead', 'end', 'write' ];

function copyProps( to, from, props ) {
	props.forEach( function(p){ to[p] = from[p]; } );
}

function bind( self, fn, args ) {
	return function(){
		return fn.apply( self, args );
	}
}

function patchServerResponse( res, async_update ) {
	var orig = {},
		queue = [],
		started = false,
		paused = false,
		last_result;

	copyProps( orig, res, proxies );

	function commit() {
		return started ||
			(started = promise.when(
				async_update( res ),
				function() {
					copyProps( res, orig, proxies );
					queue.forEach( function(c){
						last_result = c();
					} );
					if( paused )	res.emit( 'drain' );
					return true;
				},
				function( err ) {
					copyProps( res, orig, proxies );
					res.writeHead( 500, {
						'Content-Type': 'text/plain'
					} );
					res.end(
						'galette failed to update session cookie(s):\n' +
						err.toString()
					);
					return true;
				}
			));
	}

	res.writeHead = function( status ) {
		this.statusCode = status;
		queue.push( bind( this, orig.writeHead, arguments ) );
		commit();
	}

	res.end = function() {
		queue.push( bind( this, orig.end, arguments ) );
		return !( commit().then && (paused = true) ) && last_result;
	}

	res.write = function() {
		queue.push( bind( this, orig.write, arguments ) );
		return !( commit().then && (paused = true) ) && last_result;
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
