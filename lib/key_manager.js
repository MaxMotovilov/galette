// Copyright (C) 2014-2019 12 Quarters Consulting
// Copyright (C) 2012 ...Max... & Adstream Holdings
// All rights reserved.
// Redistribution and use are permitted under the modified BSD license
// available at https://github.com/MaxMotovilov/adstream-js-frameworks/wiki/License

//
//	Implements the following key management stragegy:
//
//	Key-Nonce = LSBF-48( UNIX-time-in-ms ) 				: lower 48 bit of Date.now() in LSBF
//	Key-ID = hex( Key-Nonce )
//	Key-Value = HKDF( salt = Secret, IKM = Key-Nonce ) 	: see https://tools.ietf.org/html/rfc5869
//

var	crypto = require( 'crypto' ),
	HASH_ALGORITHM = 'sha1',
	HASH_SIZE = 160/8,	// bytes
	IKM_SIZE = 48/8,	// bytes
	KEY_SIZE = 256/8;	// bytes

function HKDF( salt, ikm, info ) {
	var	hmac = crypto.createHmac( HASH_ALGORITHM, salt );
	hmac.update( ikm );
	var prk = new Buffer( hmac.digest( 'binary' ), 'binary' ),
		n = Math.ceil( KEY_SIZE / HASH_SIZE ),
		info_len = info && info.length || 0,
		okm = new Buffer( n * HASH_SIZE + 1 + info_len ),
		t = okm.slice( 0, info_len + 1 );

	for( var i=1; i<=n; ++i ) {
		t.writeUInt8( i, t.length-1 );
		if( info )	info.copy( t, t.length-info_len-1 );
		hmac = crypto.createHmac( HASH_ALGORITHM, prk );
		hmac.update( t );
		t = okm.slice( (i-1)*HASH_SIZE, i*HASH_SIZE + info_len + 1 );

		var d = hmac.digest( 'binary' );
		if( typeof d === 'string' ) {
			// node 0.8.x and below
			t.write( d, 0, HASH_SIZE, 'binary' );
		} else {
			// node 0.10.x and above
			d.copy( t, 0, 0, HASH_SIZE );
		}
	}

	return okm.slice( 0, KEY_SIZE );
}

module.exports = function( secret ) {

	if( !secret )
		secret = crypto.randomBytes( HASH_SIZE );
	else if( !Buffer.isBuffer(secret) )
		try { secret = new Buffer( secret, 'base64' ); }
		catch(e){ secret = new Buffer( secret, 'binary' ); }

	return function galette_KeyManager( id, cb ) {

		if( typeof id !== 'string' ) {
			cb = id;
			id = undefined;
		}

		var	ikm;

		if( id ) {

			if( id.length != IKM_SIZE*2 )
				throw Error( "Key ID too short" );
			ikm = new Buffer( id, 'hex' );

		} else {

			var	ts = Date.now();

			ikm = new Buffer( IKM_SIZE );

			ikm.writeUInt32LE( (ts & 0xFFFFFFFF) >>> 0, 0 );
			ikm.writeUInt16LE( (ts >> 32) & 0xFFFF, 4 );
		}

		cb( undefined, {
			seq:	ts,
			id:		ikm.toString( 'hex' ),
			value:	HKDF( secret, ikm )
		} );
	}
}

