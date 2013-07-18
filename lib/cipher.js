// Copyright (C) 2012 ...Max... & Adstream Holdings
// All rights reserved.
// Redistribution and use are permitted under the modified BSD license
// available at https://github.com/MaxMotovilov/adstream-js-frameworks/wiki/License

//
//	Implements the following encryption scheme:
//
//	IV = random-128bit()
//	Ciphertext = AES-256-CBC( Key, IV, Plaintext )
//	Transmitted = IV | Ciphertext
//	

var	crypto = require( 'crypto' ),

	CRYPTO_ALGORITHM = 'aes-256-cbc',
	KEY_SIZE = 256/8,	// bytes
	IV_SIZE = 128/8;	// bytes

module.exports = {

	cipher: function( key, plaintext, cb ) {
		crypto.randomBytes( IV_SIZE, function(err,iv) {
			if( err )
				cb( err );		
			else try {
				var ciph = crypto.createCipheriv( CRYPTO_ALGORITHM, key.toString( 'binary' ), iv.toString( 'binary' ) );
				var ct = ciph.update( plaintext.toString( 'binary' ) );
				
				if( typeof ct === 'string' ) {
					// node 0.8.x and below

					ct += ciph.final();

					var	res = new Buffer( iv.length + ct.length );

					iv.copy( res );
					res.write( ct, iv.length, ct.length, 'binary' );

					cb( undefined, res );
				} else {
					// node 0.10.x and above
					cb( undefined, Buffer.concat( [ iv, ct, ciph.final() ] ) );					
				}

			} catch( e ) {
				cb( e );
			}
		} );
	},

	decipher: function( key, xmitted, cb ) {

		var dec = crypto.createDecipheriv( CRYPTO_ALGORITHM, key.toString( 'binary' ), xmitted.slice( 0, IV_SIZE ).toString( 'binary' ) ),
			res = dec.update( xmitted.slice( IV_SIZE ).toString( 'binary' ) );

		if( typeof res === 'string' ) {
			// node 0.8.x and below
			cb( undefined, new Buffer( res + dec.final(), 'binary' ) );
		} else {
			// node 0.10.x and above
			cb( undefined, Buffer.concat( [ res, dec.final() ] ) );					
		}
	}
}

