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
				var ciph = crypto.createCipheriv( CRYPTO_ALGORITHM, key, iv );
				var ct = ciph.update( plaintext );
				
				cb( undefined, Buffer.concat( [ iv, ct, ciph.final() ] ) );

			} catch( e ) {
				cb( e );
			}
		} );
	},

	decipher: function( key, xmitted, cb ) {

		var dec = crypto.createDecipheriv( CRYPTO_ALGORITHM, key, xmitted.slice( 0, IV_SIZE ) ),
			res = dec.update( xmitted.slice( IV_SIZE ) );

		cb( undefined, Buffer.concat( [ res, dec.final() ] ) );
	}
}

