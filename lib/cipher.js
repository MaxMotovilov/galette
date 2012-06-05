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

var	CRYPTO_ALGORITHM = 'aes-256-cbc',
	KEY_SIZE = 256/8,	// bytes
	IV_SIZE = 128/8;	// bytes

module.exports = {

	cipher: function( key, plaintext, cb ) {
		crypto.randomBytes( IV_SIZE, function(iv) {
			try {
				var ciph = createCipheriv( CRYPTO_ALGORITHM, key.toString( 'binary' ), iv.toString( 'binary' ) );
				ciph.update( plaintext.toString( 'binary' ) );
				var ct = ciph.final( 'binary' ),
					res = new Buffer( iv.length + ct.length );

				iv.copy( res );
				res.write( ct, iv.length, ct.length, 'binary' );

				cb( undefined, res );
		
			} catch( e ) {
				cb( e );
			}
		} );
	},

	decipher: function( key, xmitted, cb ) {
		var dec = createDecipheriv( CRYPTO_ALGORITHM, key.toString( 'binary' ), xmitted.slice( 0, IV_SIZE ).toString( 'binary' ) );
		dec.update( xmitted.slice( IV_SIZE ).toString( 'binary' ) );
		cb( undefined, new Buffer( dec.final( 'binary' ), 'binary' );
	}
}

