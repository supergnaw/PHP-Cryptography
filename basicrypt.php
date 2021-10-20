<?php
	// slightly modified from https://stackoverflow.com/a/60283328
	function basicrypt( $action, $string, $keySeed ) {
		$output = false;
		$encrypt_method = "AES-256-CTR";
		$secret_key = hash( 'sha512', $keySeed );
		$secret_iv = hash( 'sha512', strrev( $keySeed ));

		// hash
		$key = substr( hash( 'sha512', $secret_key ), 0, 32 );

		// iv - encrypt method AES-256-CBC expects 16 bytes
		$iv = substr( hash( 'sha512', $secret_iv ), 0, 16 );

		if( 'encrypt' == $action ) {
			$output = openssl_encrypt( $string, $encrypt_method, $key, 0, $iv );
			$output = base64_encode( $output );
		} else if( 'decrypt' == $action ) {
			$output = openssl_decrypt( base64_decode( $string ), $encrypt_method, $key, 0, $iv );
		}
		return $output;
	}
