<?php
	function recursivecrypt( $action, $string, $keySeed, $recursion = 0 ) {
		$output = False;
		$encrypt_method = 'AES-256-CTR';

		// rotate key according to recursion
		if( 'encrypt' == $action ) {
			// shift to the right for encryption
			$rotKey = $keySeed;
			$keySeed = substr( $keySeed, 1 ) . substr( $keySeed, 0, 1 );
		}
		elseif( 'decrypt' == $action ) {
			// shift to the left for decryption
			$rot = $recursion % strlen( $keySeed );
			$rotKey = substr( $keySeed, $rot ) . substr( $keySeed, 0, $rot );
		}

		// generate keys and vectors
		$secret_key = hash( 'sha512', $rotKey );
		$secret_iv = hash( 'sha512', strrev( $rotKey ));

		$key = substr( hash( 'sha512', $secret_key ), 0, 32 );
		$iv = substr( hash( 'sha512', $secret_iv ), 0, 16 );

		// encrypt and decrypt actions
		if( 'encrypt' == $action ) {
			$string = openssl_encrypt( $string, $encrypt_method, $key, 0, $iv );
			$output = base64_encode( $string );
		}
		elseif( 'decrypt' == $action ) {
			$string = base64_decode( $string );
			$output = openssl_decrypt( $string, $encrypt_method, $key, 0, $iv );
		}

		// recursion
		if( False != $output && 0 < $recursion ) {
			$recursion--;
			return recursivecrypt( $action, $output, $keySeed, $recursion );
		}

		// return output
		return $output;
	}
