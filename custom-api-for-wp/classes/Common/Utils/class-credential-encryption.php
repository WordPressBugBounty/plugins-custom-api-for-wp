<?php
/**
 * Credential Encryption
 *
 * Encrypts External API authorization credentials at rest.
 *
 * Protects database dumps and backups. Anyone with wp-config.php can derive the
 * key; this is not protection against a fully compromised WordPress install.
 * Encryption is reversible so outbound Basic / Bearer / API-key calls still work.
 *
 * @package    Custom_Api_For_WordPress
 * @subpackage Custom_Api_For_WordPress/includes
 * @author     miniOrange <info@miniorange.com>
 * @link       https://miniorange.com
 */

namespace MO_CAW\Common;

if ( ! defined( 'ABSPATH' ) ) {
	die;
}

/**
 * Class Credential_Encryption
 *
 * AES-256-CBC encryption for External API authorization fields stored in the database.
 * Uses a single key derived from WordPress AUTH_KEY / SECURE_AUTH_KEY.
 */
class Credential_Encryption {

	/**
	 * Prefix applied to encrypted values so plaintext legacy data can be detected.
	 *
	 * This is a ciphertext format marker, not a key version.
	 *
	 * @var string
	 */
	const ENCRYPTED_PREFIX = 'mo_caw_enc:v1:';

	/**
	 * Encrypt authorization secrets in an External API configuration array.
	 *
	 * @param mixed $configuration Configuration array or other value.
	 * @return mixed
	 */
	public static function encrypt_authorization_fields( $configuration ) {
		return self::transform_authorization_fields( $configuration, true );
	}

	/**
	 * Decrypt authorization secrets in an External API configuration array.
	 *
	 * @param mixed $configuration Configuration array or other value.
	 * @return mixed
	 */
	public static function decrypt_authorization_fields( $configuration ) {
		return self::transform_authorization_fields( $configuration, false );
	}

	/**
	 * Whether a string looks like an encrypted credential value.
	 *
	 * @param mixed $value Value to check.
	 * @return bool
	 */
	public static function is_encrypted( $value ) {
		return is_string( $value ) && 0 === strpos( $value, self::ENCRYPTED_PREFIX );
	}

	/**
	 * Encrypt a single string value.
	 *
	 * @param string $value Plaintext value.
	 * @return string Encrypted value with prefix, or original on failure / empty.
	 */
	public static function encrypt( $value ) {
		if ( ! is_string( $value ) || '' === $value ) {
			return $value;
		}

		if ( self::is_encrypted( $value ) ) {
			return $value;
		}

		if ( ! function_exists( 'openssl_encrypt' ) ) {
			return $value;
		}

		$key = self::get_encryption_key();
		$iv  = openssl_random_pseudo_bytes( 16 );

		if ( false === $iv ) {
			return $value;
		}

		$ciphertext = openssl_encrypt( $value, 'AES-256-CBC', $key, OPENSSL_RAW_DATA, $iv );

		if ( false === $ciphertext ) {
			return $value;
		}

		return self::ENCRYPTED_PREFIX . base64_encode( $iv . $ciphertext ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode -- Encoding ciphertext, not obfuscation.
	}

	/**
	 * Decrypt a single string value.
	 *
	 * @param string $value Possibly encrypted value.
	 * @return string Plaintext, or original value if not encrypted / on failure.
	 */
	public static function decrypt( $value ) {
		if ( ! self::is_encrypted( $value ) ) {
			return $value;
		}

		if ( ! function_exists( 'openssl_decrypt' ) ) {
			return $value;
		}

		$raw = base64_decode( substr( $value, strlen( self::ENCRYPTED_PREFIX ) ), true ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode -- Decoding ciphertext, not obfuscation.

		if ( false === $raw || strlen( $raw ) < 17 ) {
			return $value;
		}

		$iv         = substr( $raw, 0, 16 );
		$ciphertext = substr( $raw, 16 );
		$key        = self::get_encryption_key();
		$plaintext  = openssl_decrypt( $ciphertext, 'AES-256-CBC', $key, OPENSSL_RAW_DATA, $iv );

		return false === $plaintext ? $value : $plaintext;
	}

	/**
	 * Encrypt or decrypt authorization.auth_config and the copied auth header value.
	 *
	 * @param mixed $configuration Configuration array or other value.
	 * @param bool  $encrypt       True to encrypt, false to decrypt.
	 * @return mixed
	 */
	private static function transform_authorization_fields( $configuration, $encrypt ) {
		if ( ! is_array( $configuration ) ) {
			return $configuration;
		}

		if ( isset( $configuration['authorization']['auth_config'] ) ) {
			$configuration['authorization']['auth_config'] = self::transform_auth_config( $configuration['authorization']['auth_config'], $encrypt );
		}

		$header_key = self::get_auth_header_key( $configuration['authorization'] ?? array() );

		if ( null !== $header_key && ! empty( $configuration['header'] ) && is_array( $configuration['header'] ) ) {
			$matched_key = self::find_header_key( $configuration['header'], $header_key );

			if ( null !== $matched_key && is_string( $configuration['header'][ $matched_key ] ) && '' !== $configuration['header'][ $matched_key ] ) {
				$configuration['header'][ $matched_key ] = $encrypt
					? self::encrypt( $configuration['header'][ $matched_key ] )
					: self::decrypt( $configuration['header'][ $matched_key ] );
			}
		}

		return $configuration;
	}

	/**
	 * Encrypt or decrypt auth_config (string token or map of secrets).
	 *
	 * @param mixed $auth_config Auth config value.
	 * @param bool  $encrypt     True to encrypt, false to decrypt.
	 * @return mixed
	 */
	private static function transform_auth_config( $auth_config, $encrypt ) {
		if ( is_string( $auth_config ) && '' !== $auth_config ) {
			return $encrypt ? self::encrypt( $auth_config ) : self::decrypt( $auth_config );
		}

		if ( ! is_array( $auth_config ) ) {
			return $auth_config;
		}

		foreach ( $auth_config as $key => $value ) {
			if ( is_string( $value ) && '' !== $value ) {
				$auth_config[ $key ] = $encrypt ? self::encrypt( $value ) : self::decrypt( $value );
			}
		}

		return $auth_config;
	}

	/**
	 * Header name that holds the copied authorization secret.
	 *
	 * @param array $authorization Authorization settings.
	 * @return string|null
	 */
	private static function get_auth_header_key( $authorization ) {
		if ( ! is_array( $authorization ) ) {
			return null;
		}

		$auth_type = $authorization['auth_type'] ?? '';

		if ( Constants::NO_AUTHORIZATION === $auth_type || '' === $auth_type ) {
			return null;
		}

		if ( Constants::BASIC_AUTHORIZATION === $auth_type || Constants::BEARER_TOKEN === $auth_type ) {
			return 'Authorization';
		}

		if ( Constants::API_KEY_AUTHENTICATION === $auth_type ) {
			$auth_config = $authorization['auth_config'] ?? array();
			if ( is_array( $auth_config ) && ! empty( $auth_config ) ) {
				return (string) array_key_first( $auth_config );
			}
		}

		return null;
	}

	/**
	 * Find a header key matching the expected name (case-insensitive).
	 *
	 * @param array  $headers      Header map.
	 * @param string $expected_key Expected header name.
	 * @return string|int|null
	 */
	private static function find_header_key( $headers, $expected_key ) {
		if ( array_key_exists( $expected_key, $headers ) ) {
			return $expected_key;
		}

		$expected_normalized = strtolower( $expected_key );

		foreach ( $headers as $key => $value ) {
			if ( is_string( $key ) && strtolower( $key ) === $expected_normalized ) {
				return $key;
			}
		}

		return null;
	}

	/**
	 * Derive a 32-byte encryption key from WordPress salts.
	 *
	 * Encrypt and decrypt always use this same derivation. There is no key id or rotation.
	 *
	 * @return string
	 */
	private static function get_encryption_key() {
		$auth_key        = defined( 'AUTH_KEY' ) ? AUTH_KEY : '';
		$secure_auth_key = defined( 'SECURE_AUTH_KEY' ) ? SECURE_AUTH_KEY : '';
		$material        = $auth_key . '|' . $secure_auth_key . '|mo_caw_credential_encryption';

		if ( '' === $auth_key || '' === $secure_auth_key ) {
			$material .= ( defined( 'ABSPATH' ) ? ABSPATH : '' ) . ( defined( 'DB_NAME' ) ? DB_NAME : '' );
		}

		return hash( 'sha256', $material, true );
	}
}
