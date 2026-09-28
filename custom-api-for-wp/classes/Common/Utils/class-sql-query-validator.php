<?php
/**
 * Validates and prepares Custom SQL API queries.
 *
 * @package    Custom_Api_For_WordPress
 * @subpackage Custom_Api_For_WordPress/includes
 * @author     miniOrange <info@miniorange.com>
 * @link       https://miniorange.com
 */

namespace MO_CAW\Common;

/**
 * Restricts Custom SQL APIs to a single SELECT with bound {{param}} values.
 */
class SQL_Query_Validator {

	const PLACEHOLDER_PATTERN = '/{{([A-Za-z0-9-_]+)}}/';

	/**
	 * Sanitize a single SQL string for storage.
	 *
	 * @param string $sql Raw SQL from the request or stored config.
	 * @return string
	 */
	public static function sanitize_query( $sql ) {
		if ( ! is_string( $sql ) ) {
			return '';
		}

		$sql = wp_unslash( $sql );
		$sql = str_replace( "\0", '', $sql );

		return trim( $sql );
	}

	/**
	 * Sanitize a list of SQL strings.
	 *
	 * @param mixed $queries Query string or list of query strings.
	 * @return array
	 */
	public static function sanitize_queries( $queries ) {
		if ( is_string( $queries ) ) {
			$queries = array( $queries );
		}

		if ( ! is_array( $queries ) ) {
			return array();
		}

		$sanitized = array();
		foreach ( $queries as $query ) {
			if ( is_array( $query ) ) {
				continue;
			}
			$sanitized[] = self::sanitize_query( (string) $query );
		}

		return $sanitized;
	}

	/**
	 * Whether every query in the list is an allowed SELECT.
	 *
	 * @param mixed $queries Query string or list of query strings.
	 * @return bool
	 */
	public static function validate_queries( $queries ) {
		if ( is_string( $queries ) ) {
			$queries = array( $queries );
		}

		if ( ! is_array( $queries ) || empty( $queries ) ) {
			return false;
		}

		foreach ( $queries as $query ) {
			if ( ! self::is_valid( $query ) ) {
				return false;
			}
		}

		return true;
	}

	/**
	 * Whether a query is a single allowed SELECT.
	 *
	 * @param string $sql SQL statement.
	 * @return bool
	 */
	public static function is_valid( $sql ) {
		if ( ! is_string( $sql ) ) {
			return false;
		}

		if ( false !== strpos( $sql, '/*!' ) ) {
			return false;
		}

		$stripped = self::strip_comments( $sql );
		if ( '' === $stripped ) {
			return false;
		}

		$without_trailing_semicolon = rtrim( $stripped, "; \t\n\r\0\x0B" );
		if ( '' === $without_trailing_semicolon || false !== strpos( $without_trailing_semicolon, ';' ) ) {
			return false;
		}

		if ( ! preg_match( '/^SELECT\b/i', $without_trailing_semicolon ) ) {
			return false;
		}

		$for_keyword_scan = self::mask_string_literals( $without_trailing_semicolon );

		$forbidden = array(
			'/\bUNION\b/i',
			'/\bINTO\s+(OUTFILE|DUMPFILE)\b/i',
			'/\bINTO\s+@/i',
			'/\bFOR\s+UPDATE\b/i',
			'/\bLOCK\s+IN\s+SHARE\s+MODE\b/i',
			'/\bLOAD_FILE\s*\(/i',
			'/\bLOAD\s+DATA\b/i',
			'/\bSLEEP\s*\(/i',
			'/\bBENCHMARK\s*\(/i',
			'/\bGET_LOCK\s*\(/i',
			'/\bEXTRACTVALUE\s*\(/i',
			'/\bUPDATEXML\s*\(/i',
			'/\bDATABASE\s*\(/i',
			'/\bUSER\s*\(/i',
			'/\bVERSION\s*\(/i',
			'/\bSCHEMA\s*\(/i',
			'/\bCURRENT_USER\s*\(/i',
			'/\bSESSION_USER\s*\(/i',
			'/\bSYSTEM_USER\s*\(/i',
			'/\bINFORMATION_SCHEMA\b/i',
			'/\bmysql\./i',
			'/\bsys\./i',
			'/\bperformance_schema\b/i',
		);

		foreach ( $forbidden as $pattern ) {
			if ( preg_match( $pattern, $for_keyword_scan ) ) {
				return false;
			}
		}

		return true;
	}

	/**
	 * Bind {{param}} values with $wpdb->prepare(). Static SELECT is returned unchanged.
	 *
	 * @param string $sql_query      Stored SQL.
	 * @param mixed  $dynamic_values Request values.
	 * @param array  $error_response JSON payload for missing parameters.
	 * @return string
	 */
	public static function prepare_for_execution( $sql_query, $dynamic_values, $error_response ) {
		global $wpdb;

		if ( ! is_array( $dynamic_values ) ) {
			$dynamic_values = array();
		}

		if ( ! preg_match( self::PLACEHOLDER_PATTERN, $sql_query ) ) {
			return $sql_query;
		}

		$params          = array();
		$sql_for_prepare = str_replace( '%', '%%', $sql_query );
		$sql_for_prepare = preg_replace_callback(
			self::PLACEHOLDER_PATTERN,
			function ( $match ) use ( $dynamic_values, $error_response, &$params ) {
				$param_name = $match[1];
				if ( ! isset( $dynamic_values[ $param_name ] ) ) {
					wp_send_json( $error_response, 400 );
				}
				$params[] = $dynamic_values[ $param_name ];
				return '%s';
			},
			$sql_for_prepare
		);

		$actual_placeholders = substr_count( $sql_for_prepare, '%s' );
		if ( empty( $params ) || count( $params ) !== $actual_placeholders ) {
			wp_send_json( $error_response, 400 );
		}

		$prepared_query = $wpdb->prepare( $sql_for_prepare, ...$params ); // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared -- Placeholders and bound values are constructed above from {{param}} tokens only.

		if ( empty( $prepared_query ) ) {
			wp_send_json( $error_response, 400 );
		}

		return $prepared_query;
	}

	/**
	 * Remove SQL comments so they cannot hide disallowed keywords.
	 *
	 * @param string $sql SQL statement.
	 * @return string
	 */
	private static function strip_comments( $sql ) {
		$sql = preg_replace( '/\/\*[\s\S]*?\*\//', ' ', $sql );
		$sql = preg_replace( '/--[^\n\r]*/', ' ', $sql );
		$sql = preg_replace( '/#[^\n\r]*/', ' ', $sql );

		if ( ! is_string( $sql ) ) {
			return '';
		}

		return trim( $sql );
	}

	/**
	 * Replace quoted string literals so denylist keywords inside them are ignored.
	 *
	 * @param string $sql SQL statement with comments already stripped.
	 * @return string
	 */
	private static function mask_string_literals( $sql ) {
		$masked = preg_replace_callback(
			'/(?:\'(?:\'\'|\\\\\'|[^\'])*\'|"(?:""|\\\\"|[^"])*")/',
			function ( $match ) {
				return str_repeat( ' ', strlen( $match[0] ) );
			},
			$sql
		);

		return is_string( $masked ) ? $masked : $sql;
	}
}
