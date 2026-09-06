<?php
// Test cases for claude.php.wordpress.xss.json-encode-echo-unsanitized
// Pattern mode: catches echo of json_encode/wp_json_encode without esc_attr().
// Annotation is placed on the line IMMEDIATELY BEFORE the first statement of the vulnerable pattern.
// Note: Semgrep PHP deep-expression match for echo is unreliable for wp_json_encode;
// explicit structural forms (direct, ternary, concat, two-statement) are used instead.

// ─── Vulnerable patterns ─────────────────────────────────────────────────────

// Form A: json_encode() as direct echo argument.
$data = get_post_meta( $post_id, '_settings', true );
// ruleid: claude.php.wordpress.xss.json-encode-echo-unsanitized
echo json_encode( $data );

// Form B: wp_json_encode() as direct echo argument.
$opts = get_option( 'plugin_settings' );
// ruleid: claude.php.wordpress.xss.json-encode-echo-unsanitized
echo wp_json_encode( $opts );

// Form C: ternary with json_encode in true branch — confirmed TP pattern.
// Source flows through helper function return — cross-file taint miss for taint rules.
$posts = get_helper_data();
// ruleid: claude.php.wordpress.xss.json-encode-echo-unsanitized
echo ( !empty( $posts ) ) ? json_encode( $posts ) : '[]';

// Form D: ternary with wp_json_encode in true branch.
$config = get_post_meta( $post_id, '_config', true );
// ruleid: claude.php.wordpress.xss.json-encode-echo-unsanitized
echo ( !empty( $config ) ) ? wp_json_encode( $config ) : '{}';

// Form E: json_encode() inline in string concatenation echo.
$meta = get_post_meta( $post_id, '_meta', true );
// ruleid: claude.php.wordpress.xss.json-encode-echo-unsanitized
echo 'value=\'' . json_encode( $meta ) . '\'';

// Form F: wp_json_encode() inline in string concatenation echo.
// ruleid: claude.php.wordpress.xss.json-encode-echo-unsanitized
echo 'data-settings=\'' . wp_json_encode( $opts ) . '\'';

// Form G: json_encode result assigned to variable, embedded in concat echo.
// ruleid: claude.php.wordpress.xss.json-encode-echo-unsanitized
$enc = json_encode( $data );
echo 'value=\'' . $enc . '\'';

// Form H: wp_json_encode result assigned, embedded in concat echo.
// ruleid: claude.php.wordpress.xss.json-encode-echo-unsanitized
$enc2 = wp_json_encode( $opts );
echo 'data-settings=\'' . $enc2 . '\'';

// ─── Safe patterns ────────────────────────────────────────────────────────────

// esc_attr() wraps the encoding — prevents single-quote attribute breakout.
$safe = get_post_meta( $post_id, '_safe', true );
// ok: claude.php.wordpress.xss.json-encode-echo-unsanitized
echo esc_attr( json_encode( $safe ) );

// esc_html() — also safe in attribute contexts.
$safe2 = get_option( 'safe_settings' );
// ok: claude.php.wordpress.xss.json-encode-echo-unsanitized
echo esc_html( wp_json_encode( $safe2 ) );

// esc_attr() in safe ternary.
// ok: claude.php.wordpress.xss.json-encode-echo-unsanitized
echo ( !empty( $data ) ) ? esc_attr( json_encode( $data ) ) : '[]';

// esc_attr() in safe concat.
$safe3 = get_post_meta( $post_id, '_c', true );
// ok: claude.php.wordpress.xss.json-encode-echo-unsanitized
echo 'value=\'' . esc_attr( json_encode( $safe3 ) ) . '\'';

// esc_attr() wrapping assigned variable.
// ok: claude.php.wordpress.xss.json-encode-echo-unsanitized
$enc3 = json_encode( $data );
echo 'value=\'' . esc_attr( $enc3 ) . '\'';

// JSON_HEX_TAG hex-encodes < > — literal angle brackets cannot appear in output.
$product_data = get_post_meta( $post_id, '_product', true );
// ok: claude.php.wordpress.xss.json-encode-echo-unsanitized
echo wp_json_encode( $product_data, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT );

// JSON_UNESCAPED_SLASHES without JSON_HEX_TAG — still vulnerable (no < > encoding).
$data_layer = get_post_meta( $post_id, '_datalayer', true );
// ruleid: claude.php.wordpress.xss.json-encode-echo-unsanitized
echo wp_json_encode( $data_layer, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE );

// Form I: bare object-method call whose name contains "json" — the json_encode()
// call lives inside the callee (invisible to Forms A/B), echoed unescaped.
class WdtLikeTable {
	public function getJsonDescription() {
		return json_encode( array( 'sSearch' => $this->searchValue ), JSON_HEX_APOS | JSON_HEX_QUOT | JSON_HEX_TAG );
	}
	public $searchValue;
}
$table = new WdtLikeTable();
// ruleid: claude.php.wordpress.xss.json-encode-echo-unsanitized
echo $table->getJsonDescription();

// Form J: bare standalone-function call whose name contains "json", echoed
// unescaped — procedural-style equivalent of Form I.
function get_json_table_config() {
	return json_encode( get_option( 'table_config' ) );
}
// ruleid: claude.php.wordpress.xss.json-encode-echo-unsanitized
echo get_json_table_config();

// Form I safe variant — esc_attr() wraps the wrapper-method call.
// ok: claude.php.wordpress.xss.json-encode-echo-unsanitized
echo esc_attr( $table->getJsonDescription() );

// Form J safe variant — esc_html() wraps the wrapper-function call.
// ok: claude.php.wordpress.xss.json-encode-echo-unsanitized
echo esc_html( get_json_table_config() );

// Previously-known FP — JSON file-download export handler.
// Output is sent as Content-disposition: attachment (file download), not rendered as
// HTML in a browser page. The application/json header() guard below now suppresses
// this shape structurally (see Form A pattern-not).
// Confirmed FP source: ultimate-dashboard 3.8.16 modules/tool/inc/process-export.php:132.
function json_export_download_fp_example() {
	$export_data = get_option( 'plugin_export_data' );
	header( 'Content-type: application/json' );
	header( 'Content-disposition: attachment; filename=export.json' );
	// ok: claude.php.wordpress.xss.json-encode-echo-unsanitized
	echo wp_json_encode( $export_data );
	exit;
}

// Form A safe variant — bare API endpoint that reflects request parameters as JSON,
// but declares Content-Type: application/json before echoing (wp_send_json()-style
// fix): the response cannot be rendered as HTML by the browser via direct navigation.
function json_response_with_content_type_header( $params ) {
	if ( ! headers_sent() ) {
		header( 'Content-Type: application/json; charset=utf-8' );
	}
	// ok: claude.php.wordpress.xss.json-encode-echo-unsanitized
	echo json_encode( $params );
}

// Form A vulnerable variant — bare API endpoint reflects merged request parameters
// as the entire JSON response with no Content-Type header at all: served under the
// framework's default content type, letting a browser render an unescaped payload.
function json_response_missing_content_type_header() {
	$params = array_merge( $_GET, $_POST );
	// ruleid: claude.php.wordpress.xss.json-encode-echo-unsanitized
	echo json_encode( $params );
	exit;
}

// AJAX autocomplete/filter handler — NOT a blanket false positive. The response
// is DB-backed (wpdb column values) and unescaped; the client-side consumer is
// expected to render each item as UI (autocomplete/select dropdown), not treat
// it as an opaque JS value. Confirmed vulnerable shape (CWE-79).
class Ajax_Autocomplete_Filter_Example {
	private function check_nonce() {
		return isset( $_REQUEST['nonce'] ) && wp_verify_nonce( sanitize_text_field( wp_unslash( $_REQUEST['nonce'] ) ), 'filter_nonce' );
	}
	public function ajax_get_filter_values() {
		$this->check_nonce();
		global $wpdb;
		$key = isset( $_POST['key'] ) ? sanitize_text_field( wp_unslash( $_POST['key'] ) ) : '';
		$values = $wpdb->get_col( $wpdb->prepare( "SELECT DISTINCT meta_value FROM {$wpdb->postmeta} WHERE meta_key = %s", $key ) );
		// ruleid: claude.php.wordpress.xss.json-encode-echo-unsanitized
		echo json_encode( $values );
	}
}

// Safe variant — same AJAX shape, but the whole encoded payload is esc_attr()-wrapped.
// (NOTE: array_map('esc_attr', $values) BEFORE json_encode() — escaping each element
// in place rather than wrapping the encode call — is NOT reliably distinguishable from
// the vulnerable shape by pattern-only matching; it still requires manual triage.)
class Ajax_Autocomplete_Filter_Safe_Example {
	public function ajax_get_filter_values_safe() {
		global $wpdb;
		$key = isset( $_POST['key'] ) ? sanitize_text_field( wp_unslash( $_POST['key'] ) ) : '';
		$values = $wpdb->get_col( $wpdb->prepare( "SELECT DISTINCT meta_value FROM {$wpdb->postmeta} WHERE meta_key = %s", $key ) );
		// ok: claude.php.wordpress.xss.json-encode-echo-unsanitized
		echo esc_attr( json_encode( $values ) );
	}
}

// Form K: wp_json_encode() concatenated into an "*_html"-named variable
// assignment — no echo in this function. The controller assigns the local,
// hands it to a view-data array, and a separate template file echoes it raw.
class Activity_Log_Formatter_Example {
	public function build_activity_content_html( $activity_row ) {
		$customer_vars = $activity_row['customer_data_vars'];
		// ruleid: claude.php.wordpress.xss.json-encode-echo-unsanitized
		$content_html = '<pre class="format-json">' . wp_json_encode( $customer_vars, JSON_PRETTY_PRINT ) . '</pre>';
		return $content_html;
	}
}

// Form L: json_encode() variant of Form K.
function build_item_html( $item_vars ) {
	// ruleid: claude.php.wordpress.xss.json-encode-echo-unsanitized
	$item_html = '<pre class="format-json">' . json_encode( $item_vars, JSON_PRETTY_PRINT ) . '</pre>';
	return $item_html;
}

// Form K safe variant — esc_html() wraps the wp_json_encode() call, matching
// the real-world fix (esc_html() + JSON_HEX_TAG together).
class Activity_Log_Formatter_Safe_Example {
	public function build_activity_content_html_safe( $activity_row ) {
		$customer_vars = $activity_row['customer_data_vars'];
		// ok: claude.php.wordpress.xss.json-encode-echo-unsanitized
		$content_html = '<pre class="format-json">' . esc_html( wp_json_encode( $customer_vars, JSON_PRETTY_PRINT | JSON_HEX_TAG ) ) . '</pre>';
		return $content_html;
	}
}

// Form K safe variant — JSON_HEX_TAG alone (no literal < > can appear in output).
function build_item_html_safe( $item_vars ) {
	// ok: claude.php.wordpress.xss.json-encode-echo-unsanitized
	$item_html = '<pre class="format-json">' . wp_json_encode( $item_vars, JSON_PRETTY_PRINT | JSON_HEX_TAG ) . '</pre>';
	return $item_html;
}

// Form F safe variant — the encoded variable was assigned via esc_url() on
// the prior line. esc_url()'s character allowlist excludes `<`, `>`, and `"`
// outright, so no attribute/script breakout character can reach the output.
// Confirmed FP: kirki 6.1.1 libraries/framework/Supports/Url.php:75-76.
function perform_redirect_safe( $redirect_url ) {
	if ( \headers_sent() ) {
		$safe_url = esc_url( $redirect_url );
		// ok: claude.php.wordpress.xss.json-encode-echo-unsanitized
		echo '<script>window.location.href = ' . wp_json_encode( $safe_url ) . ';</script>';
		exit;
	}
}
