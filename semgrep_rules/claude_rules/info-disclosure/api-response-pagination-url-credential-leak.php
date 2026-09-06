<?php

// ---- TRUE POSITIVES ----

function tp_process_response_data( $data, $include_pagination ) {
    $result = array( 'items' => array() );
    if ( $include_pagination && property_exists( $data, 'paging' ) ) {
        // ruleid: claude.php.wordpress.info-disclosure.api-response-pagination-url-credential-leak
        $result['paging'] = $data->paging;
    }
    return $result;
}

function tp_next_url_direct_assign( $api_response ) {
    $result = array();
    // ruleid: claude.php.wordpress.info-disclosure.api-response-pagination-url-credential-leak
    $result['next_url'] = $api_response->paging->next;
    return $result;
}

function tp_next_url_array_form( $api_response ) {
    $result = array();
    // ruleid: claude.php.wordpress.info-disclosure.api-response-pagination-url-credential-leak
    $result['next_url'] = $api_response['paging']['next'];
    return $result;
}

class Tp_Object_Property_Form {
    public $paging;

    public function process( $api_response ) {
        // ruleid: claude.php.wordpress.info-disclosure.api-response-pagination-url-credential-leak
        $this->paging = $api_response->paging;
    }
}

// ---- SAFE VARIANTS (ok) ----

function ok_redacted_with_remove_query_arg( $data, $include_pagination ) {
    $result = array( 'items' => array() );
    if ( $include_pagination && property_exists( $data, 'paging' ) && isset( $data->paging->next ) ) {
        $clean_next = remove_query_arg( 'access_token', $data->paging->next );
        // ok: claude.php.wordpress.info-disclosure.api-response-pagination-url-credential-leak
        $result['paging'] = (object) array( 'next' => $clean_next );
    }
    return $result;
}

function ok_redacted_with_preg_replace( $api_response ) {
    $result = array();
    // ok: claude.php.wordpress.info-disclosure.api-response-pagination-url-credential-leak
    $result['next_url'] = preg_replace( '/([?&])access_token=[^&]*/', '$1', $api_response->paging->next );
    return $result;
}

// Negative control: preg_replace() is present in the function, but for an
// UNRELATED purpose (trimming an image URL) — it must not suppress this
// hit merely by being present somewhere in the same function.
function tp_unrelated_preg_replace_in_function( $data, $image_url ) {
    $local_image_url = preg_replace( '/-\d+[Xx]\d+\./', '.', $image_url, 1 );
    $result = array( 'image' => $local_image_url );
    // ruleid: claude.php.wordpress.info-disclosure.api-response-pagination-url-credential-leak
    $result['paging'] = $data->paging;
    return $result;
}

