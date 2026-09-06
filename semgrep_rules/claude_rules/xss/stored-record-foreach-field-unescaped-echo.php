<?php

// Test cases for claude.php.wordpress.xss.stored-record-foreach-field-unescaped-echo

// --- TRUE POSITIVES ---

function render_calculations_metabox_tp1( $data ) {
    foreach ( $data as $name => $contents ) {
        echo $name;
        // ruleid: claude.php.wordpress.xss.stored-record-foreach-field-unescaped-echo
        echo ( ' = ' . $contents['value'] );
        if ( isset( $_GET['calcs_debug'] ) ) {
            // ruleid: claude.php.wordpress.xss.stored-record-foreach-field-unescaped-echo
            echo ( '<br />RAW: ' . $contents['raw'] );
        }
    }
}

function render_entry_rows_tp2( $rows ) {
    foreach ( $rows as $row ) {
        // ruleid: claude.php.wordpress.xss.stored-record-foreach-field-unescaped-echo
        print( $row['title'] );
    }
}

function render_form_entry_table_tp3( $map_data, $form_data ) {
    foreach ( $map_data as $key => $value ) {
        if ( $value['widgetType'] == 'mf-textarea' ) {
            // ruleid: claude.php.wordpress.xss.stored-record-foreach-field-unescaped-echo
            echo "<td><pre>" . ( isset( $form_data[ $key ] ) ? $form_data[ $key ] : '' ) . "</pre></td>";
        }
    }
}

function render_form_entry_signature_tp4( $map_data, $form_data ) {
    foreach ( $map_data as $key => $value ) {
        // ruleid: claude.php.wordpress.xss.stored-record-foreach-field-unescaped-echo
        echo "<img src='" . ( isset( $form_data[ $key ] ) ? $form_data[ $key ] : '' ) . "'>";
    }
}

function render_submission_field_object_tp5( $data ) {
    foreach ( $data->formData as $field ) {
        if ( $field->type == 'FileUpload' ) {
            // ruleid: claude.php.wordpress.xss.stored-record-foreach-field-unescaped-echo
            echo "<a href='" . $field->value . "'>";
            // ruleid: claude.php.wordpress.xss.stored-record-foreach-field-unescaped-echo
            echo $field->value;
        }
    }
}

// --- FALSE POSITIVES (properly escaped / not an HTML output sink) ---

function render_calculations_metabox_fp1( $data ) {
    foreach ( $data as $name => $contents ) {
        echo esc_html( $name );
        // ok: claude.php.wordpress.xss.stored-record-foreach-field-unescaped-echo
        echo ( ' = ' . esc_html( $contents['value'] ) );
        if ( isset( $_GET['calcs_debug'] ) ) {
            // ok: claude.php.wordpress.xss.stored-record-foreach-field-unescaped-echo
            echo ( '<br />RAW: ' . esc_html( $contents['raw'] ) );
        }
    }
}

function render_entry_rows_fp2( $rows ) {
    $out = array();
    foreach ( $rows as $row ) {
        $out[] = $row['title'];
    }
    // ok: claude.php.wordpress.xss.stored-record-foreach-field-unescaped-echo
    wp_send_json_success( $out );
}

function render_form_entry_table_fp3( $map_data, $form_data ) {
    foreach ( $map_data as $key => $value ) {
        if ( $value['widgetType'] == 'mf-textarea' ) {
            // ok: claude.php.wordpress.xss.stored-record-foreach-field-unescaped-echo
            echo "<td><pre>" . esc_html( isset( $form_data[ $key ] ) ? $form_data[ $key ] : '' ) . "</pre></td>";
        }
    }
}

function do_settings_fields_reimpl( $page, $section ) {
    global $wp_settings_fields;
    foreach ( (array) $wp_settings_fields[ $page ][ $section ] as $field ) {
        // ok: claude.php.wordpress.xss.stored-record-foreach-field-unescaped-echo
        echo '<th>' . $field['title'] . '</th>';
    }
}

function do_settings_sections_reimpl( $page ) {
    global $wp_settings_sections;
    foreach ( (array) $wp_settings_sections[ $page ] as $section ) {
        // ok: claude.php.wordpress.xss.stored-record-foreach-field-unescaped-echo
        echo '<h2>' . $section['title'] . '</h2>';
    }
}

function render_submission_field_object_fp4( $data ) {
    foreach ( $data->formData as $field ) {
        if ( $field->type == 'FileUpload' ) {
            // ok: claude.php.wordpress.xss.stored-record-foreach-field-unescaped-echo
            echo "<a href='" . esc_url( $field->value ) . "'>";
            // ok: claude.php.wordpress.xss.stored-record-foreach-field-unescaped-echo
            echo esc_html( $field->value );
        }
    }
}
