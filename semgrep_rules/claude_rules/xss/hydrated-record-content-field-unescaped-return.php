<?php

// Test cases for claude.php.wordpress.xss.hydrated-record-content-field-unescaped-return

// --- TRUE POSITIVES ---

class LogModel_TP1 {
    protected function formatResult( $result ) {
        foreach ( $result as $key => $row ) {
            $result[ $key ] = array_map( 'maybe_unserialize', (array) $row );
            $result[ $key ]['id'] = (int) $result[ $key ]['id'];
            // ruleid: claude.php.wordpress.xss.hydrated-record-content-field-unescaped-return
            $result[ $key ]['from'] = htmlspecialchars( $result[ $key ]['from'] );
        }
        return $result;
    }
}

class WebhookLogModel_TP2 {
    protected function prepareRows( $rows ) {
        foreach ( $rows as $idx => $entry ) {
            $rows[ $idx ] = unserialize( $entry['payload'] );
            // ruleid: claude.php.wordpress.xss.hydrated-record-content-field-unescaped-return
            $rows[ $idx ]['sender_email'] = esc_attr( $rows[ $idx ]['sender_email'] );
        }
        return $rows;
    }
}

// --- FALSE POSITIVES (sibling content field also escaped / not the hydrate idiom) ---

class LogModel_FP1 {
    protected function formatResult( $result ) {
        foreach ( $result as $key => $row ) {
            $result[ $key ] = array_map( 'maybe_unserialize', (array) $row );
            $result[ $key ]['id'] = (int) $result[ $key ]['id'];
            // ok: claude.php.wordpress.xss.hydrated-record-content-field-unescaped-return
            $result[ $key ]['from'] = htmlspecialchars( $result[ $key ]['from'] );
            $result[ $key ]['subject'] = esc_attr( $result[ $key ]['subject'] );
        }
        return $result;
    }
}

class ReportModel_FP2 {
    // Not the hydrated-row idiom at all — plain admin-authored config array,
    // no array_map/maybe_unserialize/unserialize rehydration in the loop.
    protected function formatSettings( $settings ) {
        foreach ( $settings as $key => $row ) {
            // ok: claude.php.wordpress.xss.hydrated-record-content-field-unescaped-return
            $settings[ $key ]['label'] = htmlspecialchars( $settings[ $key ]['label'] );
        }
        return $settings;
    }
}

// --- Form 2: extensibility-hook row object, selective escape, bare JSON echo ---

class EmailLogModel_TP3 {
    public function get_logs_ajax() {
        $data = $this->query_rows();
        foreach ( $data as $row ) {
            $row->actions = '';
            $row = apply_filters( 'ps_email_logs_row', $row );
            // ruleid: claude.php.wordpress.xss.hydrated-record-content-field-unescaped-return
            $row->original_subject = esc_html( $row->original_subject );
        }
        $logs['data'] = $data;
        echo json_encode( $logs );
        die;
    }
}

class WebhookEventModel_TP4 {
    public function render_events() {
        $rows = $this->fetch_events();
        foreach ( $rows as $row ) {
            $row = apply_filters( 'wh_event_row', $row );
            // ruleid: claude.php.wordpress.xss.hydrated-record-content-field-unescaped-return
            $row->label = esc_attr( $row->label );
        }
        echo wp_json_encode( $rows );
    }
}

// --- FALSE POSITIVES (fix applied: every hook-added property is guarded+escaped) ---

class EmailLogModel_FP3 {
    public function get_logs_ajax() {
        $data = $this->query_rows();
        foreach ( $data as $row ) {
            $row = apply_filters( 'ps_email_logs_row', $row );
            // ok: claude.php.wordpress.xss.hydrated-record-content-field-unescaped-return
            $row->original_subject = esc_html( $row->original_subject );
            if ( isset( $row->event_type ) ) {
                $row->event_type = esc_html( $row->event_type );
            }
        }
        $logs['data'] = $data;
        echo json_encode( $logs );
        die;
    }
}

class ReportModel_FP4 {
    // No extensibility hook on the row at all — plain wpdb result, single
    // escaped field, no bare json_encode echo anywhere in the method.
    public function get_report_row( $row ) {
        // ok: claude.php.wordpress.xss.hydrated-record-content-field-unescaped-return
        $row->title = esc_html( $row->title );
        return $row;
    }
}
