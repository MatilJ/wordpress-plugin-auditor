<?php
// Test cases for claude.php.wordpress.upload.pdf-library-output-unsanitized-filename

// === TRUE POSITIVES ===

// Vulnerable: merge-tag-substituted filename written via mPDF Output('F') with
// no sanitize_file_name() call — matches the confirmed audit finding shape.
function uacf7_generate_pdf( $replace_key, $replace_value, $pdf_name, $dir ) {
    $pdf_name = str_replace( $replace_key, $replace_value, $pdf_name );
    $pdf_dir = $dir . '/uacf7-uploads/' . $pdf_name . '.pdf';
    $mpdf = new \Mpdf\Mpdf();
    // ruleid: claude.php.wordpress.upload.pdf-library-output-unsanitized-filename
    $mpdf->Output( $pdf_dir, 'F' );
}

// Vulnerable: same shape via TCPDF's Output(), lowercase library variable name
function generate_invoice_pdf( $tags, $values, $name_template, $upload_dir ) {
    $filename = str_replace( $tags, $values, $name_template );
    $path = $upload_dir . '/invoices/' . $filename . '.pdf';
    $tcpdf = new TCPDF();
    // ruleid: claude.php.wordpress.upload.pdf-library-output-unsanitized-filename
    $tcpdf->Output( $path, 'F' );
}

// === FALSE POSITIVES ===

// Safe: sanitize_file_name() applied to the substituted value before the write
function uacf7_generate_pdf_safe( $replace_key, $replace_value, $pdf_name, $dir ) {
    // ok: claude.php.wordpress.upload.pdf-library-output-unsanitized-filename
    $pdf_name = str_replace( $replace_key, $replace_value, $pdf_name );
    $pdf_name = sanitize_file_name( $pdf_name );
    $pdf_dir = $dir . '/uacf7-uploads/' . $pdf_name . '.pdf';
    $mpdf = new \Mpdf\Mpdf();
    $mpdf->Output( $pdf_dir, 'F' );
}

// Safe: Output() called in inline/browser-stream mode (no 'F' destination) —
// nothing is written to a web-accessible directory.
function generate_report_pdf_inline( $tags, $values, $name_template ) {
    // ok: claude.php.wordpress.upload.pdf-library-output-unsanitized-filename
    $filename = str_replace( $tags, $values, $name_template );
    $mpdf = new \Mpdf\Mpdf();
    $mpdf->Output( $filename );
}
