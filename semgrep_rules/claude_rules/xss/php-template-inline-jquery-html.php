<?php
// Test cases for claude.php.wordpress.xss.php-template-inline-jquery-html
?>

<script>
jQuery.get(ajaxurl, data)
    .done(function(response) {
        var msg = "An error occured";
        if (response.message != null) {
            msg += ": " + response.message;
        }
        // ruleid: claude.php.wordpress.xss.php-template-inline-jquery-html
        jQuery('#install_error_message p').html(msg);
    });
</script>

<script>
jQuery.post(ajaxurl, params, function(data) {
    // ruleid: claude.php.wordpress.xss.php-template-inline-jquery-html
    jQuery('#result_box').html("Error: " + data.error);
});
</script>

<script>
jQuery.get(ajaxurl, data)
    .done(function(response) {
        var msg = "An error occured";
        if (response.message != null) {
            msg += ": " + response.message;
        }
        // ok: claude.php.wordpress.xss.php-template-inline-jquery-html
        jQuery('#install_error_message p').text(msg);
    });
</script>

<?php
global $wpdb;
$row = $wpdb->get_row(
    $wpdb->prepare("SELECT message FROM {$wpdb->prefix}example_log WHERE id = %d", $log_id)
);
// ok: claude.php.wordpress.xss.php-template-inline-jquery-html
$message = $row->message;
