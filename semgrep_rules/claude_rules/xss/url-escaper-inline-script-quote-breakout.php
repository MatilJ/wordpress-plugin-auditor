<?php

// Real vulnerable shape: esc_url_raw() alone inside a single-quoted JS
// assignment in an inline <script> block. esc_url_raw() does not encode
// the delimiting quote, so an attacker-controlled value breaks the string.
function render_thank_you_redirect( $thank_you ) {
	?>
	<script type="text/javascript">
		// ruleid: claude.php.wordpress.xss.url-escaper-inline-script-quote-breakout
		var thank_you = '<?php echo esc_url_raw( $thank_you ); ?>';
	</script>
	<?php
}

// Same class via document.location assignment and double-quoted JS string,
// using admin_url() (a URL-context escaper, not a JS-string escaper).
function render_redirect_script( $path ) {
	?>
	<script type="text/javascript">
		// ruleid: claude.php.wordpress.xss.url-escaper-inline-script-quote-breakout
		document.location = "<?php echo admin_url( $path ); ?>";
	</script>
	<?php
}

// Fixed shape: json_encode() supplies its own delimiting quotes and
// properly escapes quote/backslash characters for JS-string context.
function render_thank_you_redirect_fixed( $thank_you ) {
	?>
	<script type="text/javascript">
		// ok: claude.php.wordpress.xss.url-escaper-inline-script-quote-breakout
		var thank_you = <?php echo json_encode( esc_url_raw( $thank_you ) ); ?>;
	</script>
	<?php
}

// esc_url_raw() used correctly in an HTML attribute (img src), not inside
// a JS string literal -- the "=" here has no preceding whitespace, unlike
// JS assignment syntax.
function render_spinner( $img_url ) {
	?>
	<?php /* ok: claude.php.wordpress.xss.url-escaper-inline-script-quote-breakout */ ?>
	<img class="waiting" src="<?php echo esc_url( admin_url( 'images/wpspin_light.gif' ) ); ?>" alt="" />
	<?php
}

// Already wrapped in esc_js() before the quote closes -- correctly
// neutralized for JS-string context.
function render_escaped_thank_you( $thank_you ) {
	?>
	<script type="text/javascript">
		// ok: claude.php.wordpress.xss.url-escaper-inline-script-quote-breakout
		var thank_you = '<?php echo esc_js( $thank_you ); ?>';
	</script>
	<?php
}

// Standard WP DB-read pattern feeding a hardcoded, non-URL-escaper value --
// no URL-context escaper function name present at all.
function render_static_label() {
	$label = get_option( 'pods_static_label' );
	?>
	<script type="text/javascript">
		// ok: claude.php.wordpress.xss.url-escaper-inline-script-quote-breakout
		var pods_label = '<?php echo esc_js( $label ); ?>';
	</script>
	<?php
}
