<?php

class Notifications_Vulnerable {

	private $reply_to;

	public function get_reply_to_address() {

		$matches = [];
		preg_match( '/^(.+) (<.+>)$/', $this->reply_to, $matches );

		$reply_to_name = $this->process_tag( $matches[1] );
		$reply_to_addr = trim( $matches[2], '<> ' );

		// ruleid: claude.php.wordpress.email-injection.merge-tag-header-injection
		$reply_to = "$reply_to_name <{$reply_to_addr}>";

		return $reply_to;
	}

	private function process_tag( $input ) {
		return $input;
	}
}

class Mailer_Vulnerable {

	private $from_name;
	private $from_address;
	private $headers;

	public function get_headers() {

		$name = $this->process_tag( $this->from_name );
		$addr = $this->from_address;

		// ruleid: claude.php.wordpress.email-injection.merge-tag-header-injection
		$this->headers = "From: {$name} <{$addr}>\r\n";

		return $this->headers;
	}

	private function process_tag( $input ) {
		return $input;
	}
}

class Notifications_Cc_Vulnerable {

	private $cc;

	public function get_cc_address() {

		$addr = $this->replace_tags( $this->cc );

		// ruleid: claude.php.wordpress.email-injection.merge-tag-header-injection
		$headers = "Cc: {$addr}\r\n";

		return $headers;
	}

	private function replace_tags( $input ) {
		return $input;
	}
}

class Notifications_Fixed_HeaderHelper {

	private $reply_to;

	public function get_reply_to_address() {

		$matches = [];
		preg_match( '/^(.+) (<.+>)$/', $this->reply_to, $matches );

		$reply_to_name = $this->process_tag( $matches[1] );
		$reply_to_addr = trim( $matches[2], '<> ' );

		// ok: claude.php.wordpress.email-injection.merge-tag-header-injection
		$reply_to = $this->sanitize_email_header_name( $reply_to_name ) . " <{$reply_to_addr}>";

		return $reply_to;
	}

	private function process_tag( $input ) {
		return $input;
	}

	private function sanitize_email_header_name( $name ) {
		return trim( str_replace( [ "\r\n", "\r", "\n", ',', '<', '>' ], ' ', $name ) );
	}
}

class Mailer_Fixed_TextField {

	private $from_name;
	private $from_address;

	public function get_headers() {

		$name = sanitize_text_field( $this->process_tag( $this->from_name ) );
		$addr = $this->from_address;

		// ok: claude.php.wordpress.email-injection.merge-tag-header-injection
		$headers = "From: {$name} <{$addr}>\r\n";

		return $headers;
	}

	private function process_tag( $input ) {
		return $input;
	}
}

class Notifications_Body_Only {

	private $template;

	public function get_message() {

		$body = $this->process_tag( $this->template );

		// ok: claude.php.wordpress.email-injection.merge-tag-header-injection
		$message = "Message body: {$body}";

		return $message;
	}

	private function process_tag( $input ) {
		return $input;
	}
}
