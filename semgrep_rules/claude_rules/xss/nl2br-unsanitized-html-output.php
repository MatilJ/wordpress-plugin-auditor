<?php

class ExampleApiReviewModel {

	public function getText($asHtml = false){
		$text = $this->getAttribute("text");

		if($asHtml === true)
			// ruleid: claude.php.wordpress.xss.nl2br-unsanitized-html-output
			$text = nl2br($text);

		return $text;
	}

	public function getSnippet(){
		$snippet = $this->getAttribute("snippet");
		// ruleid: claude.php.wordpress.xss.nl2br-unsanitized-html-output
		return nl2br($snippet);
	}

	public function getTextFixed($asHtml = false){
		$text = $this->getAttribute("text");

		if($asHtml === true){
			$text = ExampleSanitizerUtil::normalizeContentForText($text);
			// ok: claude.php.wordpress.xss.nl2br-unsanitized-html-output
			$text = nl2br($text);
		}

		return $text;
	}

	public function getDescriptionEscaped(){
		$description = $this->getAttribute("description");
		$description = sanitize_text_field($description);
		// ok: claude.php.wordpress.xss.nl2br-unsanitized-html-output
		return nl2br($description);
	}

	public function getCommentBody(){
		$body = get_comment_meta($this->id, "body", true);
		// ok: claude.php.wordpress.xss.nl2br-unsanitized-html-output
		return esc_html(nl2br($body));
	}

	public function getLabelLink($url, $label){
		// ok: claude.php.wordpress.xss.nl2br-unsanitized-html-output
		return '<a href="?' . http_build_query($url) . '">' . nl2br(esc_html($label)) . '</a>';
	}

	public function echoFieldValue($field){
		// ok: claude.php.wordpress.xss.nl2br-unsanitized-html-output
		echo nl2br(esc_html($field["text"] ?: $field["value"]));
	}
}
