<?php
// Test cases for claude.php.wordpress.xss.get-param-foreach-html-concat

// Vulnerable patterns

// ruleid: claude.php.wordpress.xss.get-param-foreach-html-concat
foreach ($_GET as $url_parameter => $url_parameter_value) {
    if (in_array($url_parameter, array('action', 'block'))) continue;
    $iframe_parameters .= '&' . $url_parameter . '=' . $url_parameter_value;
}

// ruleid: claude.php.wordpress.xss.get-param-foreach-html-concat
foreach ($_POST as $key => $val) {
    $query_string .= '&' . $key . '=' . $val;
}

// ruleid: claude.php.wordpress.xss.get-param-foreach-html-concat
foreach ($_REQUEST as $k => $v) {
    $params .= $k . '=' . $v . '&';
}

// ruleid: claude.php.wordpress.xss.get-param-foreach-html-concat
foreach ($_GET as $name => $value) {
    $result .= '<input name="' . $name . '" value="' . $value . '">';
}

// Safe patterns

// ok: claude.php.wordpress.xss.get-param-foreach-html-concat
foreach ($_GET as $url_parameter => $url_parameter_value) {
    $iframe_parameters .= '&' . urlencode($url_parameter) . '=' . urlencode($url_parameter_value);
}

// ok: claude.php.wordpress.xss.get-param-foreach-html-concat
foreach ($_POST as $key => $val) {
    $query_string .= '&' . rawurlencode($key) . '=' . rawurlencode($val);
}

// ok: claude.php.wordpress.xss.get-param-foreach-html-concat
foreach ($_GET as $k => $v) {
    $html .= '<input value="' . esc_attr($v) . '">';
}

// ok: claude.php.wordpress.xss.get-param-foreach-html-concat
foreach ($_REQUEST as $key => $value) {
    $output .= htmlspecialchars($value);
}
