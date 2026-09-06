<?php

// By-reference mutation style: only the leaf value passes through the
// sanitizer; the array's own keys are never touched before the mutated
// array is returned to the caller.
function formSanitizer($input, $attribute = null, $fields = [])
{
    if (is_string($input)) {
        $input = sanitize_text_field($input);
    } elseif (is_array($input)) {
        // ruleid: claude.php.wordpress.xss.recursive-sanitizer-unsanitized-array-keys
        foreach ($input as $key => &$value) {
            $attribute = $attribute ? $attribute . '[' . $key . ']' : $key;
            $value = formSanitizer($value, $attribute, $fields);
            $attribute = null;
        }
    }

    return $input;
}

// Rebuilt-array style: the new array is indexed with the raw loop key while
// only the value is run through a WP sanitizer.
function buildCleanSettings($rawSettings)
{
    $clean = [];
    // ruleid: claude.php.wordpress.xss.recursive-sanitizer-unsanitized-array-keys
    foreach ($rawSettings as $key => $value) {
        $clean[$key] = sanitize_text_field($value);
    }
    return $clean;
}

// Fix idiom: the key is sanitized into its own variable and THAT is used to
// index the rebuilt array, so no raw attacker key survives.
function formSanitizerFixed($input, $attribute = null, $fields = [])
{
    if (is_string($input)) {
        return sanitize_text_field($input);
    } elseif (is_array($input)) {
        $sanitized = [];
        // ok: claude.php.wordpress.xss.recursive-sanitizer-unsanitized-array-keys
        foreach ($input as $key => $value) {
            $sanitizedKey = sanitize_text_field($key);
            $newAttribute = $attribute ? $attribute . '[' . $sanitizedKey . ']' : $sanitizedKey;
            $sanitized[$sanitizedKey] = formSanitizerFixed($value, $newAttribute, $fields);
        }
        return $sanitized;
    }

    return $input;
}

// Plain WP DB-read/display loop — no sanitizer call on $value at all, so
// this rule (which only fires when a sanitizer IS applied to the value)
// correctly stays silent; this is a different pattern class entirely.
function renderStoredOptions($form_id)
{
    $options = get_option('my_plugin_settings_' . $form_id);
    $html = '';
    // ok: claude.php.wordpress.xss.recursive-sanitizer-unsanitized-array-keys
    foreach ($options as $key => $value) {
        $html .= '<tr><th>' . esc_html($key) . '</th><td>' . esc_html($value) . '</td></tr>';
    }
    return $html;
}

// Schema-constrained shape: rest_sanitize_value_from_schema() enforces the
// declared schema's additionalProperties:false, so the resulting object's
// keys are limited to the schema's own enumerated property names, not
// attacker-suppliable field-name syntax.
function sanitizePostTypeLabels($config, $schema)
{
    $clean = rest_sanitize_value_from_schema($config, $schema);
    if (isset($clean['labels']) && is_array($clean['labels'])) {
        // ok: claude.php.wordpress.xss.recursive-sanitizer-unsanitized-array-keys
        foreach ($clean['labels'] as $key => $value) {
            $clean['labels'][$key] = sanitize_text_field($value);
        }
    }
    return $clean;
}
