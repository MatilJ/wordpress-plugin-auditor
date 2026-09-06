<?php

trait ReviewPermissions {
    public function get_items_permissions_check($request) {
        if (!is_user_logged_in()) {
            return new WP_Error('rest_forbidden_context', 'no access', ['status' => 401]);
        }
        $context = $request['context'] ?? 'view';
        if ('edit' === $context && !glsr()->can('edit_posts')) {
            return new WP_Error('rest_forbidden_context', 'not allowed', ['status' => 403]);
        }
        return true;
    }

    // ruleid: claude.php.wordpress.info-disclosure.rest-item-permission-check-missing-context-gate
    public function get_item_permissions_check($request) {
        $review = glsr_get_review($request['id']);
        if (!$this->has_read_permission($review)) {
            return new WP_Error('rest_cannot_view', 'not allowed', ['status' => 403]);
        }
        return true;
    }
}

class Widget_Reviews_Controller extends WP_REST_Controller {
    public function get_items_permissions_check($request) {
        $context = $request->get_param('context') ?? 'view';
        if ('edit' === $context && !current_user_can('edit_posts')) {
            return new WP_Error('rest_forbidden_context', 'not allowed', ['status' => 403]);
        }
        return true;
    }

    // ruleid: claude.php.wordpress.info-disclosure.rest-item-permission-check-missing-context-gate
    public function get_item_permissions_check($request) {
        $item = get_post($request['id']);
        if (empty($item)) {
            return new WP_Error('rest_invalid_id', 'not found', ['status' => 404]);
        }
        return is_user_logged_in();
    }
}

class Fixed_Reviews_Controller extends WP_REST_Controller {
    public function get_items_permissions_check($request) {
        $context = $request['context'] ?? 'view';
        if ('edit' === $context && !current_user_can('edit_posts')) {
            return new WP_Error('rest_forbidden_context', 'not allowed', ['status' => 403]);
        }
        return true;
    }

    // ok: claude.php.wordpress.info-disclosure.rest-item-permission-check-missing-context-gate
    public function get_item_permissions_check($request) {
        $review = glsr_get_review($request['id']);
        if (!$this->has_read_permission($review)) {
            return new WP_Error('rest_cannot_view', 'not allowed', ['status' => 403]);
        }
        $context = $request['context'] ?? 'view';
        if ('edit' === $context && !current_user_can('edit_posts')) {
            return new WP_Error('rest_forbidden_context', 'not allowed', ['status' => 403]);
        }
        return true;
    }
}

class AlwaysStrict_Reviews_Controller extends WP_REST_Controller {
    public function get_items_permissions_check($request) {
        $context = $request['context'] ?? 'view';
        if ('edit' === $context && !current_user_can('edit_posts')) {
            return new WP_Error('rest_forbidden_context', 'not allowed', ['status' => 403]);
        }
        return true;
    }

    // ok: claude.php.wordpress.info-disclosure.rest-item-permission-check-missing-context-gate
    public function get_item_permissions_check($request) {
        $review = glsr_get_review($request['id']);
        if (!current_user_can('edit_posts')) {
            return new WP_Error('rest_cannot_view', 'not allowed', ['status' => 403]);
        }
        return true;
    }
}
