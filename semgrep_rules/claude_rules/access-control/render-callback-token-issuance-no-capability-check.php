<?php

register_block_type('acme/views-table', array(
    // ruleid: claude.php.wordpress.access-control.render-callback-token-issuance-no-capability-check
    'render_callback' => function ($attributes, $content) {
        if (isset($attributes['formID']) && $attributes['formID']) {
            wp_enqueue_script('acme/views-table/render');

            $formId = absint($attributes['formID']);
            $token = Acme\Authentication\TokenFactory::make();
            $publicKey = Acme\Authentication\KeyFactory::make();

            wp_localize_script('acme/views-table/render', 'acmeViews', [
                'token' => $token->create($publicKey, array($formId)),
            ]);
        }
    }
));

register_block_type('acme/dashboard-widget', array(
    // ruleid: claude.php.wordpress.access-control.render-callback-token-issuance-no-capability-check
    'render_callback' => function ($attributes) {
        $session = Acme\Session\SessionFactory::make();
        wp_add_inline_script(
            'acme/dashboard-widget/render',
            'window.acmeDashboard = ' . wp_json_encode(['sessionToken' => $session->generate($attributes['widgetID'])]) . ';'
        );
        return sprintf("<div class='acme-dashboard-widget' data-id='%s'></div>", esc_attr($attributes['widgetID']));
    }
));

// ok: claude.php.wordpress.access-control.render-callback-token-issuance-no-capability-check
register_block_type('acme/views-table', array(
    'render_callback' => function ($attributes, $content) {
        if (isset($attributes['formID']) && $attributes['formID']) {
            $current_post = get_post();
            if ($current_post && 'publish' !== $current_post->post_status) {
                if (! current_user_can('manage_options')) {
                    return '';
                }
            }

            $formId = absint($attributes['formID']);
            $token = Acme\Authentication\TokenFactory::make();
            $publicKey = Acme\Authentication\KeyFactory::make();

            wp_localize_script('acme/views-table/render', 'acmeViews', [
                'token' => $token->create($publicKey, array($formId)),
            ]);
        }
    }
));

// ok: claude.php.wordpress.access-control.render-callback-token-issuance-no-capability-check
register_block_type('acme/recent-posts', array(
    'render_callback' => function ($attributes) {
        $posts = get_posts([
            'post_status' => 'publish',
            'numberposts' => absint($attributes['count']),
        ]);
        ob_start();
        foreach ($posts as $post) {
            echo esc_html($post->post_title);
        }
        return ob_get_clean();
    }
));
