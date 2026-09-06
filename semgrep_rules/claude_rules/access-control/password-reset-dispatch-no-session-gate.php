<?php

class AcmeResetPasswordHandler
{
    private $form_session_var = 'acme_lost_pwd';

    public function routeData()
    {
        // ruleid: claude.php.wordpress.access-control.password-reset-dispatch-no-session-gate
        if (! empty($_REQUEST['option']) && sanitize_text_field(wp_unslash($_REQUEST['option'])) === 'acme-change-password-form' ) {
            $this->handleAcmeChangedPwd($_POST);
        }
    }

    public function handleAcmeChangedPwd($post_data)
    {
        $user = get_user_by('login', $_SESSION['user_login']);
        reset_password($user, $post_data['new_password']);
    }
}

class AcmeDirectPostDispatch
{
    public function dispatch()
    {
        // ruleid: claude.php.wordpress.access-control.password-reset-dispatch-no-session-gate
        if (!empty($_POST['action']) && $_POST['action'] == 'do_reset_password') {
            $this->reset_user_password($_POST);
        }
    }

    public function reset_user_password($data)
    {
        wp_set_password($data['new_password'], $_SESSION['acme_user_id']);
    }
}

class AcmeFixedResetPasswordHandler
{
    private $form_session_var = 'acme_lost_pwd';

    public function routeData()
    {
        AcmeUtility::checkSession();
        // ok: claude.php.wordpress.access-control.password-reset-dispatch-no-session-gate
        if (! empty($_REQUEST['option']) && (sanitize_text_field(wp_unslash($_REQUEST['option'])) === 'acme-change-password-form') && isset($_SESSION[ $this->form_session_var ]) && strcasecmp($_SESSION[ $this->form_session_var ], 'validated') === 0 ) {
            $this->handleAcmeChangedPwd($_POST);
        }
    }

    public function handleAcmeChangedPwd($post_data)
    {
        $user = get_user_by('login', $_SESSION['user_login']);
        reset_password($user, $post_data['new_password']);
    }
}

class AcmeUnrelatedDispatch
{
    public function routeData()
    {
        // ok: claude.php.wordpress.access-control.password-reset-dispatch-no-session-gate
        if (! empty($_REQUEST['option']) && sanitize_text_field(wp_unslash($_REQUEST['option'])) === 'acme-send-notification' ) {
            $this->sendNotification($_POST);
        }
    }

    public function sendNotification($data)
    {
        wp_mail(get_option('admin_email'), 'Notice', 'A form was submitted');
    }
}

class AcmeHashEqualsGate
{
    public function routeData()
    {
        // ok: claude.php.wordpress.access-control.password-reset-dispatch-no-session-gate
        if (! empty($_REQUEST['option']) && $_REQUEST['option'] === 'acme-change-password-form' && hash_equals($_SESSION['acme_pwd_flow'], 'validated')) {
            $this->handleAcmeChangedPwd($_POST);
        }
    }

    public function handleAcmeChangedPwd($post_data)
    {
        $user_id = get_current_user_id();
        wp_set_password($post_data['new_password'], $user_id);
    }
}
