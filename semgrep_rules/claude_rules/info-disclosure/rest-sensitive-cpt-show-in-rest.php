<?php

// ruleid: claude.php.wordpress.info-disclosure.rest-sensitive-cpt-show-in-rest
register_post_type( 'ea_appointment', array(
    'public'       => false,
    'show_in_rest' => true,
    'label'        => 'Appointments',
) );

// ruleid: claude.php.wordpress.info-disclosure.rest-sensitive-cpt-show-in-rest
register_post_type( 'shop_order', array(
    'show_in_rest' => true,
    'label'        => 'Orders',
) );

// ruleid: claude.php.wordpress.info-disclosure.rest-sensitive-cpt-show-in-rest
register_post_type( 'customer_submission', array(
    'show_in_rest' => true,
    'supports'     => array( 'title', 'editor' ),
) );

// ok: claude.php.wordpress.info-disclosure.rest-sensitive-cpt-show-in-rest
register_post_type( 'portfolio', array(
    'public'       => true,
    'show_in_rest' => true,
    'label'        => 'Portfolio',
) );

// ok: claude.php.wordpress.info-disclosure.rest-sensitive-cpt-show-in-rest
register_post_type( 'ea_appointment', array(
    'public'       => false,
    'show_in_rest' => false,
    'label'        => 'Appointments',
) );
