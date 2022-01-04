<?php

if (!function_exists('set_wpdb')):
    function set_wpauth()
    {
        global $WPAuthObj;

        if (!$WPAuthObj) {
            $WPAuthObj = new Ricubai\WPAuth\WPAuth();
            $WPAuthObj->connect_db();
            $WPAuthObj->set_current_user_session();
        }
    }
endif;

if (!function_exists('wpauth')):
    /**
     * @return Ricubai\WPAuth\WPAuth Return a global instance of WPAuth.
     */
    function wpauth(): \Ricubai\WPAuth\WPAuth
    {
        global $WPAuthObj;
        return $WPAuthObj;
    }
endif;

if (!function_exists('wpdb')):
    /**
     * @return Ricubai\WPAuth\WPAuth Return a global instance of WPAuth.
     */
    function wpdb(): \Ricubai\WPAuth\WPAuth
    {
        global $WPAuthObj;
        return $WPAuthObj->wpdb;
    }
endif;
