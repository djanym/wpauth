<?php

if (!function_exists('set_wpdb')):
    function set_wpdb()
    {
        global $WPDBObj;

        if (!$WPDBObj) {
            $WPDBObj = new Ricubai\WPAuth\WPAuth();
            $WPDBObj->connect_db();
        }
    }
endif;

if (!function_exists('wpdb')):
    /*
     * @return Ricubai\WPAuth\WPAuth Return a global instance of WPAuth.
     */
    function wpdb(): \Ricubai\WPAuth\WPAuth
    {
        global $WPDBObj;
        return $WPDBObj;
    }
endif;
