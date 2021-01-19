<?php

namespace Ricubai\WPAuth;

use Ricubai\PHPHelpers\FormError;

class WPAuth
{
    /*
     * @var \Ricubai\WPAuth\DB
     */
    public $wpdb;

    public $con;

    public function connect_db()
    {
        if (!$this->wpdb) {
//            $this->wpdb = new \mysqli(WPDB_HOST, WPDB_USER, WPDB_PASSWORD, WPDB_NAME);
            $this->wpdb = new DB(WPDB_HOST, WPDB_USER, WPDB_PASSWORD, WPDB_NAME);
            $this->con = $this->wpdb->connection;
        }
    }

    /**
     * Authenticates and logs a user in with 'remember' capability.
     *
     * The credentials is an array that has 'user_login', 'user_password', and
     * 'remember' indices. If the credentials is not given, then the log in form
     * will be assumed and used if set.
     *
     * The various authentication cookies will be set by this function and will be
     * set for a longer period depending on if the 'remember' credential is set to
     * true.
     *
     * Note: wp_signon() doesn't handle setting the current user. This means that if the
     * function is called before the {@see 'init'} hook is fired, is_user_logged_in() will
     * evaluate as false until that point. If is_user_logged_in() is needed in conjunction
     * with wp_signon(), wp_set_current_user() should be called explicitly.
     *
     * @param array $credentials Optional. User info in order to sign on.
     * @return FormError User on success, FormError on failure.
     * @global string $auth_secure_cookie
     */
    public function signin($credentials)
    {
        $credentials['remember'] = $credentials['remember'] ?? false;

        // Try to get the user by username
        $user = $this->get_user_by('login', $credentials['username']);

        // If no user found, then try to get the user by email
        if (!$user && strpos($credentials['username'], '@')) {
            $user = $this->get_user_by('email', $credentials['username']);

            // If no user found by email, then return error
            if (!$user) {
                return new FormError(
                    'invalid_email',
                    __('Unknown email address. Check again or try your username.')
                );
            }
        } elseif (!$user) {
            // If email was not used, then return error.
            return new FormError(
                'invalid_username',
                __('Unknown username. Check again or try your email address.')
            );
        }

        // Check if user exists by username/email and password.
        $check = $this->compare_user_hash_pass($user['ID'], $user['user_pass'], $credentials['password']);

        if (is_error($check)) {
            return $check;
        }

        // Set authentification (logged in) cookie.
        $this->set_auth_cookie($user['ID'], $credentials['remember']);

        if (empty($_COOKIE[LOGGED_IN_KEY]) && headers_sent()) { // @TODO: test this.
            return new FormError(
                'test_cookie',
                sprintf(
                    __(
                        '<strong>ERROR</strong>: Cookies are blocked due to unexpected output. For help, please see <a href="%1$s">this documentation</a> or try the <a href="%2$s">support forums</a>.'
                    ),
                    __('https://kuwaes.org/support/article/cookies/'), // @TODO: Link
                    __('https://kuwaes.org/support/forums/') // @TODO: Link
                )
            );
        }

        return $user;
    }

    /**
     * Retrieve user info by a given field from WP DB.
     *
     * @param string $field The field to retrieve the user with. id | ID | slug | email | login.
     * @param int|string $value A value for $field. A user ID, slug, email address, or login name.
     * @return array|false User array on success, false on failure.
     */
    public function get_user_by($field, $value)
    {
        switch ($field) {
            case 'id':
                $db_field = 'ID';
                break;
            case 'slug':
                $db_field = 'user_nicename';
                break;
            case 'email':
                $db_field = 'user_email';
                break;
            case 'login':
                $db_field = 'user_login';
                break;
            default:
                return false;
        }

        $result = $this->wpdb->query(
            "SELECT * FROM wp_users WHERE "
            . mysqli_real_escape_string($this->con, $db_field)
            . " = '" . mysqli_real_escape_string($this->con, $value) . "' "
        )->fetchArray();

        return $result ?: false;
    }

    /**
     * Check if user submitted password is valid by comparing it with DB.
     * Used for login via form.
     *
     * @param int $user_id User's DB ID
     * @param string $hash User's stored hashed password
     * @param string $password User's password.
     * @return bool|FormError 'true' if the credentials are valid,
     *                          otherwise FormError.
     */
    private function compare_user_hash_pass($user_id, $hash, $password)
    {

        if (empty($password)) {
            return new FormError(
                'empty_password',
                __('<strong>ERROR</strong>: The password field is empty.')
            );
        }

        if (!$user_id) {
            return new FormError(
                'empty_id',
                __('<strong>ERROR</strong>: UA001.')
            );
        }

        global $wp_hasher;

        if (empty($wp_hasher)) {
//            require_once(ABSPATH . '/inc/class-phpass.php');
            // By default, use the portable hash from phpass
            $wp_hasher = new PasswordHash(8, true);
        }

        $check = $wp_hasher->CheckPassword($password, $hash);

        if (!$check) {
            // @TODO: check auth cookie
            return new FormError(
                'incorrect_password',
                __('<strong>ERROR</strong>: The password you entered is incorrect.')
                .
                ' <a href="' . LOST_PASS_URL . '">' .
                __('Lost your password?') .
                '</a>'
            );
        }

        return true;
    }


    /**
     * Sets the authentication cookies based on user ID.
     *
     * The $remember parameter increases the time that the cookie will be kept. The
     * default the cookie is kept without remembering is two days. When $remember is
     * set, the cookies will be kept for 14 days or two weeks.
     *
     * @param int $user_id User ID.
     * @param bool $remember Whether to remember the user.
     * @param string $token Optional. User's session token to use for this cookie.
     */
    private function set_auth_cookie($user_id, $remember = false, $token = '')
    {
        if ($remember) {
            // Sets duration of the authentication cookie expiration period.
            $expiration = time() + (14 * 3600 * 24);
            /*
             * Ensure the browser will continue to send the cookie after the expiration time is reached.
             * Needed for the login grace period in wp_validate_auth_cookie().
             */
            $expire = $expiration + (12 * 3600);
        } else {
            // Sets 2 days for cookie.
            $expiration = time() + (2 * 3600 * 24);
            $expire = $expiration;
        }

        WPSessionTokens::get_instance($user_id); die;

        if ('' === $token) {
            $manager = WPSessionTokens::get_instance($user_id);
            $token = $manager->create($expiration);
        }

        $auth_cookie_value = generate_auth_cookie_value($user_id, $expiration, 'secure_auth', $token);
        $logged_in_cookie_value = generate_auth_cookie_value($user_id, $expiration, 'logged_in', $token);

        echo 765; die;

        // Why this cookie?
        setcookie(SECURE_AUTH_KEY, $auth_cookie_value, $expire, '/', DOMAIN_NAME, true, true);
        // Check if logged in
        setcookie(LOGGED_IN_KEY, $logged_in_cookie_value, $expire, '/', DOMAIN_NAME, true, true);
    }
}
