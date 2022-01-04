<?php

namespace Ricubai\WPAuth;

use Ricubai\PHPHelpers\FormError;

class WPAuth
{
    /**
     * DB class
     * @var DB
     */
    public $wpdb;

    /**
     * @var \mysqli
     */
    public $con;

    public $db_prefix;
    public $users_table;
    public $usermeta_table;
    public $options_table;

    public function connect_db()
    {
        if (!$this->wpdb) {
//            $this->wpdb = new \mysqli(WPDB_HOST, WPDB_USER, WPDB_PASSWORD, WPDB_NAME);
            $this->wpdb = new DB(WPDB_HOST, WPDB_USER, WPDB_PASSWORD, WPDB_NAME);
            $this->con = $this->wpdb->connection;

            $this->db_prefix = WPDB_PREFIX;
            $this->users_table = WPDB_PREFIX . 'users';
            $this->usermeta_table = WPDB_PREFIX . 'usermeta';
            $this->options_table = WPDB_PREFIX . 'options';
        }
    }

    /**
     * Sets current user variable from auth session.
     * User should be logged in. Otherwise no user will be set.
     */
    public function set_current_user_session()
    {
        global $current_user;

        // Checks if a user already set, then skip
        if (
            isset($current_user)
            && ($current_user instanceof User)
            && ($current_user->ID)
        ) {
            // Already set. Nothing todo.
            // return $current_user;
            return;
        }

        // Sets current user variable from auth session cookie.
        $user = $this->get_current_user_session_from_cookie();
        if ($user instanceof User && $user->ID) {
            $current_user = $user;
        }
    }

    /**
     * Gets logged in user. Checks auth cookie.
     *
     * @return User|false User on success, false on failure.
     * @global string $auth_secure_cookie
     */
    private function get_current_user_session_from_cookie()
    {
        $user_id = $this->validate_auth_cookie('logged_in');
        if ($user_id) {
            return new User($user_id);
        }

//    clear_auth_cookie();
        return false;
//
//    global $auth_secure_cookie;
//
//    if ($auth_secure_cookie) {
//        $auth_cookie = SECURE_AUTH_COOKIE;
//    } else {
//        $auth_cookie = AUTH_COOKIE;
//    }
//
//    if (!empty($_COOKIE[$auth_cookie])) {
//        return new WP_Error('expired_session', __('Please log in again.'));
//    }
//    // If the cookie is not set, be silent.
//
//    return $user;
    }

    /**
     * Validates authentication cookie.
     *
     * The checks include making sure that the authentication cookie is set and
     * pulling in the contents (if $cookie is not used).
     *
     * Makes sure the cookie is not expired. Verifies the hash in cookie is what is
     * should be and compares the two.
     *
     * @param string $cookie Optional. If used, will validate contents instead of cookie's.
     * @param string $scheme Optional. The cookie scheme to use: 'secure_auth', or 'logged_in'.
     * @return false|int False if invalid cookie, user ID if valid.
     * @global int $login_grace_period
     *
     * @since 2.5.0
     *
     */
    private function validate_auth_cookie($scheme = 'logged_in')
    {
        $cookie_elements = self::parse_auth_cookie($scheme);
        if (!$cookie_elements) {
            return false;
        }

        $scheme = $cookie_elements['scheme'];
        $username = $cookie_elements['username'];
        $hmac = $cookie_elements['hmac'];
        $token = $cookie_elements['token'];
        $expired = $cookie_elements['expiration'];
        $expiration = $cookie_elements['expiration'];

//    // Allow a grace period for POST and Ajax requests
//    if (wp_doing_ajax() || 'POST' == $_SERVER['REQUEST_METHOD']) {
//        $expired += HOUR_IN_SECONDS;
//    }

        // Fires once an authentication cookie has expired.
        if ($expired < time()) {
            return false;
        }

        $user = $this->get_user_by('login', $username);
        // Fires if a bad username is entered in the user authentication process.
        if (!$user) {
            return false;
        }

        $pass_frag = substr($user['user_pass'], 8, 4);
        $key = \DH::get_hash($username . '|' . $pass_frag . '|' . $expiration . '|' . $token, $scheme);
        $hash = hash_hmac('sha256', $username . '|' . $expiration . '|' . $token, $key);

        // Fires if a bad authentication cookie hash is encountered.
        if (!hash_equals($hash, $hmac)) {
            return false;
        }

        // @todo: what's this exactly? Shoulw we should clear cookies if they are expired.
        $manager = WPSessionTokens::get_instance($user['ID']);
        if (!$manager->verify($token)) {
            return false;
        }

//    // Ajax/POST grace period set above
//    if ($expiration < time()) {
//        $GLOBALS['login_grace_period'] = 1;
//    }

        return $user['ID'];
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
     * Retrieve user meta field for a user from WP DB.
     *
     * @param int $user_id User ID.
     * @param string $key The meta key to retrieve.
     * @return mixed Will be value of meta data field.
     */
    public function get_user_meta($user_id, $key)
    {
        $result = $this->wpdb->query(
            "SELECT meta_value FROM wp_usermeta
            WHERE user_id = '" . mysqli_real_escape_string($this->con, $user_id) . "'
            AND meta_key = '" . mysqli_real_escape_string($this->con, $key) . "' "
        )->fetchArray();

        if (!$result) {
            return false;
        }

        $value = $result['meta_value'];
        $value = \DH::maybe_unserialize($value);

        return $value;
    }

    /**
     * Retrieve user meta field for a user from WP DB.
     *
     * @param int $user_id User ID.
     * @param string $key The meta key to retrieve.
     * @return mixed Will be value of meta data field.
     */
    public function update_user_meta($user_id, $key, $value)
    {
        if (!$key) {
            return false;
        }

        $value = wp_unslash($value);
        $value = \DH::maybe_serialize($value);

        // Check for existing row
        $q = $this->wpdb->query(
            "SELECT umeta_id FROM wp_usermeta
            WHERE user_id = '" . mysqli_real_escape_string($this->con, $user_id) . "'
                AND meta_key = '" . mysqli_real_escape_string($this->con, $key) . "' "
        )->fetchArray();

        // If nothing found then insert a new one.
        if (!$q || !$q['umeta_id']) {
            $this->wpdb->query(
                "INSERT INTO wp_usermeta
                SET user_id = '" . mysqli_real_escape_string($this->con, $user_id) . "',
                    meta_key = '" . mysqli_real_escape_string($this->con, $key) . "',
                    meta_value = '" . mysqli_real_escape_string($this->con, $value) . "' "
            );
            return true;
        }

        // Update value
        $this->wpdb->query(
            "UPDATE wp_usermeta
            SET meta_value = '" . mysqli_real_escape_string($this->con, $value) . "'
            WHERE user_id = '" . mysqli_real_escape_string($this->con, $user_id) . "'
                AND meta_key = '" . mysqli_real_escape_string($this->con, $key) . "' "
        );

        return true;
    }

    /**
     * Retrieves an option value based on an option name.
     *
     * If the option does not exist, and a default value is not provided,
     * boolean false is returned.
     *
     * @param string $option Name of the option to retrieve. Expected to not be SQL-escaped.
     * @param mixed $default Optional. Default value to return if the option does not exist.
     * @return mixed Value of the option. A value of any type may be returned, including
     *               scalar (string, boolean, float, integer), null, array, object.
     *               Scalar and null values will be returned as strings as long as they originate
     *               from a database stored option value. If there is no option in the database,
     *               boolean `false` is returned.
     */
    function get_option($option, $default = false)
    {
        $option = trim($option);
        if (empty($option)) {
            return false;
        }

        // Distinguish between `false` as a default, and not passing one.
        $passed_default = func_num_args() > 1;

        $result = $this->wpdb->query(
            $this->wpdb->prepare(
                "SELECT option_value FROM $this->options_table WHERE option_name = %s LIMIT 1",
                $option
            )
        )->fetchArray();

        if (isset($result['option_value'])) {
            $value = $result['option_value'];
        } else {
            $value = null;
        }

        return \DH::maybe_unserialize($value);
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

        if ('' === $token) {
            $manager = WPSessionTokens::get_instance($user_id);
            $token = $manager->create($expiration);
        }

        $auth_cookie_value = $this->generate_auth_cookie_value($user_id, $expiration, 'secure_auth', $token);
        $logged_in_cookie_value = $this->generate_auth_cookie_value($user_id, $expiration, 'logged_in', $token);

        // Why this cookie?
        setcookie(SECURE_AUTH_KEY, $auth_cookie_value, $expire, '/', DOMAIN_NAME, true, true);
        // Check if logged in
        setcookie(LOGGED_IN_KEY, $logged_in_cookie_value, $expire, '/', DOMAIN_NAME, true, true);
    }

    /**
     * Generates authentication cookie contents.
     *
     * @param int $user_id User ID.
     * @param int $expiration The time the cookie expires as a UNIX timestamp.
     * @param string $scheme Optional. The cookie scheme to use: 'auth', 'secure_auth', or 'logged_in'.
     *                           Default 'auth'.
     * @param string $token User's session token to use for this cookie.
     * @return string Authentication cookie contents. Empty string if user does not exist.
     */
    private function generate_auth_cookie_value($user_id, $expiration, $scheme = 'secure_auth', $token = '')
    {
        $user = $this->get_user_by('id', $user_id);
        if (!$user) {
            return false;
        }

        if (!$token) {
            $manager = WPSessionTokens::get_instance($user_id);
            $token = $manager->create($expiration);
        }

        $pass_frag = substr($user['user_pass'], 8, 4);
        $key = \DH::get_hash($user['user_login'] . '|' . $pass_frag . '|' . $expiration . '|' . $token, $scheme);
        $hash = hash_hmac('sha256', $user['user_login'] . '|' . $expiration . '|' . $token, $key);
        return $user['user_login'] . '|' . $expiration . '|' . $token . '|' . $hash;
    }

    /**
     * Parses a cookie into its components.
     *
     * @param string $cookie Authentication cookie.
     * @param string $scheme Optional. The cookie scheme to use: 'auth', 'secure_auth', or 'logged_in'.
     * @return array|false Authentication cookie components.
     */
    private static function parse_auth_cookie($scheme = '')
    {
        switch ($scheme) {
            case 'secure_auth':
                $cookie_name = SECURE_AUTH_KEY;
                break;
            case 'logged_in':
                $cookie_name = LOGGED_IN_KEY;
                break;
            default:
                $cookie_name = SECURE_AUTH_KEY;
                $scheme = 'secure_auth';
        }

        if (empty($_COOKIE[$cookie_name])) {
            return false;
        }
        $cookie = $_COOKIE[$cookie_name];

        $cookie_elements = explode('|', $cookie);
        if (count($cookie_elements) !== 4) {
            return false;
        }

        [$username, $expiration, $token, $hmac] = $cookie_elements;

        return compact('username', 'expiration', 'token', 'hmac', 'scheme');
    }

    /**
     * Retrieves the global WP_Roles instance and instantiates it if necessary.
     *
     * @return WP_Roles WP_Roles global instance if not already instantiated.
     * @global WP_Roles $wp_roles WordPress role management object.
     *
     */
    public static function wp_roles()
    {
        global $wp_roles;

        if (!isset($wp_roles)) {
            $wp_roles = new WPRoles();
        }
        return $wp_roles;
    }
}
