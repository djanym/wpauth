<?php
/**
 * Session API: WPUserMetaSessionTokens class
 *
 * @package WordPress
 * @subpackage Session
 * @since 4.7.0
 */

namespace Ricubai\WPAuth;

/**
 * Meta-based user sessions token manager.
 *
 * @since 4.0.0
 *
 * @see WPSessionTokens
 */
class WPUserMetaSessionTokens extends WPSessionTokens
{

    /**
     * Retrieves all sessions of the user.
     *
     * @return array Sessions of the user.
     * @since 4.0.0
     *
     */
    protected function get_sessions()
    {
        $sessions = wpauth()->get_user_meta($this->user_id, 'session_tokens');

        if (!is_array($sessions)) {
            return array();
        }

        $sessions = array_map(array($this, 'prepare_session'), $sessions);
        return array_filter($sessions, array($this, 'is_still_valid'));
    }

    /**
     * Converts an expiration to an array of session information.
     *
     * @param mixed $session Session or expiration.
     * @return array Session.
     */
    protected function prepare_session($session)
    {
        if (is_int($session)) {
            return array('expiration' => $session);
        }

        return $session;
    }

    /**
     * Retrieves a session based on its verifier (token hash).
     *
     * @param string $verifier Verifier for the session to retrieve.
     * @return array|null The session, or null if it does not exist
     * @since 4.0.0
     *
     */
    protected function get_session($verifier)
    {
        $sessions = $this->get_sessions();

        if (isset($sessions[$verifier])) {
            return $sessions[$verifier];
        }

        return null;
    }

    /**
     * Updates a session based on its verifier (token hash).
     *
     * @param string $verifier Verifier for the session to update.
     * @param array $session Optional. Session. Omitting this argument destroys the session.
     * @since 4.0.0
     *
     */
    protected function update_session($verifier, $session = null)
    {
        $sessions = $this->get_sessions();

        if ($session) {
            $sessions[$verifier] = $session;
        } else {
            unset($sessions[$verifier]);
        }

        $this->update_sessions($sessions);
    }

    /**
     * Updates the user's sessions in the usermeta table.
     *
     * @param array $sessions Sessions.
     * @since 4.0.0
     *
     */
    protected function update_sessions($sessions)
    {
        if ($sessions) {
            wpauth()->update_user_meta($this->user_id, 'session_tokens', $sessions);
        } else {
            wpauth()->delete_user_meta($this->user_id, 'session_tokens');
        }
    }

    /**
     * Destroys all sessions for this user, except the single session with the given verifier.
     *
     * @param string $verifier Verifier of the session to keep.
     * @since 4.0.0
     *
     */
    protected function destroy_other_sessions($verifier)
    {
        $session = $this->get_session($verifier);
        $this->update_sessions(array($verifier => $session));
    }

    /**
     * Destroys all session tokens for the user.
     *
     * @since 4.0.0
     */
    protected function destroy_all_sessions()
    {
        $this->update_sessions(array());
    }

    /**
     * Destroys all sessions for all users.
     *
     * @since 4.0.0
     */
    public static function drop_sessions()
    {
        delete_metadata('user', 0, 'session_tokens', false, true);
    }
}
