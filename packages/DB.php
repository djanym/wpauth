<?php

namespace Ricubai\WPAuth;

/**
 * Class DB
 * Common methods:
 *      query()->fetchArray();
 *      query()->fetchAll();
 *      query()->numRows();
 * @package Ricubai\WPAuth
 */
class DB
{
    public $connection;
    protected $query;
    protected $show_errors = true;
    protected $query_closed = true;
    public $query_count = 0;

    public function __construct($dbhost = 'localhost', $dbuser = 'root', $dbpass = '', $dbname = '', $charset = 'utf8')
    {
        $this->connection = new \mysqli($dbhost, $dbuser, $dbpass, $dbname);
        if ($this->connection->connect_error) {
            $this->error('Failed to connect to MySQL - ' . $this->connection->connect_error);
        }
        $this->connection->set_charset($charset);
    }

    public function query($query)
    {
        if (!$this->query_closed) {
            $this->query->close();
        }
        if ($this->query = $this->connection->prepare($query)) {
            if (func_num_args() > 1) {
                $x = func_get_args();
                $args = array_slice($x, 1);
                $types = '';
                $args_ref = array();
                foreach ($args as $k => &$arg) {
                    if (is_array($args[$k])) {
                        foreach ($args[$k] as $j => &$a) {
                            $types .= $this->_gettype($args[$k][$j]);
                            $args_ref[] = &$a;
                        }
                    } else {
                        $types .= $this->_gettype($args[$k]);
                        $args_ref[] = &$arg;
                    }
                }
                array_unshift($args_ref, $types);
                call_user_func_array(array($this->query, 'bind_param'), $args_ref);
            }
            $this->query->execute();
            if ($this->query->errno) {
                $this->error('Unable to process MySQL query (check your params) - ' . $this->query->error);
            }
            $this->query_closed = false;
            $this->query_count++;
        } else {
            $this->error('Unable to prepare MySQL statement (check your syntax) - ' . $this->connection->error);
        }
        return $this;
    }


    public function fetchAll($callback = null)
    {
        $params = array();
        $row = array();
        $meta = $this->query->result_metadata();
        while ($field = $meta->fetch_field()) {
            $params[] = &$row[$field->name];
        }
        call_user_func_array(array($this->query, 'bind_result'), $params);
        $result = array();
        while ($this->query->fetch()) {
            $r = array();
            foreach ($row as $key => $val) {
                $r[$key] = $val;
            }
            if ($callback != null && is_callable($callback)) {
                $value = call_user_func($callback, $r);
                if ($value == 'break') {
                    break;
                }
            } else {
                $result[] = $r;
            }
        }
        $this->query->close();
        $this->query_closed = true;
        return $result;
    }

    public function fetchArray()
    {
        $params = array();
        $row = array();
        $meta = $this->query->result_metadata();
        while ($field = $meta->fetch_field()) {
            $params[] = &$row[$field->name];
        }
        call_user_func_array(array($this->query, 'bind_result'), $params);
        $result = array();
        while ($this->query->fetch()) {
            foreach ($row as $key => $val) {
                $result[$key] = $val;
            }
        }
        $this->query->close();
        $this->query_closed = true;
        return $result;
    }

    /**
     * Prepares a SQL query for safe execution. Uses sprintf()-like syntax.
     *
     * The following directives can be used in the query format string:
     *   %d (integer)
     *   %f (float)
     *   %s (string)
     *   %% (literal percentage sign - no argument needed)
     *
     * All of %d, %f, and %s are to be left unquoted in the query string and they need an argument passed for them.
     * Literals (%) as parts of the query must be properly written as %%.
     *
     * This function only supports a small subset of the sprintf syntax; it only supports %d (integer), %f (float), and %s (string).
     * Does not support sign, padding, alignment, width or precision specifiers.
     * Does not support argument numbering/swapping.
     *
     * Both %d and %s should be left unquoted in the query string.
     *
     *     prepare( "SELECT * FROM `table` WHERE `column` = %s AND `field` = %d", 'foo', 1337 );
     *     prepare( "SELECT DATE_FORMAT(`field`, '%%c') FROM `table` WHERE `column` = %s", 'foo' );
     *
     * @param string $query Query statement with sprintf()-like placeholders
     * @param array|mixed $args The array of variables to substitute into the query's placeholders if being called like
     *                              {@link https://secure.php.net/vsprintf vsprintf()}, or the first variable to substitute into the query's placeholders if
     *                              being called like {@link https://secure.php.net/sprintf sprintf()}.
     * @param mixed $args,... further variables to substitute into the query's placeholders if being called like
     *                              {@link https://secure.php.net/sprintf sprintf()}.
     * @return string|void Sanitized query string, if there is a query to prepare.
     */
    public function prepare($query, $args)
    {
        if (is_null($query)) {
            return;
        }

        $args = func_get_args();
        array_shift($args);
        // If args were passed as an array (as in vsprintf), move them up
        if (isset($args[0]) && is_array($args[0])) {
            $args = $args[0];
        }
        $query = str_replace("'%s'", '%s', $query); // in case someone mistakenly already singlequoted it
        $query = str_replace('"%s"', '%s', $query); // doublequote unquoting
        $query = preg_replace('|(?<!%)%f|', '%F', $query); // Force floats to be locale unaware
        $query = preg_replace('|(?<!%)%s|', "'%s'", $query); // quote the strings, avoiding escaped strings like %%s
        array_walk($args, array($this, 'escape_by_ref'));
        return @vsprintf($query, $args);
    }

    /**
     * Escapes content by reference for insertion into the database, for security
     *
     * @param string $string to escape
     */
    private function escape_by_ref( &$string ) {
        if ( ! is_float( $string ) )
            $string = $this->_real_escape( $string );
    }

    /**
     * Real escape, using mysqli_real_escape_string() or mysql_real_escape_string()
     *
     * @param  string $string to escape
     * @return string escaped
     */
    private function _real_escape( $string ) {
        if ( $this->connection ) {
                return mysqli_real_escape_string( $this->connection, $string );
        }
        die('DB001');
    }

    /**
     * Escape data. Works on arrays.
     *
     * @uses wpdb::_real_escape()
     * @since  2.8.0
     * @access public
     *
     * @param  string|array $data
     * @return string|array escaped
     */
    private function _escape( $data ) {
        if ( is_array( $data ) ) {
            foreach ( $data as $k => $v ) {
                if ( is_array( $v ) ) {
                    $data[$k] = $this->_escape( $v );
                } else {
                    $data[$k] = $this->_real_escape( $v );
                }
            }
        } else {
            $data = $this->_real_escape( $data );
        }

        return $data;
    }

    public function close()
    {
        return $this->connection->close();
    }

    public function numRows()
    {
        $this->query->store_result();
        return $this->query->num_rows;
    }

    public function affectedRows()
    {
        return $this->query->affected_rows;
    }

    public function lastInsertID()
    {
        return $this->connection->insert_id;
    }

    public function error($error)
    {
        if ($this->show_errors) {
            exit($error);
        }
    }

    private function _gettype($var)
    {
        if (is_string($var)) {
            return 's';
        }
        if (is_float($var)) {
            return 'd';
        }
        if (is_int($var)) {
            return 'i';
        }
        return 'b';
    }

}
