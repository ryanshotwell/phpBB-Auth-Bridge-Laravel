<?php

namespace
{
    if (!defined('IN_PHPBB')) {
        exit;
    }
    
    const LARAVEL_URL = 'https://example.com';
    const LARAVEL_API_KEY = 'your-secret-api-key';

    // User properties from Laravel as key and phpBB as value
    define('LARAVEL_CUSTOM_USER_DATA', serialize([
        'email' => 'user_email',
        //'dob' => 'user_birthday',
    ]));

    function curlResponseHeaderCallback($ch, $headerLine): int
    {
        preg_match_all('/^Set-Cookie:\s*([^;]*)/mi', $headerLine, $matches);
        
        foreach($matches[1] as $item) {
            parse_str($item, $cookie);
            setcookie(key($cookie), $cookie[key($cookie)], time() + 86400, '/');
        }
    
        // Needed by curl
        return strlen($headerLine);
    }
}

namespace laravel\bridgebb\auth\provider
{
    use Exception;
    use phpbb\auth\provider\base;
    use phpbb\auth\provider\provider_interface;
    use phpbb\db\driver\driver_interface;
    use phpbb\request\request_interface;
    
    /**
     * Laravel authentication provider for phpBB3
     */
    class LaravelAuthBridge extends base implements provider_interface
    {
        /**
         * @var driver_interface
         */
        protected driver_interface $db;
    
        /**
         * Database Authentication Constructor
         *
         * @param driver_interface $db
         */
        public function __construct(driver_interface $db)
        {
            $this->db = $db;
        }
    
        /**
         * {@inheritdoc}
         */
        public function login($username, $password)
        {
            if (self::validate_session(['username' => $username]) && $this->_getUserByUsername($username)) {
                return self::_success(self::autologin());
            }
            elseif (is_null($password)) {
                return self::_error(LOGIN_ERROR_PASSWORD, 'NO_PASSWORD_SUPPLIED');
            }
            elseif (is_null($username)) {
                return self::_error(LOGIN_ERROR_USERNAME, 'LOGIN_ERROR_USERNAME');
            }
            else {
                return self::_apiValidate($username, $password);
            }
        }

        // If user auth on laravel side but not in phpBB try to auto login
        public function autologin()
        {
            try {
                $request = self::_make_api_request([],'GET');
                $response = json_decode($request, true);

                if (isset($response['data']['username']) && isset($response['code'])) {
                    if ($response['code'] === '200' && $response['data']['username']) {
                        $row = $this->_getUserByUsername($response['data']['username']);
                        return ($row) ? : [];
                    }
                }
                return [];
            }
            catch (Exception $e) {
                return [];
            }
        }
    
        /**
         * Validate the current session
         *
         * @param array $user
         *
         * @return bool Returns true if the session is valid or false if the user is not logged in, the user is invalid, or an error occurred
         */
        public function validate_session($user): bool
        {
            // User is not logged in
            if ($user['username'] == 'Anonymous') {
                return false;
            }
            
            try {
                $request = self::_make_api_request([], 'GET');
                $response = json_decode($request, true);

                if (isset($response['data']['username']) && isset($response['code'])) {
                    if ($response['code'] === '200' && $response['data']['username'] != '') {
                        return (mb_strtolower($user['username']) == mb_strtolower($response['data']['username']));
                    }
                }

                return false;
            }
            catch (Exception $e) {
                return false;
            }
        }

        public function logout($user, $newSession): void
        {
            try {
                if (self::validate_session($user)) {
                    self::_make_api_request([], 'DELETE');
                }
            }
            catch (Exception $e) {
            }
        }

        private function _make_api_request($data, string $method)
        {
            global $request;

            $ch = curl_init();
            
            $requestCookies = '';
            
            $cookies = $request->get_super_global(request_interface::COOKIE);
            
            foreach ($cookies as $key => $value) {
                $requestCookies .= "$key=$value;";
            }

            $curlConfig = [
                CURLOPT_URL            => LARAVEL_URL . '/auth-bridge/login',
                CURLOPT_COOKIESESSION  => true,
                CURLOPT_COOKIE         => $requestCookies,
                CURLINFO_HEADER_OUT    => true,
                CURLOPT_HEADERFUNCTION => 'curlResponseHeaderCallback',
                CURLOPT_RETURNTRANSFER => true
            ];

            if ($method == 'POST') {
                $curlConfig[CURLOPT_POST] = true;
                $curlConfig[CURLOPT_POSTFIELDS] = $data;
            }
            elseif ($method == 'DELETE') {
                $curlConfig[CURLOPT_CUSTOMREQUEST] = 'DELETE';
            }

            curl_setopt_array($ch, $curlConfig);
            $result = curl_exec($ch);
            curl_close($ch);
            
            return $result;
        }

        private function _apiValidate($username, $password)
        {
            try {
                $post_data = http_build_query(
                    array(
                        'appkey' => LARAVEL_API_KEY,
                        'username' => $username,
                        'password' => $password
                    )
                );
                
                $request = self::_make_api_request($post_data,'POST');
                $response = json_decode($request, true);
                
                if ($response['code'] === '200') {
                    return self::_handleAuthSuccess($username, $password, $response['data']);
                }
                else {
                    return self::_error(LOGIN_ERROR_USERNAME, 'LOGIN_ERROR_USERNAME');
                }
            }
            catch (Exception $e) {
                return self::_error(LOGIN_ERROR_EXTERNAL_AUTH, $e->getMessage());
            }
        }

        private function _handleAuthSuccess($username, $password, $user_laravel)
        {
            global $request;
            
            $server = $request->get_super_global(request_interface::SERVER);
            
            if ($row = $this->_getUserByUsername($username)) {
                // User inactive
                if ($row['user_type'] == USER_INACTIVE || $row['user_type'] == USER_IGNORE) {
                    return self::_error(LOGIN_ERROR_ACTIVE, 'ACTIVE_ERROR', $row);
                }
                else {
                    // Session hack
                    header("Location: http://" . $server['HTTP_HOST'] . $server['REQUEST_URI']);
                    die();
                }
            }
            else {
                // this is the user's first login so create an empty profile
                user_add(self::_createUserRow($username, sha1($password), $user_laravel));
                
                // Session hack
                header("Location: http://" . $server['HTTP_HOST'] . $server['REQUEST_URI']);
                die();
            }
        }

        private function _createUserRow($username, $password, $user_laravel)
        {
            global $user;
            
            // first retrieve default group id
            $row = $this->_get_default_group_id();
            if (!$row) {
                trigger_error('NO_GROUP');
            }

            // generate user account data
            $userRow = [
                'username' => $username,
                'user_password' => phpbb_hash($password),
                'group_id' => (int) $row['group_id'],
                'user_type' => USER_NORMAL,
                'user_ip' => $user->ip,
            ];

            if (LARAVEL_CUSTOM_USER_DATA && $laravel_fields = unserialize(LARAVEL_CUSTOM_USER_DATA)) {
                foreach ($laravel_fields as $key => $value) {
                    if (isset($user_laravel[$key])) {
                        $userRow[$value] = $user_laravel[$key];
                    }
                }
            }
            
            return $userRow;
        }

        private function _error(string $status, string $message, array $row = ['user_id' => ANONYMOUS])
        {
            return array(
                'status' => $status,
                'error_msg' => $message,
                'user_row' => $row,
            );
        }

        private function _success(array $row): array
        {
            return [
                'status' => LOGIN_SUCCESS,
                'error_msg' => false,
                'user_row' => $row,
            ];
        }
    
        /**
         * Get all of a user's details by their username
         *
         * @param $username
         *
         * @return mixed
         */
        private function _getUserByUsername($username)
        {
            $username = mb_strtolower($username);
            
            $sql = 'SELECT * FROM ' . USERS_TABLE . " WHERE LOWER(username) = '{$this->db->sql_escape($username)}'";
            $result = $this->db->sql_query($sql);
            $row = $this->db->sql_fetchrow($result);
            $this->db->sql_freeresult($result);
            
            return $row;
        }
    
        /**
         * Get the group ID for a user's default group
         *
         * @return mixed
         */
        private function _get_default_group_id()
        {
            $sql = 'SELECT group_id ';
            $sql .= 'FROM ' . GROUPS_TABLE . ' ';
            $sql .= "WHERE group_name = '{$this->db->sql_escape('REGISTERED')}' AND group_type = " . GROUP_SPECIAL;
            $result = $this->db->sql_query($sql);
            $row = $this->db->sql_fetchrow($result);
            $this->db->sql_freeresult($result);

            return $row;
        }
    }
}
