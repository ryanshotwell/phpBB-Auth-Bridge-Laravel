<?php

namespace ryanshotwell\phpbbbridgelaravel\auth\provider;

use Exception;
use phpbb\auth\provider\base;
use phpbb\auth\provider\provider_interface;
use phpbb\db\driver\driver_interface;
use phpbb\passwords\manager;
use phpbb\request\request_interface;

/**
 * Laravel authentication provider for phpBB3
 */
class laravel_auth_bridge extends base implements provider_interface
{
    /**
     * @var driver_interface
     */
    protected driver_interface $db;
    
    protected manager $passwords_manager;
    
    /**
     * Database Authentication Constructor
     *
     * @param driver_interface $db
     */
    public function __construct(driver_interface $db, manager $passwords_manager, request_interface $request)
    {
        $this->db = $db;
        $this->passwords_manager = $passwords_manager;
        $this->request = $request;
        
        define("LARAVEL_URL", 'http://laravel-phpbb.ryanshotwell.com');
        define("LARAVEL_API_KEY", '98w347rgyhb875re36ybuikj');
        
        // User properties from Laravel as key and phpBB as value
        define('LARAVEL_CUSTOM_USER_DATA', serialize([
            'email' => 'email',
            //'dob' => 'user_birthday',
        ]));
    }
    
    /**
     * {@inheritdoc}
     */
    public function login($username, $password)
    {
        /*if (self::validate_session(['username' => $username]) && $this->_getUserByUsername($username))
        {
            error_log('valid_session');
            return self::_success(self::autologin());
        }*/
        
        if (is_null($password))
        {
            return self::_error(LOGIN_ERROR_PASSWORD, 'NO_PASSWORD_SUPPLIED');
        }
        
        if (is_null($username))
        {
            return self::_error(LOGIN_ERROR_USERNAME, 'LOGIN_ERROR_USERNAME');
        }
        
        error_log('do login check');
        return self::_apiValidate($username, $password);
    }
    
    // If user auth on laravel side but not in phpBB try to auto login
    public function autologin()
    {
        try
        {
            $request = self::_make_api_request([], 'GET');
            $response = json_decode($request, true);
            
            if (isset($response['data']['username']) && isset($response['code']))
            {
                if ($response['code'] === '200' && $response['data']['username'])
                {
                    $row = $this->_getUserByUsername($response['data']['username']);
                    return ($row) ? : [];
                }
            }
            
            return [];
        }
        catch (Exception $e)
        {
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
        try
        {
            $request = self::_make_api_request([], 'GET');
            $response = json_decode($request, true);
            error_log('validate_session response ' . print_r($response, true));
        
            if (isset($response['data']['username']) && isset($response['code']))
            {
                if ($response['code'] === '200' && $response['data']['username'] != '')
                {
                    return (mb_strtolower($user['username']) == mb_strtolower($response['data']['username']));
                }
            }
        }
        catch (Exception $e)
        {
            return false;
        }
    
        // A valid session is now determined by the user type (anonymous/bot or not)
        if (!isset($user['user_type']) || $user['user_type'] == USER_IGNORE)
        {
            return true;
        }
    
        return false;
        
        // User is not logged in
        /*if (!isset($user['user_type']) || $user['user_type'] == USER_IGNORE) {
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
        }*/
    }
    
    public function logout($user, $newSession): void
    {
        try
        {
            if (self::validate_session($user))
            {
                self::_make_api_request([], 'DELETE');
            }
        }
        catch (Exception $e)
        {
        }
    }
    
    /**
     * {@inheritdoc}
     */
    public function acp()
    {
        return [
            'laravel_base_url',
            'api_key'
        ];
    }
    
    private function _make_api_request($data, string $method)
    {
        global $request;
        
        $requestCookies = '';
        
        $cookies = $request->get_super_global(request_interface::COOKIE);
        
        foreach ($cookies as $key => $value) {
            $requestCookies .= "$key=$value;";
        }
        
        $ch = curl_init(LARAVEL_URL . '/auth-phpbb/login');
        
        curl_setopt($ch, CURLOPT_COOKIESESSION, true);
        curl_setopt($ch, CURLOPT_COOKIE, $requestCookies);
        
        curl_setopt($ch, CURLINFO_HEADER_OUT, true);
        curl_setopt($ch, CURLOPT_HEADERFUNCTION, function($ch, $headerLine) {
            preg_match_all('/^Set-Cookie:\s*([^;]*)/mi', $headerLine, $matches);
            
            foreach ($matches[1] as $item) {
                parse_str($item, $cookie);
                setcookie(key($cookie), $cookie[key($cookie)], time() + 86400, '/');
            }
            
            // Needed by curl
            return strlen($headerLine);
        });
        
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        
        if ($method == 'POST') {
            curl_setopt($ch, CURLOPT_POST, true);
            curl_setopt($ch, CURLOPT_POSTFIELDS, $data);
        }
        elseif ($method == 'DELETE') {
            curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'DELETE');
        }
        
        curl_setopt($ch, CURLOPT_VERBOSE, true);
        curl_setopt($ch, CURLOPT_STDERR, fopen('/tmp/curl.txt', 'w+'));
        
        $result = curl_exec($ch);
        curl_close($ch);
        
        return $result;
    }
    
    private function _apiValidate($username, $password)
    {
        try {
            $post_data = http_build_query([
                'appkey' => LARAVEL_API_KEY,
                'username' => $username,
                'password' => $password
            ]);
            
            $request = self::_make_api_request($post_data, 'POST');
            $response = json_decode($request, true);
            error_log('_apiValidate ' . print_r($response, true));
            
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
                //return self::_success($row);
    
                // Session hack
                header("Location: http://" . $server['HTTP_HOST'] . $server['REQUEST_URI']);
                die();
            }
        }
        else {
            // this is the user's first login so create an empty profile
            user_add(self::_createUserRow($username, sha1($password), $user_laravel));
            
            //return self::_success($row);
            
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
            'user_password' => $this->passwords_manager->hash($password),
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
