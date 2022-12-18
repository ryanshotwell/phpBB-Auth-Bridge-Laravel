<?php

namespace ryanshotwell\phpbbbridgelaravel;

use phpbb\extension\base;

class ext extends base
{
    /**
     * @var array An array of installation error messages
     */
    protected array $errors = [];
    
    /**
     * Check whether the extension can be enabled.
     *
     * @return bool|array True if it can be enabled. False if not, or an array of error messages in phpBB 3.3.
     */
    public function is_enableable()
    {
        // Check requirements
        $this->phpbb_requirement();
        $this->php_requirement();
        
        return count($this->errors) ? $this->enable_failed() : true;
    }
    
    /**
     * Check phpBB 3.3.0 minimum requirement.
     *
     * @return void
     */
    protected function phpbb_requirement()
    {
        if (phpbb_version_compare(PHPBB_VERSION, '3.3.0', '<')) {
            $this->errors[] = 'PHPBB_VERSION_ERROR';
        }
    }
    
    /**
     * Check PHP 8.0 minimum requirement.
     *
     * @return void
     */
    protected function php_requirement()
    {
        if (phpbb_version_compare(PHP_VERSION, '8.0', '<')) {
            $this->errors[] = 'PHP_VERSION_ERROR';
        }
    }
    
    /**
     * Generate the best enable failed response for the current phpBB environment.
     * Return error messages in phpBB 3.3 or newer. Return boolean false otherwise.
     *
     * @return array|bool
     */
    protected function enable_failed()
    {
        if (phpbb_version_compare(PHPBB_VERSION, '3.3.0-b1', '>=')) {
            $language = $this->container->get('language');
            $language->add_lang('common', 'ryanshotwell/phpbbbridgelaravel');
            return array_map([$language, 'lang'], $this->errors);
        }
        
        return false;
    }
}
