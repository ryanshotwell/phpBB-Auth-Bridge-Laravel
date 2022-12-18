<?php

if (!defined('IN_PHPBB')) {
    exit;
}

if (empty($lang) || !is_array($lang)) {
    $lang = [];
}

$lang = array_merge($lang, [
    'PHP_VERSION_ERROR'		=> 'PHP 8.0 or newer is required to use this extension.',
    'PHPBB_VERSION_ERROR'	=> 'phpBB 3.3.0 or newer is required to use this extension.',
]);
