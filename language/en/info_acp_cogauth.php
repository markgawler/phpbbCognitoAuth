<?php
/**
 *
 * AWS Cognito Authentication. An extension for the phpBB Forum Software package.
 *
 * @copyright (c) 2018, Mark Gawler
 * @license GNU General Public License, version 2 (GPL-2.0)
 *
 */

if (!defined('IN_PHPBB'))
{
	exit;
}

if (empty($lang) || !is_array($lang))
{
	$lang = array();
}

$lang = array_merge($lang, array(
	'ACP_COGAUTH_TITLE'			=> 'AWS Cognito Auth Module API',
	'ACP_COGAUTH_TITLE_CFG'		=> 'API Settings',
	'ACP_COGAUTH_CORE_SETTING_SAVED'	=> 'Settings have been saved successfully!',
	'APC_COGAUTH_SECRET_KEY'	=> 'Cogauth Secret Key',

));
