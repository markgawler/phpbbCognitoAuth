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

	'ACP_COGAUTH'					=> 'Settings',
	'ACP_COGAUTH_GOODBYE'			=> 'Should say goodbye?',
	'ACP_COGAUTH_SETTING_SAVED'	=> 'Settings have been saved successfully!',

));
