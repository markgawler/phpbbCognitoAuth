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
	'ACP_COGAUTH_SETTING_SAVED'		=> 'Settings have been saved successfully!',
	'COGAUTH_SETTINGS'				=> 'Settings',

	'COGAUTH_AWS_REGION'			=> 'AWS Region',
	'COGAUTH_AWS_SECRET'			=> 'Access Key Secret',
	'COGAUTH_AWS_KEY'				=> 'Access Key ID',

	'COGAUTH_APP_CLIENT_ID'			=> 'Cognito Client ID',
	'COGAUTH_POOL_ID'				=> 'Cognito User Pool ID',
	'COGAUTH_POOL_NAME'				=> 'Cognito User Pool Name',
	'COGAUTH_CLIENT_SECRET'			=> 'Cognito Client Secret',
	'COGAUTH_APP_NAME'			=> 'APP Client Name',

	'COGAUTH_AWS_REGION_EXPLAIN'	=> 'AWS Region',
	'COGAUTH_AWS_SECRET_EXPLAIN'	=> 'AWS Account Credentials, Cognito Admin User Secret Key',
	'COGAUTH_AWS_KEY_EXPLAIN'		=> 'AWS Account Credentials, Cognito Admin User Access Key ID',


	'COGAUTH_CLIENT_ID_EXPLAIN'		=> 'AWS Cognito Client ID',
	'COGAUTH_POOL_ID_EXPLAIN'		=> 'AWS Cognito User Pool ID',
	'COGAUTH_CLIENT_SECRET_EXPLAIN' => 'AWS Cognito Client Secret',

	'COGAUTH_PASSWORD_ERROR' 		=> 'Unexpected error setting password (Cognito)',
	'COGAUTH_EMAIL_CHANGE_ERROR'	=> 'Unexpected error updating email (Cognito)',
	'COGAUTH_ACP_PROFILE_CHANGE_ERROR'	=> 'Unexpected error updating user profile (Cognito)',

	'COGAUTH_AWS_KEY_SET_ERROR' 	=> 'Invalid Configuration: User Pool ID not found in Region',
	'COGAUTH_ACP_CHECK_REGION' 		=> 'Check the AWS region is valid',
	'COGAUTH_ACP_NOT_CONFIGURED'	=> 'AWS Cognito User Pool not configured',

	'COGAUTH_CONFIGURATION_ERROR'	=> '<strong>CogAuth, Configuration error:</strong><br>»Action: "%1$s", Error Code: "%2$s"<br>Message: "%3$s"',
	'COGAUTH_UNEXPECTED_ERROR'	 	=> '<strong>CogAuth, Unexpected error:</strong><br>»Action: "%1$s", Error Code: "%2$s"<br>Message: "%3$s"',
	'COGAUTH_UNEXPECTED_CHALLENGE'	=> '<strong>CogAuth, Unexpected result:</strong><br>»Action: "%1$s", <br>Result: "%2$s"',
	'COGAUTH_AUTO_PASSWD_RESET'		=> '<strong>Cognito password mismatch, automatically reset</strong><br>» %1$s',
	'COGAUTH_MIGRATE_USER'			=> '<strong>User Migrated to Cognito User Pool</strong><br>» %1$s',
	'COGAUTH_NO_ACCESS_TOKEN'		=> '<strong>AWS Cognito login error, phpBB login only, see error log.</strong>',

	'COGAUTH_HOSTED_UI_STATUS_FAIL' => 'An unexpected status code %1$s returned. User not logged in.',
	'COGAUTH_HOSTED_UI_FAIL' => 'An unexpected internal error: "%1$s". User not logged in.',
	'COGAUTH_HOSTED_UI_INVALID' => 'An invalid authentication response was received.',
	'COGAUTH_HOSTED_UI_404' => 'Page not found'
));
