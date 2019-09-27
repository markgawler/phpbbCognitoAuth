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
	'ACP_COGAUTH_TITLE'	=> 'AWS Cognito Auth',
	'ACP_COGAUTH_TITLE_CFG'	=> 'IAM Access Key Settings',
	'ACP_COGAUTH_MISC_TITLE' => 'Miscellaneous Settings',
	'ACP_COGAUTH_TITLE_MISC' => 'Miscellaneous Settings',
	'ACP_COGAUTH_TITLE_POOL' => 'User Pool Settings',
	'ACP_COGAUTH_CORE_SETTING_SAVED' => 'Settings have been saved successfully!',
	'CA_AUTOLOGIN_LENGTH_EXPLAIN' => 'Number of days after which "Remember Me" login keys are removed (1 to 3650, the AWS Cognito Refresh Token validity range).',
	'CA_AUTOLOGIN_LENGTH' => '"Remember Me" login key expiration length (in days)',
	'ACP_COGAUTH_AWS_ERROR' => 'AWS Returned the following Error',
	'APC_COGAUTH_CREATE_USER_POOL' => 'Create Cognito User Pool',
	'APC_COGAUTH_AWS_ACCESS_KEY' => 'IAM Access Key Settings',
	'APC_COGAUTH_AWS_USE_USER_POOL' => 'Use Existing User Pool',
	'APC_COGAUTH_AWS_CREATE_USER_POOL' => 'Create New User Pool',
	'APC_COGAUTH_AWS_APP_CLIENT' => 'Configure App Client',

	'APC_COGAUTH_CRON_ACCESS_TOKENS' => 'Cron Frequency',
	'ACP_COGAUTH_TOKEN_CLEANUP'	=> 'Access Token cleanup check frequency (minutes)',
	'ACP_COGAUTH_TOKEN_CLEANUP_EXPLAIN' => 'Removal of Cogauth sessions information for expired phpBB sessions and expired AWS Cognito Access tokens. Range one minute to one day (1440 minutes)',

	'APC_COGAUTH_PURGE_ACCESS_TOKENS' => 'Purge expired access tokens',
	'APC_COGAUTH_PURGE_TOKENS'			=> 'Purge Expired Tokens',
	'APC_COGAUTH_PURGE_TOKENS_EXPLAIN'	=> 'Purge any expired access tokens, both sessions and auto loging sesions are checked (this replicates the cron task)',

	'APC_HOSTED_UI' => 'Hosted UI Support (Experimental)',
	'APC_HOSTED_UI_EXPLAIN' => 'Enable support for Cognito Hosted UI support, this will require configuration in the AWS Console',
	'APC_COGAUTH_HOSTED_UI_DOMAIN' => 'Cognito Hosted UI Domain name',
	'APC_COGAUTH_HOSTED_UI_DOMAIN_EXPLAIN' => 'The domain name for the Hosted UI, this must be set via the AWS Control Panel if the Hosted UI is used',
));
