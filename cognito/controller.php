<?php
/**
 * * *
 * AWS Cognito Authentication. An extension for the phpBB Forum Software package.
 *
 * @copyright (c) 2019, Mark Gawler
 * @license GNU General Public License, version 2 (GPL-2.0)
 *
 * @package     mrfg\cogauth\cognito
 *
 * Date: 31/07/19
 */

namespace mrfg\cogauth\cognito;

class controller
{
	/** @var \mrfg\cogauth\cognito\auth_result $auth_result */
	protected $auth_result;

	/** @var \mrfg\cogauth\cognito\cognito $cognito */
	protected $cognito;

	/** @var \phpbb\user $user */
	protected $user;

	 /**
	 * @param	\mrfg\cogauth\cognito\auth_result    $auth_result
	 * @param   \mrfg\cogauth\cognito\cognito $cognito
	 */
	public function __construct(
		\phpbb\user $user,
		\mrfg\cogauth\cognito\auth_result $auth_result,
		\mrfg\cogauth\cognito\cognito $cognito
	)
	{
		$this->auth_result = $auth_result;
		$this->cognito = $cognito;
		$this->user = $user;
	}

	/**
	 *
	 * @return bool | string False if no access token or refresh failed.
	 *                       Access token
	 *
	 * @throws \mrfg\cogauth\cognito\exception\cogauth_internal_exception
	 * @since 1.0
	 */
	public function get_access_token()
	{
		$result = $this->auth_result->get_access_token_from_sid($this->user->session_id);
		if ($result !== false)
		{
			$token = $result['token'];
			switch ($result['mode']) {
				case 'access_token':
					return $token;
				break;
				case 'refresh':
					# Refresh the Access_Token and store the result if valid
					$response = $this->cognito->refresh_access_token(
						$token,
						$result['user_id']);
					if ($this->auth_result->validate_and_store_auth_response(
						$response['AuthenticationResult'], true))
					{
						return $response['AuthenticationResult']['AccessToken'];
					}
				break;
				default:
					throw new \mrfg\cogauth\cognito\exception\cogauth_internal_exception(
						'Unexpected response, mode: ' . $result['mode']);
			}
		}
		return false;
	}
}
