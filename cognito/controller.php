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

	/** @var \mrfg\cogauth\cognito\user $user */
	protected $user;

	/** @var \phpbb\log\log_interface $log */
	protected $log;

	/**@var \phpbb\config\config $config Config object */
	protected $config;

	/**
	 * @param \mrfg\cogauth\cognito\user $user
	 * @param \mrfg\cogauth\cognito\auth_result $auth_result
	 * @param \mrfg\cogauth\cognito\cognito $cognito
	 * @param \phpbb\log\log_interface $log
	 * @param \phpbb\config\config $config

	 */
	public function __construct(
		\mrfg\cogauth\cognito\user $user,
		\mrfg\cogauth\cognito\auth_result $auth_result,
		\mrfg\cogauth\cognito\cognito $cognito,
		\phpbb\log\log_interface $log,
		\phpbb\config\config $config)
	{
		$this->auth_result = $auth_result;
		$this->cognito = $cognito;
		$this->user = $user;
		$this->log = $log;
		$this->config = $config;
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
		$sid = $this->user->get_phpbb_session_id();
		$result = $this->auth_result->get_access_token_from_sid($sid);
		if ($result !== false)
		{
			$token = $result['token'];
			switch ($result['mode']) {
				case 'access_token':
					return $token;
				break;
				case 'refresh':
					# Refresh the Access_Token and store the result if valid
					$response = $this->cognito->refresh_access_token($token, $result['user_id']);
					$var_res = $this->auth_result->validate_and_store_auth_response(
						$response['AuthenticationResult'], true);
					if ($var_res instanceof validation_result)
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

	public function login($jwt_tokens)
	{
		$result = $this->auth_result->validate_and_store_auth_response($jwt_tokens);

		if ($result instanceof validation_result)
		{
			if (!$result->is_new_user())
			{
				// Login
				return $this->user->login($result);
			}
			else
			{
				// New user registered via Cognito UI, create phpBB user and Normalize (cognito) User
				$id = $this->create_user();
				$result->phpbb_user_id = (int) $id;
				$this->cognito->normalize_user((int) $id);
				return $this->user->login($result);

			}
		}
		return false;
	}

	/**
	 *
	 * @return int
	 *
	 * @since 1.0
	 */
	public function create_user()
	{
		$attr = $this->auth_result->get_user_attributes();
		$id = $this->user->add_user($attr);
		return $id;
	}

	/**
	 * @param string $password
	 * @param array  $phpbb_auth_result
	 *
	 * @return array
	 *
	 * @throws \Exception
	 * @since 1.0
	 */
	public function login_phpbb($password, $phpbb_auth_result)
	{
		$user_row = $phpbb_auth_result['user_row'];
		if ($user_row['user_id'] == ANONYMOUS)
		{
			if ($user_row['status'] != LOGIN_ERROR_USERNAME)
			{
				return $phpbb_auth_result;
			}
			else
			{
				//todo if Cognito user exists create phpBB user, this may not me a requirement as this can only occur if
				// the user is created prior to the configuration of phpBB to use the Cognito User Pool.
				return $phpbb_auth_result;
			}
		}
		// cogauth_master_auth = 0 phpBB, 1 = Cognito
		$use_cognito_authentication = $this->config['cogauth_master_auth'];
		$authenticated_phpbb = ($user_row['status'] === LOGIN_SUCCESS);
		$authenticated_cognito = false;
		$user_confirmed = false;

		// Auth plugins get the password untrimmed.
		// For compatibility we trim() here.
		$password = trim($password);

		// Find the user in AWS Cognito, we only authenticate against cognito if user exists and confirmed
		// if the user does not exist, but has authenticated via phpBB rules the user is migrated.
		$cognito_user = $this->cognito->get_user($user_row['user_id']);

		$auth_status = array();
		if ($cognito_user['status'] == COG_USER_FOUND && $cognito_user['user_status'] == 'CONFIRMED')
		{
			$user_confirmed = true;
			$auth_status = $this->cognito->authenticate($user_row['user_id'], $password);
			if  ($auth_status['status'])
			{
				$authenticated_cognito = true;
				error_log('Aws Cognito authenticated');
			}
		}

		// At this point we have tested authentication with both phpBB and Cognito.

		// Test for overriding the master authentication directory for newly created users / migrating users
		if (!$cognito_user['phpbb_password_valid'] ){
			// Cognito created user, first login via phpBB (phpBB password is random)
			$use_cognito_authentication = true;
		} elseif ($cognito_user['status'] != COG_USER_FOUND)
		{
			// User has not been migrated yet
			$use_cognito_authentication = false;
			$auth_status['session_token'] = null;
		}

		if ($user_confirmed && $use_cognito_authentication && !$authenticated_cognito)
		{
			switch ($auth_status['status'])
			{
				case COG_LOGIN_DISABLED:
					//todo How do we resolve this should phpBB or Cognito win?
					return array(
						'status'    => LOGIN_ERROR_ACTIVE,
						'error_msg' => 'ACCOUNT_DEACTIVATED',
						'user_row'  => $user_row,
					);
				case COG_LOGIN_ERROR_ATTEMPTS:
					// todo There have been to many login attempts via Cognito, should we block phpBB login as well?
					return array(
						'status'    => LOGIN_ERROR_ATTEMPTS,
						'error_msg' => 'LOGIN_ERROR_ATTEMPTS',
						'user_row'  => $user_row,
					);
				break;

				default:
					// COG_LOGIN_SUCCESS - can't happen here
					// COG_CONFIGURATION_ERROR - Can happen trapped later
					// COG_LOGIN_NO_AUTH
					// COG_USER_NOT_FOUND - can't happen here
					// COG_LOGIN_ERROR_PASSWORD
					error_log('Unauthenticated, status: ' . $auth_status['status']);
			}
		}

		// if phpBB authenticated or Cognito authenticated,
		if (($authenticated_phpbb && !$use_cognito_authentication) ||
			($authenticated_cognito && $use_cognito_authentication))
		{
			// Authenticated either by phpBB or Cognito.
			// Reset login attempts for phpBB if Cognito authenticated, this is probable a new to phpBB user
			if (!$authenticated_phpbb &&
				$use_cognito_authentication &&
				$user_row['user_login_attempts'] != 0)
			{
				$this->user->reset_phpbb_login_attempts($user_row['user_id']);
			}


			// Migrate user to AWS Cognito as phpBB login success
			if ($cognito_user['status'] == COG_USER_NOT_FOUND)
			{
				// Migrate the user
				$this->cognito->migrate_user($user_row['username'], $password, $user_row['user_id'], $user_row['user_email']);
				$user_ip = (empty($this->user->get_ip())) ? '' : $this->user->get_ip();
				$this->log->add('user' ,$user_row['user_id'] , $user_ip, 'COGAUTH_MIGRATE_USER', time(), array($user_row['username']));
			}
			elseif ($authenticated_cognito == false && $cognito_user['status'] == COG_USER_FOUND &&	!$use_cognito_authentication &&
				($auth_status['status'] == COG_LOGIN_ERROR_PASSWORD ||  $cognito_user['user_status'] == 'FORCE_CHANGE_PASSWORD'))
			{
				// Cognito user exists, but failed to authenticate password (other failures dont get this far).
				// automatic password reset
				// todo: this should be configurable.
				// todo: log different error if FORCE_CHANGE_PASSWORD
				$this->cognito->admin_change_password($user_row['user_id'],$password);
				$user_ip = (empty($this->user->get_ip())) ? '' : $this->user->get_ip();
				$this->log->add('user' ,$user_row['user_id'] , $user_ip, 'COGAUTH_AUTO_PASSWD_RESET', time(),array($user_row['username']));
			}
			elseif (!$cognito_user['phpbb_password_valid'])
			{
				// Update the phpBB password on users first phpBB login
				$this->user->update_phpbb_password($user_row['user_id'],$password);
				$this->user->set_phpbb_password_status($user_row['user_id'],true);
			}

			// Successful login... set user_login_attempts to zero...
			return array(
				'status'    => LOGIN_SUCCESS,
				'error_msg' => false,
				'user_row'  => $user_row,
				'session_token' => $auth_status['session_token'],
			);
		}
		return $phpbb_auth_result;
	}

}
