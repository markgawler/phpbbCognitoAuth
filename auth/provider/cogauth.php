<?php
/**
 * Created by PhpStorm.
 * User: mrfg
 * Date: 03/08/18
 * Time: 18:26
 */

namespace mrfg\cogauth\auth\provider;

class cogauth extends \phpbb\auth\provider\base
{
	/**
	 * phpBB passwords manager
	 *
	 * @var \phpbb\passwords\manager
	 */
	protected $passwords_manager;

	/**
	 * DI container
	 *
	 * @var \Symfony\Component\DependencyInjection\ContainerInterface
	 */
	protected $phpbb_container;

	/**
	 * @var \phpbb\config\config $config Config object
	 */
	protected $config;

	/**
	 * @var \phpbb\user
	 */
	protected $user;

	/**
	 * @var \phpbb\language\language
	 */
	protected $language;

	/**
	 * @var \phpbb\db\driver\driver_interface
	 */
	protected $db;

	/**
	 * @var \mrfg\cogauth\cognito\cognito
	 */
	protected $cognito_client;

	/**  @var \mrfg\cogauth\cognito\web_token_phpbb $web_token */
	protected $web_token;

	/** @var \phpbb\log\log_interface	$log */
	protected $log;

	/**
	 * Database Authentication Constructor
	 *
	 * @param	\phpbb\db\driver\driver_interface                         $db
	 * @param	\phpbb\config\config                                      $config
	 * @param	\phpbb\passwords\manager                                  $passwords_manager
	 * @param	\phpbb\user                                               $user
	 * @param	\phpbb\language\language                                  $language
	 * @param	\Symfony\Component\DependencyInjection\ContainerInterface $phpbb_container DI container
	 * @param 	\mrfg\cogauth\cognito\cognito                             $cognito_client
	 * @param 	\mrfg\cogauth\cognito\web_token_phpbb                     $web_token
	 * @param   \phpbb\log\log_interface                                   $log	Logger instance
	 */
	public function __construct(
		\phpbb\db\driver\driver_interface $db,
		\phpbb\config\config $config,
		\phpbb\passwords\manager $passwords_manager,
		\phpbb\user $user,
		\phpbb\language\language $language,
		\Symfony\Component\DependencyInjection\ContainerInterface $phpbb_container,
		\mrfg\cogauth\cognito\cognito $cognito_client,
		\mrfg\cogauth\cognito\web_token_phpbb $web_token,
		\phpbb\log\log_interface $log)
	{
		$this->db = $db;
		$this->config = $config;
		$this->passwords_manager = $passwords_manager;
		$this->user = $user;
		$this->language = $language;
		$this->phpbb_container = $phpbb_container;
		$this->cognito_client = $cognito_client;
		$this->web_token = $web_token;
		$this->log =$log;
	}

	/**
	 * {@inheritdoc}
	 */
	public function init()
	{
		// region and pool may have changed so force refresh of the keys
		$keys = $this->web_token->download_jwt_web_keys(true);
		if ($keys === false)
		{
			/** @noinspection PhpUndefinedFieldInspection */
			$message = $this->language->lang('COGAUTH_AWS_KEY_SET_ERROR') . adm_back_link($this->u_action);
			trigger_error($message,E_USER_WARNING);
		}
	}

	/**
	 * @param $username
	 * @param $password
	 *
	 * @return array
	 *
	 * @since version
	 * @throws \Exception
	 */
	public function login($username, $password)
	{
		error_log('CogAuth Provider');
		$authenticated_phpbb = false;
		$authenticated_cognito = false;
		// Auth plugins get the password untrimmed.
		// For compatibility we trim() here.
		$password = trim($password);

		// do not allow empty password
		if (!$password)
		{
			return array(
				'status'    => LOGIN_ERROR_PASSWORD,
				'error_msg' => 'NO_PASSWORD_SUPPLIED',
				'user_row'  => array('user_id' => ANONYMOUS),
			);
		}

		if (!$username)
		{
			return array(
				'status'    => LOGIN_ERROR_USERNAME,
				'error_msg' => 'LOGIN_ERROR_USERNAME',
				'user_row'  => array('user_id' => ANONYMOUS),
			);
		}

		$username_clean = utf8_clean_string($username);
		$sql = 'SELECT *
			FROM ' . USERS_TABLE . "
			WHERE username_clean = '" . $this->db->sql_escape($username_clean) . "'";
		$result = $this->db->sql_query($sql);
		$row = $this->db->sql_fetchrow($result);
		$this->db->sql_freeresult($result);

		if (($this->user->ip && !$this->config['ip_login_limit_use_forwarded']) ||
			($this->user->forwarded_for && $this->config['ip_login_limit_use_forwarded']))
		{
			$sql = 'SELECT COUNT(*) AS attempts
				FROM ' . LOGIN_ATTEMPT_TABLE . '
				WHERE attempt_time > ' . (time() - (int) $this->config['ip_login_limit_time']);
			if ($this->config['ip_login_limit_use_forwarded'])
			{
				$sql .= " AND attempt_forwarded_for = '" . $this->db->sql_escape($this->user->forwarded_for) . "'";
			}
			else
			{
				$sql .= " AND attempt_ip = '" . $this->db->sql_escape($this->user->ip) . "' ";
			}

			$result = $this->db->sql_query($sql);
			$attempts = (int) $this->db->sql_fetchfield('attempts');
			$this->db->sql_freeresult($result);

			$attempt_data = array(
				'attempt_ip'            => $this->user->ip,
				'attempt_browser'       => trim(substr($this->user->browser, 0, 149)),
				'attempt_forwarded_for' => $this->user->forwarded_for,
				'attempt_time'          => time(),
				'user_id'               => ($row) ? (int) $row['user_id'] : 0,
				'username'              => $username,
				'username_clean'        => $username_clean,
			);
			$sql = 'INSERT INTO ' . LOGIN_ATTEMPT_TABLE . $this->db->sql_build_array('INSERT', $attempt_data);
			$this->db->sql_query($sql);
		}
		else
		{
			$attempts = 0;
		}

		if (!$row)
		{
			if ($this->config['ip_login_limit_max'] && $attempts >= $this->config['ip_login_limit_max'])
			{
				return array(
					'status'    => LOGIN_ERROR_ATTEMPTS,
					'error_msg' => 'LOGIN_ERROR_ATTEMPTS',
					'user_row'  => array('user_id' => ANONYMOUS),
				);
			}

			return array(
				'status'    => LOGIN_ERROR_USERNAME,
				'error_msg' => 'LOGIN_ERROR_USERNAME',
				'user_row'  => array('user_id' => ANONYMOUS),
			);
		}

		$show_captcha = ($this->config['max_login_attempts'] && $row['user_login_attempts'] >= $this->config['max_login_attempts']) ||
			($this->config['ip_login_limit_max'] && $attempts >= $this->config['ip_login_limit_max']);

		// If there are too many login attempts, we need to check for a confirm image
		// Every auth module is able to define what to do by itself...
		if ($show_captcha)
		{
			/* @var $captcha_factory \phpbb\captcha\factory */
			$captcha_factory = $this->phpbb_container->get('captcha.factory');
			$captcha = $captcha_factory->get_instance($this->config['captcha_plugin']);
			$captcha->init(CONFIRM_LOGIN);
			$vc_response = $captcha->validate($row);
			if ($vc_response)
			{
				return array(
					'status'    => LOGIN_ERROR_ATTEMPTS,
					'error_msg' => 'LOGIN_ERROR_ATTEMPTS',
					'user_row'  => $row,
				);
			}
			else
			{
				$captcha->reset();
			}

		}

		// Find the user in AWS Cognito, we only authenticate against cognito if user exists and confirmed
		// otherwise we attempt to migrate the user if the user authenticated via phpBB rules.
		$cognito_user = $this->cognito_client->get_user($row['user_id']);

		if ($cognito_user['status'] == COG_USER_FOUND &&  $cognito_user['user_status'] == 'CONFIRMED')
		{
			$auth_status = $this->cognito_client->authenticate($row['user_id'], $password);
			switch ($auth_status['status'])
			{
				case COG_LOGIN_SUCCESS:
					$authenticated_cognito = true;
					error_log('Aws Cognito authenticated');
				break;

				case COG_LOGIN_DISABLED:
					return array(
						'status'    => LOGIN_ERROR_ACTIVE,
						'error_msg' => 'ACCOUNT_DEACTIVATED',
						'user_row'  => $row,
					);
				case COG_LOGIN_ERROR_ATTEMPTS:
					return array(
						'status'    => LOGIN_ERROR_ATTEMPTS,
						'error_msg' => 'LOGIN_ERROR_ATTEMPTS',
						'user_row'  => $row,
					);
				break;

				default:
					// COG_CONFIGURATION_ERROR - Can happen trapped later
					// COG_LOGIN_NO_AUTH
					// COG_USER_NOT_FOUND - can't happen here
					// COG_LOGIN_ERROR_PASSWORD
					error_log('Unauthenticated, status: ' . $auth_status['status']);
			}

		}
		else
		{
			$auth_status['session_token'] = null;
		}
		// Check password phpBB rules...
		//else
		//$authenticated = false;
		if ($this->passwords_manager->check($password, $row['user_password'], $row))
		{
			// Check for old password hash...
			if ($this->passwords_manager->convert_flag || strlen($row['user_password']) == 32)
			{
				$hash = $this->passwords_manager->hash($password);

				// Update the password in the users table to the new format
				$sql = 'UPDATE ' . USERS_TABLE . "
					SET user_password = '" . $this->db->sql_escape($hash) . "'
					WHERE user_id = {$row['user_id']}";
				$this->db->sql_query($sql);

				$row['user_password'] = $hash;
			}
			$authenticated_phpbb = true;
		}
		if ($authenticated_phpbb)
		{
			// Authenticated either by phpBB or Cognito.
			$sql = 'DELETE FROM ' . LOGIN_ATTEMPT_TABLE . '
				WHERE user_id = ' . $row['user_id'];
			$this->db->sql_query($sql);

			if ($row['user_login_attempts'] != 0)
			{
				// Successful, reset login attempts (the user passed all stages)
				$sql = 'UPDATE ' . USERS_TABLE . '
					SET user_login_attempts = 0
					WHERE user_id = ' . $row['user_id'];
				$this->db->sql_query($sql);
			}

			// User inactive...
			if ($row['user_type'] == USER_INACTIVE || $row['user_type'] == USER_IGNORE || $cognito_user['user_status'] == 'UNCONFIRMED' )
			{
				return array(
					'status'    => LOGIN_ERROR_ACTIVE,
					'error_msg' => 'ACTIVE_ERROR',
					'user_row'  => $row,
				);
			}

			// Migrate user to AWS Cognito as phpBB login success
			if ($cognito_user['status'] == COG_USER_NOT_FOUND)
			{
				// Migrate the user
				$this->cognito_client->migrate_user($row['username'], $password, $row['user_id'], $row['user_email']);
				$user_ip = (empty($this->user->ip)) ? '' : $this->user->ip;
				$this->log->add('user' ,$row['user_id'] , $user_ip, 'COGAUTH_MIGRATE_USER', time(), array($row['username']));
			}
			elseif ($authenticated_cognito == false && $cognito_user['status'] == COG_USER_FOUND &&
				($auth_status['status'] == COG_LOGIN_ERROR_PASSWORD ||  $cognito_user['user_status'] == 'FORCE_CHANGE_PASSWORD'))
			{

				// Cognito user exists, but failed to authenticate password (other failures dont get this far).
				// automatic password reset
				// todo: this should be configurable.
				// todo: log different error if FORCE_CHANGE_PASSWORD
				$this->cognito_client->admin_change_password($row['user_id'],$password);
				$user_ip = (empty($this->user->ip)) ? '' : $this->user->ip;
				$this->log->add('user' ,$row['user_id'] , $user_ip, 'COGAUTH_AUTO_PASSWD_RESET', time(),array($row['username']));
			}

			// Successful login... set user_login_attempts to zero...
			return array(
				'status'    => LOGIN_SUCCESS,
				'error_msg' => false,
				'user_row'  => $row,
				'session_token' => $auth_status['session_token'],
			);
		}

		// Password incorrect - increase login attempts
		$sql = 'UPDATE ' . USERS_TABLE . '
			SET user_login_attempts = user_login_attempts + 1
			WHERE user_id = ' . (int) $row['user_id'] . '
				AND user_login_attempts < ' . LOGIN_ATTEMPTS_MAX;
		$this->db->sql_query($sql);

		// Give status about wrong password...
		return array(
			'status'    => ($show_captcha) ? LOGIN_ERROR_ATTEMPTS : LOGIN_ERROR_PASSWORD,
			'error_msg' => 'LOGIN_ERROR_PASSWORD',
			'user_row'  => $row,
		);
	}


	public function acp()
	{
		// These are fields required in the config table
		return array(
			'cogauth_client_id',
			'cogauth_client_secret'
		);
	}

	public function get_acp_template($new_config)
	{
		return array(
			'TEMPLATE_FILE' => '@mrfg_cogauth/auth_provider_cogauth.html',
			'TEMPLATE_VARS' => array(
				'COGAUTH_CLIENT_ID' => $new_config['cogauth_client_id'],
				'COGAUTH_CLIENT_SECRET' => $new_config['cogauth_client_secret'],
			)
		);
	}

}
