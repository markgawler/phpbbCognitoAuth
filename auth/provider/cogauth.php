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

	/** @var \phpbb\config\config $config Config object */
	protected $config;

	/** @var \phpbb\user */
	protected $user;

	/** @var  \mrfg\cogauth\cognito\user $cognito_user*/
	protected $cognito_user;

	/** @var \phpbb\language\language */
	protected $language;

	/** @var \phpbb\db\driver\driver_interface */
	protected $db;

	/** @var \mrfg\cogauth\cognito\cognito */
	protected $cognito;

	/** @var \phpbb\log\log_interface $log */
	protected $log;

	/** @var \phpbb\auth\auth |\PHPUnit_Framework_MockObject_MockObject  $auth */
	protected $auth;

	/**
	 * Database Authentication Constructor
	 *
	 * @param	\phpbb\db\driver\driver_interface                         $db
	 * @param	\phpbb\config\config                                      $config
	 * @param	\phpbb\passwords\manager                                  $passwords_manager
	 * @param	\phpbb\user                                               $user
	 * @param 	\mrfg\cogauth\cognito\user 								  $cognito_user
	 * @param	\phpbb\language\language                                  $language
	 * @param	\Symfony\Component\DependencyInjection\ContainerInterface $phpbb_container DI container
	 * @param 	\mrfg\cogauth\cognito\cognito                             $cognito
	 * @param   \phpbb\log\log_interface                                   $log	Logger instance
	 */
	public function __construct(
		\phpbb\db\driver\driver_interface $db,
		\phpbb\config\config $config,
		\phpbb\passwords\manager $passwords_manager,
		\phpbb\user $user,
		\mrfg\cogauth\cognito\user $cognito_user,
		\phpbb\language\language $language,
		\Symfony\Component\DependencyInjection\ContainerInterface $phpbb_container,
		\mrfg\cogauth\cognito\cognito $cognito,
		\phpbb\log\log_interface $log)
	{
		$this->db = $db;
		$this->config = $config;
		$this->passwords_manager = $passwords_manager;
		$this->user = $user;
		$this->cognito_user = $cognito_user;
		$this->language = $language;
		$this->phpbb_container = $phpbb_container;
		$this->cognito = $cognito;
		$this->log =$log;
	}

	/**
	 * {@inheritdoc}
	 */
	public function init()
	{
		// Check the configuration is valid
		$result = $this->cognito->describe_user_pool_client();
		if ( ! $result instanceof \Aws\Result )
		{
			/** @noinspection PhpUndefinedFieldInspection */
			trigger_error($result . adm_back_link($this->u_action), E_USER_WARNING);
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
		$cognito_user = $this->cognito->get_user($row['user_id']);

		if ($cognito_user['status'] == COG_USER_FOUND && $cognito_user['user_status'] == 'CONFIRMED')
		{
			$auth_status = $this->cognito->authenticate($row['user_id'], $password);
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


		if ($cognito_user['phpbb_password_valid'] && $this->passwords_manager->check($password, $row['user_password'], $row))
		{
			// Check for old password hash...
			if ($this->passwords_manager->convert_flag || strlen($row['user_password']) == 32)
			{
				$row['user_password'] = $this->update_phpbb_password($row['user_id'], $password);
			}
			$authenticated_phpbb = true;
		}

		// At this point we have tested authentication with both phpBB and Cognito.

		// cogauth_master_auth = 0 phpBB, 1 = Cognito
		$use_cognito_authentication = $this->config['cogauth_master_auth'];

		// Test for overriding the master authentication directory
		if (!$cognito_user['phpbb_password_valid'] ){
			// Cognito created user, first login via phpBB (phpBB password is random)
			$use_cognito_authentication = true;
		} elseif ($cognito_user['status'] != COG_USER_FOUND)
		{
			// User has not been migrated yet
			$use_cognito_authentication = false;
		}
		error_log('use_cognito_authentication: ' . $use_cognito_authentication);

		// if phpBB authenticated or Cognito authenticated a new (to phpBB) user,
		if (($authenticated_phpbb && !$use_cognito_authentication) ||
			($authenticated_cognito && $use_cognito_authentication))
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
				$this->cognito->migrate_user($row['username'], $password, $row['user_id'], $row['user_email']);
				$user_ip = (empty($this->user->ip)) ? '' : $this->user->ip;
				$this->log->add('user' ,$row['user_id'] , $user_ip, 'COGAUTH_MIGRATE_USER', time(), array($row['username']));
			}
			elseif ($authenticated_cognito == false && $cognito_user['status'] == COG_USER_FOUND && !$use_cognito_authentication &&
				($auth_status['status'] == COG_LOGIN_ERROR_PASSWORD ||  $cognito_user['user_status'] == 'FORCE_CHANGE_PASSWORD'))
			{
				// Cognito user exists, but failed to authenticate password (other failures dont get this far).
				// automatic password reset
				// todo: this should be configurable.
				// todo: log different error if FORCE_CHANGE_PASSWORD
				$this->cognito->admin_change_password($row['user_id'],$password);
				$user_ip = (empty($this->user->ip)) ? '' : $this->user->ip;
				$this->log->add('user' ,$row['user_id'] , $user_ip, 'COGAUTH_AUTO_PASSWD_RESET', time(),array($row['username']));
			}

			// Update the phpBB password on users first phpBB login
			if (!$cognito_user['phpbb_password_valid'])
			{
				$this->update_phpbb_password($row['user_id'],$password);
				$this->cognito_user->set_phpbb_password_status($row['user_id'],true);
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

	/**
	 * @param string $user_id
	 * @param  string $password
	 * @return string
	 */
	protected function update_phpbb_password($user_id, $password)
	{
		$hash = $this->passwords_manager->hash($password);

		// Update the password in the users table to the new format
		$sql = 'UPDATE ' . USERS_TABLE . "
					SET user_password = '" . $this->db->sql_escape($hash) . "'
					WHERE user_id = {$user_id}";
		$this->db->sql_query($sql);
		return $hash;
	}

	public function acp()
	{
		// These are fields required in the config table
		return array();
	}

	public function get_acp_template($new_config)
	{
		$pool_id = '';
		$pool_name = '';
		$client_id = '';
		$client_name = '';
		$user_pool = $this->cognito->describe_user_pool();
		if  ($user_pool instanceof \Aws\Result)
		{
			$pool_id = $user_pool['UserPool']['Id'];
			$pool_name = $user_pool['UserPool']['Name'];
		}

		$app_client = $this->cognito->describe_user_pool_client();
		if ($app_client instanceof \Aws\Result)
		{
			$client_name = $app_client['UserPoolClient']['ClientName'];
			$client_id = $app_client['UserPoolClient']['ClientId'];
		}
		return array(
			'TEMPLATE_FILE' => '@mrfg_cogauth/auth_provider_cogauth.html',
			'TEMPLATE_VARS' => array(
				'COGAUTH_POOL_NAME'   => $pool_name,
				'COGAUTH_POOL_ID'     => $pool_id,
				'COGAUTH_CLIENT_NAME' => $client_name,
				'COGAUTH_CLIENT_ID'   => $client_id,
			)
		);
	}

}
