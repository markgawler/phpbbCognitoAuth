<?php
/**
 * * * *
 * AWS Cognito Authentication. An extension for the phpBB Forum Software package.
 *
 * @copyright (c) 2019, Mark Gawler
 * @license GNU General Public License, version 2 (GPL-2.0)
 *
 * @package     mrfg\cogauth\auth\provider
 */


namespace mrfg\cogauth\auth\provider;

use Aws\Result;
use mrfg\cogauth\cognito\cognito;
use mrfg\cogauth\cognito\controller;
use phpbb\auth\provider\db;
use phpbb\captcha\factory;
use phpbb\config\config;
use phpbb\db\driver\driver_interface;
use phpbb\passwords\manager;
use phpbb\request\request_interface;
use phpbb\user;

class cogauth extends db
{

	/** @var \mrfg\cogauth\cognito\cognito */
	protected $cognito;

	/** @var \mrfg\cogauth\cognito\controller */
	protected $controller;
	/**
	 * cogauth_provider constructor.
	 *
	 * @param	factory 			$captcha_factory
	 * @param	config				$config
	 * @param  	driver_interface	$db
	 * @param	manager				$passwords_manager
	 * @param	request_interface 	$request
	 * @param	user				$user
	 * @param	string				$phpbb_root_path
	 * @param	string				$php_ext
	 * @param  	cognito $cognito
	 * @param  	\mrfg\cogauth\cognito\controller $controller
	 */
	public function __construct(
		factory $captcha_factory,
		config $config,
		driver_interface $db,
		manager $passwords_manager,
		request_interface $request,
		user $user,
		$phpbb_root_path,
		$php_ext,
		cognito $cognito,
		controller $controller)
	{
		parent::__construct($captcha_factory, $config, $db, $passwords_manager, $request, $user, $phpbb_root_path, $php_ext);

		$this->cognito = $cognito;
		$this->controller = $controller;
	}

	/**
	 * {@inheritdoc}
	 */
	public function init()
	{
		// Check the configuration is valid
		$result = $this->cognito->describe_user_pool_client();
		if ( ! $result instanceof Result )
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
	 * @throws \Exception
	 */
	public function login($username, $password): array
	{
		$result = parent::login($username, $password);

		return $this->controller->login_phpbb($password, $result);
	}

	/**
	 * {@inheritdoc}
	 */
	public function acp(): ?array
	{
		// These are fields required in the config table
		return array();
	}

	/**
	 * @return array
	 * @param array $new_config
	 */
	public function get_acp_template($new_config): array
	{
		$pool_id = '';
		$pool_name = '';
		$client_id = '';
		$client_name = '';
		$user_pool = $this->cognito->describe_user_pool();
		if  ($user_pool instanceof Result)
		{
			$pool_id = $user_pool['UserPool']['Id'];
			$pool_name = $user_pool['UserPool']['Name'];
		}

		$app_client = $this->cognito->describe_user_pool_client();
		if ($app_client instanceof Result)
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
