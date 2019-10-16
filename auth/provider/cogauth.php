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

class cogauth extends \phpbb\auth\provider\db
{

	/** @var \mrfg\cogauth\cognito\cognito */
	protected $cognito;

	/** @var \mrfg\cogauth\cognito\controller */
	protected $controller;
	/**
	 * cogauth_provider constructor.
	 *
	 * @param	\phpbb\db\driver\driver_interface		$db
	 * @param	\phpbb\config\config 		$config
	 * @param	\phpbb\passwords\manager	$passwords_manager
	 * @param	\phpbb\request\request		$request
	 * @param	\phpbb\user			$user
	 * @param	\Symfony\Component\DependencyInjection\ContainerInterface $phpbb_container DI container
	 * @param	string				$phpbb_root_path
	 * @param	string				$php_ext
	 * @param  \mrfg\cogauth\cognito\cognito $cognito
	 * @param  \mrfg\cogauth\cognito\controller $controller
	 */
	public function __construct(
		\phpbb\db\driver\driver_interface $db,
		\phpbb\config\config $config,
		\phpbb\passwords\manager $passwords_manager,
		\phpbb\request\request $request,
		\phpbb\user $user,
		\Symfony\Component\DependencyInjection\ContainerInterface $phpbb_container,
		$phpbb_root_path,
		$php_ext,
		\mrfg\cogauth\cognito\cognito $cognito,
		\mrfg\cogauth\cognito\controller $controller)
	{
		parent::__construct($db, $config, $passwords_manager, $request, $user, $phpbb_container, $phpbb_root_path, $php_ext);

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
	 * @throws \Exception
	 * @since 1.0
	 */
	public function login($username, $password)
	{
		$result = parent::login($username, $password);

		return $this->controller->login_phpbb($password, $result);
	}

	/**
	 * {@inheritdoc}
	 */
	public function acp()
	{
		// These are fields required in the config table
		return array();
	}

	/**
	 * @return array
	 * @param array $new_config
	 * @since version
	 */
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
