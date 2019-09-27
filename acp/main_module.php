<?php
/**
 *
 * @package phpBB Extension - Cogauth phpBB Extension
 * @copyright (c) 2013 phpBB Group
 * @license http://opensource.org/licenses/gpl-2.0.php GNU General Public License v2
 *
 */

namespace mrfg\cogauth\acp;

class main_module
{
	/** @var string $page_title The page title */
	public $page_title;

	/** @var string $u_action Custom form action */
	public $u_action;

	/** @var string $tpl_name The page template name */
	public $tpl_name;

	/** @var \phpbb\language\language $language Language object */
	public $language;

	/**
	 * @param $id
	 * @param $mode
	 * @throws \Exception
	 */
	function main(/** @noinspection PhpUnusedParameterInspection */ $id  , $mode)
	{
		/**@var	\Symfony\Component\DependencyInjection\ContainerInterface $phpbb_container */
		global $phpbb_container;

		/** @var \phpbb\config\config $config Config object */
		$config = $phpbb_container->get('config');

		/** @var \phpbb\request\request $request Request object */
		$request  = $phpbb_container->get('request');

		/** @var \phpbb\template\template $template Template object */
		$template = $phpbb_container->get('template');

		/** @var \phpbb\language\language $language Language object */
		$language = $phpbb_container->get('language');
		$this->language = $language;

		/** @var \mrfg\cogauth\cognito\cognito $cognito */
		$cognito = $phpbb_container->get('mrfg.cogauth.cognito');

		$this->tpl_name = 'cogauth_body';
		$this->page_title = $language->lang('ACP_COGAUTH_TITLE');

		$submit = $request->is_set_post('submit');
		$submit_create_user_pool = $request->is_set_post('create_user_pool');
		$submit_use_user_pool = $request->is_set_post('use_user_pool');
		$submit_use_app_client = $request->is_set_post('use_app_client');
		$submit_clean_access_tokens = $request->is_set_post('clean_access_tokens');
		add_form_key('mrfg/cogauth');

		$commonVars = array(
			'COGAUTH_ACP_MODE'	=> $mode,
			'U_ACTION'			=> $this->u_action,
		);
		if ($submit && !check_form_key('mrfg/cogauth')) {
				trigger_error('FORM_INVALID');
			}
		switch ($mode)
		{
			case 'aws_access':
				if ($submit)
				{
					$region = $request->variable('cogauth_aws_region', '');
					$cognito->update_credentials(
						$request->variable('cogauth_aws_region', ''),
						$request->variable('cogauth_aws_key', ''),
						$request->variable('cogauth_aws_secret', '')
					);
					if (strlen($region) <1 )
					{
						trigger_error($this->language->lang('COGAUTH_ACP_CHECK_REGION') . ': ' .
							adm_back_link($this->u_action), E_USER_WARNING);
					} else {
						$result = $cognito->list_user_pools();
						$this->submit_result_handler($result);
					}
				}

				$template->assign_vars(array_merge($commonVars, array(
					'COGAUTH_AWS_REGION' => $config['cogauth_aws_region'],
					'COGAUTH_AWS_KEY' => $config['cogauth_aws_key'],
					'COGAUTH_AWS_SECRET' => $config['cogauth_aws_secret'],
				)));
			break;
			case 'user_pool':
				$pool_name = '';
				$new_name = '';
				$client_name = '';
				$pool_id = '';
				$client_id = '';

				if ($submit_use_user_pool)
				{
					$cognito->update_user_pool_id($request->variable('cogauth_pool_id', ''));
					$result = $cognito->describe_user_pool();
					if ($result instanceof \Aws\Result)
					{
						//todo: Changes via AWS console should get reflected here on change (may be a Lambda trigger?)
						if ($result['UserPool']['CustomDomain'])
						{
							$config->set('cogauth_hosted_ui_domain',$result['UserPool']['CustomDomain']);
						}
						else
						{
							$config->set('cogauth_hosted_ui_domain',$result['UserPool']['Domain'] . '.auth.'
								. $config['cogauth_aws_region'] . '.amazoncognito.com');
						}

						// Add the phpbb_user_id cutom attribute is it dose not exist.
						$attributes = $result['UserPool']['SchemaAttributes'];
						$add_attr = true;
						foreach ($attributes as $a)
						{
							if ($a['Name'] == 'custom:phpbb_user_id')
							{
								$add_attr = false;
							}
						}
						if ($add_attr)
						{
							$result = $cognito->add_custom_attribute(); // Add Custom Attribute phpbb_user_id
						}
					}
					$this->submit_result_handler($result);
				}
				elseif ($submit_create_user_pool)
				{
					$new_name = $request->variable('cogauth_new_pool_name', '');
					$result = $cognito->create_user_pool($new_name);
					if ($result instanceof \Aws\Result)
					{
						//store the new user_pool id
						$cognito->update_user_pool_id($result['UserPool']['Id']);
					}
					$this->submit_result_handler($result);
				}
				elseif ($submit_use_app_client)
				{
					$config->set('cogauth_hosted_ui', $request->variable('cogauth_hosted_ui', 0));
					$max_login = $request->variable('cogauth_refresh_token_expiration_days', 30);
					$client_id = $request->variable('cogauth_app_client_id', '');
					$result = $cognito->update_user_pool_client($max_login, $client_id);
					if  ($result instanceof \Aws\Result)
					{
						//todo:  collect other data password policies etc.
						$pool_name = $result['UserPool']['Name'];
					}
					$this->submit_result_handler($result);
				}

				$user_pool = $cognito->describe_user_pool();
				if  ($user_pool instanceof \Aws\Result)
				{
					$pool_id = $user_pool['UserPool']['Id'];
					$pool_name = $user_pool['UserPool']['Name'];
				}

				$validity = $config['max_autologin_time'];

				$app_client = $cognito->describe_user_pool_client();
				if ($app_client instanceof \Aws\Result)
				{
					//todo:  collect other data password policies etc.
					$client = $app_client['UserPoolClient'];
					$client_name = $client['ClientName'];
					$validity = $client['RefreshTokenValidity'];
					$client_id = $client['ClientId'];
				}

				$template->assign_vars(array_merge($commonVars, array(
					'COGAUTH_POOL_ID' => $pool_id,
					'COGAUTH_POOL_NAME' => $pool_name,
					'COGAUTH_NEW_POOL_NAME' => $new_name,
					'COGAUTH_APP_CLIENT_ID' => $client_id,
					'COGAUTH_CLIENT_NAME' => $client_name,
					'COGAUTH_REFRESH_TOKEN_EXP_DAYS' => $validity,
					'COGAUTH_HOSTED_UI' => $config['cogauth_hosted_ui'],
					'COGAUTH_HOSTED_UI_DOMAIN' => $config['cogauth_hosted_ui_domain'],
				)));
			break;
			case 'misc':
				if ($submit)
				{
					$config->set('cogauth_token_cleanup_gc', $request->variable('cogauth_token_cleanup_gc', ''));
					trigger_error($this->language->lang('ACP_COGAUTH_CORE_SETTING_SAVED') . adm_back_link($this->u_action));
				}
				$template->assign_vars(array_merge($commonVars, array(
					'COGAUTH_TOKEN_CLEANUP' => $config['cogauth_token_cleanup_gc'],
				)));

				if ($submit_clean_access_tokens)
				{
					$auth_result = $phpbb_container->get('mrfg.cogauth.auth_result');
					$auth_result->cleanup_session_tokens($config['max_autologin_time']);
				}

			break;
		}
	}


	protected function submit_result_handler($result)
	{
		if ($result instanceof \Aws\Result)
		{
			trigger_error($this->language->lang('ACP_COGAUTH_CORE_SETTING_SAVED') . adm_back_link($this->u_action));
		} elseif (gettype($result) == 'string')
		{
			trigger_error($this->language->lang('ACP_COGAUTH_AWS_ERROR') . ': ' . $result .
				adm_back_link($this->u_action), E_USER_WARNING);
		} else {
			// This shouldn't happen
			trigger_error("Unhandled Error" .
				adm_back_link($this->u_action),E_USER_WARNING);
		}
	}
}
