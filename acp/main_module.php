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


		add_form_key('mrfg/cogauth');

		$commonVars = array(
			'COGAUTH_ACP_MODE'	=> $mode,
			'U_ACTION'			=> $this->u_action,
		);
		switch ($mode)
		{
			case 'settings':
				$pool_name = '';
				if ($submit)
				{
					if (!check_form_key('mrfg/cogauth'))
					{
						trigger_error('FORM_INVALID');
					}
					else
					{
						$cognito->update_user_pool_id($request->variable('cogauth_pool_id', ''));
						$cognito->update_credentials(
							$request->variable('cogauth_aws_region', ''),
							$request->variable('cogauth_aws_key', ''),
							$request->variable('cogauth_aws_secret', '')
						);
						$result = $cognito->describe_user_pool();
						$this->submit_result_handler($result);
					}
				}
				else
				{
					$result = $cognito->describe_user_pool();
				}

				if  ($result instanceof \Aws\Result)
				{
					//todo:  collect other data password policies etc.
					$pool_name = $result['UserPool']['Name'];
				}
				$template->assign_vars(array_merge($commonVars, array(
					'COGAUTH_AWS_REGION' => $config['cogauth_aws_region'],
					'COGAUTH_AWS_KEY' => $config['cogauth_aws_key'],
					'COGAUTH_AWS_SECRET' => $config['cogauth_aws_secret'],
					'COGAUTH_POOL_ID' => $config['cogauth_pool_id'],
					'COGAUTH_POOL_NAME' => $pool_name,
					'COGAUTH_REFRESH_TOKEN_EXP_DAYS' => $config['max_autologin_time'],
				)));
			break;
			case 'app_client':
				if ($submit)
				{
					if (!check_form_key('mrfg/cogauth')) {
						trigger_error('FORM_INVALID');
					} else {
						$config->set('cogauth_token_cleanup_gc', $request->variable('cogauth_token_cleanup_gc', ''));
						$cognito->update_client_id($request->variable('cogauth_client_id', ''));

						$max_login = $request->variable('cogauth_refresh_token_expiration_days', 30);
						$result = $cognito->set_refresh_token_expiration($max_login);

						$this->submit_result_handler($result);
					}
				}
				$name = '';
				$validity = $config['max_autologin_time'];
				$result = $cognito->describe_user_pool_client();
				if ($result instanceof \Aws\Result)
				{
					$client = $result['UserPoolClient'];
					$name = $client['ClientName'];
					$validity = $client['RefreshTokenValidity'];
				}
				$template->assign_vars(array_merge($commonVars, array(
					'COGAUTH_REFRESH_TOKEN_EXP_DAYS' => $validity,
					'COGAUTH_TOKEN_CLEANUP' => $config['cogauth_token_cleanup_gc'],
					'COGAUTH_CLIENT_ID' => $config['cogauth_client_id'],
					'COGAUTH_CLIENT_NAME' => $name
				)));

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
			trigger_error("Unhandled Error" .
				adm_back_link($this->u_action),E_USER_WARNING);
		}
	}
}
