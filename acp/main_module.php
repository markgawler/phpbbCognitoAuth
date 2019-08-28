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

				if ($submit) {
					if (!check_form_key('mrfg/cogauth')) {
						trigger_error('FORM_INVALID');
					} else {

						$config->set('cogauth_aws_region', $request->variable('cogauth_aws_region', ''));
						$config->set('cogauth_aws_key', $request->variable('cogauth_aws_key', ''));
						$config->set('cogauth_aws_secret', $request->variable('cogauth_aws_secret', ''));
						$config->set('cogauth_pool_id', $request->variable('cogauth_pool_id', ''));
						$config->set('cogauth_token_cleanup_gc', $request->variable('cogauth_token_cleanup_gc', ''));
						$config->set('max_autologin_time', $request->variable('cogauth_refresh_token_expiration_days', ''));
						trigger_error($language->lang('ACP_COGAUTH_CORE_SETTING_SAVED') . adm_back_link($this->u_action));
					}
				}

				$template->assign_vars(array_merge($commonVars, array(
					'COGAUTH_AWS_REGION' => $config['cogauth_aws_region'],
					'COGAUTH_AWS_KEY' => $config['cogauth_aws_key'],
					'COGAUTH_AWS_SECRET' => $config['cogauth_aws_secret'],
					'COGAUTH_POOL_ID' => $config['cogauth_pool_id'],
					'COGAUTH_TOKEN_CLEANUP' => $config['cogauth_token_cleanup_gc'],
					'COGAUTH_REFRESH_TOKEN_EXP_DAYS' => $config['max_autologin_time'],

				)));
			break;
		}
	}
}
