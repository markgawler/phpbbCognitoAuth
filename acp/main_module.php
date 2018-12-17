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
	//  var $u_action;

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
		global $phpbb_container;

		/** @var \phpbb\config\config $config Config object */
		$config = $phpbb_container->get('config');

		/** @var \phpbb\db\driver\driver_interface $db Database object */
		//$db = $phpbb_container->get('db');

		/** @var \phpbb\request\request $request Request object */
		$request  = $phpbb_container->get('request');

		/** @var \phpbb\template\template $template Template object */
		$template = $phpbb_container->get('template');

		/** @var \phpbb\language\language $language Language object */
		$language = $phpbb_container->get('language');

		global $user;
		global $phpbb_root_path, $phpbb_admin_path, $phpEx;
		//global $db, $table_prefix;

		$this->tpl_name = 'main_body';

		$this->page_title = $language->lang('ACP_COGAUTH_TITLE');

		$submit = $request->is_set_post('submit');


		add_form_key('mrfg/cogauth');

		$commonVars = array(
			'COGAUTH_ACP_MODE'	=> $mode,
			'U_ACTION'			=> $this->u_action,
		);
error_log("Mode: ". $mode);
		switch ($mode)
		{
			case 'settings':

				if ($submit) {
					if (!check_form_key('mrfg/cogauth')) {
						trigger_error('FORM_INVALID');
					} else {

						$config->set('mrfg_cogauth_secret_key', $request->variable('cogauth_secret_key', ''));

						trigger_error($language->lang('ACP_COGAUTH_CORE_SETTING_SAVED') . adm_back_link($this->u_action));
					}
				}

				$template->assign_vars(array_merge($commonVars, array(
					'COGAUTH_SECRET_KEY' 	=> $config['cogauth_secret_key'],

				)));
			break;
			//end case
		}
	}
}
