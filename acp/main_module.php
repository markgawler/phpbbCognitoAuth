<?php
/**
 *
 * AWS Cognito Authentication. An extension for the phpBB Forum Software package.
 *
 * @copyright (c) 2018, Mark Gawler
 * @license GNU General Public License, version 2 (GPL-2.0)
 *
 */

namespace mrfg\cogauth\acp;

/**
 * AWS Cognito Authentication ACP module.
 */
class main_module
{
	public $page_title;
	public $tpl_name;
	public $u_action;

	public function main(/** @noinspection PhpUnusedParameterInspection */ $id, $mode)
	{
		/** @var \phpbb\language\language $language Language object */
		/** @var \phpbb\request\request $request Request object */
		/** @var \phpbb\config\config $config Config object */

		global $config, $request, $template, $language;

		$this->tpl_name = 'acp_cogauth_body';
		$this->page_title = $language->lang('ACP_COGAUTH_TITLE');
		add_form_key('cogauth/acp_form');

		if ($request->is_set_post('submit'))
		{
			if (!check_form_key('cogauth/acp_form'))
			{
				trigger_error('FORM_INVALID', E_USER_WARNING);
			}

			$config->set('cogauth_cogauth_enabled', $request->variable('cogauth_cogauth_enabled', 0));

			trigger_error($language->lang('ACP_COGAUTH_SETTING_SAVED') . adm_back_link($this->u_action));
		}

		$template->assign_vars(array(
			'U_ACTION'				=> $this->u_action,
			'COGAUTH_ENABLED'		=> $config['cogauth_cogauth_enabled'],
		));
	}
}
