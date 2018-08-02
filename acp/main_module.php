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

	public function main($id, $mode)
	{
		global $config, $request, $template, $user;

		$user->add_lang_ext('mrfg/cogauth', 'common');
		$this->tpl_name = 'acp_demo_body';
		$this->page_title = $user->lang('ACP_COGAUTH_TITLE');
		add_form_key('cogauth/acp_form');

		if ($request->is_set_post('submit'))
		{
			if (!check_form_key('cogauth/acp_form'))
			{
				trigger_error('FORM_INVALID', E_USER_WARNING);
			}

			$config->set('cogauth_goodbye', $request->variable('cogauth_goodbye', 0));

			trigger_error($user->lang('ACP_COGAUTH_SETTING_SAVED') . adm_back_link($this->u_action));
		}

		$template->assign_vars(array(
			'U_ACTION'				=> $this->u_action,
			'COGAUTH_GOODBYE'		=> $config['cogauth_goodbye'],
		));
	}
}
