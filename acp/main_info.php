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
 * AWS Cognito Authentication ACP module info.
 */
class main_info
{
	public function module()
	{
		return array(
			'filename'	=> '\mrfg\cogauth\acp\main_module',
			'title'		=> 'ACP_COGAUTH_TITLE',
			'modes'		=> array(
				'settings'	=> array(
					'title'	=> 'ACP_COGAUTH',
					'auth'	=> 'ext_mrfg/cogauth && acl_a_board',
					'cat'	=> array('ACP_COGAUTH_TITLE')
				),
			),
		);
	}
}
