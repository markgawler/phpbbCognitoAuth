<?php
/**
 *
 * @package phpBB Extension - Cogauth phpBB Extension
 * @copyright (c) 2018 Mark Gawler
 * @license GNU General Public License v2
 *
 */

namespace mrfg\cogauth\acp;

class main_info
{
	function module()
	{
		return array(
			'filename'	=> '\mrfg\cogauth\acp\main_module',
			'title'		=> 'ACP_COGAUTH_TITLE',
			'version'	=> '1.0.5',
			'modes'		=> array(
				'aws_access'	=> array(
					'title' => 'ACP_COGAUTH_TITLE_CFG',
					'auth' => 'ext_mrfg/cogauth && acl_a_board',
					'cat' => array('ACP_COGAUTH_TITLE')
				),
				'user_pool'	=> array(
					'title' => 'ACP_COGAUTH_TITLE_POOL',
					'auth' => 'ext_mrfg/cogauth && acl_a_board',
					'cat' => array('ACP_COGAUTH_POOL_TITLE')
				),
				'misc'	=> array(
					'title' => 'ACP_COGAUTH_TITLE_MISC',
					'auth' => 'ext_mrfg/cogauth && acl_a_board',
					'cat' => array('ACP_COGAUTH_MISC_TITLE')
				),
			),
		);
	}
}
