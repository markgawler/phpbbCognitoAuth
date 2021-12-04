<?php
/**
 *
 * AWS Cognito Authentication. An extension for the phpBB Forum Software package.
 *
 * @copyright (c) 2018, Mark Gawler
 * @license GNU General Public License, version 2 (GPL-2.0)
 *
 */

namespace mrfg\cogauth\migrations;

use phpbb\db\migration\migration;

/** @noinspection PhpUnused */

class install_db_table_authentication_class extends migration
{
	static public function depends_on(): array
	{
		return array('\mrfg\cogauth\migrations\install_acp_module');
	}

	public function update_schema(): array
	{
		return array(
			'add_tables'	=> array(
				$this->table_prefix . 'cogauth_authentication'	=> array(
					'COLUMNS'	=> array(
						'session_token' => array('CHAR:32', 0),
						'expires' => array('INT:11', 0),
						'uuid' => array('CHAR:36', ''),
						'username' => array('VCHAR:255', ''),
						'preferred_username' => array('VCHAR:255', ''),
						'nickname' => array('VCHAR:255', ''),
						'email' => array('VCHAR:100', ''),
						'phpbb_user_id' => array('INT:11',0),
						'sid'		=> array('CHAR:32', ''),
						'access_token'	=> array('TEXT', ''),
						'refresh_token' => array('TEXT',''),
						'autologin' => array('TINT:1',0),
						'last_active' => array('INT:11', 0),
						'first_active' => array('INT:11', 0),
					),
					'PRIMARY_KEY'	=> array('session_token',),
					'KEYS' => array(
						'i_d'            => array('INDEX', 'sid')),
				)
			),
		);
	}
	public function revert_schema(): array
	{
		return array(
			'drop_tables'	=> array(
				$this->table_prefix . 'cogauth_authentication',
			),
		);
	}
}
