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


class install_db_table extends \phpbb\db\migration\migration
{
	static public function depends_on()
	{
		return array('\mrfg\cogauth\migrations\install_acp_module');
	}

	public function update_schema()
	{
		return array(
			'add_tables'	=> array(
				$this->table_prefix . 'cogauth_session'	=> array(
					'COLUMNS'	=> array(
						'session_token' => array('CHAR:32', 0),
						'last_active' => array('INT:11', 0),
						'juser_id' => array('INT:11'),
						'user_id' => array('INT:11'),
						'sid'		=> array('CHAR:32', ''),
						'access_token'	=> array('TEXT', ''),
						'expires_at' => array('INT:11', 0),
						'id_token' => array('TEXT',''),
						'refresh_token' => array('TEXT',''),
						'token_type'  => array('VCHAR:32',''),
						'username_clean' => array('VCHAR:255',''),
					),
					'PRIMARY_KEY'	=> array('session_token',),
					'KEYS' => array(
						'i_d'            => array('INDEX', 'sid')),
				),
			),
		);
	}
	public function revert_schema()
	{
		return array(
			'drop_tables'	=> array(
				$this->table_prefix . 'cogauth_session',
			),
		);
	}
}