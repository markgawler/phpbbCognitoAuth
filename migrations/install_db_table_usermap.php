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

/** @noinspection PhpUnused */

class install_db_table_usermap extends \phpbb\db\migration\migration
{
	static public function depends_on()
	{
		return array('\mrfg\cogauth\migrations\install_db_table_authentication_class');
	}

	public function update_schema()
	{
		return array(
			'add_tables'	=> array(
				$this->table_prefix . 'cogauth_usermap' => array(
					'COLUMNS' => array(
						'phpbb_user_id' => array('INT:11',0),
						'cognito_username' => array('VCHAR:255', ''),
						'password_sync' => array('TINT:1',0),
					),
					'PRIMARY_KEY'	=> array('phpbb_user_id',),
					//'KEYS' => array(
					//	'user_nm'  => array('UNIQUE', 'cognito_username'),
					//)
				)
			),
		);
	}
	public function revert_schema()
	{
		return array(
			'drop_tables'	=> array(
				$this->table_prefix . 'cogauth_usermap',
			),
		);
	}
}
