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


class update_db_table extends \phpbb\db\migration\migration
{

	static public function depends_on()
	{
		return array('\mrfg\cogauth\migrations\install_db_table');
	}

	public function update_schema()
	{
		return array(
			'drop_columns'  => array(
				$this->table_prefix . 'cogauth_session'  => array('expires_in'),
			),
			'add_columns'   => array(
				$this->table_prefix . 'cogauth_session' => array('expires_at' => array('INT:11', 0)),
			),
		);
	}

	public function revert_schema()
	{
		return array();

	}

}