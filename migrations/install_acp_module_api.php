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

class install_acp_module_api extends \phpbb\db\migration\migration
{
	public function effectively_installed()
	{
		return isset($this->config['cogauth_secret_key']);
	}

	static public function depends_on()
	{
		return array('\mrfg\cogauth\migrations\install_db_table');

	}

	public function update_data()
	{
		return array(

			array('config.add', array('cogauth_secret_key', '')),

			array('module.add', array(
				'acp',
				'ACP_CAT_DOT_MODS',
				'ACP_COGAUTH_TITLE'
			)),

			array('module.add', array(
				'acp',
				'ACP_COGAUTH_TITLE',
				array(
					'module_basename'	=> '\mrfg\cogauth\acp\main_module',
					'modes'				=> array('settings'),
				),
			)),
		);
	}


}