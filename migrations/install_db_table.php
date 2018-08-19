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
	//public function effectively_installed()
	//{
	//	return isset($this->config['cogauth_pool_id']);
	//}

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
						'sid'		=> array('CHAR:32', ''),
						'access_token'	=> array('TEXT', ''),
						'expires_in' => array('INT:11', 0),
						'id_token' => array('TEXT',''),
						'refresh_token' => array('TEXT',''),
						'token_type'  => array('VCHAR:32',''),
					),
					'PRIMARY_KEY'	=> array('sid',),
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
/*
"AuthenticationResult": {
	"AccessToken": "string",
      "ExpiresIn": number,
      "IdToken": "string",
      "NewDeviceMetadata": {
		"DeviceGroupKey": "string",
         "DeviceKey": "string"
      },
      "RefreshToken": "string",
      "TokenType": "string"
*/