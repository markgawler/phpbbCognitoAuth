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

class install_acp_module extends \phpbb\db\migration\migration
{
	public function effectively_installed()
	{
		return isset($this->config['cogauth_pool_id']);
	}

	static public function depends_on()
	{
		return array('\phpbb\db\migration\data\v31x\v314');
	}

	public function update_data()
	{
		return array(
			array('config.add', array('cogauth_pool_id', '')),
			array('config.add', array('cogauth_client_id', '')),
			array('config.add', array('cogauth_aws_region', '')),
			array('config.add', array('cogauth_aws_secret', '')),
			array('config.add', array('cogauth_aws_key', '')),
			array('config.add', array('cogauth_token_cleanup_gc', 300)),
			array('config.add', array('cogauth_token_cleanup_last_gc', 0)),
			array('config.add', array('cogauth_client_secret', '')),
			array('config_add', array('cogauth_hosted_ui',0)),
			array('config_add', array('cogauth_hosted_ui_domain',0)),
			array('config_add', array('cogauth_master_auth',0)),
		);
	}
}
