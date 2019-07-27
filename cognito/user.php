<?php
/**
 * *
 * AWS Cognito Authentication. An extension for the phpBB Forum Software package.
 *
 * @package     mrfg\cogauth\cognito
 * @subpackage	user
 *
 * @copyright (c) 2018, Mark Gawler
 * @license GNU General Public License, version 2 (GPL-2.0)
 *
 * Date: 20/07/19
 */

namespace mrfg\cogauth\cognito;


class user
{

	/** @var \phpbb\db\driver\driver_interface */
	protected $db;

	/** @var string cognito username */
	protected $cognito_username;

	/**
	 * user constructor.
	 **
	 * @param \phpbb\db\driver\driver_interface $db
	 */
	public function __construct(
		\phpbb\db\driver\driver_interface $db)
	{
		$this->db = $db;
	}

	/**
	 * @param int $user_id phpBB user id
	 *
	 * @return string cognito username
	 *
	 * @since version
	 */
	public function get_cognito_username($user_id)
	{
		return 'u' . str_pad($user_id, 6, "0", STR_PAD_LEFT);
	}
}