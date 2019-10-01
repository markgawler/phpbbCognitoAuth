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
	/** @var \phpbb\user $user */
	protected $user;

	/** @var \phpbb\auth\auth $auth */
	protected $auth;

	/** @var \phpbb\db\driver\driver_interface */
	protected $db;

	/** @var string cognito username */
	protected $cognito_username;

	/**
	 * user constructor.
	 **
	 * @param \phpbb\user $user
	 * @param \phpbb\auth\auth $auth
	 * @param \phpbb\db\driver\driver_interface $db
	 */
	public function __construct(
		\phpbb\user $user,
		\phpbb\auth\auth $auth,
		\phpbb\db\driver\driver_interface $db)
	{
		$this->user = $user;
		$this->auth = $auth;
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

	/** Return the phpBB user ID
	 * @param string $cognito_username
	 * @return int
	 */
	public function get_phpbb_user_id($cognito_username)
	{
		return (int) substr($cognito_username,1);
	}

	/**
	 * Automatically login a user,
	 *
	 * @param validation_result $validation
	 *
	 * @return bool True is login success
	 * @since 1.0
	 */
	public function login($validation)
	{
		if ($validation instanceof validation_result && !$validation->is_new_user())
		{
			$this->user->session_create($validation->phpbb_user_id, false, false, true);  //todo  remember me
			$this->auth->acl($this->user->data);
			$this->user->setup();
			return true;

		}
		return false;
	}

	public function get_phpbb_session_id()
	{
		return $this->user->session_id;
	}

}
