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

	/** @var \phpbb\config\config $config */
	protected $config;


	/** @var \phpbb\passwords\manager $passwords_manager */
	protected $passwords_manager;

	/** @var \phpbb\template\template */
	protected $template;

	/** @var \phpbb\controller\helper */
	protected $helper;

	/** @var string $phpbb_root_path */
	protected $phpbb_root_path;

	/** @var string $php_ext */
	protected $php_ext;

	/**
	 * user constructor.
	 **
	 * @param \phpbb\user $user
	 * @param \phpbb\auth\auth $auth
	 * @param \phpbb\db\driver\driver_interface $db
	 * @param \phpbb\config\config $config
	 * @param \phpbb\passwords\manager $passwords_manager
	 * @param	string			$phpbb_root_path
	 * @param	string			$php_ext
	 */
	public function __construct(
		\phpbb\user $user,
		\phpbb\auth\auth $auth,
		\phpbb\db\driver\driver_interface $db,
		\phpbb\config\config $config,
		\phpbb\passwords\manager $passwords_manager,
		$phpbb_root_path,
		$php_ext)
	{
		$this->user = $user;
		$this->auth = $auth;
		$this->db = $db;
		$this->config = $config;
		$this->passwords_manager = $passwords_manager;
		$this->phpbb_root_path = $phpbb_root_path;
		$this->php_ext = $php_ext;
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
	/** @noinspection PhpUnused */
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

	public function add_user($user_attributes)
	{
		/** @noinspection PhpIncludeInspection */
		include_once($this->phpbb_root_path . 'includes/functions_user.' . $this->php_ext);
		// Which group by default?
		$group_name = 'REGISTERED';

		$sql = 'SELECT group_id
				FROM ' . GROUPS_TABLE . "
				WHERE group_name = '" . $this->db->sql_escape($group_name) . "'
					AND group_type = " . GROUP_SPECIAL;
		$result = $this->db->sql_query($sql);
		$row = $this->db->sql_fetchrow($result);
		$this->db->sql_freeresult($result);

		if (!$row)
		{
			trigger_error('NO_GROUP');
		}

		$group_id = $row['group_id'];

		$user_type = USER_NORMAL;
		$user_inactive_reason = 0;
		$user_inactive_time = 0;

		$user_password = gen_rand_string_friendly(max(8, mt_rand((int) $this->config['min_pass_chars'], (int) $this->config['max_pass_chars'])));

		error_log($user_password);

		$user_row = array(
			'username'				=> $user_attributes['cognito:username'],
			'user_password'			=> $this->passwords_manager->hash($user_password),
			'user_email'			=> $user_attributes['email'],
			'group_id'				=> (int) $group_id,
			'user_timezone'			=> $this->config['board_timezone'],
			'user_lang'				=> $this->user->lang_name,
			'user_type'				=> $user_type,
			'user_actkey'			=> '',
			'user_ip'				=> $this->user->ip,
			'user_regdate'			=> time(),
			'user_inactive_reason'	=> $user_inactive_reason,
			'user_inactive_time'	=> $user_inactive_time,
		);

		if ($this->config['new_member_post_limit'])
		{
			$user_row['user_new'] = 1;
		}

		// Register user...
		$cp_data = false;                           // Custom Profile Filed data.
		$user_id = user_add($user_row, $cp_data);  	//phpBB register
		return $user_id;
	}

}
