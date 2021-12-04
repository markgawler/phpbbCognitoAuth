<?php
/**
 * *
 * AWS Cognito Authentication. An extension for the phpBB Forum Software package.
 *
 * @copyright (c) 2018, Mark Gawler
 * @license GNU General Public License, version 2 (GPL-2.0)
 *
 * Date: 19/08/18
 */

namespace mrfg\cogauth\cognito;
use Exception;
use mrfg\cogauth\jwt\exception\TokenVerificationException;
use mrfg\cogauth\cognito\exception\cogauth_authentication_exception;
use phpbb\db\driver\driver_interface;
use phpbb\log\log_interface;

class auth_result
{
	/** @var \phpbb\db\driver\driver_interface */
	protected $db;

	/** @var \mrfg\cogauth\cognito\web_token_phpbb  */
	protected $web_token;

	/** @var int $time_now  */
	protected $time_now;

	/** @var string $access_token */
	protected $access_token;

	/** @var string $refresh_token */
	protected $refresh_token;

	/** @var string $uuid cognito sub, UUID for the user */
	protected $uuid;

	/** @var string $cognito_username */
	protected $cognito_username;

	/** @var string $preferred_username  */
	protected $preferred_username;

	/** @var string $nickname */
	protected $nickname;

	/** @var int $expires */
	protected $expires;

	/** @var string $email */
	protected $email;

	/** @var string $sid phpBB sid */
	protected $sid;

	/** @var string $session_token */
	protected $session_token;

	/** @var string cogauth_authentication database table name */
	protected $cogauth_authentication;

	/** @var integer $phpbb_user_id */
	protected $phpbb_user_id;

	/** @var \phpbb\log\log_interface $log */
	protected $log;

	/** @var boolean $autologin */
	protected $autologin;

	/** @var integer $last_active */
	protected $last_active;

	/** @var integer $first_active */
	protected $first_active;
	/**
	 * Database Authentication Constructor
	 *
	 * @param \mrfg\cogauth\cognito\web_token_phpbb $web_token
	 * @param \phpbb\db\driver\driver_interface     $db                     *
	 * @param \phpbb\log\log_interface              $log
	 * @param string                                $cogauth_authentication - db table name
	 */
	public function __construct( web_token_phpbb $web_token, driver_interface $db, log_interface $log, string $cogauth_authentication)
	{
		$this->web_token = $web_token;
		$this->db = $db;
		$this->cogauth_authentication = $cogauth_authentication;  //DB Table name

		$this->time_now = time();
		$this->log = $log;
	}

	/**
	 * Store or update the Authentication result
	 *
	 * @param array $response  - AWS Authentication Result
	 * @param bool  $refreshed - true is the storing a refreshed Access token
	 *
	 * @return boolean | validation_result False if validation fails otherwise a session_token.
	 *
	 * @since 1.0
	 */
	public function validate_and_store_auth_response(array $response, bool $refreshed = false)
	{
		try
		{
			$id_token = $this->web_token->decode_token($response['IdToken']);
			$this->web_token->decode_token($response['AccessToken']);
		} catch  (TokenVerificationException $e)
		{
			//todo log error
			//error_log($e->getMessage());
			$this->log->add('critical', $this->phpbb_user_id, 0, $e->getMessage());
			return false;
		}

		$this->store_access_token($response['AccessToken']);

		# If this is a refreshed Access Token do not decode and store the parameters.
		if (! $refreshed)
		{
			$this->store_id_token($id_token);
		}
		$this->store_refresh_token($response['RefreshToken']);

		# Only commit the data to DB if the session_token has been set previously and this is a token refresh.
		# The data cannot be committed until after the login as the user id is unknown and the SID will change at login.
		if ($this->session_token && $refreshed){
			$this->update_auth_data();
		}
		return new validation_result($this->get_session_token(),$this->phpbb_user_id);
	}


	/**
	 * Stores decoded and store ID token,
	 * @param $token
	 **
	 * @since 1.0
	 */
	protected function store_id_token($token){
		$user_name = $token['cognito:username'];
		// Only store the interesting bits
		$this->uuid = $token['sub'];
		$this->cognito_username = $user_name;
		$this->preferred_username = ($token['preferred_username']) ?: $user_name;
		$this->nickname = ($token['nickname']) ?: $user_name;
		$this->expires = $token['exp'];
		$this->email = $token['email'];
		$this->phpbb_user_id = ($token['custom:phpbb_user_id']) ? (int) $token['custom:phpbb_user_id'] : 0;

		/*if (array_key_exists('custom:phpbb_user_id', $token))
		{
			$this->phpbb_user_id = (int) $token['custom:phpbb_user_id'];
		}
		else
		{
			// New User
			$this->phpbb_user_id = 0;
		}
		/*else
		{
			if ($this->phpbb_user_id != $token['custom:phpbb_user_id'])
			{
				//todo: verify claims
				throw ;
			}
		}
		*/
	}

	/**
	 * Return the interesting user attributes extracted from the id_token
	 *
	 * @return array
	 *
	 * @since version
	 */
	public function get_user_attributes(): array
	{
		return array(
			'sub' => $this->uuid,
			'cognito:username' => $this->cognito_username,
			'preferred_username' => $this->preferred_username,
			'nickname' => $this->nickname,
			'exp' => $this->expires,
			'email' => $this->email,
			'custom:phpbb_user_id' => (string) $this->phpbb_user_id);
	}

	/**
	 * @param array $attributes
	 *
	 * @since version
	 */
	public function set_user_attributes(array $attributes)
	{
		$this->preferred_username = $attributes['preferred_username'];
		$this->nickname = $attributes['nickname'];
		$this->email = $attributes['email'];
		$this->phpbb_user_id = (int) $attributes['custom:phpbb_user_id'];
	}

	/**
	 * Decoded and store Access token,
	 * @param $token
	 *
	 *
	 * @since 1.0
	 */
	protected function store_access_token($token){
		$this->access_token = $token;
	}

	/**
	 * Stores a refresh token,
	 * @param $token
	 *
	 * @since 1.0
	 */
	protected function store_refresh_token($token){
		$this->refresh_token = $token;
	}

	/**
	 * Called once a session is authenticated, to commit the ID, Access and Refresh tokens
	 * to the Database,
	 *
	 * @param $phpbb_user_id
	 * @param $sid
	 * @return string session_token
	 *
	 * @throws cogauth_authentication_exception;
	 *
	 * @since 1.0
	 */
	public function authenticated($phpbb_user_id, $sid){
		if ($sid == ""){
			throw new cogauth_authentication_exception(
				'Attempt to set authenticated failed, Invalid SID');
		}

		if ($this->access_token == ""){
			// This can happen when the cognito user exists but fails to authenticate after
			// phpbb has successfully authenticated (due to a configuration error?). This will
			// also happen when attempting to migrate a user whose password is weaker than the
			// Cognito password strength rules.
			// If the error is not trapped at the authentication stage an auto password change
			// will be initiated which also fails and the user ends in the "FORCE_CHANGE_PASSWORD"
			// state. This should not occur as known cases are now trapped.
			$this->log->add('user', $phpbb_user_id, 0,
				'COGAUTH_NO_ACCESS_TOKEN', $this->time_now);
		}
		else
		{
			$this->last_active = $this->time_now;
			if ($this->first_active == null) {
				$this->first_active = $this->time_now;
			}
			$this->sid = $sid;
			$this->commit_auth_data($phpbb_user_id, $sid);
			return $this->session_token;
		}
		return false;
	}

	/**
	 * @param int    $phpbb_user_id
	 * @param string $sid
	 */
	protected function commit_auth_data(int $phpbb_user_id, string $sid)
	{
		$fields = array(
			'session_token' => $this->get_session_token(),
			'expires'  		=> $this->expires,
			'uuid'			=> $this->uuid,
			'username' 		=> $this->cognito_username,
			'preferred_username' => $this->preferred_username,
			'nickname' 		=> $this->nickname,
			'email' 		=> $this->email,
			'phpbb_user_id' => $phpbb_user_id,
			'sid' 			=> $sid,
			'access_token'  => $this->access_token,
			'refresh_token' => $this->refresh_token,
			'autologin'		=> $this->autologin ?? false,
			'last_active'	=> $this->last_active,
			'first_active'	=> $this->first_active);

		$sql = 'INSERT INTO ' . $this->cogauth_authentication . ' ' . $this->db->sql_build_array('INSERT', $fields);

		$this->db->sql_query($sql);
		$this->phpbb_user_id = $phpbb_user_id;
		$this->sid = $sid;
	}

	/**
	 */
	protected function update_auth_data()
	{
		$data = array(
			'expires'  		=> $this->expires,
			'uuid'			=> $this->uuid,
			'username' 		=> $this->cognito_username,
			'preferred_username' => $this->preferred_username,
			'nickname' 		=> $this->nickname,
			'email' 		=> $this->email,
			'phpbb_user_id' => $this->phpbb_user_id,
			'sid' 			=> $this->sid,
			'access_token'  => $this->access_token,
			'refresh_token' => $this->refresh_token,
			'autologin'		=> $this->autologin ?? false,
			'last_active'	=> $this->last_active,
			'first_active'	=> $this->first_active);

		$sql = 'UPDATE ' . $this->cogauth_authentication . ' SET ' .
			$this->db->sql_build_array('UPDATE', $data) .
			" WHERE session_token = '" . $this->session_token . "'";

		$this->db->sql_query($sql);
	}

	/**
	 * @param string $selector - SQL fragment to select auth data
	 *
	 * @return bool True if data loaded, False if no authentication data for selector
	 *
	 * @since 1.0
	 */
	private function load_auth_data(string $selector): bool
	{
		$sql = 'SELECT * FROM ' .$this->cogauth_authentication . ' WHERE ' . $selector;
		$result = $this->db->sql_query($sql);
		$row = $this->db->sql_fetchrow($result);
		$this->db->sql_freeresult($result);
		if ($row)
		{
			$this->session_token = $row['session_token'];
        	$this->expires = $row['expires'];
			$this->uuid = $row['uuid'];
			$this->cognito_username = $row['username'];
			$this->preferred_username = $row['preferred_username'];
			$this->nickname = $row['nickname'];
			$this->email = $row['email'];
			$this->phpbb_user_id = $row['phpbb_user_id'];
			$this->sid = $row['sid'];
			$this->access_token = $row['access_token'];
			$this->refresh_token = $row['refresh_token'];
		}
		else
		{
			// ensure all data is cleared.
			$this->session_token = "";
			$this->expires = null;
			$this->uuid = null;
			$this->cognito_username = null;
			$this->preferred_username = null;
			$this->nickname = null;
			$this->email = null;
			$this->phpbb_user_id = null;
			$this->sid = "";
			$this->access_token = null;
			$this->refresh_token = null;
			return false;
		}
		return true;
	}

	/**
	 * Get the access token for the SID
	 * If the access token has expired attempt to refresh it
	 *
	 * @param string $sid
	 * @return    bool | array
	 *        False if fails to get access token from store,
	 *        Array [mode = access_token] [token = access token string]
	 *              [mode = refresh] [token = refresh token] [user_id = phpbb_user_id]	 */
	public function get_access_token_from_sid(string $sid)
	{
		if ($this->sid !== $sid || $this->access_token == null)
		{
			$sql = "sid = '" . $this->db->sql_escape($sid) . "'";
			if (!$this->load_auth_data($sql)){
				return false;
			}
		}
		return $this->get_access_token();
	}

	/**
	 * Get the access token for the Session Token
	 * If the access token has expired attempt to refresh it
	 *
	 * @param string $session_token
	 * @return    bool | array
	 *        False if fails to get access token from store,
	 *        Array [mode = access_token] [token = access token string]
	 *              [mode = refresh] [token = refresh token] [user_id = phpbb_user_id]
	 */
	public function get_access_token_from_session_token(string $session_token)
	{
		if ($this->session_token !== $session_token || $this->access_token == null)
		{
			$sql = "session_token = '" . $this->db->sql_escape($session_token) . "'";
			if (! $this->load_auth_data($sql)){
				return false;
			}
		}
		return $this->get_access_token();
	}

	/**
	 *
	 * @return  array [mode = access_token] [token = access token string]
	 *                [mode = refresh] [token = refresh token] [user_id = phpbb_user_id]
	 * @since version
	 */
	private function get_access_token(): array
	{
		// refresh if the access_token expires in less than 300 seconds (5 min)
		if ($this->time_now  > ($this->expires - 300))
		{
			# Refresh the access token
			return array(
				'mode'    => 'refresh',
				'token'   => $this->refresh_token,
				'user_id' => $this->phpbb_user_id);
		}
		else
		{
			return array(
				'mode' => 'access_token',
				'token' => $this->access_token);
		}
	}


	/**
	 * Returns the unique session token for this cognito session
	 *
	 * @param bool $initialise if true create a session token when the token is null
	 * @return string session_token
	 *
	 * @since 1,0
	 */
	public function get_session_token(bool $initialise = true): ?string
	{
		if (! $this->session_token && $initialise){
			$this->session_token = $this->get_unique_token();
		}
		return $this->session_token;
	}

	/**
	 * @return string A unique Token
	 */
	private function get_unique_token(): string
	{
		$token = "";
		$code_alphabet = "ABCDEFGHILKMNOPQRSTUVWXYZ";
		$code_alphabet .= "abcdefghijklmnopqrstuvwxyz";
		$code_alphabet .= "0123456789";
		$max = strlen($code_alphabet);

		try
		{
			for ($i = 0; $i < 32; $i++)
			{
				$token .= $code_alphabet[random_int(0, $max - 1)];
			}
		}
		catch (Exception $e)
		{
			return "";
		}
		return $token;
	}

	/**
	 * Delete the Session token for a session token
	 *
	 * @param string $session_id phpbb session_id
	 * @return int number of rows deleted
	 *
	 * @since 1.0
	 */
	public function kill_session(string $session_id): int
	{
		$sql = 'DELETE FROM ' . $this->cogauth_authentication . " WHERE sid = '" . $this->db->sql_escape($session_id) ."'";
		$this->db->sql_query($sql);
		return $this->db->sql_affectedrows();
	}

	/**
	 * Clean up session tokens
	 *
	 * @param integer $max_session_length the maximum session length in days.
	 * @since 1.0
	 */
	public function cleanup_session_tokens(int $max_session_length)
	{
		// Expire non auto login sessions
		// The rule for deleting rows for phpbb_cogauth_authentication is that for non auto login rows once the sid is
		// deleted from the phpbb_sessions table it is safe to delete the row.
		//todo: investigate optimising by adding "phpbb_sessions.session_user_id != 1"
		$cogauth_table = $this->cogauth_authentication;

		//  todo: Getting this to works with both MySQL and SQLite was more problematic than expected, revisit to optimise / tidy
		$sql = "DELETE FROM " . $cogauth_table . " WHERE sid IN "
		. "(SELECT S.sid FROM (SELECT sid FROM " . $cogauth_table. " WHERE autologin = 0) AS S LEFT JOIN "
		. SESSIONS_TABLE. " ON S.sid = " .SESSIONS_TABLE . ".session_id WHERE "
		. SESSIONS_TABLE . ".session_id is NULL)";

		$this->db->sql_query($sql);

		//expire auto login
		$expire_time = $this->time_now - ($max_session_length * 86400); // Max Session length in seconds (from days)
		$sql = 'DELETE FROM ' . $this->cogauth_authentication . " WHERE first_active < " . $expire_time;
		$this->db->sql_query($sql);

	}

	/**
	 * @param bool $autologin
	 *
	 * @since 1.0
	 */
	public function set_autologin(bool $autologin)
	{
		$this->autologin = $autologin;
	}

}
