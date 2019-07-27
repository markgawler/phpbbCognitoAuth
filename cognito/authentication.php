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
use mrfg\cogauth\jwt\exception\TokenVerificationException;
use mrfg\cogauth\cognito\exception\cogauth_authentication_exception;

class authentication
{
	/** @var \phpbb\db\driver\driver_interface */
	protected $db;

	/** @var \mrfg\cogauth\cognito\web_token_phpbb  */
	protected $web_token;

	/** @var \mrfg\cogauth\cognito\cognito */
	protected $cognito;

	/** @var int $time_now  */
	protected $time_now;

	/** @var string $access_token */
	protected $access_token;

	/** @var string $refresh_token */
	protected $refresh_token;

	/** @var string $uuid cogneto sub, UUID for the user */
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

	/** @var boolean $authenticated */
	protected $authenticated;

	/** @var string $sid phpBB sid */
	protected $sid;

	/** @var string $session_token */
	protected $session_token;

	/** @var string cogauth_authentication database table name */
	protected $cogauth_authentication;

	/** @var integer $phpbb_user_id */
	protected $phpbb_user_id;

	/**
	 * Database Authentication Constructor
	 *
	 * @param \mrfg\cogauth\cognito\web_token_phpbb $web_token
	 * @param \mrfg\cogauth\cognito\cognito $cognito
	 * @param \phpbb\db\driver\driver_interface $db
     * @param	string      $cogauth_authentication - db table name
	 */
	public function __construct(
		\mrfg\cogauth\cognito\web_token_phpbb $web_token,
		\mrfg\cogauth\cognito\cognito $cognito,
		\phpbb\db\driver\driver_interface $db,
		$cogauth_authentication)
	{
		$this->web_token = $web_token;
		$this->cognito =$cognito;
		$this->db = $db;
		$this->cogauth_authentication = $cogauth_authentication;  //DB Table name

		$this->time_now = time();

		$this->authenticated = False;
		$this->access_token = null;
		$this->refresh_token = null;

	}

	/**
	 *
	 * @param array $response - AWS Authentication Result
	 *
	 * @return boolean False if validation fails.
	 *
	 * @since 1.0
	 */
	public function validate_and_store_auth_response($response){
		try
		{
			$id_token = $this->web_token->decode_token($response['id_token']);
			$this->web_token->decode_token($response['access_token']);
		} catch  (TokenVerificationException $e)
		{
			return false;
		}

		$this->store_access_token($response['access_token']);
		$this->store_id_token($id_token);
		$this->store_refresh_token($response['refresh_token']);


		return true;

	}

	/**
	 * Update the stored the Access and Refres token
	 * @param string|\Jose\Component\Signature\Serializer\string $access_token AWS Cognito Access Token
	 * @param string $refresh_token AWS Cognito Refresh token
	 *
	 * @return bool True if Acess token is valid
	 *
	 * @since 1.0
	 */
	public function store_refreshed_access_token($access_token, $refresh_token)
	{
		try
		{
			$decoded_token = $this->web_token->decode_token($access_token);
		} catch  (TokenVerificationException $e)
		{
			return false;
		}
		$this->expires = $decoded_token['expires']; //todo is this exp or expires

		$this->store_access_token($access_token);
		$this->store_refresh_token($refresh_token);
		$this->update_auth_data();
		return true;
	}


	/**
	 * Stores decoded and store ID token,
	 * @param $token
	 **
	 * @since 1.0
	 */
	protected function store_id_token($token){

		// Only store the interesting bits
		$this->uuid = $token['sub'];
		$this->cognito_username =  $token['cognito:username'];
		$this->preferred_username = $token['preferred_username'];
		$this->nickname = $token['nickname'];
		$this->expires = $token['expires'];  //todo is this exp ore expires
		$this->email = $token['email'];
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
			throw new \mrfg\cogauth\cognito\exception\cogauth_authentication_exception(
				'Atempt to set authenticated failed, Invalid SID');
		}
		if ($this->access_token == ""){
			throw new \mrfg\cogauth\cognito\exception\cogauth_authentication_exception(
				'Atempt to set authenticated failed, No Access Token');
		}
		$this->sid = $sid;
		$this->store_auth_data($phpbb_user_id, $sid);
		return $this->session_token;
	}

	/**
	 * @param int    $phpbb_user_id
	 * @param string $sid
	 */
	protected function store_auth_data($phpbb_user_id, $sid)
	{
		$fields = array(
			'session_token' => $this->get_session_token(),
			'expires'  		=> $this->expires,
			'uuid'			=> $this->uuid,
			'username' 		=> $this->cognito_username,
			'prefered_username' => $this->preferred_username,
			'nickname' 		=> $this->nickname,
			'email' 		=> $this->email,
			'phpbb_user_id' => $phpbb_user_id,
			'sid' 			=> $sid,
			'access_token'  => $this->access_token,
			'refresh_token' => $this->refresh_token);

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
			'prefered_username' => $this->preferred_username,
			'nickname' 		=> $this->nickname,
			'email' 		=> $this->email,
			'phpbb_user_id' => $this->phpbb_user_id,
			'sid' 			=> $this->sid,
			'access_token'  => $this->access_token,
			'refresh_token' => $this->refresh_token);

		$sql = 'UPDATE ' . $this->cogauth_authentication . ' SET ' .
			$this->db->sql_build_array('UPDATE', $data) .
			" WHERE session_token = '" . $this->session_token . "'";

		$this->db->sql_query($sql);
	}



	/**
	 * @param string $selector - SQL fragment to select auth data
	 *
	 * @return bool True if data loaded, False if no authentication data for selsctor
	 *
	 * @since 1.0
	 */
	private function load_auth_data($selector)
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
			$this->preferred_username = $row['prefered_username'];
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
			$this->expires = null;;
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
	 * @param  string $sid
	 * @return 	string | bool false or Cognito Access Token
	 */
	public function get_access_token_from_sid($sid)
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
	 * @return 	string | bool  false or Cognito Access Token
	 */
	public function get_access_token_from_session_token($session_token)
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
	 * @return bool|string|null
	 *
	 * @since version
	 */
	private function get_access_token()
	{
		// refresh if the token expires in less than 300 seconds (5 min)
		if ($this->time_now  > ($this->expires - 300))
		{
			# Refresh the access token
			$access_token = $this->cognito->refresh_access_token_for_username(
				$this->refresh_token, $this->cognito_username, $this->phpbb_user_id);
			if ($access_token)
			{
				$this->access_token = $access_token;
			}
			else {
				return false;
			}
		}
		return $this->access_token;
	}


	/**
	 * Returns the unique session token for this cognito session
	 *
	 * @return string session_token
	 *
	 * @since 1,0
	 */
	public function get_session_token()
	{
		if (! $this->session_token ){
			$this->session_token = $this->get_unique_token();
		}
		return $this->session_token;
	}

	/**
	 * @param $length
	 * @return string A unique Token
	 */
	private function get_unique_token($length = 32){
		$token = "";
		$code_alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
		$code_alphabet.= "abcdefghijklmnopqrstuvwxyz";
		$code_alphabet.= "0123456789";
		$max = strlen($code_alphabet);

		try
		{
			for ($i = 0; $i < $length; $i++)
			{
				$token .= $code_alphabet[random_int(0, $max - 1)];
			}
		} catch (\Exception $e)
		{
			return "";
		}
		return $token;
	}
}