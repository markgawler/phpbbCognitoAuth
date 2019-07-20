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

	/**
	 * Database Authentication Constructor
	 *
	 * @param \mrfg\cogauth\cognito\web_token_phpbb $web_token
	 * @param \phpbb\db\driver\driver_interface $db
     * @param	string      $cogauth_authentication - db table name
	 */
	public function __construct(
		\mrfg\cogauth\cognito\web_token_phpbb $web_token,
		\phpbb\db\driver\driver_interface $db,
		$cogauth_authentication)
	{
		$this->web_token = $web_token;
		$this->db = $db;
		$this->cogauth_authentication = $cogauth_authentication;

		$this->time_now = time();

		$this->authenticated = False;
		$this->access_token = "";
		$this->refresh_token = "";

	}

	/**
	 *
	 * @param string $responce - json encoded response
	 *
	 * @return boolean False if validation fails.
	 *
	 * @since 1.0
	 */
	public function validate_and_store_auth_response($responce_json){
		$response =json_decode($responce_json,true);

		try
		{
			$id_token = $this->web_token->decode_token($response['id_token']);
			$access_token = $this->web_token->decode_token($response['access_token']);
		} catch  (TokenVerificationException $e)
		{
			return false;
		}

		$this->store_access_token($access_token);
		$this->store_id_token($id_token);
		$this->store_refresh_token($response['refresh_token']);
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
		$this->expires = $token['expires'];
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
	 * @param int $user_id
	 * @param string $sid
	 */
	protected function store_auth_data($user_id, $sid)
	{
		$fields = array(
			'session_token' => $this->get_session_token(),
        	'expires'  		=> $this->expires,
			'uuid'			=> $this->uuid,
			'username' 		=> $this->cognito_username,
			'prefered_username' => $this->preferred_username,
			'nickname' 		=> $this->nickname,
			'email' 		=> $this->email,
			'phpbb_user_id' => $user_id,
			'sid' 			=> $sid,
			'access_token'  => $this->access_token,
			'refresh_token' => $this->refresh_token);

		$sql = 'INSERT INTO ' . $this->cogauth_authentication . ' ' . $this->db->sql_build_array('INSERT', $fields);

		$this->db->sql_query($sql);
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