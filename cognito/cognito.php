<?php
/**
 *
 * AWS Cognito Authentication. An extension for the phpBB Forum Software package.
 *
 * @copyright (c) 2018, Mark Gawler
 * @license GNU General Public License, version 2 (GPL-2.0)
 *
 * Date: 19/08/18
 *
 */

namespace mrfg\cogauth\cognito;
use Aws\CognitoIdentityProvider\Exception\CognitoIdentityProviderException;

use mrfg\cogauth\cognito\exception\TokenVerificationException;
//use phpbb\request\request;
//use phpbb\request\request_interface;

define('COG_LOGIN_SUCCESS', 1);
define('COG_LOGIN_NO_AUTH', 2);
define('COG_USER_NOT_FOUND', 3);
define('COG_LOGIN_ERROR_PASSWORD',4);
define('COG_USER_FOUND',7);
define('COG_LOGIN_DISABLED', 8);
define('COG_LOGIN_ERROR_ATTEMPTS', 9);
define('COG_ERROR',99);

define('COG_MIGRATE_SUCCESS',10);
define('COG_MIGRATE_FAIL', 11);


class cognito
{
	/**@var \phpbb\config\config $config Config object */
	protected $config;

	/**@var \phpbb\request\request_interface $request Request object */
	protected $request;

	/** @var \phpbb\user */
	protected $user;

	/**@var  \Aws\CognitoIdentityProvider\CognitoIdentityProviderClient */
	protected $client;

	/**@var $string */
	protected $user_pool_id;

	/**@var $string */
	protected $client_id;

	/** @var String */
	protected $client_secret;

	/** @var string */
	protected $region;

	/** @var \phpbb\db\driver\driver_interface */
	protected $db;

	/**@var string */
	protected $cogauth_session;

	/**@var array $auth_result */
	protected $auth_result;

    /** @var \mrfg\cogauth\cognito\web_token_phpbb */
    protected $web_token;

    /** @var \phpbb\log\log_interface $log */
    protected $log;

    /** @var string  The key to the cogauth_session table */
	protected $session_token;

	/** @var int Time in seconds */
	protected $last_active;

	/**	@var  int $user_id  The phpBB user ID associated with this cogauth_session */
	protected $user_id = 0;

	/**	@var string $username_clean Normalised form of the phpBB username for this session*/
	protected $username_clean = '';

	/** @var int $time_now  */
	protected $time_now;

	/**
	 * Database Authentication Constructor
	 *
	 * @param	\phpbb\db\driver\driver_interface $db
	 * @param	\phpbb\config\config              $config
	 * @param	\phpbb\user                       $user
	 * @param   \phpbb\request\request_interface  $request
	 * @param   \phpbb\log\log_interface 		  $log
     * @param   cognito_client_wrapper            $client,
     * @param   web_token_phpbb                   $web_token
     * @param	string                            $cogauth_session - db table name
	 */
	public function __construct(
		\phpbb\db\driver\driver_interface $db,
		\phpbb\config\config $config,
		\phpbb\user $user,
		\phpbb\request\request_interface $request,
		\phpbb\log\log_interface $log,
        cognito_client_wrapper $client,
        web_token_phpbb $web_token,
        $cogauth_session)
	{
		$this->db = $db;
		$this->config = $config;
		$this->user = $user;
		$this->request = $request;
		$this->cogauth_session =$cogauth_session;

		$this->time_now = time();

		$this->user_pool_id = $config['cogauth_pool_id'];
		$this->client_id = $config['cogauth_client_id'];
		$this->client_secret = $config['cogauth_client_secret'];
        $this->region = $config['cogauth_aws_region'];

        $this->auth_result = array();

        $args = array(
            'credentials' => array(
                'key' => $config['cogauth_aws_key'],
                'secret' => $config['cogauth_aws_secret'],
            ),
            'version' => '2016-04-18',
            'region' =>  $this->region,
        );
        $this->client = $client;
        $client->create_client($args);
        $this->web_token = $web_token;
        $this->log = $log;
    }

	/**
	 * @param int $user_id phpBB User ID
	 * @param string $password
	 * @param string $username_clean - the cleaned version of the username to be stored
	 * @throws \Exception
	 * @return array
	 *
	 *  status:
	 * 		COG_LOGIN_SUCCESS
	 * 		COG_LOGIN_NO_AUTH
	 *  	COG_USER_NOT_FOUND
	 *		COG_LOGIN_ERROR_PASSWORD
	 *      COG_LOGIN_DISABLED
	 *      COG_LOGIN_ERROR_ATTEMPTS
	 *
	 */
	public function authenticate($user_id, $password, $username_clean)
	{
		try {
			$response = $this->authenticate_user($user_id, $password);

			if (isset($response['AuthenticationResult']))
			{
				// Successful login.
				// Store the result locally. The result will be stored in the database once the logged in
				// session has started  (the SID changes so we cant store it in the DB yet).
				$token = $this->get_unique_token();
				$this->session_token = $token;
				$this->store_auth_result($response['AuthenticationResult'],$user_id, $username_clean);
				return array(
					'status'    => COG_LOGIN_SUCCESS,
					'response'  => $response['AuthenticationResult'],
					'session_token' => $token
				);
			} else {
				return array(
					'status'    => COG_LOGIN_NO_AUTH,
					'response'  => $response['ChallengeName']
				);
			}

		} catch (CognitoIdentityProviderException $e) {
			switch ($e->getAwsErrorCode())
			{
				case 'UserNotFoundException':
					$status = COG_USER_NOT_FOUND;
				break;
				case 'NotAuthorizedException':
					// Try to translate the Cognito error
					switch ($e->getAwsErrorMessage())
					{
						case 'Password attempts exceeded':
							$status = COG_LOGIN_ERROR_ATTEMPTS;
						break;
						case 'User is disabled':
							$status = COG_LOGIN_DISABLED;
						break;
						default:
							$status = COG_LOGIN_ERROR_PASSWORD;
					}
				break;

				default;
					$status = COG_LOGIN_NO_AUTH;
					$this->handleCognitoIdentityProviderException($e, $user_id, 'authenticate');
			}
		}
		return array(
			'status'    => $status,
			'response' => null,
		);
	}

	/**
	 * @param int $user_id phpBB user id
	 * @param String $password
	 * @return \Aws\Result
	 */
	private function authenticate_user($user_id, $password)
	{
		$username = $this->cognito_username($user_id);
		$response = $this->client->admin_initiate_auth(array(
			'AuthFlow' => 'ADMIN_NO_SRP_AUTH',
			'AuthParameters' => array(
				'USERNAME' => $username,
				'PASSWORD' => $password,
				'SECRET_HASH' => $this->cognito_secret_hash($username),
			),
			'ClientId' => $this->client_id,
			'UserPoolId' => $this->user_pool_id,
		));
		return $response;
	}

	protected function refresh_access_token($refresh_token, $user_id)
	{
		error_log('refresh_access_token');
		$username = $this->cognito_username($user_id);
		$response = $this->client->admin_initiate_auth(array(
			'AuthFlow'       => 'REFRESH_TOKEN_AUTH',
			'AuthParameters' => array(
				'REFRESH_TOKEN' => $refresh_token,
				'SECRET_HASH'   => $this->cognito_secret_hash($username),
			),
			'ClientId'       => $this->client_id,
			'UserPoolId'     => $this->user_pool_id,
		));

		return $response;
	}

	/**
	 * @param int $user_id phpBB user id
	 * @return string
	 */
	protected function cognito_username($user_id)
	{
		return 'u' . str_pad($user_id, 6, "0", STR_PAD_LEFT);
	}

	/**
	 * @param string $username
	 *
	 * @return string
	 */
	protected function cognito_secret_hash($username)
	{
		return $this->hash($username . $this->client_id);
	}

	/**
	 * @param string $message
	 *
	 * @return string
	 */
	protected function hash($message)
	{
        $hash = hash_hmac(
			'sha256',
			$message,
			$this->client_secret,
			true
		);
		return base64_encode($hash);
	}

	/**
	 * @param $length
	 * @return string A unique Token
	 * @throws \Exception
	 */
	private function get_unique_token($length = 32){
		$token = "";
		$code_alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
		$code_alphabet.= "abcdefghijklmnopqrstuvwxyz";
		$code_alphabet.= "0123456789";
		$max = strlen($code_alphabet);

		for ($i=0; $i < $length; $i++) {
			$token .= $code_alphabet[random_int(0, $max-1)];
		}

		return $token;
	}

	/**
	 * @param array $auth_result
	 * @param int $user_id
	 * @param string $username_clean
	 * @param bool $update True is this is to update (i.e. result of refreshing access_token)
	 */
	private function store_auth_result($auth_result, $user_id, $username_clean, $update = false)
	{
		if ($auth_result['AccessToken'])
		{
			$data1 = array(
				'access_token'  => $auth_result['AccessToken'],
				'expires_at'    => $auth_result['ExpiresIn'] + $this->time_now,
				'id_token'      => $auth_result['IdToken'],
				'token_type'    => $auth_result['TokenType'],
			);
			if ($update)
			{
				$sql = 'UPDATE ' . $this->cogauth_session . ' SET ' . $this->db->sql_build_array('UPDATE', $data1) .
					" WHERE session_token = '" . $this->session_token . "'";
			}
			else
			{
				$data2 = array(
					'user_id'		=> $user_id,
					'username_clean' => $username_clean,
					'sid'           => '',
					'session_token' => $this->session_token,
					'refresh_token' => $auth_result['RefreshToken'],
				);
				$fields = array_merge($data1, $data2);
				$sql = 'INSERT INTO ' . $this->cogauth_session . ' ' . $this->db->sql_build_array('INSERT', $fields);
			}

			$this->db->sql_query($sql);
		}
	}

	/**
	 * @param \Aws\CognitoIdentityProvider\Exception\CognitoIdentityProviderException $e
	 * @param int $user_id 			phpBB user ID
	 * @param string $action		Action Message inserted in to error log for debugging
	 * @param boolean $ignore_use_not_found	Don't log UserNotFoundException
	 * @return bool returns true if UserNotFoundException AND UserNotFound not ignored. Otherwise false.
	 */
	protected function handleCognitoIdentityProviderException($e, $user_id, $action, $ignore_use_not_found = false)
	{
		if ($e->getAwsErrorCode() == 'UserNotFoundException' and $ignore_use_not_found)
		{
			// Can only happen if the Cognito user is deleted after the user logs in.
			return true;
		}
		$user_ip = (empty($this->user->ip)) ? '' : $this->user->ip;
		$this->log->add('critical' ,$user_id , $user_ip, 'COGAUTH_UNEXPECTED_ERROR', $this->time_now,
			array($action, $e->getAwsErrorCode(), $e->getAwsErrorMessage()));
		return false;
	}

	/**
	 * @param string $nickname - Non normalised username
	 * @param string $password
	 * @param int	 $user_id - phpBB numeric user ID
	 * @param string $email
	 * @return array
	 * @throws /Exception
	 */
	public function migrate_user($nickname, $password, $user_id, $email)
	{
		$user_attributes = $this->build_attributes_array(array(
			'preferred_username' => utf8_clean_string($nickname),
			'email' => $email,
			'nickname' => $nickname,
			'email_verified' => "True"
		));

		$result = $this->admin_create_user($user_id, $password, $user_attributes);
		if ($result['status'] === COG_MIGRATE_SUCCESS)
		{
			try
			{
				$response = $this->authenticate_user($user_id, $password);
			}
			catch (CognitoIdentityProviderException $e)
			{
				$this->handleCognitoIdentityProviderException($e, $user_id, 'migrate_user - authenticate_user');
				return $result;
			}
			return $this->admin_respond_to_auth_challenge($response, $password, $user_id);
		}
		return $result;
	}

	/**
	 * @param array $attributes
	 * @return array
	 */
	private function build_attributes_array(array $attributes)
	{
		$userAttributes = array();
		foreach ($attributes as $key => $value) {
			$userAttributes[] = array(
				'Name' => (string)$key,
				'Value' => (string)$value,
			);
		}
		return $userAttributes;
	}

	/**
	 * @param int $user_id phpBB user id
	 * @param string $password
	 * @param $user_attributes
	 * @return array
	 */
	private function admin_create_user($user_id, $password, $user_attributes)
	{
		$username = $this->cognito_username($user_id);

		try {
			$response = $this->client->admin_create_user(array(
				'UserPoolId' => $this->user_pool_id,
				'Username' => $username,
				'TemporaryPassword' => $password,
				'MessageAction' => 'SUPPRESS',
				'SecretHash' => $this->cognito_secret_hash($username),
				'UserAttributes' => $user_attributes,
			));
		}
		catch (CognitoIdentityProviderException $e) {

			switch ($e->getAwsErrorCode())
			{
				case 'InvalidPasswordException':
					return  array(
						'status' => COG_MIGRATE_FAIL,
						'error' => $e->getAwsErrorCode(),
					);
				break;

				default:
					$this->handleCognitoIdentityProviderException($e, $user_id, 'admin_create_user');
					return  array(
						'status' => COG_MIGRATE_FAIL,
						'error' => $e->getAwsErrorCode(),
					);
			}
		}
		return array(
			'status' => COG_MIGRATE_SUCCESS,
			'error' => '',
			'response' => $response
		);
	}

	/**
	 * @param \Aws\result $response
	 * @param string $password
	 * @param int $user_id phpBB user id
	 * @return array
	 */
	private function admin_respond_to_auth_challenge($response, $password, $user_id)
	{
		$username = $this->cognito_username($user_id);
		switch ($response['ChallengeName'])
		{
			case 'NEW_PASSWORD_REQUIRED':
				$params = array('ChallengeName'      => "NEW_PASSWORD_REQUIRED",
								'ClientId'           => $this->client_id,
								'UserPoolId'         => $this->user_pool_id,
								'ChallengeResponses' => array(
									'NEW_PASSWORD' => $password,
									'USERNAME'     => $username,
									'SECRET_HASH'  => $this->cognito_secret_hash($username)),
								'Session'            => $response['Session']);
				try
				{
					$response = $this->client->admin_respond_to_auth_challenge($params);
					if (isset($response['AuthenticationResult']))
					{
						// login success, store the result locally. The result will be stored in the database once the logged in
						// session has started  (the SID changes so we cant store it in the DB yet).
						$this->auth_result = $response['AuthenticationResult'];
					}
				}
				catch (CognitoIdentityProviderException $e)
				{
					$this->handleCognitoIdentityProviderException($e, $user_id, 'admin_respond_to_auth_challenge');

					return array(
						'status' => COG_MIGRATE_FAIL,
						'error'  => $e->getAwsErrorCode(),
					);
				}
			break;

			default:
				$user_ip = (empty($this->user->ip)) ? '' : $this->user->ip;
				$this->log->add('critical' ,$user_id , $user_ip, 'COGAUTH_UNEXPECTED_CHALLENGE', $this->time_now,
					array('admin_respond_to_auth_challenge', $response['ChallengeName']));

				$response = null;
		}
		return  array(
			'status' => COG_MIGRATE_SUCCESS ,
			'error' => '',
		);
	}

	/**
	 * @param int $user_id phpBB user_id
	 * @param string $access_token
	 * @param string $old_password
	 * @param string $new_password
	 * @return boolean True = Success, False = Fail
	 */
	public function change_password($user_id, $access_token, $old_password, $new_password)
	{
		$username = $this->cognito_username($user_id);
		try {
			/** @var $access_token \Jose\Component\Signature\Serializer\string */
			if ($username !=  $this->web_token->verify_access_token($access_token))
			{
				return false;
			}
		} catch (TokenVerificationException $e)
		{
			return false;
		}

		try {
			$this->client->change_password(array(
				'AccessToken' => $access_token,
				'PreviousPassword' => $old_password,
				'ProposedPassword' => $new_password,
			));
			return true;
		} catch (CognitoIdentityProviderException $e) {
			return $this->handleCognitoIdentityProviderException($e,$user_id,'change_password', true);
		}
	}

	/**
	 * @param int $user_id phpBB user_id
	 * @param string $email
	 * @param string $access_token
	 * @return bool (True success, False fail)
	 */
	public function update_user_email($user_id, $email, $access_token)
	{
		$username = $this->cognito_username($user_id);
		try {
			/** @var $access_token \Jose\Component\Signature\Serializer\string */
			if ($username != $this->web_token->verify_access_token($access_token))
			{
				return false;
			}
        } catch (TokenVerificationException $e)
        {
            return false;
        }

		$attr = $this->build_attributes_array(array(
			'email' => $email,
		));
		try
		{
			$this->client->update_user_attributes(array(
					'AccessToken'    => $access_token,
					'UserAttributes' => $attr,
			));
			return true;
		} catch (CognitoIdentityProviderException $e)
		{
			return $this->handleCognitoIdentityProviderException($e,$user_id,'update_user_email', true);
		}
	}

	/**
	 * Admin only Change user password function. This is a hack as the user is deleted and recreated
	 * @param integer $user_id phpBB User ID
	 * @param $new_password
	 */
	public function admin_change_password($user_id, $new_password)
	{
		$user = $this->get_user($user_id);
		if ($user['status'] === COG_USER_FOUND)
		{
			$this->admin_delete_user_internal($user_id);
			$user_attributes = $this->clean_attributes($user['user_attributes']); // remove non mutatable  attribute
			$result = $this->admin_create_user($user_id,$new_password,$user_attributes);
			if ($result['status'] == COG_MIGRATE_SUCCESS)
			{
				try
				{
					$response = $this->authenticate_user($user_id, $new_password);
					$this->admin_respond_to_auth_challenge($response, $new_password, $user_id);
				} catch (CognitoIdentityProviderException $e)
				{
					$this->handleCognitoIdentityProviderException($e,$user_id,'admin_change_password');
				}
			}
		}

	}

	/**
	 * @param int $user_id phpBB user Id
	 * @return array
	 *
	 * user_status = UNCONFIRMED | CONFIRMED | ARCHIVED | COMPROMISED | UNKNOWN | RESET_REQUIRED | FORCE_CHANGE_PASSWORD
	 * status =  COG_USER_FOUND | COG_USER_NOT_FOUND | COG_ERROR
	 */
	public function get_user($user_id)
	{
		$username = $this->cognito_username($user_id);
		try
		{
			$response = $this->client->admin_get_user(array(
				"Username"   => $username,
				"UserPoolId" => $this->user_pool_id
			));
			return array(
				'status' => COG_USER_FOUND,
				'user_status' => $response['UserStatus'],
				'user_attributes' => $response['UserAttributes']
			);

		} catch (CognitoIdentityProviderException $e) {
			$user_not_found = $this->handleCognitoIdentityProviderException($e,$user_id,'get_user', true);
			if ($user_not_found)
			{
				$status = COG_USER_NOT_FOUND;
			}
			else{
				$status = COG_ERROR;
			}
			/*switch ($e->getAwsErrorCode())
			{
				case 'UserNotFoundException':
					$status = COG_USER_NOT_FOUND;
				break;
				default:
					$status = COG_ERROR;
					error_log($e->getAwsErrorMessage());
			}*/
		}

		return array(
			'status' => $status,
			'user_status' => '',
			'user_attributes' => ''
		);

	}

	/**
	 * Delete a user by user id
	 *
	 * @param int $user_id phpBB user ID
	 */
	private function admin_delete_user_internal($user_id)
	{
		$user_id = $this->cognito_username($user_id);

		$this->client->admin_delete_user(
			array('Username' => $user_id,
				  'UserPoolId' => $this->user_pool_id)
		);
	}

	/**
	 * Removes the non-mutatable attributes from name value pair array.:
	 * 	- sub
	 * @param array() $attributes
	 * @return array
	 */
	private function clean_attributes($attributes)
	{
		$result = array();
		foreach ($attributes as $key => $value) {
			if ($value['Name'] != 'sub')
			{
				$result[] = $value;
			}
		}
		return $result;
	}

	/**
	 * Administrator function to update a users email.
	 * @param integer $user_id phpBB User ID
	 * @param string $new_email
	 */
	public function admin_update_email($user_id, $new_email)
	{
		$attributes = array('email' => $new_email,
							'email_verified' => "True");
		$this->update_user_attributes($attributes, $user_id);
	}

	/**
	 * @param array $attributes
	 * @param int $user_id phpBB user id
	 */
	private function update_user_attributes($attributes, $user_id)
	{
		$data = array(
			'UserAttributes' => $this->build_attributes_array($attributes),
			'Username'       => $this->cognito_username($user_id),
			'UserPoolId'     => $this->user_pool_id,
		);
		try {
			$this->client->admin_update_user_attributes($data);
		} catch (CognitoIdentityProviderException $e)
		{
			$this->handleCognitoIdentityProviderException($e,$user_id,'update_user_attributes');
			//throw $e;
		}
	}

	/**
	 * Administrator function to update a users username
	 * 	this updates the preferred_username and nickname
	 *
	 * @param integer $user_id phpBB User ID
	 * @param string $new_username phpBB username (Nickname for Cognito)
	 */
	public function admin_update_username($user_id, $new_username)
	{
		$attributes = array('preferred_username' => utf8_clean_string($new_username),
							'nickname' => $new_username);
		$this->update_user_attributes($attributes, $user_id);
	}

	/**
	 * @param integer $user_id phpBB user ID
	 */
	public function admin_delete_user($user_id)
	{
		try {
			$this->admin_delete_user_internal($user_id);
		} catch (CognitoIdentityProviderException $e)
		{
			// 'UserNotFoundException'  No user to delete, do nothing
			$this->handleCognitoIdentityProviderException($e,$user_id,'admin_delete_user',true);
		}
	}

	/**
	 * @param integer $user_id phpBB user ID
	 */
	public function admin_enable_user($user_id)
	{
		$username = $this->cognito_username($user_id);
		try {
			$this->client->admin_enable_user(array(
				'Username' => $username,
				'UserPoolId' => $this->user_pool_id));
		}
		catch (CognitoIdentityProviderException $e)
		{
			error_log('CognitoIdentityProviderException:' . $e->getAwsErrorCode());
			//'UserNotFoundException': // No user to enable, do nothing
			$this->handleCognitoIdentityProviderException($e,$user_id,'admin_enable_user',true);
		}
	}

	/**
	 * @param integer $user_id phpBB user ID
	 */
	public function admin_disable_user($user_id)
	{
		$username = $this->cognito_username($user_id);
		try {
			$this->client->admin_disable_user(array(
				'Username' => $username,
				'UserPoolId' => $this->user_pool_id));
		}
		catch (CognitoIdentityProviderException $e)
		{
			// 'UserNotFoundException': // No user to disable, do nothing
			$this->handleCognitoIdentityProviderException($e,$user_id,'admin_disable_user',true);
		}
	}

	/**
	 * Get the access token for the current SID (or Session Token if suplied)
	 * If the access token has expired attempt to refresh it
	 * @param  string $session_token Can be used as an alternative to the SID, when the SID may not be set.
	 * @return 	\Jose\Component\Signature\Serializer\string | false $access_token Cognito Access Token
	 */
	public function get_access_token($session_token = null)
	{
		$sql = 'SELECT access_token, refresh_token, expires_at, user_id FROM ' . $this->cogauth_session . ' WHERE ';
		if ($session_token)
		{
			$sql .= "session_token = '" . $this->db->sql_escape($session_token) . "'";
		}
		else
		{
			$sql .= "sid = '" . $this->db->sql_escape($this->user->session_id) . "'";
		}
		$result = $this->db->sql_query($sql);
		$row = $this->db->sql_fetchrow($result);
		$this->db->sql_freeresult($result);

		if (!$row)
		{
			return false;
		}
		if ($this->time_now  > ($row['expires_at'] - 300))
		{
			$user_id = $row['user_id'];
			try
			{
				$response = $this->refresh_access_token($row['refresh_token'], $user_id);
				if (isset($response['AuthenticationResult']))
				{
					// Successful refresh of access token
					$this->store_auth_result($response['AuthenticationResult'], $user_id, $row['username_clean'],true);
					return $response['AuthenticationResult']['AccessToken'];
				}
			} catch (CognitoIdentityProviderException $e)
			{
				$this->handleCognitoIdentityProviderException($e, $user_id, 'refresh_access_tokens');
				return false;
			}
		}

		return $row['access_token'];
	}

	/**
	 * @param $session_token
	 * @return array (active = bool, [username = cognito username])
	 */
	public function validate_session($session_token)
	{
		$this->load_user_data($session_token);
		$access_token = $this->get_access_token($session_token);
		if (!$access_token)
		{
			// No valid token found in DB
			return array('active' => false);
		}
		try
		{
			$username = $this->web_token->verify_access_token($access_token);

			return array(
				'active' => true,
				'user_id' => $this->user_id,
				'username' => $username,
				'username_clean' => $this->username_clean);
		} catch (TokenVerificationException $e)
		{
			if ($e->getMessage() == 'token expired')
			{
				error_log('Expired fff');
				//todo we should try refreshing the token here
				return array('active' => false);
			}
			else
			{
				error_log($e->getMessage());
				return array('active' => false);
			}
		}
	}


	/**
	 * Attempt to refresh all access tokens that will expire in the next ten minutes
	 *
	 * @since 1.2
	 */
	public function refresh_access_tokens()
	{
		error_log('GC: refresh_access_tokens');
		$refresh_time = $this->time_now + 600;  // refresh any access tokens that expire next 10 minutes
		$sql = 'SELECT * FROM ' . $this->cogauth_session . " WHERE expires_at < " . $refresh_time;
		$result = $this->db->sql_query($sql);

		while ($row = $this->db->sql_fetchrow($result))
		{
			try
			{
				$user_id = $row['user_id'];
				$response = $this->refresh_access_token($row['refresh_token'],$user_id);
				$this->session_token = $row['session_token'];
				if (isset($response['AuthenticationResult']))
				{
					// Successful refresh of access token
					$this->store_auth_result($response['AuthenticationResult'], $user_id, $row['username_clean'],true);

				}
			} catch (CognitoIdentityProviderException $e)
			{
				$this->handleCognitoIdentityProviderException($e, $user_id, 'refresh_access_tokens');
			}
		}
		$this->db->sql_freeresult($result);
	}


	/**
	 * Loads the session user data ( user_id,username_clean,last_active)
	 * @param string session_token to get the data for.
	 */
	public function load_user_data($session_token)
	{
		$sql = 'SELECT user_id,username_clean,last_active  FROM ' . $this->cogauth_session . " WHERE session_token = '" . $this->db->sql_escape($session_token) . "'";

		$result = $this->db->sql_query($sql);
		$row = $this->db->sql_fetchrow($result);
		$this->db->sql_freeresult($result);

		$this->last_active = $row['last_active'];
		$this->username_clean = $row['username_clean'];
		$this->user_id = $row['user_id'];
	}

	/**
	 * Get the cognito_session table key
	 * @return string
	 */
	public function get_session_token()
	{
		return $this->session_token;
	}

	/**
	 * Store the cognito_session table key
	 * @param string $token;
	 */
	public function store_session_token($token)
	{
		$this->session_token = $token;
	}

	/**
	 * @param string $phpbb_sid        phpBB SID
	 */
	public function store_sid($phpbb_sid)
	{
		if (!$this->session_token)
		{
			// This will happen on auto login as authenticate is not called to start the session
			// As this is an auto login the previous SID must be in the cookie, so we use this to find the
			// session_token.
			$cookie_sid = $this->request->variable($this->config['cookie_name'] . '_sid', '', false, \phpbb\request\request_interface::COOKIE);

			$sql = 'SELECT session_token FROM ' . $this->cogauth_session . " WHERE sid = '" . $this->db->sql_escape($cookie_sid) . "'";
			$this->db->sql_query($sql);
			$row = $this->db->sql_fetchrow();
			$this->session_token = $row['session_token'];
		}

		$data = array('sid' => $phpbb_sid, 'last_active' => $this->time_now);
		$sql = 'UPDATE ' . $this->cogauth_session . ' SET ' . $this->db->sql_build_array('UPDATE', $data) .
			" WHERE session_token = '" . $this->session_token . "'";
		$this->db->sql_query($sql);
		$affected_rows = $this->db->sql_affectedrows();

		if ($affected_rows == 0)
		{
			error_log('store_sid - Failed to store SID');
		}

	}


	/**
	 * todo is this required?
	 */
	public function update_last_active()
	{
		$sid = $this->user->session_id;
		$data = array('last_active' => $this->time_now,);
		$sql = 'UPDATE ' . $this->cogauth_session . ' SET ' . $this->db->sql_build_array('UPDATE', $data) .
			" WHERE sid = '" . $sid . "'";
		$this->db->sql_query($sql);

	}

	/**
	 * @param string $session_id phpBB Session id
	 * @return int number of rows deleted
	 */
	public function phpbb_session_killed($session_id)
	{
		$sql = 'DELETE FROM ' . $this->cogauth_session . " WHERE sid = '" . $this->db->sql_escape($session_id) ."'";
		$this->db->sql_query($sql);
		return $this->db->sql_affectedrows();
	}

	/**
	 * @return int number of rows deleted
	 *
	 * todo this is not used, logic needs amending to delete when refresh token expires.
	 */
	public function delete_expired_sessions()
	{
		error_log('GC: delete_expired_sessions');
		$sql = 'DELETE FROM ' . $this->cogauth_session . " WHERE expires_at < " . $this->time_now;
		$this->db->sql_query($sql);
		return $this->db->sql_affectedrows();
	}
}
