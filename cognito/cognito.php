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

	/**@var \phpbb\request\request $request Request object */
	protected $request;

	/** @var \phpbb\user */
	protected $user;

	/**@var \Aws\Sdk */
	protected $aws;

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

	/** @var \mrfg\cogauth\cognito\cognito_client_wrapper $aws_wrapper */
	protected $aws_wrapper;

	/**@var array $auth_result */
	protected $auth_result;

    /** @var \mrfg\cogauth\cognito\web_token */
    protected $web_token;

    /** @var \phpbb\log\log_interface $log */
    protected $log;

	/**
	 * Database Authentication Constructor
	 *
	 * @param	\phpbb\db\driver\driver_interface	$db
	 * @param	\phpbb\config\config 		        $config
	 * @param	\phpbb\user			                $user
	 * @param 	\phpbb\log\log_interface			$log
     * @param   cognito_client_wrapper              $client,
     * @param   web_token                           $web_token
     * @param	string				                $cogauth_session
	 */
	public function __construct(
		\phpbb\db\driver\driver_interface $db,
		\phpbb\config\config $config,
		\phpbb\user $user,
		\phpbb\log\log_interface $log,
        cognito_client_wrapper $client,
        web_token $web_token,
        $cogauth_session)
	{
		$this->db = $db;
		$this->config = $config;
		$this->user = $user;
		$this->cogauth_session =$cogauth_session;

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
	 * @param int $user_id phpBB user Id
	 * @return array
	 *
	 * User Status UNCONFIRMED | CONFIRMED | ARCHIVED | COMPROMISED | UNKNOWN | RESET_REQUIRED | FORCE_CHANGE_PASSWORD
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
	 * @param int $user_id phpBB User ID
	 * @param string $password
	 *
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
	public function authenticate($user_id, $password)
	{
		try {
			$response = $this->authenticate_user($user_id, $password);

			if (isset($response['AuthenticationResult']))
			{
				// Successful login.
				// Store the result locally. The result will be stored in the database once the logged in
				// session has started  (the SID changes so we cant store it in the DB yet).
				$this->auth_result = $response['AuthenticationResult'];
				return array(
					'status'    => COG_LOGIN_SUCCESS,
					'response'  => $response['AuthenticationResult']
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
					//error_log('AWS ERROR (Auth): ' . $e->getAwsErrorMessage());
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
				//error_log('Unhandled response');
				$user_ip = (empty($this->user->ip)) ? '' : $this->user->ip;
				$this->log->add('critical' ,$user_id , $user_ip, 'COGAUTH_UNEXPECTED_CHALLENGE', time(),
					array('admin_respond_to_auth_challenge', $response['ChallengeName']));

				$response = null;
		}
		return  array(
			'status' => COG_MIGRATE_SUCCESS ,
			'error' => '',
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

			//error_log('Create User Fail: ' . $e->getAwsErrorCode());
			//error_log('AWS Message: ' . $e->getAwsErrorMessage());
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
	 * @param \Aws\CognitoIdentityProvider\Exception\CognitoIdentityProviderException $e
	 * @param int $user_id 			phpBB user ID
	 * @param string $action		Action Message
	 * @param boolean $ignore_use_not_found	Don't log UserNotFoundException
	 * @return bool returns true if UserNotFoundException AND UserNotFound not ignored. Otherwise false.
	 */
	private function handleCognitoIdentityProviderException($e, $user_id, $action, $ignore_use_not_found = false)
	{
		if ($e->getAwsErrorCode() == 'UserNotFoundException' and $ignore_use_not_found)
		{
			// Can only happen if the Cognito user is deleted after the user logs in.
			return true;
		}
		$user_ip = (empty($this->user->ip)) ? '' : $this->user->ip;
		$this->log->add('critical' ,$user_id , $user_ip, 'COGAUTH_UNEXPECTED_ERROR', time(),
			array($action, $e->getAwsErrorCode(), $e->getAwsErrorMessage()));
		return false;
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
	 * @return string Cognito Access Token
	 */
	public function get_access_token()
	{
		$sid = $this->user->session_id;
		$sql = 'SELECT access_token FROM ' . $this->cogauth_session . " WHERE sid = '" . $this->db->sql_escape($sid) ."'";
		$result = $this->db->sql_query($sql);
		$row = $this->db->sql_fetchrow($result);
		$this->db->sql_freeresult($result);
		return $row['access_token'];
	}

	/**
	 * @param string $session_id  phpBB SID
	 */
	public function store_auth_result($session_id)
	{
		$auth_result = $this->auth_result;
		if ($auth_result['AccessToken'])
		{
			$data = array('sid'           => $session_id,
						  'access_token'  => $auth_result['AccessToken'],
						  'expires_at'    => $auth_result['ExpiresIn'] +time(),
						  'id_token'      => $auth_result['IdToken'],
						  'refresh_token' => $auth_result['RefreshToken'],
						  'token_type'    => $auth_result['TokenType']);
			$sql = 'INSERT INTO ' . $this->cogauth_session . ' ' . $this->db->sql_build_array('INSERT', $data);
			$this->db->sql_query($sql);
		}
	}

	/**
	 * @param string $session_id phpBB Session id
	 * @return int nuber of rows deleted
	 */
	public function phpbb_session_killed($session_id)
	{
		$sql = 'DELETE FROM ' . $this->cogauth_session . " WHERE sid = '" . $this->db->sql_escape($session_id) ."'";
		$this->db->sql_query($sql);
		return $this->db->sql_affectedrows();
	}

	/**
	 * @return int number of rows deleted
	 */
	public function delete_expired_sessions()
	{
		$sql = 'DELETE FROM ' . $this->cogauth_session . " WHERE expires_at < " . time();
		$this->db->sql_query($sql);
		return $this->db->sql_affectedrows();
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
	 * @return string
	 */
	public function cognito_username($user_id)
	{
		return 'u' . str_pad($user_id, 6, "0", STR_PAD_LEFT);
	}


	/**
	 * @param string $username
	 *
	 * @return string
	 */
	public function cognito_secret_hash($username)
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

}
