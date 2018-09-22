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

use mrfg\cogauth\cognito\exception\TokenExpiryException;
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

	/**@var $String */
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

	/**
	 * Database Authentication Constructor
	 *
	 * @param	\phpbb\db\driver\driver_interface	$db
	 * @param	\phpbb\config\config 		        $config
	 * @param	\phpbb\user			                $user
     * @param   cognito_client_wrapper              $client,
     * @param   web_token                           $web_token
     * @param	string				                $cogauth_session
	 */
	public function __construct(
		\phpbb\db\driver\driver_interface $db,
		\phpbb\config\config $config,
		\phpbb\user $user,
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
    }


	/**
	 * @param string $user_id
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
			switch ($e->getAwsErrorCode())
			{
				case 'UserNotFoundException':
					$status = COG_USER_NOT_FOUND;
				break;
				default:
					$status = COG_ERROR;
					error_log($e->getAwsErrorMessage());
			}
		}

		return array(
			'status' => $status,
			'user_status' => '',
			'user_attributes' => ''
		);

	}


	/**
	 * @param string $user_id
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
		$username = $this->cognito_username($user_id);
		try {
			$response = $this->authenticate_user($username, $password);

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
					error_log('AWS ERROR (Auth): ' . $e->getAwsErrorMessage());
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
					error_log('Unhandled Authentication Error: ' . $e->getAwsErrorCode());
					error_log('Unhandled Authentication Error: ' . $e->getAwsErrorMessage());
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
	 * @param int	 $user_id - numeric user ID
	 * @param string $email
	 * @return array
	 * @throws /Exception
	 */
	public function migrate_user($nickname, $password, $user_id, $email)
	{
		error_log('User Migration --');
		$username = $this->cognito_username($user_id);

		$user_attributes = $this->build_attributes_array(array(
			'preferred_username' => utf8_clean_string($nickname),
			'email' => $email,
			'nickname' => $nickname,
			'email_verified' => "True"
		));

		$result = $this->admin_create_user($username,$password,$user_attributes);
		if ($result['status'] === COG_MIGRATE_SUCCESS)
		{
			try
			{
				$response = $this->authenticate_user($username, $password);
			}
			catch (CognitoIdentityProviderException $e)
			{
				error_log('Authentication: ErrorCode : ' . $e->getAwsErrorCode());
				throw $e;
			}

			return $this->admin_respond_to_auth_challenge($response, $password, $username);
		}
		return $result;
	}

	private function admin_respond_to_auth_challenge($response, $password, $username)
	{
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
					error_log('Challenge: ErrorCode : ' . $e->getAwsErrorCode());

					return array(
						'status' => COG_MIGRATE_FAIL,
						'error'  => $e->getAwsErrorCode(),
					);
				}
			break;

			default:
				error_log('Unhandled response');
				$response = null;
		}
		return  array(
			'status' => COG_MIGRATE_SUCCESS ,
			'error' => '',
		);
	}


	/**
	 * @param String $username
	 * @param String $password
	 * @return \Aws\Result
	 */
	private function authenticate_user($username, $password)
	{
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
	 * @param string $username phpBB username (Cognito nickname)
	 * @param string $password
	 * @param $user_attributes
	 * @return array
	 */
	private function admin_create_user($username, $password, $user_attributes)
	{
		try {
			$response = $this->client->AdminCreateUser(array(
				'UserPoolId' => $this->user_pool_id,
				'Username' => $username,
				'TemporaryPassword' => $password,
				'MessageAction' => 'SUPPRESS',
				'SecretHash' => $this->cognito_secret_hash($username),
				'UserAttributes' => $user_attributes,
			));
		}
		catch (CognitoIdentityProviderException $e) {
			error_log('Create User Fail: ' . $e->getAwsErrorCode());
			error_log('AWS Message: ' . $e->getAwsErrorMessage());
			switch ($e->getAwsErrorCode())
			{
				case 'InvalidPasswordException':
					return  array(
						'status' => COG_MIGRATE_FAIL,
						'error' => $e->getAwsErrorCode(),
					);
				break;

				default:
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
	 * @param string $access_token
	 * @param string $old_password
	 * @param string $new_password
	 * @return boolean True = Success, False = Fail
	 */
	public function change_password($access_token, $old_password, $new_password)
	{
		//TODO $this->verifyAccessToken($access_token);

		try {
			$this->client->change_password(array(
				'AccessToken' => $access_token,
				'PreviousPassword' => $old_password,
				'ProposedPassword' => $new_password,
			));
			return true;
		} catch (CognitoIdentityProviderException $e) {
			error_log('changePassword: ' . $e->getAwsErrorCode());
			// TODO Error handling
			return false;
		}
	}

	/**
	 * @param string $email
	 * @param string $access_token
	 * @return bool (True success, False fail)
	 */
	public function update_user_email($email, $access_token)
	{
        try {
            $this->web_token->verify_access_token($access_token);
        } catch (TokenVerificationException $e)
        {
            error_log('update_user_email: ' . $e->getMessage());
            return false;
        } catch (TokenExpiryException $e)
        {
            error_log('update_user_email: ' . $e->getMessage());
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
			// TODO Error handling
			error_log('update_user_email: ' . $e->getAwsErrorCode());
			return false;
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
			$username = $this->cognito_username($user_id);
			$this->admin_delete_user_internal($username);
			$user_attributes = $this->clean_attributes($user['user_attributes']); // remove non mutatable  attribute
			$result = $this->admin_create_user($username,$new_password,$user_attributes);
			if ($result['status'] == COG_MIGRATE_SUCCESS)
			{
				try
				{
					$response = $this->authenticate_user($username, $new_password);
					$this->admin_respond_to_auth_challenge($response, $new_password, $username);
				} catch (CognitoIdentityProviderException $e)
				{
					// TODO Error handling
					error_log('admin_change_password: ' . $e->getAwsErrorCode());
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
		$username = $this->cognito_username($user_id);
		try {
			$this->admin_delete_user_internal($username);
		} catch (CognitoIdentityProviderException $e)
		{
			switch ($e->getAwsErrorCode())
			{
				case 'UserNotFoundException': // No user to delete, do nothing
				break;
				default:
					// TODO Error handling
					error_log('admin_delete_user: ' . $e->getAwsErrorMessage() .', ' . $e->getAwsErrorCode());
			}
		}
	}

	/**
	 * @param integer $user_id phpBB user ID
	 */
	public function admin_enable_user($user_id)
	{
		error_log('Enable User');
		$username = $this->cognito_username($user_id);
		try {
			$this->client->adminEnableUser(array(
				'Username' => $username,
				'UserPoolId' => $this->user_pool_id));
		}
		catch (CognitoIdentityProviderException $e)
		{
			switch ($e->getAwsErrorCode())
			{
				case 'UserNotFoundException': // No user to enable, do nothing
				break;
				default:
					// TODO Error handling
					error_log('enable_user: ' . $e->getAwsErrorMessage() .', ' . $e->getAwsErrorCode());
			}
		}
	}

	/**
	 * @param integer $user_id phpBB user ID
	 */
	public function admin_disable_user($user_id)
	{
		error_log('Disable User');

		$username = $this->cognito_username($user_id);
		try {
			$this->client->admin_disable_user(array(
				'Username' => $username,
				'UserPoolId' => $this->user_pool_id));
		}
		catch (CognitoIdentityProviderException $e)
		{
			switch ($e->getAwsErrorCode())
			{
				case 'UserNotFoundException': // No user to disable, do nothing
				break;
				default:
					// TODO Error handling
					error_log('disable_user: ' . $e->getAwsErrorMessage() .', ' . $e->getAwsErrorCode());
			}
		}
	}

	/**
	 * Delete a user by user id
	 * @param string $username
	 */
	private function admin_delete_user_internal($username)
	{
		$this->client->admin_delete_user(
			array('Username' => $username,
				  'UserPoolId' => $this->user_pool_id)
		);
	}

	/**
	 * @param array $attributes
	 * @param string $user_id
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
			// TODO Error handling
			error_log('update_user_attributes: ' . $e->getAwsErrorCode());
			throw $e;
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
        // TODO Validate token
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
						  'expires_in'    => $auth_result['ExpiresIn'],
						  'id_token'      => $auth_result['IdToken'],
						  'refresh_token' => $auth_result['RefreshToken'],
						  'token_type'    => $auth_result['TokenType']);
			$sql = 'INSERT INTO ' . $this->cogauth_session . ' ' . $this->db->sql_build_array('INSERT', $data);
			$this->db->sql_query($sql);
		}
		else
		{
			error_log('Null access token?');
		}
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
	 * @param $user_id
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
