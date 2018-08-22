<?php
/**
 * Created by PhpStorm.
 * User: mrfg
 * Date: 19/08/18
 * Time: 20:00
 */

namespace mrfg\cogauth\cognito;
use Aws\CognitoIdentityProvider\Exception\CognitoIdentityProviderException;


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

	/**
	 * @var \phpbb\config\config $config Config object
	 */
	protected $config;

	/**
	 * @var \phpbb\request\request $request Request object
	 */
	protected $request;

	/**
	 * @var \phpbb\user
	 */
	protected $user;

	/**
	 * @var \Aws\Sdk
	 */
	protected $aws;

	/**
	 * @var  \Aws\CognitoIdentityProvider\CognitoIdentityProviderClient
	 */
	protected $client;

	/**
	 * @var $String
	 */
	protected $user_pool_id;

	/**
	 * @var $string
	 */
	protected $client_id;

	/**
	 * @var String
	 */
	protected $client_secret;

	/**
	 * @var \phpbb\db\driver\driver_interface
	 */
	protected $db;

	/**
	 * @var string
	 */
	protected $cogauth_session;

	/**
	 * @var array $auth_result
	 */
	protected $auth_result;

	/**
	 * Database Authentication Constructor
	 *
	 * @param	\phpbb\db\driver\driver_interface		$db
	 * @param	\phpbb\config\config 		$config
	 * @param	\phpbb\user			$user
	 * @param	string				$cogauth_session
	 */
	public function __construct(
		\phpbb\db\driver\driver_interface $db,
		\phpbb\config\config $config,
		\phpbb\user $user,
		$cogauth_session)
	{
		$this->db = $db;
		$this->config = $config;
		$this->user = $user;
		$this->cogauth_session =$cogauth_session;

		$this->user_pool_id = $config['cogauth_pool_id'];
		$this->client_id = $config['cogauth_client_id'];
		$this->client_secret = $config['cogauth_client_secret'];

		$this->aws = new \Aws\Sdk(
			array(
				'credentials' => array(
					'key' => $config['cogauth_aws_key'],
					'secret' => $config['cogauth_aws_secret'],
				),
				'version' => '2016-04-18',
				'region' => $config['cogauth_aws_region'],
			)
		);
		$this->client = $this->aws->createCognitoIdentityProvider();
		$this->auth_result = array();
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
			$response = $this->client->AdminGetUser(array(
				"Username"   => $username,
				"UserPoolId" => $this->user_pool_id
			));
			return array(
				'status' => COG_USER_FOUND,
				'user_status' => $response['UserStatus']
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
			'user_status' => ''
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
			$response = $this->client->adminInitiateAuth(array(
				'AuthFlow' => 'ADMIN_NO_SRP_AUTH',
				'AuthParameters' => array(
					'USERNAME' => $username,
					'PASSWORD' => $password,
					'SECRET_HASH' => $this->cognitoSecretHash($username),
				),
				'ClientId' => $this->client_id,
				'UserPoolId' => $this->user_pool_id,
			));

			if (isset($response['AuthenticationResult']))
			{
				// login success, store the result locally. The result will be stored in the database once the logged in
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
			//$this->handleAuthenticateResponse($response->toArray()));

		} catch (CognitoIdentityProviderException $e) {
			switch ($e->getAwsErrorCode())
			{
				case 'UserNotFoundException':
					$status = COG_USER_NOT_FOUND;
				break;
				case 'NotAuthorizedException':
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
	 * @param string $username
	 * @param string $password
	 * @param string $user_id
	 * @param string $email
	 * @return array
	 * @throws /Exception
	 */
	public function migrate_user($username, $password, $user_id, $email)
	{
		error_log('User Migration --');
		$cog_user = $this->cognito_username($user_id);

		$user_attributes = $this->buildAttributesArray(array(
			'preferred_username' => utf8_clean_string($username),
			'email' => $email,
			'nickname' => $username,
		));

		try {
			//$response =
			$this->client->AdminCreateUser(array(
				'UserPoolId' => $this->user_pool_id,
				'Username' => $cog_user,
				'TemporaryPassword' => $password,
				'MessageAction' => 'SUPPRESS',
				'SecretHash' => $this->cognitoSecretHash($cog_user),
				'UserAttributes' => $user_attributes,
			));
		}
		catch (CognitoIdentityProviderException $e) {
			error_log('Migration Fail: ' . $e->getAwsErrorCode());
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

		try {
			//TODO Duplicate code here and Authenticate :-(
			$response = $this->client->adminInitiateAuth(array(
				'AuthFlow' => 'ADMIN_NO_SRP_AUTH',
				'AuthParameters' => array(
					'USERNAME' => $cog_user,
					'PASSWORD' => $password,
					'SECRET_HASH' => $this->cognitoSecretHash($cog_user),
				),
				'ClientId' => $this->client_id,
				'UserPoolId' => $this->user_pool_id,
			));

			//return $this->handleAuthenticateResponse($response->toArray());
		} catch (CognitoIdentityProviderException $e) {
			error_log('Authentication: ErrorCode : ' . $e->getAwsErrorCode());
			throw $e;

		}

		switch ($response['ChallengeName'])
		{
			case 'NEW_PASSWORD_REQUIRED':
				$params = array('ChallengeName'      => "NEW_PASSWORD_REQUIRED",
								'ClientId'           => $this->client_id,
								'UserPoolId'         => $this->user_pool_id,
								'ChallengeResponses' => array(
									'NEW_PASSWORD'	=> $password,
									'USERNAME'   	=> $cog_user,
									'SECRET_HASH'	=> $this->cognitoSecretHash($cog_user)),
								'Session' => $response['Session']
				);
				try
				{
					$response = $this->client->adminRespondToAuthChallenge($params);
					if (isset($response['AuthenticationResult']))
					{
						// login success, store the result locally. The result will be stored in the database once the logged in
						// session has started  (the SID changes so we cant store it in the DB yet).
						$this->auth_result = $response['AuthenticationResult'];
					}
				} catch (CognitoIdentityProviderException $e) {
					error_log('Challenge: ErrorCode : ' . $e->getAwsErrorCode());

					return  array(
						'status' => COG_MIGRATE_FAIL,
						'error' => $e->getAwsErrorCode(),
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
	 * @param string $access_token
	 * @param string $old_password
	 * @param string $new_password
	 * @throws \Exception
	 * throws TokenExpiryException
	 * throws TokenVerificationException
	 */
	public function changePassword($access_token, $old_password, $new_password)
	{
		//TODO $this->verifyAccessToken($access_token);

		try {
			$this->client->changePassword(array(
				'AccessToken' => $access_token,
				'PreviousPassword' => $old_password,
				'ProposedPassword' => $new_password,
			));
		} catch (CognitoIdentityProviderException $e) {
			error_log($e->getAwsErrorCode());
			throw $e;
			// TODO CognitoResponseException::createFromCognitoException($e);
		}
	}



	/**
	 *
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

	public function store_auth_result($session_id)
	{
		$auth_result = $this->auth_result;
		$data = array('sid'           => $session_id,
					  'access_token'  => $auth_result['AccessToken'],
					  'expires_in'    => $auth_result['ExpiresIn'],
					  'id_token'      => $auth_result['IdToken'],
					  'refresh_token' => $auth_result['RefreshToken'],
					  'token_type'    => $auth_result['TokenType']);
		$sql = 'INSERT INTO ' . $this->cogauth_session . ' ' . $this->db->sql_build_array('INSERT', $data);
		$this->db->sql_query($sql);
	}

	/**
	 * @param array $attributes
	 * @return array
	 */
	private function buildAttributesArray(array $attributes)
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
	public function cognitoSecretHash($username)
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
}