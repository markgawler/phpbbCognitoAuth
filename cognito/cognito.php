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
use InvalidArgumentException;
use mrfg\cogauth\jwt\exception\TokenVerificationException;

define('COG_LOGIN_SUCCESS', 1);
define('COG_LOGIN_NO_AUTH', 2);
define('COG_USER_NOT_FOUND', 3);
define('COG_LOGIN_ERROR_PASSWORD',4);
define('COG_USER_FOUND',7);
define('COG_LOGIN_DISABLED', 8);
define('COG_LOGIN_ERROR_ATTEMPTS', 9);

define('COG_CONFIGURATION_ERROR',98);
define('COG_ERROR',99);

define('COG_MIGRATE_SUCCESS',20);
define('COG_MIGRATE_FAIL', 21);

class cognito
{
	/** @var  \Aws\CognitoIdentityProvider\CognitoIdentityProviderClient */
	protected $client;

	/** @var \Aws\Sdk $aws_sdk */
	protected $aws_sdk;

	/**@var \phpbb\config\config $config Config object */
	protected $config;

	/**@var \phpbb\request\request_interface $request Request object */
	protected $request;

	/** @var \phpbb\user */
	protected $user;

	/**@var $string */
	protected $user_pool_id;

	/**@var $string */
	protected $client_id;

	/** @var String */
	protected $client_secret;

	/** @var string */
	protected $region;

	/**@var array $auth_response */
	protected $auth_response;

    /** @var \mrfg\cogauth\cognito\web_token_phpbb */
    protected $web_token;

    /** @var \phpbb\log\log_interface $log */
    protected $log;

	/**	@var  int $user_id  The phpBB user ID */
	protected $user_id = 0;

	/** @var int $time_now  */
	protected $time_now;

	/* @var bool */
	protected $autologin;

	/** @var \mrfg\cogauth\cognito\user $cognito_user */
	protected $cognito_user;

	/** @var \mrfg\cogauth\cognito\auth_result $auth_result */
	protected $auth_result;

	/** @var \phpbb\language\language  */
	protected $language;

	/**
	 * Constructor
	 *
	 * @param	\phpbb\config\config                $config
	 * @param	\phpbb\user                         $user
	 * @param	\phpbb\language\language            $language
	 * @param   \phpbb\request\request_interface    $request
	 * @param   \phpbb\log\log_interface            $log
     * @param   \mrfg\cogauth\cognito\web_token_phpbb $web_token
	 * @param 	\mrfg\cogauth\cognito\user          $cognito_user
	 * @param	\mrfg\cogauth\cognito\auth_result	$authentication
	 * @param 	\Aws\Sdk							$aws_sdk
	 */
	public function __construct(
		\phpbb\config\config $config,
		\phpbb\user $user,
		\phpbb\language\language $language,
		\phpbb\request\request_interface $request,
		\phpbb\log\log_interface $log,
		\mrfg\cogauth\cognito\web_token_phpbb $web_token,
		\mrfg\cogauth\cognito\user $cognito_user,
		\mrfg\cogauth\cognito\auth_result $authentication,
		\Aws\Sdk $aws_sdk)
	{
		$this->aws_sdk = $aws_sdk;
		$this->config = $config;
		$this->user = $user;
		$this->language = $language;
		$this->request = $request;
		$this->cognito_user = $cognito_user;
		$this->auth_result = $authentication;

		$this->time_now = time();

		$this->user_pool_id = $config['cogauth_pool_id'];
		$this->client_id = $config['cogauth_client_id'];
		$this->client_secret = $config['cogauth_client_secret'];
        $this->region = $config['cogauth_aws_region'];

        $this->auth_response = array();
		$this->client = $this->create_identity_provider(
			$this->region, $config['cogauth_aws_key'], $config['cogauth_aws_secret']);
		$this->web_token = $web_token;
        $this->log = $log;
    }

    public function update_credentials($region, $key, $secret)
	{
		$this->region = $region;
		$this->config->set('cogauth_aws_region', $region);
		$this->config->set('cogauth_aws_key', $key);
		$this->config->set('cogauth_aws_secret', $secret);
		$this->client = $this->create_identity_provider($region, $key, $secret);
	}

	/**
	 * @param string $region
	 * @param string $key
	 * @param string $secret
	 *
	 * @return  \Aws\CognitoIdentityProvider\CognitoIdentityProviderClient
	 */
	private function create_identity_provider($region, $key, $secret)
	{
		$args = array(
			'credentials' => array(
				'key' => $key,
				'secret' => $secret,
			),
			'version' => '2016-04-18',
			'region' =>  $region,
		);
		//todo: is there a delete to call id client is not null?
		return $this->aws_sdk->createCognitoIdentityProvider($args);
	}

	/** Update client_credentials
	 *
	 * @param string $client_id
	 * @param string $client_secret
	 */
	public function update_client_credentials($client_id, $client_secret = '')
	{
		$this->client_id = $client_id;
		$this->config->set('cogauth_client_id', $client_id);
		$this->client_secret = $client_secret;
		$this->config->set('cogauth_client_secret', $client_secret);
	}

	/**
	 * Update client_id
	 * @param string $user_pool_id
	 */
	public function update_user_pool_id($user_pool_id)
	{
		$this->user_pool_id = $user_pool_id;
		$this->config->set('cogauth_pool_id', $user_pool_id);

		// Update keys when User Pool changed
		$this->web_token->download_jwt_web_keys(true);

	}


	/**
	 * @param int $user_id phpBB User ID
	 * @param string $password
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
	 *      COG_CONFIGURATION_ERROR
	 *
	 */
	public function authenticate($user_id, $password)
	{
		try {
			$response = $this->authenticate_user($user_id, $password);
			$token = false;
			if (isset($response['AuthenticationResult']))
			{
				// Successful login (maybe!).
				// The login will still fail if the claims in the id_token are invalid or the phpBB_user_id attribute is
				// null / missing  //todo validate the phpbb_user_id and claims
				// Store the result locally. The result will be stored in the database once the logged in
				// session has started  (the SID changes so we cant store it in the DB yet).
				//$token = $this->authentication->get_session_token();
				//$this->session_token = $token;
				$result = $this->auth_result->validate_and_store_auth_response($response['AuthenticationResult']);
				if ($result instanceof validation_result)
				{
					// todo Test for new user (this would only happen if the user pool had users before
					// todo the hosted UI was enabled for the user pool.
					$token = $result->cogauth_token;
				}
		}

			if ($token)
			{
				return array(
					'status'    => COG_LOGIN_SUCCESS,
					'response'  => $response['AuthenticationResult'],
					'session_token' => $token
				);
			}
				return array(
					'status'    => COG_LOGIN_NO_AUTH,
					'response'  => $response['ChallengeName']
			);

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

						case 'Unable to verify secret hash for client ' . $this->client_id:
							$status = COG_CONFIGURATION_ERROR;
							$user_ip = (empty($this->user->ip)) ? '' : $this->user->ip;
							$this->log->add('critical' ,$user_id , $user_ip, 'COGAUTH_CONFIGURATION_ERROR', $this->time_now,
								array('Authenticate', $e->getAwsErrorCode(), $e->getAwsErrorMessage()));
						break;

						default:
							$status = COG_LOGIN_ERROR_PASSWORD;
					}
				break;

				default;
					$status = COG_LOGIN_NO_AUTH;
					$this->handle_cognito_identity_provider_exception($e, $user_id, 'authenticate');
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
		$username = $this->cognito_user->get_cognito_username($user_id);
		$response = $this->client->AdminInitiateAuth(array(
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

	public function refresh_access_token($refresh_token, $user_id)
	{
		$username = $this->cognito_user->get_cognito_username($user_id);
		$response = $this->client->adminInitiateAuth(array(
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
	 * @param \Aws\CognitoIdentityProvider\Exception\CognitoIdentityProviderException $e
	 * @param int $user_id 			phpBB user ID
	 * @param string $action		Action Message inserted in to error log for debugging
	 * @param boolean $ignore_use_not_found	Don't log UserNotFoundException
	 * @return bool returns true if UserNotFoundException AND UserNotFound not ignored. Otherwise false.
	 */
	protected function handle_cognito_identity_provider_exception($e, $user_id, $action, $ignore_use_not_found = false)
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
			'email_verified' => "True",
			'custom:phpbb_user_id' => $user_id,
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
				$this->handle_cognito_identity_provider_exception($e, $user_id, 'migrate_user - authenticate_user');
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
		$username = $this->cognito_user->get_cognito_username($user_id);

		try {
			$response = $this->client->adminCreateUser(array(
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
					$this->handle_cognito_identity_provider_exception($e, $user_id, 'admin_create_user');
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
		$username = $this->cognito_user->get_cognito_username($user_id);
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
					$response = $this->client->adminRespondToAuthChallenge($params);
					if (isset($response['AuthenticationResult']))
					{
						// login success, store the result locally. The result will be stored in the database once the logged in
						// session has started  (the SID changes so we cant store it in the DB yet).
						$this->auth_response = $response['AuthenticationResult'];
					}
				}
				catch (CognitoIdentityProviderException $e)
				{
					$this->handle_cognito_identity_provider_exception($e, $user_id, 'admin_respond_to_auth_challenge');

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
		$username = $this->cognito_user->get_cognito_username($user_id);
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
			$this->client->changePassword(array(
				'AccessToken' => $access_token,
				'PreviousPassword' => $old_password,
				'ProposedPassword' => $new_password,
			));
			return true;
		} catch (CognitoIdentityProviderException $e) {
			return $this->handle_cognito_identity_provider_exception($e,$user_id,'change_password', true);
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
		$username = $this->cognito_user->get_cognito_username($user_id);
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
			$this->client->updateUserAttributes(array(
					'AccessToken'    => $access_token,
					'UserAttributes' => $attr,
			));
			return true;
		} catch (CognitoIdentityProviderException $e)
		{
			return $this->handle_cognito_identity_provider_exception($e,$user_id,'update_user_email', true);
		}
	}

	/**
	 * Admin only Change user password function. This is a hack as the user is deleted and recreated
	 * @param integer $user_id phpBB User ID
	 * @param $new_password
	 *
	 * todo: uae AdminSetUserPassword
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
					$this->handle_cognito_identity_provider_exception($e,$user_id,'admin_change_password');
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
		$username = $this->cognito_user->get_cognito_username($user_id);
		try
		{
			$response = $this->client->adminGetUser(array(
				"Username"   => $username,
				"UserPoolId" => $this->user_pool_id
			));
			return array(
				'status' => COG_USER_FOUND,
				'user_status' => $response['UserStatus'],
				'user_attributes' => $response['UserAttributes']
			);

		} catch (CognitoIdentityProviderException $e) {
			$user_not_found = $this->handle_cognito_identity_provider_exception($e,$user_id,'get_user', true);
			if ($user_not_found)
			{
				$status = COG_USER_NOT_FOUND;
			}
			else{
				$status = COG_ERROR;
			}
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
		$user_id = $this->cognito_user->get_cognito_username($user_id);

		$this->client->adminDeleteUser(
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
			'Username'       => $this->cognito_user->get_cognito_username($user_id),
			'UserPoolId'     => $this->user_pool_id,
		);
		try {
			$this->client->adminUpdateUserAttributes($data);
		} catch (CognitoIdentityProviderException $e)
		{
			$this->handle_cognito_identity_provider_exception($e,$user_id,'update_user_attributes');
		}
	}

	/**
	 * @param string $user_name - Cognito Username
	 * @param string $email
	 * @param string $nickname - Human Friendly Username (will be the same as  Cognito Username for Hosted UI created users)
	 *
	 * @since 1.0
	 */
	public function normalize_user($user_name, $email, $nickname = null)
	{

		if (empty($nickname))
		{
			$nickname = $user_name;
		}
		$attributes = array(
			'preferred_username' => utf8_clean_string($nickname),
			'email' => utf8_strtolower($email),
			'nickname' => $nickname,
		);
		$data = array(
			'UserAttributes' => $this->build_attributes_array($attributes),
			'Username'       => $user_name,
			'UserPoolId'     => $this->user_pool_id,
		);
		try {
			$this->client->adminUpdateUserAttributes($data);
		} catch (CognitoIdentityProviderException $e)
		{
			$this->handle_cognito_identity_provider_exception($e, 0,'normalize_user');
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
			$this->handle_cognito_identity_provider_exception($e,$user_id,'admin_delete_user',true);
		}
	}

	/**
	 * @param integer $user_id phpBB user ID
	 */
	public function admin_enable_user($user_id)
	{
		$username = $this->cognito_user->get_cognito_username($user_id);
		try {
			$this->client->adminEnableUser(array(
				'Username' => $username,
				'UserPoolId' => $this->user_pool_id));
		}
		catch (CognitoIdentityProviderException $e)
		{
			// 'UserNotFoundException': // No user to enable, do nothing
			$this->handle_cognito_identity_provider_exception($e,$user_id,'admin_enable_user',true);
		}
	}

	/**
	 * @param integer $user_id phpBB user ID
	 */
	public function admin_disable_user($user_id)
	{
		$username = $this->cognito_user->get_cognito_username($user_id);
		try {
			$this->client->adminDisableUser(array(
				'Username' => $username,
				'UserPoolId' => $this->user_pool_id));
		}
		catch (CognitoIdentityProviderException $e)
		{
			// 'UserNotFoundException': // No user to disable, do nothing
			$this->handle_cognito_identity_provider_exception($e,$user_id,'admin_disable_user',true);
		}
	}


	/**
	 * Create a new App Client for a User Pool
	 * @param string $name
	 * @param string $user_pool_id
	 *
	 * @return \Aws\Result
	 *
	 * @since 1.0
	 */
	protected function create_user_pool_client($name, $user_pool_id)
	{
		$params =  array_merge(
			$this->get_user_pool_client_default_parameters(),
			array('ClientName' => $name,
				  'UserPoolId' => $user_pool_id,
				  'GenerateSecret' => true,
				  'ReadAttributes' => array('custom:phpbb_user_id','email','email_verified','nickname','preferred_username'),
				  //'WriteAttributes' => array('custom:phpbb_user_id','email','email_verified','nickname','preferred_username')
				));
		return $this->client->createUserPoolClient($params);
	}

	/**
	 * Set the Refresh Token Expiration for the App Client
 	 * @param integer $days (0 = use current config value)
	 * @param string $client_id (null is the client ID is not changing)

	 * @return \Aws\Result | string  containing Aws/Result or String containing error message
	 *
	 * @since 1.0
	 */
	public function update_user_pool_client($days = 0, $client_id = null)
	{
		if ($client_id == null)
		{
			$client_id =$this->client_id;
		}
		$this->update_max_autologin_time($days);
		try
		{
			$params =  array_merge(
				$this->get_user_pool_client_default_parameters(),
				array('ClientId' => $client_id,
					));
			$pool_client =  $this->client->updateUserPoolClient($params);
			$this->update_client_credentials(
				$pool_client['UserPoolClient']['ClientId'],
				$pool_client['UserPoolClient']['ClientSecret']);
			return $pool_client;
		}
		catch (CognitoIdentityProviderException | InvalidArgumentException $e)
		{
			return $this->handle_identity_provider_exception_for_acp($e);
		}
	}

	/**
	 * @return array UpdateUserPool parameters.
	 */
	protected function get_user_pool_client_default_parameters()
	{
		$days = $this->config['max_autologin_time'];

		$result = array(
			'UserPoolId'           => $this->user_pool_id,
			'RefreshTokenValidity' => (int) $days,
			'ExplicitAuthFlows'    => array('ADMIN_NO_SRP_AUTH'),
		);

		if ($this->config['cogauth_hosted_ui'])
		{
			$prefix = $this->config['server_protocol'] . $this->config['server_name'] . $this->config['script_path'];

			return array_merge($result, array(
				'CallbackURLs'      => array($prefix . '/app.php/cogauth/auth/callback'),
				'LogoutURLs'        => array($prefix . '/app.php/cogauth/auth/signout'),
				'AllowedOAuthFlows' => array('code', 'implicit'),        // code | implicit | client_credentials
				//'SupportedIdentityProviders' => array('COGNITO','Facebook'),//COGNITO, Facebook, Google and LoginWithAmazon.
				'SupportedIdentityProviders' => array('COGNITO'),//COGNITO, Facebook, Google and LoginWithAmazon.
				'AllowedOAuthFlowsUserPoolClient' => true,
				'AllowedOAuthScopes'   => array('email','openid','profile'),			//"phone", "email", "openid", and "Cognito".
					// 'profile' - required for custom attribute to appear in the id_token (hosted ui login requires this)
			));
		} else
		{
			return $result;
		}
	}

	/**
	 * @return string uri of hosted ui for User Pool App Client
	 */
	public function get_hosted_ui_uri()
	{
		$callback =  $this->config['server_protocol'] . $this->config['server_name'] . $this->config['script_path'] . '/app.php/cogauth/auth/callback';
		$uri = 'https://' . $this->config['cogauth_hosted_ui_domain'] . '/login?response_type=code&client_id=' . $this->client_id . '&redirect_uri=' .$callback;
		return $uri;
	}

	/**
	 * @param integer $days  validity time in days of autologin key (0 = use current config value)
	 * @return integer
	 */
	protected function update_max_autologin_time($days)
	{
		if ( $days > 0 )
		{
			$this->config->set('max_autologin_time', $days);
		} else {
			$days = $this->config['max_autologin_time'];
		}
		return (int) $days;
	}

	/**
	 * @return \Aws\Result | string containing Aws/Result or String containing error message
	 */
	public function describe_user_pool_client()
	{
		if (strlen($this->client_id) >= 1 or strlen($this->user_pool_id >= 1))
		{
			try
			{
				$result = $this->client->describeUserPoolClient(array(
					'ClientId'   => $this->client_id,
					'UserPoolId' => $this->user_pool_id));
				return $result;
			}
			catch (CognitoIdentityProviderException | InvalidArgumentException $e)
			{
				return $this->handle_identity_provider_exception_for_acp($e);
			}
		} else {
			return $this->language->lang('COGAUTH_ACP_NOT_CONFIGURED');
		}

	}

	/**
	 * @return \Aws\Result | string  containing Aws/Result or String containing error message
	 */
	public function describe_user_pool()
	{
		try{
			$result = $this->client->describeUserPool(array(
				'UserPoolId' => $this->user_pool_id
			));

			return $result;
		}
		catch (CognitoIdentityProviderException | InvalidArgumentException $e)
		{
			return $this->handle_identity_provider_exception_for_acp($e);
		}
	}

	/**
	 * @param integer $max_results
	 * @return \Aws\Result | string containing Aws/Result or String containing error message
	 */
	public function list_user_pools($max_results = 1)
	{
		try{
			$result = $this->client->listUserPools(array(
				'MaxResults' => $max_results
			));
			return $result;
		}
		catch (CognitoIdentityProviderException | InvalidArgumentException $e)
		{
			return $this->handle_identity_provider_exception_for_acp($e);
		}
	}

	/**
	 * @param string $name The name of the user pool to create
	 *
	 * @return \Aws\Result | string containing Aws/Result or String containing error message
	 * @since 1.0
	 */
	public function create_user_pool($name)
	{
		$this->config->set('cogauth_hosted_ui',0);
		try{
			$user_pool = $this->client->createUserPool(array(
				'Schema' => array(
					array(
						'Name' => 'email',
						'AttributeDataType' => 'String',
						'DeveloperOnlyAttribute' => false,
						'Mutable' => true,
						'Required' => true,
						'StringAttributeConstraints' => array('MaxLength' => '2028', 'MinLength' => '0')),
					$this->get_custom_attribute(),
				),
				'PoolName' => $name,
				'AliasAttributes' => array('email', 'preferred_username'),
				'AutoVerifiedAttributes' => array('email'),
				'Policies' => array('PasswordPolicy' => array(
							'MinimumLength' => (int) $this->config['min_pass_chars'],
            				//todo: translate config('pass_complex') in to the following
            				'RequireLowercase' => true,
            				'RequireNumbers' => false,
            				'RequireSymbols' => false,
            				'RequireUppercase' => true,
            				'TemporaryPasswordValidityDays' => 7,
				)),
			));

			$pool_client = $this->create_user_pool_client($name . '_app_client', $user_pool['UserPool']['Id']);
			$this->update_client_credentials(
				$pool_client['UserPoolClient']['ClientId'],
				$pool_client['UserPoolClient']['ClientSecret']);

			return $user_pool;
		}
		catch (CognitoIdentityProviderException | InvalidArgumentException $e)
		{
			return $this->handle_identity_provider_exception_for_acp($e);
		}
	}

	/**
	 *
	 * @return \Aws\Result | string containing Aws/Result or String containing error message
	 * @since 1.0
	 */
	public function add_custom_attribute()
	{
		try{
			$result = $this->client->addCustomAttributes(array(
				'CustomAttributes' => array($this->get_custom_attribute()),
				'UserPoolId' => $this->user_pool_id,
			));
			return $result;
		}
		catch ( CognitoIdentityProviderException $e)
		{
			return $this->handle_identity_provider_exception_for_acp($e);
		}
	}

	protected function get_custom_attribute()
	{
		return array(
			'Name' => 'phpbb_user_id',
			'AttributeDataType' => 'Number',
			'DeveloperOnlyAttribute' => false,
			'Mutable' => true,
			'Required' => false,
			'NumberAttributeConstraints' => array('MinValue' => '0', 'MaxValue' => '99999999'));
	}

	/**
	 * @param $e CognitoIdentityProviderException
	 *
	 * @return string Error message to display in ACP
	 *
	 * @since 1.0
	 */
	protected function handle_identity_provider_exception_for_acp($e)
	{
		if ($e instanceof CognitoIdentityProviderException)
		{
			$message = $e->getAwsErrorMessage();
			if ( empty($message)) {
				$message = $e->getMessage() . '<br>' . $this->language->lang('COGAUTH_ACP_CHECK_REGION');
			}
		} else {
			$message = $e->getMessage();
		}

		return $message;
	}
}
