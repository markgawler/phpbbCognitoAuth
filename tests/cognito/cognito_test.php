<?php
/**
 *
 * AWS Cognito Authentication. An extension for the phpBB Forum Software package.
 *
 * @copyright (c) 2018, Mark Gawler
 * @license GNU General Public License, version 2 (GPL-2.0)
 *
 * Date: 14/09/18
 *
 * Cognito interface test
 */

namespace mrfg\cogauth\tests\cognito;
use Aws\CognitoIdentityProvider\Exception\CognitoIdentityProviderException;
use mrfg\cogauth\cognito\validation_result;

/** @noinspection PhpIncludeInspection */
include_once __DIR__ . '/../../vendor/autoload.php';

class cognito_test extends \phpbb_test_case
{
    /** @var $user \phpbb\user */
    protected $user;

    /** @var $language \phpbb\language\language */
    protected $language;

    /** @var $cognito_client \phpbb\config\config */
    protected $config;

	/** @var $cognito_user \mrfg\cogauth\cognito\user|\PHPUnit_Framework_MockObject_MockObject */
	protected $cognito_user;

	/** @var $web_token \mrfg\cogauth\cognito\web_token_phpbb|\PHPUnit_Framework_MockObject_MockObject */
	protected $web_token;

	/** @var $authentication \mrfg\cogauth\cognito\auth_result|\PHPUnit_Framework_MockObject_MockObject */
	protected $authentication;

	/** @var $client \mrfg\cogauth\cognito\cognito */
	protected $cognito;

	/** @var $log \phpbb\log\log_interface |\PHPUnit_Framework_MockObject_MockObject */
	protected $log;

	/** @var $request \phpbb\request\request_interface */
	protected $request;

	/** @var \Aws\CognitoIdentityProvider\CognitoIdentityProviderClient | \PHPUnit_Framework_MockObject_MockObject $provider */
	protected $provider;


    public function setUp()
    {
        parent::setUp();

		$this->user = $this->getMockBuilder('\phpbb\user')
			->disableOriginalConstructor()
			->getMock();

		$this->language = $this->getMockBuilder('\phpbb\language\language')
			->disableOriginalConstructor()
			->getMock();

        $this->config = $this->getMockBuilder('\phpbb\config\config')
            ->disableOriginalConstructor()
            ->getMock();

        $this->web_token = $this->getMockBuilder('\mrfg\cogauth\cognito\web_token_phpbb')
            ->disableOriginalConstructor()
            ->setMethods(array('verify_access_token'))
            ->getMock();

		$this->cognito_user = $this->getMockBuilder('\mrfg\cogauth\cognito\user')
			->disableOriginalConstructor()
			->setMethods(array('get_cognito_username'))
			->getMock();

		$this->authentication = $this->getMockBuilder('\mrfg\cogauth\cognito\auth_result')
			->disableOriginalConstructor()
			->setMethods(array(
				'validate_and_store_auth_response',
				'authenticated',
				'get_session_token'))
			->getMock();

		$this->log = $this->getMockBuilder('\phpbb\log\log_interface')
			->disableOriginalConstructor()
			->getMock();

		$this->request = $this->getMockBuilder('\phpbb\request\request_interface')
			->disableOriginalConstructor()
			->getMock();


		$this->provider = $this->getMockBuilder('\Aws\CognitoIdentityProvider\CognitoIdentityProviderClient')
			->disableOriginalConstructor()
			->setMethods(array(
				'adminGetUser',
				'adminInitiateAuth',
				'updateUserAttributes',
				'changePassword',
				'adminDisableUser',
				'adminEnableUser'))
			->getMock();

		/** @var  \Aws\Sdk  | \PHPUnit_Framework_MockObject_MockObject $aws_sdk */
		$aws_sdk = $this->getMockBuilder('\Aws\Sdk')
			->setMethods(array('createCognitoIdentityProvider'))
			->disableOriginalConstructor()
			->getMock();

		$aws_sdk->method('createCognitoIdentityProvider')
			->will($this->returnValue($this->provider));

        $map = array(
            array('cogauth_pool_id', 'eu-west-1_T0xxxxx1'),
            array('cogauth_client_id', 'faaaaaaaaaaaaaaaaaaaaaav7'),
            array('cogauth_client_secret', '110aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaai'),
            array('cogauth_aws_key', 'AKAAAAAAAAAAAAAAAAAQ'),
            array('cogauth_aws_secret', 'BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAG'),
            array('cogauth_aws_region', 'eu-west-1')
        );
        $this->config->method('offsetGet')->will($this->returnValueMap($map));

		$this->cognito = new \mrfg\cogauth\cognito\cognito(
			$this->config,
			$this->user,
			$this->language,
			$this->request,
			$this->log,
			$this->web_token,
			$this->cognito_user,
			$this->authentication,
			$aws_sdk);

	}

    public function test_get_user_valid()
    {

        $attr = array(
            array(
                'Name' => 'preferred_username',
                'Value' => 'frederick'),
            array(
                'Name' => 'nickname',
                'Value' => 'fred')
        );
        $this->provider->method('adminGetUser')
            ->willReturn(array(
                'UserStatus' => 'CONFIRMED',
                'UserAttributes' => $attr));

        $this->provider->expects($this->once())
            ->method('adminGetUser')
            ->with(array(
                "Username" => 'u001234',
                "UserPoolId" => 'eu-west-1_T0xxxxx1'));

		$this->cognito_user->expects($this->once())
			->method('get_cognito_username')
			->with('1234')
			->willReturn('u001234');

		$this->authentication->method('validate_and_store_auth_response')
			->willReturn(new validation_result('',1234));

        $response = $this->cognito->get_user('1234');
        $this->assertTrue($response['status'] == COG_USER_FOUND, 'Asserting status is COG_USER_FOUND');
        $this->assertTrue($response['user_status'] == 'CONFIRMED', 'Asserting user_status is CONFIRMED');
        $this->assertTrue($response['user_attributes'] == $attr, 'Asserting user attributes are correct');

	}

	/**
	 * @throws \Exception
	 */
    public function test_authenticate_user()
    {
        $hash = base64_encode(hash_hmac(
            'sha256',
            'u001234' . 'faaaaaaaaaaaaaaaaaaaaaav7',
            '110aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaai',
            true
        ));

        $this->provider->method('adminInitiateAuth')
            ->willReturn(array(
                'AuthenticationResult' => array('AccessToken' => 'token_string_1234'),
                'ChallengeName' => 'NEW_PASSWORD_REQUIRED',
                'ChallengeParameters' => array(),
                'Session' => 'QWERTYUIOP'
            ));

        $this->provider->expects($this->once())
            ->method('adminInitiateAuth')
            ->with(array(
                'AuthFlow' => 'ADMIN_NO_SRP_AUTH',
                'AuthParameters' => array(
                    'USERNAME' => 'u001234',
                    'PASSWORD' => 'Str0n@-p@ssw0rd',
                    'SECRET_HASH' => $hash,
                ),
                'ClientId' => 'faaaaaaaaaaaaaaaaaaaaaav7',
                'UserPoolId' => 'eu-west-1_T0xxxxx1',
            ));

		$this->cognito_user->expects($this->once())
			->method('get_cognito_username')
			->with('1234')
			->willReturn('u001234');

		$this->authentication->method('validate_and_store_auth_response')
			->willReturn(new validation_result('xx',1234));

        $response = $this->cognito->authenticate(1234, 'Str0n@-p@ssw0rd');
        $this->assertTrue($response['status'] === COG_LOGIN_SUCCESS);
        $this->assertTrue($response['response'] == array('AccessToken' => 'token_string_1234'), 'Asserting AccessToken is returned');
    }

    public function test_update_user_email()
    {
    	$this->web_token->expects($this->once())
            ->method('verify_access_token')
            ->with('9876543210')
			->willReturn('u000123');

        $this->provider->expects($this->once())
            ->method('updateUserAttributes')
            ->with(array(
                'AccessToken' => '9876543210',
                'UserAttributes' => array(array(
                    'Name' => 'email',
                    'Value' => 'fred@mail.com',
                )),
            ));

        $this->cognito_user->expects($this->once())
			->method('get_cognito_username')
			->with('123')
			->willReturn('u000123');

        $response = $this->cognito->update_user_email(123,'fred@mail.com', '9876543210');
        $this->assertTrue($response, 'Asserting update_user_email');
    }


    public function test_update_user_email_fail01()
    {
        $this->web_token->method('verify_access_token')
            ->willThrowException(new \mrfg\cogauth\jwt\exception\TokenVerificationException);

        $this->web_token->expects($this->once())
            ->method('verify_access_token')
            ->with('9876543210')
			->willReturn('u000123');

		$this->provider->expects($this->never())
            ->method('updateUserAttributes');

        $response = $this->cognito->update_user_email(123,'fred@mail.com', '9876543210');
        $this->assertFalse($response, 'Asserting update_user_email failed');
    }

	public function test_change_email_user_not_found()
	{
		// this can only happen is the cognito user gets deleted after login. The access toke would in all other cases be invalid

		/* @var $command \Aws\CommandInterface */
		$command = $this->getMockBuilder('\Aws\CommandInterface')
			->disableOriginalConstructor()
			->getMock();

		$this->web_token->expects($this->once())
			->method('verify_access_token')
			->with('4567890123')
			->willReturn('u000135');

		$this->provider->expects($this->once())
			->method('updateUserAttributes')
			->willThrowException(new CognitoIdentityProviderException('some message',
				$command,array('code' => 'UserNotFoundException')));

		$this->cognito_user->expects($this->once())
			->method('get_cognito_username')
			->with('135')
			->willReturn('u000135');

		$response = $this->cognito->update_user_email(
			135,'fred@mail.com','4567890123');
		$this->assertTrue($response, 'Asserting update_user_email fail access user not found');
	}



    public function test_change_password()
	{
		$this->web_token->expects($this->once())
			->method('verify_access_token')
			->with('5678901234')
			->willReturn('u000321');

		$this->provider->expects($this->once())
			->method('changePassword')
			->with(array(
				'AccessToken' => '5678901234',
				'PreviousPassword' => 'sTr0NgPaSsWoD',
				'ProposedPassword' => 'PaSsWoDsTr0Ng'
			));

		$this->cognito_user->expects($this->once())
			->method('get_cognito_username')
			->with('321')
			->willReturn('u000321');

		$response = $this->cognito->change_password(
			321,'5678901234', 'sTr0NgPaSsWoD', 'PaSsWoDsTr0Ng');
		$this->assertTrue($response, 'Asserting change_password');
	}

	public function test_change_password_wrong_pwd()
	{
		/* @var $command \Aws\CommandInterface */
		$command = $this->getMockBuilder('\Aws\CommandInterface')
			->disableOriginalConstructor()
			->getMock();

		$this->web_token->expects($this->once())
			->method('verify_access_token')
			->with('5678901234')
			->willReturn('u000123');

		$this->provider->method('changePassword')
			->willThrowException(new CognitoIdentityProviderException('some message',$command,array()));

		$response = $this->cognito->change_password(
			321,'5678901234', 'sTr0NgPaSsWoD', 'PaSsWoDsTr0Ng');
		$this->assertFalse($response, 'Asserting change_password fail');
	}

	public function test_change_password_invalid_token()
	{
		$this->web_token->method('verify_access_token')
			->willThrowException(new \mrfg\cogauth\jwt\exception\TokenVerificationException);

		$this->web_token->expects($this->once())
			->method('verify_access_token')
			->with('4567890123')
			->willReturn('u000131');

		$this->provider->expects($this->never())
			->method('changePassword');

		$response = $this->cognito->change_password(
			313,'4567890123', 'sTr0NgPaSsWoD', 'PaSsWoDsTr0Ng');
		$this->assertFalse($response, 'Asserting change_password fail access token invalid');
	}

	public function test_change_password_user_not_found()
	{
		// this can only happen is the cognito user gets deleted after login. The access toke would in all other cases be invalid

		/* @var $command \Aws\CommandInterface */
		$command = $this->getMockBuilder('\Aws\CommandInterface')
			->disableOriginalConstructor()
			->getMock();


		$this->log->expects($this->never())
			->method('add');

		$this->web_token->expects($this->once())
			->method('verify_access_token')
			->with('4567890123')
			->willReturn('u000132');

		$this->provider->expects($this->once())
			->method('changePassword')
			->willThrowException(new CognitoIdentityProviderException('some message',
				$command,array('code' => 'UserNotFoundException')));


		$this->cognito_user->expects($this->once())
			->method('get_cognito_username')
			->with('132')
			->willReturn('u000132');

		$response = $this->cognito->change_password(
			132,'4567890123', 'sTr0NgPaSsWoD', 'PaSsWoDsTr0Ng');
		$this->assertTrue($response, 'Asserting change_password fail user not found');
	}

	public function test_change_password_unexpected_error()
	{
		// As the title says an unexpected error occurred, most likely to be network issue.
		/* @var $command \Aws\CommandInterface */
		$command = $this->getMockBuilder('\Aws\CommandInterface')
			->disableOriginalConstructor()
			->getMock();


		$this->log->expects($this->once())
			->method('add')
			->with('critical',132,'', 'COGAUTH_UNEXPECTED_ERROR', time(),
				array('change_password','ResourceNotFoundException',null));

		$this->web_token->expects($this->once())
			->method('verify_access_token')
			->with('4567890123')
			->willReturn('u000132');

		$this->provider->expects($this->once())
			->method('changePassword')
			->willThrowException(new CognitoIdentityProviderException('some message',
				$command,array('code' => 'ResourceNotFoundException')));

		$this->cognito_user->expects($this->once())
			->method('get_cognito_username')
			->with('132')
			->willReturn('u000132');

		$response = $this->cognito->change_password(
			132,'4567890123', 'sTr0NgPaSsWoD', 'PaSsWoDsTr0Ng');
		$this->assertFalse($response, 'Asserting change_password fail with ResourceNotFoundException');
	}

	public function test_disable_user()
	{
		$this->provider->expects($this->once())
			->method('adminDisableUser')
			->with(array('Username' => 'u000033', 'UserPoolId' => 'eu-west-1_T0xxxxx1'));

		$this->cognito_user->expects($this->once())
			->method('get_cognito_username')
			->with('33')
			->willReturn('u000033');

		$this->cognito->admin_disable_user(33);
	}

	public function test_enable_user()
	{
		$this->provider->expects($this->once())
			->method('adminEnableUser')
			->with(array('Username' => 'u000033', 'UserPoolId' => 'eu-west-1_T0xxxxx1'));

		$this->cognito_user->expects($this->once())
			->method('get_cognito_username')
			->with('33')
			->willReturn('u000033');

		$this->cognito->admin_enable_user(33);
	}

}
