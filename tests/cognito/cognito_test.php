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

namespace mrfg\cogauth\tests\event_listener;
use Aws\CognitoIdentityProvider\Exception\CognitoIdentityProviderException;

class cognito_test extends \phpbb_test_case
{
    /** @var $user \phpbb\user */
    protected $user;

    /** @var $cognito_client \phpbb\config\config */
    protected $config;

    /** @var $db \phpbb\db\driver\driver_interface */
    protected $db;

    /** @var $web_token \mrfg\cogauth\cognito\web_token|\PHPUnit_Framework_MockObject_MockObject */
    protected $web_token;

    /** @var $client  \mrfg\cogauth\cognito\cognito_client_wrapper| \PHPUnit_Framework_MockObject_MockObject */
	protected $client;

	/** @var \phpbb\log\log_interface $log*/
	protected $log;

    public function setUp()
    {
        parent::setUp();

		$this->user = $this->getMockBuilder('\phpbb\user')
			->disableOriginalConstructor()
			->getMock();

        $this->db = $this->getMockBuilder('\phpbb\db\driver\driver_interface')
            ->disableOriginalConstructor()
            ->getMock();

        $this->config = $this->getMockBuilder('\phpbb\config\config')
            ->disableOriginalConstructor()
            ->getMock();

        $this->web_token = $this->getMockBuilder('\mrfg\cogauth\cognito\web_token')
            ->disableOriginalConstructor()
            ->setMethods(array('verify_access_token'))
            ->getMock();

		$this->client = $this->getMockBuilder('\mrfg\cogauth\cognito\cognito_client_wrapper')
			->disableOriginalConstructor()
			->getMock();

		$this->log = $this->getMockBuilder('\phpbb\log\log_interface')
			->disableOriginalConstructor()
			->getMock();

        $map = array(
            array('cogauth_pool_id', 'eu-west-1_T0xxxxx1'),
            array('cogauth_client_id', 'faaaaaaaaaaaaaaaaaaaaaav7'),
            array('cogauth_client_secret', '110aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaai'),
            array('cogauth_aws_key', 'AKAAAAAAAAAAAAAAAAAQ'),
            array('cogauth_aws_secret', 'BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAG'),
            array('cogauth_aws_region', 'eu-west-1')
        );
        $this->config->method('offsetGet')->will($this->returnValueMap($map));
    }

    public function test_get_user_valid()
    {
        /** @var $client \mrfg\cogauth\cognito\cognito_client_wrapper */
        $cognito = new \mrfg\cogauth\cognito\cognito($this->db, $this->config, $this->user, $this->log, $this->client, $this->web_token, '');

        $attr = array(
            array(
                'Name' => 'preferred_username',
                'Value' => 'frederick'),
            array(
                'Name' => 'nickname',
                'Value' => 'fred')
        );
        $this->client->method('admin_get_user')
            ->willReturn(array(
                'UserStatus' => 'CONFIRMED',
                'UserAttributes' => $attr));

        $this->client->expects($this->once())
            ->method('admin_get_user')
            ->with(array(
                "Username" => 'u001234',
                "UserPoolId" => 'eu-west-1_T0xxxxx1'));

        $response = $cognito->get_user('1234');
        $this->assertTrue($response['status'] == COG_USER_FOUND, 'Asserting status is COG_USER_FOUND');
        $this->assertTrue($response['user_status'] == 'CONFIRMED', 'Asserting user_status is CONFIRMED');
        $this->assertTrue($response['user_attributes'] == $attr, 'Asserting user attributes are correct');

    }


    public function test_authenticate_user()
    {
        $hash = base64_encode(hash_hmac(
            'sha256',
            'u001234' . 'faaaaaaaaaaaaaaaaaaaaaav7',
            '110aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaai',
            true
        ));

        /** @var $client \mrfg\cogauth\cognito\cognito_client_wrapper */
        $cognito = new \mrfg\cogauth\cognito\cognito($this->db, $this->config, $this->user, $this->log, $this->client, $this->web_token, '');

        $this->client->method('admin_initiate_auth')
            ->willReturn(array(
                'AuthenticationResult' => array('AccessToken' => 'token_string_1234'),
                'ChallengeName' => 'NEW_PASSWORD_REQUIRED',
                'ChallengeParameters' => array(),
                'Session' => 'QWERTYUIOP'
            ));

        $this->client->expects($this->once())
            ->method('admin_initiate_auth')
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

        $response = $cognito->authenticate(1234, 'Str0n@-p@ssw0rd');
        $this->assertTrue($response['status'] === COG_LOGIN_SUCCESS);
        $this->assertTrue($response['response'] == array('AccessToken' => 'token_string_1234'), 'Asserting AccessToken is returned');
    }

    public function test_update_user_email()
    {
        /** @var $client \mrfg\cogauth\cognito\cognito_client_wrapper */
        $cognito = new \mrfg\cogauth\cognito\cognito($this->db, $this->config, $this->user, $this->log, $this->client, $this->web_token, '');

        $this->web_token->expects($this->once())
            ->method('verify_access_token')
            ->with('9876543210')
			->willReturn('u000123');

        $this->client->expects($this->once())
            ->method('update_user_attributes')
            ->with(array(
                'AccessToken' => '9876543210',
                'UserAttributes' => array(array(
                    'Name' => 'email',
                    'Value' => 'fred@mail.com',
                )),
            ));

        $response = $cognito->update_user_email(123,'fred@mail.com', '9876543210');
        $this->assertTrue($response, 'Asserting update_user_email');
    }


    public function test_update_user_email_fail01()
    {
        /** @var $client \mrfg\cogauth\cognito\cognito_client_wrapper */
        $cognito = new \mrfg\cogauth\cognito\cognito($this->db, $this->config, $this->user, $this->log, $this->client, $this->web_token, '');

        $this->web_token->method('verify_access_token')
            ->willThrowException(new \mrfg\cogauth\cognito\exception\TokenVerificationException);

        $this->web_token->expects($this->once())
            ->method('verify_access_token')
            ->with('9876543210')
			->willReturn('u000123');

		$this->client->expects($this->never())
            ->method('update_user_attributes');

        $response = $cognito->update_user_email(123,'fred@mail.com', '9876543210');
        $this->assertFalse($response, 'Asserting update_user_email failed');
    }

	public function test_change_email_user_not_found()
	{
		// this can only happen is the cognito user gets deleted after login. The access toke would in all other cases be invalid

		/* @var $command \Aws\CommandInterface */
		$command = $this->getMockBuilder('\Aws\CommandInterface')
			->disableOriginalConstructor()
			->getMock();

		/** @var $client \mrfg\cogauth\cognito\cognito_client_wrapper */
		$cognito = new \mrfg\cogauth\cognito\cognito($this->db, $this->config, $this->user, $this->log, $this->client, $this->web_token, '');

		$this->web_token->expects($this->once())
			->method('verify_access_token')
			->with('4567890123')
			->willReturn('u000135');

		$this->client->expects($this->once())
			->method('update_user_attributes')
			->willThrowException(new CognitoIdentityProviderException('some message',
				$command,array('code' => 'UserNotFoundException')));

		$response = $cognito->update_user_email(
			135,'fred@mail.com','4567890123');
		$this->assertTrue($response, 'Asserting update_user_email fail access user not found');
	}



    public function test_change_password()
	{
		/** @var $client \mrfg\cogauth\cognito\cognito_client_wrapper */
		$cognito = new \mrfg\cogauth\cognito\cognito($this->db, $this->config, $this->user, $this->log, $this->client, $this->web_token, '');

		$this->web_token->expects($this->once())
			->method('verify_access_token')
			->with('5678901234')
			->willReturn('u000321');

		$this->client->expects($this->once())
			->method('change_password')
			->with(array(
				'AccessToken' => '5678901234',
				'PreviousPassword' => 'sTr0NgPaSsWoD',
				'ProposedPassword' => 'PaSsWoDsTr0Ng'
			));

		$response = $cognito->change_password(
			321,'5678901234', 'sTr0NgPaSsWoD', 'PaSsWoDsTr0Ng');
		$this->assertTrue($response, 'Asserting change_password');
	}

	public function test_change_password_wrong_pwd()
	{
		/* @var $command \Aws\CommandInterface */
		$command = $this->getMockBuilder('\Aws\CommandInterface')
			->disableOriginalConstructor()
			->getMock();

		/** @var $client \mrfg\cogauth\cognito\cognito_client_wrapper */
		$cognito = new \mrfg\cogauth\cognito\cognito($this->db, $this->config, $this->user, $this->log, $this->client, $this->web_token, '');

		$this->web_token->expects($this->once())
			->method('verify_access_token')
			->with('5678901234')
			->willReturn('u000123');

		$this->client->method('change_password')
			->willThrowException(new CognitoIdentityProviderException('some message',$command,array()));

		$response = $cognito->change_password(
			321,'5678901234', 'sTr0NgPaSsWoD', 'PaSsWoDsTr0Ng');
		$this->assertFalse($response, 'Asserting change_password fail');
	}

	public function test_change_password_invalid_token()
	{
		/** @var $client \mrfg\cogauth\cognito\cognito_client_wrapper */
		$cognito = new \mrfg\cogauth\cognito\cognito($this->db, $this->config, $this->user, $this->log, $this->client, $this->web_token, '');

		$this->web_token->method('verify_access_token')
			->willThrowException(new \mrfg\cogauth\cognito\exception\TokenVerificationException);

		$this->web_token->expects($this->once())
			->method('verify_access_token')
			->with('4567890123')
			->willReturn('u000131');

		$this->client->expects($this->never())
			->method('change_password');

		$response = $cognito->change_password(
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

		/** @var $client \mrfg\cogauth\cognito\cognito_client_wrapper */
		$cognito = new \mrfg\cogauth\cognito\cognito($this->db, $this->config, $this->user, $this->log, $this->client, $this->web_token, '');

		$this->web_token->expects($this->once())
			->method('verify_access_token')
			->with('4567890123')
			->willReturn('u000132');

		$this->client->expects($this->once())
			->method('change_password')
			->willThrowException(new CognitoIdentityProviderException('some message',
				$command,array('code' => 'UserNotFoundException')));

		$response = $cognito->change_password(
			132,'4567890123', 'sTr0NgPaSsWoD', 'PaSsWoDsTr0Ng');
		$this->assertTrue($response, 'Asserting change_password fail user not found');
	}

}