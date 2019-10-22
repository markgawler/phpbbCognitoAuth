<?php
/**
 * * *
 * AWS Cognito Authentication. An extension for the phpBB Forum Software package.
 *
 * @copyright (c) 2019, Mark Gawler
 * @license GNU General Public License, version 2 (GPL-2.0)
 *
 * @package     mrfg\cogauth\tests\cognito
 *
 * Date: 31/10/16
 */

namespace mrfg\cogauth\tests\cognito;

use mrfg\cogauth\cognito\validation_result;

class cognito_controller_test extends \phpbb_test_case
{
	/** @var \mrfg\cogauth\cognito\user | \PHPUnit_Framework_MockObject_MockObject $user */
	protected $user;

	/** @var \mrfg\cogauth\cognito\auth_result | \PHPUnit_Framework_MockObject_MockObject $auth_result */
	protected $auth_result;

	/** @var \mrfg\cogauth\cognito\cognito | \PHPUnit_Framework_MockObject_MockObject $cognito */
	protected $cognito;

	/** @var \phpbb\config\config | \PHPUnit_Framework_MockObject_MockObject  */
	protected $config;

	/** @var \phpbb\log\log_interface | \PHPUnit_Framework_MockObject_MockObject  */
	protected $log;

	public function setUp()
	{
		parent::setUp();

		$this->user = $this->getMockBuilder('\mrfg\cogauth\cognito\user')
			->disableOriginalConstructor()
			->getMock();

		$this->auth_result = $this->getMockBuilder('\mrfg\cogauth\cognito\auth_result')
			->disableOriginalConstructor()
			->getMock();

		$this->cognito = $this->getMockBuilder('mrfg\cogauth\cognito\cognito')
			->disableOriginalConstructor()
			->getMock();

		$this->log = $this->getMockBuilder('\phpbb\log\log_interface')
			->disableOriginalConstructor()
			->getMock();

		$this->config = $this->getMockBuilder('\phpbb\config\config')
			->disableOriginalConstructor()
			->getMock();
	}

	public function test_get_access_token_fail()
	{
		$sid = 1234;

		$this->user->method('get_phpbb_session_id')->willReturn($sid);

		$controller = new \mrfg\cogauth\cognito\controller(
			$this->user,
			$this->auth_result,
			$this->cognito,
			$this->log,
			$this->config);


		$this->auth_result->expects($this->once())
			->method('get_access_token_from_sid')
			->with($sid)
			->willReturn(False);

		/** @noinspection PhpUnhandledExceptionInspection */
		$this->assertFalse($controller->get_access_token(), 'Asserting no token returned');
	}

	public function test_get_access_token_no_refresh()
	{
		$sid = 12345678;
		$response = array('AuthenticationResult' =>
							array('AccessToken' => 'token_string_1234',
								  'RefreshToken' => 'token_string_5678',
								  'IdToken' => 'token_string_9012'));
		$access_token = $response['AuthenticationResult']['AccessToken'];
		//$this->user->session_id = $sid;
		$this->user->method('get_phpbb_session_id')->willReturn($sid);


		$controller = new \mrfg\cogauth\cognito\controller(
			$this->user,
			$this->auth_result,
			$this->cognito,
			$this->log,
			$this->config);

		$this->auth_result->expects($this->once())
			->method('get_access_token_from_sid')
			->with($sid)
			->willReturn(array('mode' => 'access_token',
							   'token' => $access_token));

		/** @noinspection PhpUnhandledExceptionInspection */
		$this->assertEquals($controller->get_access_token(), $access_token,'Asserting token returned');

	}

	public function test_get_access_token_with_refresh()
	{
		$sid = 987654321;
		$user_id = 1234;
		$response = array('AuthenticationResult' =>
							array('AccessToken' => 'access_token_string_9876',
								  'RefreshToken' => 'refresh_token_string_5432',
								  'IdToken' => 'id_token_string_1098'));
		$access_token = $response['AuthenticationResult']['AccessToken'];
		$refresh_token = $response['AuthenticationResult']['RefreshToken'];

		//$this->user->session_id = $sid;
		$this->user->method('get_phpbb_session_id')->willReturn($sid);

		$controller = new \mrfg\cogauth\cognito\controller(
			$this->user,
			$this->auth_result,
			$this->cognito,
			$this->log,
			$this->config);

		$this->auth_result->expects($this->once())
			->method('get_access_token_from_sid')
			->with($sid)
			->willReturn(array('mode' => 'refresh', 'token' => $refresh_token, 'user_id' => $user_id));

		$this->cognito->expects($this->once())
			->method('refresh_access_token')
			->with($refresh_token, $user_id)
			->willReturn($response);

		$this->auth_result->expects($this->once())
			->method('validate_and_store_auth_response')
			->with($response['AuthenticationResult'], true)
			->willReturn(new validation_result('88453297852475',$user_id));

		/** @noinspection PhpUnhandledExceptionInspection */
		$this->assertEquals($access_token, $controller->get_access_token(),'Asserting token returned');
	}


}
