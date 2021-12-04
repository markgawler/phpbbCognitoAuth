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

use mrfg\cogauth\cognito\controller;

class cognito_controller_phpbb_login_cognito_user_test extends \phpbb_test_case
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

	/** @var array  */
	protected $cog_user;

	/** @var array  */
	protected $user_row;

	/** @var array  */
	protected $response;

	/** @var array  */
	protected $user_attrib;

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
//			->setMethods(array('get_user','admin_change_password','migrate_user'))
			->getMock();

		$this->log = $this->getMockBuilder('\phpbb\log\log_interface')
			->disableOriginalConstructor()
			->getMock();

		$this->config = $this->getMockBuilder('\phpbb\config\config')
			->disableOriginalConstructor()
//			->setMethods(array('offsetGet'))
			->getMock();


		$user_id =123;
		$username = 'Heather';
		$email = 'my@email.com';
		$this->user_row =  array(
			'username' => $username,
			'user_id' => $user_id,
			'user_email' => $email);

		$this->user_attrib = array (
			0 => array (
				'Name' => 'sub',
				'Value' => '50b633be-aaaa-bbbb-cccc-dddddddcc3d3'),
			1 => array (
				'Name' => 'email_verified',
				'Value' => 'True'),
			2 => array (
				'Name' => 'custom:phpbb_user_id',
				'Value' => $user_id),
			3 => array (
				'Name' => 'nickname',
				'Value' => $username),
			4 => array (
				'Name' => 'preferred_username',
				'Value' => strtolower($username)),
			5 => array (
				'Name' => 'email',
				'Value' => $email),
		);

		$this->response = array (
			'AccessToken' => 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaA',
			'ExpiresIn' => 3600,
			'TokenType' => 'Bearer',
			'RefreshToken' => 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
			'IdToken' => 'ccccccccccccccccccccccccccccccccccccccc',
		);
	}

	public function test_phpbb_login_user_cogauth_master()
	{
		$auth_status = array (
			'status' => COG_LOGIN_SUCCESS,
			'response' => $this->response,
			'session_token' => 'mooyB1DE3jsdfghjkjhgfddfgh',
		);

		$this->phpbb_login_user_common(true, $auth_status);
	}
	public function test_phpbb_login_user_phpbb_master()
	{
		$auth_status = array (
			'status' => COG_LOGIN_SUCCESS,
			'response' => $this->response,
			'session_token' => 'mooyB1DE3jsdfghjkjhgfddfgh',
		);
		$this->phpbb_login_user_common(false, $auth_status);

	}

	// login with valid phpBB login but failed cogauth login, but cogauth master,
	public function test_phpbb_login_user_cogauth_master_fail_pwd()
	{
		// this should fail to login as cogauth wins
		$auth_status = array (
			'status' => COG_LOGIN_ERROR_PASSWORD,
			'response' => null,
			'session_token' => '',
		);
		$result = array(
			'status' => LOGIN_ERROR_PASSWORD,
			'error_msg' => 'LOGIN_ERROR_PASSWORD',
			'user_row' => $this->user_row);
		$this->phpbb_login_user_common(true, $auth_status, $result);
	}

	// login with valid phpBB login but failed cogauth login, but cogauth master,
	public function test_phpbb_login_user_cogauth_master_fail_misc()
	{
		// this should fail to login as cogauth wins
		$auth_status = array (
			'status' => COG_LOGIN_NO_AUTH,
			'response' => null,
			'session_token' => '',
		);
		$result = array(
			'status' => LOGIN_ERROR_EXTERNAL_AUTH,
			'error_msg' => 'COGAUTH_UNHANDLED_LOGIN_ERROR',
			'user_row' => $this->user_row);
		$this->phpbb_login_user_common(true, $auth_status, $result);
	}



	// login with valid phpBB login but failed cogauth login, but cogauth master,
	public function test_phpbb_login_user_phpbb_master_update_password()
	{
		$auth_status = array (
			'status' => false,
			'response' => null,
			'session_token' => '',
		);
		$this->phpbb_login_user_common(false, $auth_status);
	}

	public function phpbb_login_user_common($cogauth_master_auth, $auth_status, $result = null)
	{

		$password = 'urhreiughui';

		$result_phpbb = array(
			'user_row' => $this->user_row,
			'status' => LOGIN_SUCCESS,
			'error_msg' => false);

		if ($result == null)
		{
			$result = $result_phpbb;
		}


		$cog_user = array(
			'status'               => COG_USER_FOUND,
			'user_status'          => 'CONFIRMED',
			'user_attributes'      => $this->user_attrib,
			'phpbb_password_valid' => true);


		$this->cognito->expects($this->never())
			->method('admin_change_password');
		$this->cognito->expects($this->never())
			->method('migrate_user');
		$this->user->expects($this->never())
			->method('reset_phpbb_login_attempts');
		$this->user->expects($this->never())
			->method('update_phpbb_password');
		$this->user->expects($this->never())
			->method('set_phpbb_password_status');


		$this->config->expects($this->once())
			->method('offsetGet')
			->with('cogauth_master_auth')
			->willReturn($cogauth_master_auth);


		$this->cognito->expects($this->once())
			->method('get_user')
			->with($this->user_row['user_id'])
			->willReturn($cog_user);

		$this->cognito->expects($this->once())
			->method('authenticate')
			->with($this->user_row['user_id'], $password)
			->willReturn($auth_status);


		$controller = new controller(
			$this->user,
			$this->auth_result,
			$this->cognito,
			$this->log,
			$this->config);

		/** @noinspection PhpUnhandledExceptionInspection */
		$this->assertEquals($result, $controller->login_phpbb($password, $result_phpbb));
	}

	// login with valid phpBB login but failed cogauth login, but cogauth master,
	public function test_phpbb_login_user_cogauth_master_fail_confirm()
	{
		$result = array(
			'status' => LOGIN_ERROR_ACTIVE,
			'error_msg' => 'ACTIVE_ERROR',
			'user_row' => $this->user_row);

		$cog_user = array(
			'status'               => COG_USER_FOUND,
			'user_status'          => 'UNCONFIRMED',
			'user_attributes'      => $this->user_attrib,
			'phpbb_password_valid' => true);

		$password = 'urhreiughui';
		$cogauth_master_auth = True;

		$result_phpbb = array(
			'user_row' => $this->user_row,
			'status' => LOGIN_SUCCESS,
			'error_msg' => false);

		$this->cognito->expects($this->never())
			->method('admin_change_password');
		$this->cognito->expects($this->never())
			->method('migrate_user');
		$this->user->expects($this->never())
			->method('reset_phpbb_login_attempts');
		$this->user->expects($this->never())
			->method('update_phpbb_password');
		$this->user->expects($this->never())
			->method('set_phpbb_password_status');

		$this->cognito->expects($this->never())
			->method('authenticate');

		$this->config->expects($this->once())
			->method('offsetGet')
			->with('cogauth_master_auth')
			->willReturn($cogauth_master_auth);

		$this->log->expects($this->once())
			->method(('add'))
			->with('user', $this->user_row['user_id'],'','COGAUTH_CONFIRMED_ERROR');

		$this->cognito->expects($this->once())
			->method('get_user')
			->with($this->user_row['user_id'])
			->willReturn($cog_user);

		$controller = new controller(
			$this->user,
			$this->auth_result,
			$this->cognito,
			$this->log,
			$this->config);

		/** @noinspection PhpUnhandledExceptionInspection */
		$this->assertEquals($result, $controller->login_phpbb($password, $result_phpbb));
	}

}
