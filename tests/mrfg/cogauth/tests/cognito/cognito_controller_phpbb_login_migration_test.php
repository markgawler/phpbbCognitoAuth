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

class cognito_controller_phpbb_login_migration_test extends \phpbb_test_case
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


		$this->cognito->expects($this->never())
			->method('authenticate');
		$this->user->expects($this->never())
			->method('reset_phpbb_login_attempts');
		$this->user->expects($this->never())
			->method('update_phpbb_password');
		$this->user->expects($this->never())
			->method('set_phpbb_password_status');
		$this->cognito->expects($this->never())
			->method('admin_change_password');

		$this->cog_user = array(
			'status' => COG_USER_NOT_FOUND,
			'user_status' => null,
			'phpbb_password_valid' => null);
	}

	// No phpBB user
	// Return the phpbb results array without calling cognito
	public function test_phpbb_login_user_no_phpbb_user()
	{
		$this->cognito->expects($this->never())
			->method('get_user');
		$this->cognito->expects(($this->never()))
			->method('migrate_user');

		$controller = new controller(
			$this->user,
			$this->auth_result,
			$this->cognito,
			$this->log,
			$this->config);

		// test for noon LOGIN_ERROR_USERNAME case
		$result = array(
			'user_row' => array('user_id' => ANONYMOUS),
			'status' => LOGIN_ERROR_PASSWORD);

		/** @noinspection PhpUnhandledExceptionInspection */
		$this->assertEquals($result, $controller->login_phpbb('urhreiughui',$result));


		// Currently there is not difference in behavior if the user exists in cognito, this may change
		$result = array(
			'user_row' => array('user_id' => ANONYMOUS),
			'status' => LOGIN_ERROR_USERNAME);
		/** @noinspection PhpUnhandledExceptionInspection */
		$this->assertEquals($result, $controller->login_phpbb('urhreiughui',$result));

	}


	public function test_phpbb_login_user_migration_cogauth_master()
	{
		$user_id =123;
		$username = 'Heather';
		$password = 'urhreiughui';
		$email = 'my@email.com';

		$result_phpbb = array(
			'user_row' => array(
				'username' => $username,
				'user_id' => $user_id,
				'user_email' => $email),
			'status' => LOGIN_SUCCESS,
			'error_msg' => false);

		$this->cognito->expects($this->once())
			->method('get_user')
			->with($user_id)
			->willReturn($this->cog_user);

		$this->cognito->expects($this->once())
			->method('migrate_user')
			->with($username, $password, $user_id, $email);

		$this->config->expects($this->once())
			->method('offsetGet')
			->with('cogauth_master_auth')
			->willReturn(true);

		$controller = new controller(
			$this->user,
			$this->auth_result,
			$this->cognito,
			$this->log,
			$this->config);

		/** @noinspection PhpUnhandledExceptionInspection */
		$this->assertEquals($result_phpbb, $controller->login_phpbb($password, $result_phpbb));
	}

	public function test_phpbb_login_user_migration_phpbb_master()
	{
		$user_id =432;
		$username = 'Heather';
		$password = 'urhreifffughui';
		$email = 'my@email.gg.com';

		$result_phpbb = array(
			'user_row' => array(
				'username' => $username,
				'user_id' => $user_id,
				'user_email' => $email),
			'status' => LOGIN_SUCCESS,
			'error_msg' => false);

		$this->cognito->expects($this->once())
			->method('get_user')
			->with($user_id)
			->willReturn($this->cog_user);

		$this->cognito->expects($this->once())
			->method('migrate_user')
			->with($username, $password, $user_id, $email);

		$this->config->expects($this->once())
			->method('offsetGet')
			->with('cogauth_master_auth')
			->willReturn(false);

		$controller = new controller(
			$this->user,
			$this->auth_result,
			$this->cognito,
			$this->log,
			$this->config);

		/** @noinspection PhpUnhandledExceptionInspection */
		$this->assertEquals($result_phpbb, $controller->login_phpbb($password, $result_phpbb));
	}
}
