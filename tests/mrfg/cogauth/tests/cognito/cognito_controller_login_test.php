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
use mrfg\cogauth\cognito\validation_result;

class cognito_controller_login_test extends \phpbb_test_case
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

	public function test_login_existing_user()
	{
		$user_id = 3211;
		$token = array('Dummy Token');
		$validation_result = new validation_result('randomtoken01', $user_id);

		$this->auth_result->expects($this->once())
			->method('validate_and_store_auth_response')
			->with($token)
			->willReturn($validation_result);


		$this->user->expects($this->once())
			->method('login')
			->with($validation_result)
			->willReturn(true);

		$controller = new controller(
			$this->user,
			$this->auth_result,
			$this->cognito,
			$this->log,
			$this->config);

		$this->assertTrue($controller->login($token));
		$this->assertEquals($user_id,$validation_result->phpbb_user_id);
		$this->assertFalse($validation_result->is_new_user());
	}

	public function test_login_new_user()
	{
		$user_id = 998;
		$token = array('Dummy Token');
		$validation_result = new validation_result('randomtoken02', 0);
		$attributes = array(
			'sub' => 'aaaaaaaa-xxxx-yyyy-zzzz-ssssssssssss',
			'cognito:username' => 'frANk',
			'preferred_username' => 'frank',
			'nickname' => 'frANk',
			'exp' => 0,
			'email' => 'frank@email.com',
			'custom:phpbb_user_id' => (string) $user_id);

		$this->auth_result->expects($this->once())
			->method('validate_and_store_auth_response')
			->with($token)
			->willReturn($validation_result);

		$this->auth_result->expects($this->once())
			->method('get_user_attributes')
			->willReturn($attributes);

		$this->user->expects($this->once())
			->method('add_user')
			->with($attributes)
			->willReturn($user_id);

		$this->user->expects($this->once())
			->method('login')
			->with($validation_result)
			->willReturn(true);

		$this->cognito->expects($this->once())
			->method('normalize_user')
			->with($user_id);

		$controller = new controller(
			$this->user,
			$this->auth_result,
			$this->cognito,
			$this->log,
			$this->config);

		$this->assertTrue($validation_result->is_new_user());
		$this->assertTrue($controller->login($token));
		$this->assertEquals($user_id,$validation_result->phpbb_user_id);
		$this->assertFalse($validation_result->is_new_user());

	}

}
