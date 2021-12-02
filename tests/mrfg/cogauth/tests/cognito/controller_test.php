<?php
/**
 *
 * AWS Cognito Authentication. An extension for the phpBB Forum Software package.
 *
 * @copyright (c) 2019, Mark Gawler
 * @license GNU General Public License, version 2 (GPL-2.0)
 *
 * Date: 20/07/19
 *
 * User Class Tests
 */

namespace mrfg\cogauth\tests\cognito;

use mrfg\cogauth\cognito\validation_result;

class controller_test extends \phpbb_test_case
{
	/** @var \mrfg\cogauth\cognito\auth_result|\PHPUnit_Framework_MockObject_MockObject  $auth_result */
	protected $auth_result;

	/** @var \mrfg\cogauth\cognito\cognito|\PHPUnit_Framework_MockObject_MockObject $cognito */
	protected $cognito;

	/** @var \mrfg\cogauth\cognito\user|\PHPUnit_Framework_MockObject_MockObject $user */
	protected $user;

	/** @var \mrfg\cogauth\cognito\controller |\PHPUnit_Framework_MockObject_MockObject $controller */
	protected $controller;

	/** @var \phpbb\log\log_interface |\PHPUnit_Framework_MockObject_MockObject $log */
	protected $log;

	/**@var \phpbb\config\config |\PHPUnit_Framework_MockObject_MockObject $config Config object */
	protected $config;

	public function setUp()
	{
		parent::setUp();

		$this->auth_result = $this->getMockBuilder('\mrfg\cogauth\cognito\auth_result')
			->disableOriginalConstructor()
			->getMock();

		$this->cognito = $this->getMockBuilder('\mrfg\cogauth\cognito\cognito')
			->disableOriginalConstructor()
			->getMock();

		$this->user = $this->getMockBuilder('\mrfg\cogauth\cognito\user')
			->disableOriginalConstructor()
			->getMock();

		$this->log = $this->getMockBuilder('\phpbb\log\log_interface')
			->disableOriginalConstructor()
			->getMock();

		$this->config = $this->getMockBuilder('\phpbb\config\config')
			->disableOriginalConstructor()
			->getMock();

		$this->controller = new \mrfg\cogauth\cognito\controller(
			$this->user,
			$this->auth_result,
			$this->cognito,
			$this->log,
			$this->config);


	}

	public function test_login_existing_user()
	{
		$dummy_jwt_tokens = array('IdToken' => 'id_token_string',
			  'AccessToken' => 'access_token_string',
			  'RefreshToken' => 'refresh_token_string');
		$validation = new validation_result('qwert',321);

		$this->auth_result->expects($this->once())
			->method('validate_and_store_auth_response')
			->with($dummy_jwt_tokens)
			->willReturn($validation);

		$this->user->expects($this->once())
			->method('login')
			->with($validation)
			->willReturn(true);

		$result = $this->controller->login($dummy_jwt_tokens);
		$this->assertTrue($result,'Asserting successful login');
	}
	public function test_login_new_user()
	{
		$dummy_jwt_tokens = array('IdToken' => 'id_token_string',
								  'AccessToken' => 'access_token_string',
								  'RefreshToken' => 'refresh_token_string');
		$validation = new validation_result('qwert',0);

		$user_attr = array(
			'cognito:username' => 'Fredx',
			'preferred_username' => 'fred',
			'nickname' => 'Fred',
			'email' => 'fred@mail.com',
			'custom:phpbb_user_id' => (string) 0);

		$this->auth_result->expects($this->once())
			->method('validate_and_store_auth_response')
			->with($dummy_jwt_tokens)
			->willReturn($validation);

		$this->auth_result->expects($this->once())
			->method('get_user_attributes')
			->willReturn($user_attr);

		$this->user->expects($this->once())
			->method('login')
			->with($validation)
			->willReturn(true);

		$this->user->expects($this->once())
			->method('add_user')
			->with($user_attr)
			->willReturn(432);

		$this->cognito->expects($this->once())
			->method('normalize_user')
			->with(432);

		$result = $this->controller->login($dummy_jwt_tokens);
		$this->assertTrue($result,'Asserting successful login');
	}

}
