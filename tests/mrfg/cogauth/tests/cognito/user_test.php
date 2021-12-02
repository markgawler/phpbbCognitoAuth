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

class auth_provider_test extends \phpbb_test_case
{
	/** @var $db \phpbb\db\driver\driver_interface|\PHPUnit_Framework_MockObject_MockObject */
	protected $db;

	/** @var $user \mrfg\cogauth\cognito\user|\PHPUnit_Framework_MockObject_MockObject  */
	protected $user;

	/** @var \phpbb\user |\PHPUnit_Framework_MockObject_MockObject $phpbb_user */
	protected $phpbb_user;

	/** @var \phpbb\auth\auth |\PHPUnit_Framework_MockObject_MockObject  $auth */
	protected $auth;

	/** @var \phpbb\passwords\manager | \PHPUnit_Framework_MockObject_MockObject  $passwords_manager */
	protected $passwords_manager;

	/** @var \phpbb\config\config $config */
	protected $config;

	public function setUp()
	{
		parent::setUp();

		$this->phpbb_user = $this->getMockBuilder('\phpbb\user')
			->disableOriginalConstructor()
			->getMock();

		$this->db = $this->getMockBuilder('\phpbb\db\driver\driver_interface')
		->disableOriginalConstructor()
		->getMock();

		$this->passwords_manager = $this->getMockBuilder('\phpbb\passwords\manager')
			->disableOriginalConstructor()
			->getMock();

		$this->user = $this->getMockBuilder('\mrfg\cogauth\cognito\user')
			->disableOriginalConstructor()
			->getMock();

		$this->auth = $this->getMockBuilder('\phpbb\auth\auth')
			->disableOriginalConstructor()
			->getMock();

		$this->config = $this->getMockBuilder('\phpbb\config\config')
			->disableOriginalConstructor()
			->getMock();

		$this->user = new \mrfg\cogauth\cognito\user(
			$this->phpbb_user,
			$this->auth,
			$this->db,
			$this->config,
			$this->passwords_manager,
			'',
			'',
			''
		);


	}

	public function test_get_cognito_username_simple()
	{
		$this->assertEquals('u000001',$this->user->get_cognito_username(1));
		$this->assertEquals('u000020',$this->user->get_cognito_username(20));
		$this->assertEquals('u300020',$this->user->get_cognito_username(300020));
		$this->assertEquals('u4000020',$this->user->get_cognito_username(4000020));

	}


}
