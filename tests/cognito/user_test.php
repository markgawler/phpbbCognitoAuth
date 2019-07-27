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

class user_test extends \phpbb_test_case
{
	/** @var $db \phpbb\db\driver\driver_interface|\PHPUnit_Framework_MockObject_MockObject */
	protected $db;

	/** @var $user \mrfg\cogauth\cognito\user */
	protected $user;

	public function setUp()
	{
		parent::setUp();

		$this->db = $this->getMockBuilder('\phpbb\db\driver\driver_interface')
			->disableOriginalConstructor()
			->getMock();

		$this->user = new \mrfg\cogauth\cognito\user($this->db);

	}

	public function test_get_cognito_username_simple()
	{
		$this->assertEquals('u000001',$this->user->get_cognito_username(1));
		$this->assertEquals('u000020',$this->user->get_cognito_username(20));
		$this->assertEquals('u300020',$this->user->get_cognito_username(300020));
		$this->assertEquals('u4000020',$this->user->get_cognito_username(4000020));

	}
}