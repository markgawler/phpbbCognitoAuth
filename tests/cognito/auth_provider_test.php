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
	/** @var \phpbb\passwords\manager | \PHPUnit_Framework_MockObject_MockObject  $passwords_manager */
	protected $passwords_manager;

	/** @var \Symfony\Component\DependencyInjection\ContainerInterface */
	protected $phpbb_container;

	/** @var \phpbb\config\config $config Config object */
	protected $config;

	/** @var \phpbb\user */
	protected $user;

	/** @var $user \mrfg\cogauth\cognito\user|\PHPUnit_Framework_MockObject_MockObject  */
	protected $cognito_user;

	/** @var \phpbb\language\language |\PHPUnit_Framework_MockObject_MockObject*/
	protected $language;

	/** @var $db \phpbb\db\driver\driver_interface|\PHPUnit_Framework_MockObject_MockObject */
	protected $db;

	/** @var \mrfg\cogauth\cognito\cognito |\PHPUnit_Framework_MockObject_MockObject*/
	protected $cognito;

	/**  @var \mrfg\cogauth\cognito\web_token_phpbb $web_token |\PHPUnit_Framework_MockObject_MockObject*/
	protected $web_token;

	/** @var \phpbb\log\log_interface $log |\PHPUnit_Framework_MockObject_MockObject*/
	protected $log;

	/** @var \phpbb\auth\auth |\PHPUnit_Framework_MockObject_MockObject  $auth */
	protected $auth;


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




	}

	public function test_get_cognito_username_simple()
	{


	}


}
