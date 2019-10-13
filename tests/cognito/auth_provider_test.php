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
///home/mrfg/git/phpbb/phpBB/includes/functions_acp.php

/** @noinspection PhpIncludeInspection */
include_once __DIR__ . '/../../vendor/autoload.php';
include_once  'phpBB/includes/functions_acp.php';

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

	/** @var \phpbb\log\log_interface $log |\PHPUnit_Framework_MockObject_MockObject*/
	protected $log;

	public function setUp()
	{
		parent::setUp();

		$this->passwords_manager = $this->getMockBuilder('\phpbb\passwords\manager')
			->disableOriginalConstructor()
			->getMock();

		$this->phpbb_container = $this->getMockBuilder('\Symfony\Component\DependencyInjection\ContainerInterface')
			->disableOriginalConstructor()
			->getMock();

		$this->config = $this->getMockBuilder('\phpbb\config\config')
			->disableOriginalConstructor()
			->getMock();

		$this->user = $this->getMockBuilder('\phpbb\user')
			->disableOriginalConstructor()
			->getMock();

		$this->cognito_user = $this->getMockBuilder('\mrfg\cogauth\cognito\user')
			->disableOriginalConstructor()
			->getMock();

		$this->language = $this->getMockBuilder('\phpbb\language\language')
			->disableOriginalConstructor()
			->getMock();

		$this->db = $this->getMockBuilder('\phpbb\db\driver\driver_interface')
			->disableOriginalConstructor()
			//->setMethods(array('sql_escape', 'sql_query', 'sql_fetchrow'))
			->getMock();

		$this->cognito = $this->getMockBuilder('\mrfg\cogauth\cognito\cognito')
			->disableOriginalConstructor()
			->getMock();

		$this->log = $this->getMockBuilder('phpbb\log\log_interface')
			->disableOriginalConstructor()
			->getMock();

	}

	public function test_init_happy_day()
	{
		$this->cognito->expects($this->once())
			->method('describe_user_pool_client')
			->willReturn(new \Aws\Result());

		$cogauth = new \mrfg\cogauth\auth\provider\cogauth(
			$this->db,
			$this->config,
			$this->passwords_manager,
			$this->user,
			$this->cognito_user,
			$this->language,
			$this->phpbb_container,
			$this->cognito,
			$this->log
		);
		$cogauth->init();

	}
	public function test_init_error()
	{
		$this->cognito->expects($this->once())
		->method('describe_user_pool_client')
		->willReturn('');

		$cogauth = new \mrfg\cogauth\auth\provider\cogauth(
			$this->db,
			$this->config,
			$this->passwords_manager,
			$this->user,
			$this->cognito_user,
			$this->language,
			$this->phpbb_container,
			$this->cognito,
			$this->log
		);

		$this->setExpectedTriggerError(512,0);
		$cogauth->init();
	}

	public function test_login_password_and_username_checks()
	{

		$cogauth = new \mrfg\cogauth\auth\provider\cogauth(
			$this->db,
			$this->config,
			$this->passwords_manager,
			$this->user,
			$this->cognito_user,
			$this->language,
			$this->phpbb_container,
			$this->cognito,
			$this->log
		);
		$expected = array(
			'status'    => LOGIN_ERROR_PASSWORD,
			'error_msg' => 'NO_PASSWORD_SUPPLIED',
			'user_row'  => array('user_id' => ANONYMOUS));

		$result = $cogauth->login('','');
		$this->assertEquals($expected, $result, 'verify no password check (empty)');

		$result = $cogauth->login('','  ');
		$this->assertEquals($expected, $result, 'verify no password check (trim to empty)');

		$expected = array(
			'status'    => LOGIN_ERROR_USERNAME,
			'error_msg' => 'LOGIN_ERROR_USERNAME',
			'user_row'  => array('user_id' => ANONYMOUS));

		$result = $cogauth->login('','passw0rd');
		$this->assertEquals($expected, $result, 'verify username check (empty)');

	}

	public function test_login_checks_phpbb_user()
	{
		$password = 'p@ssword';
		$username = 'MyUserName';
		$username_clean = utf8_clean_string($username);
		$sql = "SELECT * FROM " . USERS_TABLE . " WHERE username_clean = '". $username_clean . "'";
		$row = array(
			'user_id' => '123',
			'username' => $username,
			'user_email' => '',
			'user_type' => USER_NORMAL,
			'user_login_attempts' => 0,
			'user_password' => ''
			);

		$this->db->expects($this->once())
			->method('sql_escape')
			->with($username_clean)
			->willReturn($username_clean);

		$this->db->expects($this->once())
		->method('sql_query')
			->with($sql)
			->willReturn('dummy');

		$this->db->expects($this->once())
			->method('sql_fetchrow')
			->with('dummy')
			->willReturn($row);

		$cogauth = new \mrfg\cogauth\auth\provider\cogauth(
			$this->db,
			$this->config,
			$this->passwords_manager,
			$this->user,
			$this->cognito_user,
			$this->language,
			$this->phpbb_container,
			$this->cognito,
			$this->log);

		$result = $cogauth->login($username,$password);
	}

}
