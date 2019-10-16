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
/** @noinspection PhpIncludeInspection */
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

	/** @var \phpbb\log\log_interface  |\PHPUnit_Framework_MockObject_MockObject $log*/
	protected $log;

	/** @var \phpbb\request\request |\PHPUnit_Framework_MockObject_MockObject $request */
	protected $request;

	/** @var \mrfg\cogauth\cognito\controller | \PHPUnit_Framework_MockObject_MockObject $controller */
	protected $controller;

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

		$this->controller = $this->getMockBuilder('\mrfg\cogauth\cognito\controller')
			->disableOriginalConstructor()
			->getMock();

		$this->request = $this->getMockBuilder('\phpbb\request\request')
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
			$this->request,
			$this->user,
			$this->phpbb_container,
			'',
			'',
			$this->cognito,
			$this->controller
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
			$this->request,
			$this->user,
			$this->phpbb_container,
			'',
			'',
			$this->cognito,
			$this->controller
		);

		$this->setExpectedTriggerError(512,0);
		$cogauth->init();
	}

}
