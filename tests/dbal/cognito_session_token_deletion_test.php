<?php
/**
 * @package     mrfg\cogauth\tests\dbal;

 * @subpackage
 *
 * @copyright   A copyright
 * @license     A "Slug" license name e.g. GPL2
 */

namespace mrfg\cogauth\tests\dbal;

/** @noinspection PhpIncludeInspection */
include_once __DIR__ . '/../../vendor/autoload.php';

/*
class cognito_test_functions extends \mrfg\cogauth\cognito\cognito
{
	public function set_time_now($time_now)
	{
		$this->time_now = $time_now;
	}
}
*/
class cognito_session_token_deletion_test extends \phpbb_database_test_case
{
	/** @var $user \phpbb\user */
	protected $user;

	/** @var $cognito_client \phpbb\config\config */
	protected $config;

	/** @var $db \phpbb\db\driver\driver_interface */
	protected $db;

	/** @var \phpbb\db\tools\tools */
	protected $db_tools;

	/** @var string */
	protected $table_prefix;

	/** @var $web_token \mrfg\cogauth\cognito\web_token_phpbb|\PHPUnit_Framework_MockObject_MockObject */
	protected $web_token;

	/** @var $ \mrfg\cogauth\cognito\user|\PHPUnit_Framework_MockObject_MockObject */
	protected $cognito_user;

	/** @var $authentication \mrfg\cogauth\cognito\authentication|\PHPUnit_Framework_MockObject_MockObject */
	protected $authentication;

	/** @var $client  \mrfg\cogauth\cognito\cognito_client_wrapper| \PHPUnit_Framework_MockObject_MockObject */
	protected $client;

	/** @noinspection PhpUndefinedClassInspection */
	/** @var $cognito \mrfg\cogauth\tests\dbal\cognito_test_functions | \PHPUnit_Framework_MockObject_MockObject  */
	protected $cognito;

	/** @var $request \phpbb\request\request_interface */
	protected $request;

	protected $log;

	protected $initial_row_count;


	static protected function setup_extensions()
	{
		return array('mrfg/cogauth');
	}

	public function getDataSet()
	{
		return $this->createXMLDataSet(dirname(__FILE__) . '/fixtures/token_deletion.xml');
	}

	public function setUp()
	{
		parent::setUp();

		global $table_prefix;

		$this->table_prefix = $table_prefix;
		$this->db = $this->new_dbal();
		$this->db_tools = new \phpbb\db\tools\tools($this->db);

		$this->user = $this->getMockBuilder('\phpbb\user')
			->disableOriginalConstructor()
			->getMock()
		;

		// Config
		$this->config = $this->getMockBuilder('\phpbb\config\config')
			->disableOriginalConstructor()
			->getMock()
		;
		$map = array(
			array('session_length', '100'),
			array('cogauth_max_session_hours', 3),
		);
		$this->config->method('offsetGet')->will($this->returnValueMap($map));

		$this->web_token = $this->getMockBuilder('\mrfg\cogauth\cognito\web_token_phpbb')
			->disableOriginalConstructor()
			->getMock();

		$this->cognito_user = $this->getMockBuilder('\mrfg\cogauth\cognito\user')
			->disableOriginalConstructor()
			->setMethods(array('get_cognito_username'))
			->getMock();

		$this->authentication = $this->getMockBuilder('\mrfg\cogauth\cognito\authentication')
			->disableOriginalConstructor()
			->setMethods(array(
				'validate_and_store_auth_response',
				'authenticated',
				'get_session_token'))
			->getMock();

		$this->client = $this->getMockBuilder('\mrfg\cogauth\cognito\cognito_client_wrapper')
			->disableOriginalConstructor()
			->getMock();

		$this->log = $this->getMockBuilder('\phpbb\log\log_interface')
			->disableOriginalConstructor()
			->getMock();

		$this->request = $this->getMockBuilder('\phpbb\request\request_interface')
			->disableOriginalConstructor()
			->getMock();

		$construct_args = array(
			$this->db, $this->config, $this->user, $this->request, $this->log,
			$this->client, $this->web_token, $this->cognito_user,
			$this->authentication, $this->table_prefix . 'cogauth_session');

		$this->cognito = $this->getMockBuilder('\mrfg\cogauth\tests\dbal\cognito_test_functions')
			->setMethods(array('refresh_access_token','handleCognitoIdentityProviderException'))
			->setConstructorArgs($construct_args)
			->getMock();

		$this->initial_row_count = $this->count_rows();

	}

	protected function count_rows($where_token_id_equals = false)
	{
		if ($where_token_id_equals)
		{
			$where = " WHERE session_token = '" . $where_token_id_equals . "'";
		}
		else
		{
			$where = '';
		}
		$sql = 'SELECT COUNT(*) AS session_rows FROM ' . $this->table_prefix . 'cogauth_session' . $where;
		$result = $this->db->sql_query($sql);
		$rows = (int) $this->db->sql_fetchfield('session_rows');
		$this->db->sql_freeresult($result);
		return $rows;
	}

	public function test_expire_token_none()
	{
		$this->cognito->set_time_now(1546345800);

		$this->cognito->cleanup_session_tokens();
		$this->assertEquals($this->initial_row_count, $this->count_rows(),'Asserting no rows deleted from cogauth_session table');

	}
	public function test_expire_token_one()
	{
		$this->cognito->set_time_now(1546345800+100);
		$this->cognito->cleanup_session_tokens();
		$this->assertEquals(0, $this->count_rows('54MQHz2q89Bjc4HEjq82bhgfdzmXD6u1'), 'Asserting correct row deleted from cogauth_session table');
		$this->assertEquals($this->initial_row_count - 1, $this->count_rows(),'Asserting one row deleted from cogauth_session table');
	}

	public function test_expire_token_two()
	{
		$this->cognito->set_time_now(1546345800+200);
		$this->cognito->cleanup_session_tokens();

		$this->assertEquals(0, $this->count_rows('NtMQHz2q89Bjc4HEjq82brEJ6zmXD6u1'), 'Asserting correct row deleted from cogauth_session table');
		$this->assertEquals(0, $this->count_rows('54MQHz2q89Bjc4HEjq82bhgfdzmXD6u1'), 'Asserting correct row deleted from cogauth_session table');
		$this->assertEquals($this->initial_row_count - 2, $this->count_rows(),'Asserting two rows deleted from cogauth_session table');
	}

	public function test_expire_token_autologin()
	{
		$this->cognito->set_time_now(1546345700 + 10800 ); //Time now = First active  + 3 hours and 1 second
		$this->cognito->cleanup_session_tokens();

		$this->assertEquals($this->initial_row_count - 2, $this->count_rows(),'Asserting no auto login rows deleted (At 3 hours)');
	}
	public function test_expire_token_autologin_expired()
	{
		$this->cognito->set_time_now(1546345700 + 10800 + 1); //Time now = First active  + 3 hours and 1 second
		$this->cognito->cleanup_session_tokens();

		$this->assertEquals(1, $this->count_rows(),'Asserting all bar one rows deleted');
		$this->assertEquals(1, $this->count_rows('ddddddddddddc4HEjq82bhgfdzmXD6u1'), 'Asserting correct row remains');
	}

	public function test_expire_token_autologin_expired_all()
	{
		$this->cognito->set_time_now(1546345900 + 10800 + 1); //Time now = First active  + 3 hours and 1 second
		$this->cognito->cleanup_session_tokens();
		$this->assertEquals(0, $this->count_rows(),'Asserting all rows deleted');
	}

}