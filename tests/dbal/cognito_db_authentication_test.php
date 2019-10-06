<?php
/**
 *
 * AWS Cognito Authentication. An extension for the phpBB Forum Software package.
 *
 * @copyright (c) 2018, Mark Gawler
 * @license GNU General Public License, version 2 (GPL-2.0)
 *
 * Date: 14/09/18
 *
 * Cognito interface test
 */

namespace mrfg\cogauth\tests\dbal;

/*
class auth_result_test_functions extends \mrfg\cogauth\cognito\auth_result
{
	public function set_time_now($time_now)
	{
		$this->time_now = $time_now;
	}
}
*/

use mrfg\cogauth\cognito\validation_result;

class cognito_authentication_test extends \phpbb_database_test_case
{
	/* @var $db \phpbb\db\driver\driver_interface */
    protected $db;

	/** @var \phpbb\db\tools\tools */
	protected $db_tools;

	/** @var string */
	protected $table_prefix;

	/** @var $web_token \mrfg\cogauth\cognito\web_token_phpbb|\PHPUnit_Framework_MockObject_MockObject */
	protected $web_token;

	/** @var $cognito  \mrfg\cogauth\cognito\cognito|\PHPUnit_Framework_MockObject_MockObject  */
	protected $cognito;

	/** @var $log \phpbb\log\log_interface |\PHPUnit_Framework_MockObject_MockObject */
	protected $log;

	static protected function setup_extensions()
	{
		return array('mrfg/cogauth');
	}

	public function getDataSet()
	{
		return $this->createXMLDataSet(dirname(__FILE__) . '/fixtures/authentication.xml');
	}


	public function setUp()
    {
		parent::setUp();

		global $table_prefix;

		$this->table_prefix = $table_prefix;

		$this->db = $this->new_dbal();
		$this->db_tools = new \phpbb\db\tools\tools($this->db);


		$this->web_token = $this->getMockBuilder('\mrfg\cogauth\cognito\web_token_phpbb')
			->disableOriginalConstructor()
			->setMethods(array('decode_token'))
			->getMock();

		$this->cognito = $this->getMockBuilder('\mrfg\cogauth\cognito\cognito')
			->disableOriginalConstructor()
			->setMethods(array('refresh_access_token_for_username'))
			->getMock();

		$this->cognito = $this->getMockBuilder('\mrfg\cogauth\cognito\cognito')
			->disableOriginalConstructor()
			->setMethods(array('refresh_access_token_for_username'))
			->getMock();

		$this->log = $this->getMockBuilder('\phpbb\log\log_interface')
			->disableOriginalConstructor()
			->getMock();
	}


	public function test_db_columns()
	{
		$columns = array('session_token', 'expires', 'uuid', 'username', 'preferred_username', 'nickname', 'email',
						 'phpbb_user_id', 	'sid', 'access_token', 'refresh_token');

		foreach ($columns as $c) {
			$this->assertTrue(
				$this->db_tools->sql_column_exists($this->table_prefix . 'cogauth_authentication', $c),
				'Asserting that column "' . $c . '" exists');
		}
	}

	public function test_validate_and_store_auth_response_happy_day()
	{
		$time_now = time();
		$id_token = 'A simple ID Token';
		$access_token = 'A simple Acces Token';
		$refresh_token = 'A Simple Refresh Token';

		$sid = 'cd4e8aaaaaaaaaaaaaaaaaaaaaaaaae2';
		$expires = '1546345899';
		$uuid = 'aaaaaaaa-xxxx-yyyy-zzzz-eeeeeeeeeeee';
		$cognito_username = 'fred the rock flintston';
		$nickname = 'Fred Flint';
		$email = 'fred_1999929135@tfbnw.ne';
		$phpbb_user_id = 1234;
		$preferred_username = 'Frederick Flintstone';

		$id_token_decoded = array(
			'sub' => $uuid,
			'cognito:username' => $cognito_username,
			'nickname' => $nickname,
			'exp' => $expires,
			'email' => $email,
			'preferred_username' => $preferred_username);
		$access_token_decoded = 'decoded access token';

		$auth_response = array(
			'IdToken'=> $id_token,
			'AccessToken' => $access_token,
			'RefreshToken' => $refresh_token);

		$map=array(
			array($id_token, $id_token_decoded),
			array($access_token, $access_token_decoded)
		);
		$this->web_token->expects($this->exactly(2))
			->method('decode_token')->will($this->returnValueMap($map));

		$auth = new auth_result_test_functions(
			$this->web_token, $this->db, $this->log, $this->table_prefix . 'cogauth_authentication');
		$auth->set_time_now($time_now);

		// Validate the Database Store
		$session_token =  $auth->get_session_token();
		$fields = array(
			'session_token' => $session_token,
			'expires'  		=> $expires,
			'uuid'			=> $uuid,
			'username' 		=> $cognito_username,
			'preferred_username' => $preferred_username,
			'nickname' 		=> $nickname,
			'email' 		=> $email,
			'phpbb_user_id' => $phpbb_user_id,
			'sid' 			=> $sid,
			'access_token'  => $access_token,
			'refresh_token' => $refresh_token,
			'autologin'		=> false,
			'last_active'	=> $time_now,
			'first_active'	=> $time_now);

		$result = $auth->validate_and_store_auth_response($auth_response);

		$this->assertEquals(new validation_result($session_token), $result,'Asserting validate_and_store_auth_response is True');

		/** @noinspection PhpUnhandledExceptionInspection */
		$auth->authenticated($phpbb_user_id, $sid);

		$sql = 'SELECT * FROM ' . $this->table_prefix . "cogauth_authentication WHERE  session_token = '" . $session_token . "'";
		$result = $this->db->sql_query($sql);
		$rows = $this->db->sql_fetchrow();
		$this->db->sql_freeresult($result);

		$this->assertEquals($fields, $rows,'Database values match');
	}


	public function test_phpbb_session_killed_01()
	{
		$auth = new \mrfg\cogauth\cognito\auth_result(
			$this->web_token, $this->db,$this->log, $this->table_prefix . 'cogauth_authentication');

		$session_id = 'a652e8fe432c7b6d6e42eb134ae9054a';
		$rows = $auth->kill_session($session_id);
		$this->assertEquals(1,$rows, 'Asserting one row is effected.');
	}

	public function test_phpbb_session_killed_02()
	{
		$auth = new \mrfg\cogauth\cognito\auth_result(
			$this->web_token, $this->db, $this->log,$this->table_prefix . 'cogauth_authentication');

		$session_id = '12';
		$rows = $auth->kill_session($session_id);
		$this->assertEquals(0,$rows, 'Asserting no rows effected.');
	}


}
