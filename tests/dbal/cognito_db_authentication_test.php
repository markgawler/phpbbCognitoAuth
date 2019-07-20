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

	}


	public function test_db_columns()
	{
		$columns = array('session_token', 'expires', 'uuid', 'username', 'prefered_username', 'nickname', 'email',
						 'phpbb_user_id', 	'sid', 'access_token', 'refresh_token');

		foreach ($columns as $c) {
			$this->assertTrue(
				$this->db_tools->sql_column_exists($this->table_prefix . 'cogauth_authentication', $c),
				'Asserting that column "' . $c . '" exists');
		}
	}

	public function test_validate_and_store_auth_response_happy_day()
	{
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
			'expires' => $expires,
			'email' => $email,
			'preferred_username' => $preferred_username);
		$access_token_decoded = 'decoded access token';

		$encoded_response = json_encode((array(
			'id_token'=> $id_token,
			'access_token' => $access_token,
			'refresh_token' => $refresh_token)));

		$map=array(
			array($id_token, $id_token_decoded),
			array($access_token, $access_token_decoded)
		);
		$this->web_token->expects($this->exactly(2))
			->method('decode_token')->will($this->returnValueMap($map));

		$auth = new \mrfg\cogauth\cognito\authentication(
			$this->web_token, $this->db,$this->table_prefix . 'cogauth_authentication');

		// Validate the Database Store
		$session_token =  $auth->get_session_token();
		$fields = array(
			'session_token' => $session_token,
			'expires'  		=> $expires,
			'uuid'			=> $uuid,
			'username' 		=> $cognito_username,
			'prefered_username' => $preferred_username,
			'nickname' 		=> $nickname,
			'email' 		=> $email,
			'phpbb_user_id' => $phpbb_user_id,
			'sid' 			=> $sid,
			'access_token'  => $access_token_decoded,
			'refresh_token' => $refresh_token);

		$result = $auth->validate_and_store_auth_response($encoded_response);

		$this->assertTrue($result,'Asserting validate_and_store_auth_response is True');

		$auth->authenticated($phpbb_user_id, $sid);

		$sql = 'SELECT * FROM ' . $this->table_prefix . "cogauth_authentication WHERE  session_token = '" . $session_token . "'";
		$result = $this->db->sql_query($sql);
		$rows = $this->db->sql_fetchrow();
		$this->db->sql_freeresult($result);

		$this->assertEquals($fields, $rows,'Database values match');
	}
}