<?php
/**
 *
 * AWS Cognito Authentication. An extension for the phpBB Forum Software package.
 *
 * @copyright (c) 2019, Mark Gawler
 * @license GNU General Public License, version 2 (GPL-2.0)
 *
 * Date: 13/07/19
 *
 * Authentication Class Tests
 */

namespace mrfg\cogauth\tests\cognito;

use mrfg\cogauth\cognito\auth_result;
use mrfg\cogauth\cognito\validation_result;

class auth_result_test_functions extends auth_result
{
	public function set_time_now($time_now)
	{
		$this->time_now = $time_now;
	}
}


class auth_result_test extends \phpbb_test_case
{
	/** @var $web_token \mrfg\cogauth\cognito\web_token_phpbb|\PHPUnit_Framework_MockObject_MockObject */
	protected $web_token;

	/** @var $db \phpbb\db\driver\driver_interface|\PHPUnit_Framework_MockObject_MockObject */
	protected $db;

	/** @var $cognito  \mrfg\cogauth\cognito\cognito|\PHPUnit_Framework_MockObject_MockObject  */
	protected $cognito;

	/** @var $log \phpbb\log\log_interface |\PHPUnit_Framework_MockObject_MockObject */
	protected $log;

	public function setUp()
    {
        parent::setUp();

		$this->db = $this->getMockBuilder('\phpbb\db\driver\driver_interface')
			->disableOriginalConstructor()
			->getMock();

		$this->web_token = $this->getMockBuilder('\mrfg\cogauth\cognito\web_token_phpbb')
			->disableOriginalConstructor()
			->setMethods(array('decode_token'))
			->getMock();

		$this->cognito = $this->getMockBuilder('\mrfg\cogauth\cognito\cognito')
			->disableOriginalConstructor()
			->setMethods(array('refresh_access_token_for_username'))
			->getMock();

		$this->log = $this->getMockBuilder('\phpbb\log\log_interface')
			->disableOriginalConstructor()
			->getMock();
    }

    public function test_get_session_token()
	{
		$auth = new auth_result($this->web_token, $this->db, $this->log,'cogauth_authentication');

		// Get the session token but don't create a token if one does not exist.
		$token = $auth->get_session_token(false);
		$this->assertNull($token, 'Validating token not initialized ');

		// Get the session token this time create one
		$token = $auth->get_session_token();
		$this->assertNotNull($token, 'Validating creation of token');

		// fetch the session token
		$this->assertEquals($token, $auth->get_session_token(false), 'validating correct retrieval');
		$this->assertEquals($token, $auth->get_session_token(), 'validating correct retrieval');
	}

    public function test_validate_and_store_auth_response_happy_day()
    {
    	$time_now = time();
		$id_token = 'A simple ID Token';
		$access_token = 'A simple Access Token';
		$refresh_token = 'A Simple Refresh Token';

		$sid = 'cd4e8aaaaaaaaaaaaaaaaaaaaaaaaae2';
		$expires = '1546345899';
		$uuid = 'aaaaaaaa-xxxx-yyyy-zzzz-eeeeeeeeeeee';
		$cognito_username = 'fred the rock flintstones';
		$nickname = 'Fred Flint';
		$email = 'fred_1999929135@tfbnw.ne';
		$phpbb_user_id = 1234;
		$preferred_username = 'Frederick Flintstones';

		$id_token_decoded = array(
			'sub' => $uuid,
			'cognito:username' => $cognito_username,
			'nickname' => $nickname,
			'exp' => $expires,
			'email' => $email,
			'preferred_username' => $preferred_username,
			'custom:phpbb_user_id' => (string) $phpbb_user_id);
		$access_token_decoded = 'decoded access token';

    	$auth_response = array(
    		'IdToken'=> $id_token,
			'AccessToken' => $access_token,
			'RefreshToken' => $refresh_token);


    	$map = array(
			array($id_token, $id_token_decoded),
			array($access_token, $access_token_decoded)
		);
		$this->web_token->expects($this->exactly(2))
			->method('decode_token')->will($this->returnValueMap($map));

		$auth = new auth_result_test_functions(
			$this->web_token, $this->db, $this->log,'cogauth_authentication');
		$auth->set_time_now($time_now);

		$session_token =$auth->get_session_token();
		// Validate the Database Store
		$sql_fields = array(
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
			'autologin' 	=> 0,
			'last_active'	=> $time_now,
			'first_active'	=> $time_now);

		$this->db->expects($this->once())
			->method('sql_build_array')
			->with($this->equalTo('INSERT'), $this->equalTo($sql_fields));

		$this->db->expects($this->once())->method('sql_query');


    	$result = $auth->validate_and_store_auth_response($auth_response);

    	$this->assertEquals(new validation_result($session_token,$phpbb_user_id),$result,'Asserting validate_and_store_auth_response is well formed validation object');


		/** @noinspection PhpUnhandledExceptionInspection */
		$session_token = $auth->authenticated($phpbb_user_id, $sid);
		$this->assertEquals($sql_fields['session_token'],$session_token,
			'Session_Token returned correctly');
	}


	public function test_validate_and_store_auth_response_cognito_created_user()
	{
		$time_now = time();
		$id_token = 'A simple ID Token';
		$access_token = 'A simple Access Token';
		$refresh_token = 'A Simple Refresh Token';

		$sid = 'cd4e8aaaaaaaaaaggggaaaaaaaaaaae2';
		$expires = '1546345899';
		$uuid = 'aaaaaaaa-xxxx-yyyy-zzzz-eeeeeeeeeeee';
		$cognito_username = 'Fred';
		$nickname = 'Fred';
		$email = 'fred_1999929135@tfbnw.ne';
		$phpbb_user_id = 55;
		$preferred_username = 'Fred';

		// note missing fields in the id token as this is a native Cognito created user
		$id_token_decoded = array(
			'sub' => $uuid,
			'cognito:username' => $cognito_username,
			'exp' => $expires,
			'email' => $email);
		$access_token_decoded = 'decoded access token';

		$auth_response = array(
			'IdToken'=> $id_token,
			'AccessToken' => $access_token,
			'RefreshToken' => $refresh_token);


		$map = array(
			array($id_token, $id_token_decoded),
			array($access_token, $access_token_decoded)
		);
		$this->web_token->expects($this->exactly(2))
			->method('decode_token')->will($this->returnValueMap($map));

		$auth = new auth_result_test_functions(
			$this->web_token, $this->db, $this->log,'cogauth_authentication');
		$auth->set_time_now($time_now);

		$session_token =$auth->get_session_token();
		// Validate the Database Store
		$sql_fields = array(
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
			'autologin' 	=> 0,
			'last_active'	=> $time_now,
			'first_active'	=> $time_now);

		$this->db->expects($this->once())
			->method('sql_build_array')
			->with($this->equalTo('INSERT'), $this->equalTo($sql_fields));

		$this->db->expects($this->once())->method('sql_query');


		$result = $auth->validate_and_store_auth_response($auth_response);

		$this->assertEquals(new validation_result($session_token,0),$result,'Asserting validate_and_store_auth_response is well formed validation object');


		/** @noinspection PhpUnhandledExceptionInspection */
		$session_token = $auth->authenticated($phpbb_user_id, $sid);
		$this->assertEquals($sql_fields['session_token'],$session_token,
			'Session_Token returned correctly');
	}

	public function test_authenticated_no_access_token()
	{
		$time_now = time();
		$this->db->expects($this->never())
			->method('sql_build_array');



		$this->log->expects($this->once())
			->method('add')
			->with('user', '1234', 0,'COGAUTH_NO_ACCESS_TOKEN',$time_now);

		$auth = new auth_result_test_functions(
			$this->web_token, $this->db, $this->log,'cogauth_authentication');
		$auth->set_time_now($time_now);

		/** @noinspection PhpUnhandledExceptionInspection */
		$auth->authenticated('1234', 'dddd');

	}

	public function test_authenticated_no_sid()
	{
		$dummy_access_token = 'Dummy Access token';
		$dummy_id_token = 'Dummy ID token';
		$auth_response = array(
			'IdToken'=> $dummy_id_token,
			'AccessToken' => $dummy_access_token,
			'RefreshToken' => '');

		$id_token_decoded = array(
			'sub' =>  'aaaaaaaa-xxxx-yyyy-zzzz-eeeeeeeeeeee',
			'cognito:username' => '',
			'nickname' => '',
			'exp' => '',
			'email' => '',
			'preferred_username' => '');
		$access_token_decoded = 'decoded access token';

		$map=array(
			array($dummy_id_token, $id_token_decoded),
			array($dummy_access_token, $access_token_decoded)
		);
		$this->web_token->expects($this->exactly(2))
			->method('decode_token')->will($this->returnValueMap($map));

		$this->db->expects($this->never())
			->method('sql_build_array');

		//$this->setExpectedException('\mrfg\cogauth\cognito\exception\cogauth_authentication_exception');
		//todo: confirm this is the correct replacement
		$this->expectException('\mrfg\cogauth\cognito\exception\cogauth_authentication_exception');


		$auth = new auth_result(
			$this->web_token, $this->db, $this->log,'cogauth_authentication');

		$result = $auth->validate_and_store_auth_response($auth_response);
		$this->assertInstanceOf(validation_result::class, $result, 'validating a response');
		$this->assertEquals(32, strlen($result->cogauth_token),'Validating response');

		/** @noinspection PhpUnhandledExceptionInspection */
		$auth->authenticated('1234', '');

	}

	public function test_get_access_token_from_sid_no_data(){

		$auth = new \mrfg\cogauth\tests\cognito\auth_result_test_functions(
			$this->web_token, $this->db, $this->log,'cogauth_authentication');
		$time_now = time();
		$auth->set_time_now($time_now);

		// Check the sid is escaped
		$this->db->expects($this->once())
			->method('sql_escape')
			->willReturn('qwerty_esc');

		// Is he SQL query formed correctly

		$this->db->expects($this->once())
			->method('sql_query')
			->with("SELECT * FROM cogauth_authentication WHERE sid = 'qwerty_esc'")
			->willReturn(array());

		$result = $auth->get_access_token_from_sid('qwerty');
		$this->assertTrue(! $result, "Asserting no access token returned");

	}
	public function test_get_access_token_from_session_token_no_data(){

		$auth = new \mrfg\cogauth\tests\cognito\auth_result_test_functions(
			$this->web_token, $this->db,$this->log, 'cogauth_authentication');
		$time_now = time();
		$auth->set_time_now($time_now);

		// Check the session_token is escaped
		$this->db->expects($this->once())
			->method('sql_escape')
			->willReturn('asdfg_esc');

		// Is he SQL query formed correctly
		$this->db->expects($this->once())
			->method('sql_query')
			->with("SELECT * FROM cogauth_authentication WHERE session_token = 'asdfg_esc'")
			->willReturn(array());

		$result = $auth->get_access_token_from_session_token('asdfg');
		$this->assertFalse($result, "Asserting no access token returned");

	}


	public function test_get_access_token_from_sid_load_auth_data_null(){
		$time_now = time();

		$row = array ();

		$auth = new \mrfg\cogauth\tests\cognito\auth_result_test_functions(
			$this->web_token, $this->db, $this->log,'cogauth_authentication');
		$auth->set_time_now($time_now);

		// Is he SQL query formed correctly
		$this->db->expects($this->once())
			->method('sql_fetchrow')
			->willReturn($row);

		//Assert no refresh required
		$this->cognito->expects($this->never())
			->method('refresh_access_token_for_username');

		$result = $auth->get_access_token_from_sid('a652e8feaaaaaaaaaaaaaaaaaaaaa54a');
		$this->assertFalse($result, "Asserting null access token returned");

	}

}

