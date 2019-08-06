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

class auth_result_test_functions extends \mrfg\cogauth\cognito\auth_result
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

	/** @var $web_token \mrfg\cogauth\cognito\auth_result */
	protected $auth;

	/** @var $cognito  \mrfg\cogauth\cognito\cognito|\PHPUnit_Framework_MockObject_MockObject  */
	protected $cognito;


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

		//$this->auth = $this->getMockBuilder('\mrfg\cogauth\cognito\authentication')
		//	->setMethods(array('authenticated'));

    }

    public function test_get_session_token()
	{
		$auth = new \mrfg\cogauth\cognito\auth_result(
			$this->web_token, $this->db,'cogauth_authentication');

		// Get the session token but dont create a token if one dosn't exist.
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


    	$map = array(
			array($id_token, $id_token_decoded),
			array($access_token, $access_token_decoded)
		);
		$this->web_token->expects($this->exactly(2))
			->method('decode_token')->will($this->returnValueMap($map));


		$auth = new \mrfg\cogauth\cognito\auth_result(
			$this->web_token, $this->db,'cogauth_authentication');

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
			'refresh_token' => $refresh_token);

		$this->db->expects($this->once())
			->method('sql_build_array')
			->with($this->equalTo('INSERT'), $this->equalTo($sql_fields));

		$this->db->expects($this->once())->method('sql_query');


    	$result = $auth->validate_and_store_auth_response($auth_response);

    	$this->assertEquals($session_token,$result,'Asserting validate_and_store_auth_response is True');


		/** @noinspection PhpUnhandledExceptionInspection */
		$session_token = $auth->authenticated($phpbb_user_id, $sid);
		$this->assertEquals($sql_fields['session_token'],$session_token,
			'Session_Token returned correctly');
	}

	public function test_authenticated_no_access_token()
	{
		$this->db->expects($this->never())
			->method('sql_build_array');

		$this->setExpectedException('\mrfg\cogauth\cognito\exception\cogauth_authentication_exception');

		$auth = new \mrfg\cogauth\cognito\auth_result(
			$this->web_token, $this->db,'cogauth_authentication');

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

		$this->setExpectedException('\mrfg\cogauth\cognito\exception\cogauth_authentication_exception');

		$auth = new \mrfg\cogauth\cognito\auth_result(
			$this->web_token, $this->db,'cogauth_authentication');

		$result = $auth->validate_and_store_auth_response($auth_response);
		$this->assertEquals(strlen($result),32,'Validating response');

		/** @noinspection PhpUnhandledExceptionInspection */
		$auth->authenticated('1234', '');

	}

	public function test_get_access_token_from_sid_no_data(){

		$auth = new \mrfg\cogauth\tests\cognito\auth_result_test_functions(
			$this->web_token, $this->db,'cogauth_authentication');
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
			$this->web_token, $this->db,'cogauth_authentication');
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

	//todo fix after refactor
	/*public function test_get_access_token_from_sid_load_auth_data(){
		$time_now = time();

		$row = array (
			'session_token' => 'NtMQHaaaaaaaaaaaaaaaaaaaaaaaaaa1',
			'expires' => $time_now + 5000,
			'uuid' => 'aaaaaaaa-bbbb-xxxx-dddd-eeeeeeeeeeee',
			'username' => 'u000101',
			'preferred_username' => '',
			'nickname' => '',
			'email' => 1221,
			'phpbb_user_id' => '',
			'sid' => 'a652e8feaaaaaaaaaaaaaaaaaaaaa54a',
			'access_token' =>'eyJraWQiOiJndlwvcmNDQTBMWUhMd2-piUlVmMU.Fwe',
			'refresh_token' => 'eyJjdHkiOiJKV1Qiffffffffffffff.U2R0NNIiwi-'
		);

		$auth = new \mrfg\cogauth\tests\cognito\authentication_test_functions(
			$this->web_token, $this->db,'cogauth_authentication');
		$time_now = time();
		$auth->set_time_now($time_now);

		// Check the session_token is escaped
		$this->db->expects($this->once())
			->method('sql_escape')
			->with('a652e8feaaaaaaaaaaaaaaaaaaaaa54a')
			->willReturn('aeaaaaaaaaaaaaaaaaa54a');

		// Is he SQL query formed correctly
		$this->db->expects($this->once())
			->method('sql_query')
			->with("SELECT * FROM cogauth_authentication WHERE sid = 'aeaaaaaaaaaaaaaaaaa54a'");

		// Is he SQL query formed correctly
		$this->db->expects($this->once())
			->method('sql_fetchrow')
			->willReturn($row);


		//Assert no refresh required
		$this->cognito->expects($this->never())
			->method('refresh_access_token_for_username');

		$result = $auth->get_access_token_from_sid('a652e8feaaaaaaaaaaaaaaaaaaaaa54a');
		$this->assertEquals($row['access_token'], $result, "Asserting access token returned");

	}
*/
	//todo fix after refactor
	/*public function test_get_access_token_from_sid_load_auth_data_refresh(){
		$time_now = time();
		$refresh_token ='eyJjdHkiO.refresh.token.ffffff.U2R0NNIiwi-';
		$cognito_username = 'u000101';
		$phpbb_user_id = 1221;
		$row = array (
			'session_token' => 'NtMQHaaaaaaaaaaaa.refresh.aaaaa1',
			'expires' => $time_now + 299,
			'uuid' => 'aaaaaaaa-bbbb-xxxx-dddd-eeeeeeeeeeee',
			'username' => $cognito_username,
			'preferred_username' => '',
			'nickname' => '',
			'email' => '',
			'phpbb_user_id' => $phpbb_user_id,
			'sid' => 'a652e8feaaaaa.refresh.aaaaaaa54a',
			'access_token' =>'eyJraWQiOiJndlwvcmNDQTBMWUhMd2-piUlVmMU.Fwe',
			'refresh_token' => $refresh_token
		);
		$new_token = 'eyJjdeeeee.new.token.aaffffff.U2R0NNIiwi-';

		$auth = new \mrfg\cogauth\tests\cognito\authentication_test_functions(
			$this->web_token, $this->db,'cogauth_authentication');
		$time_now = time();
		$auth->set_time_now($time_now);

		// Is he SQL query formed correctly
		$this->db->expects($this->once())
			->method('sql_fetchrow')
			->willReturn($row);

		//Assert no refresh required
		$this->cognito->expects($this->once())
			->method('refresh_access_token_for_username')
			->with($refresh_token, $cognito_username, $phpbb_user_id)
			->willReturn($new_token);

		$result = $auth->get_access_token_from_sid('a652e8feaaaaaaaaaaaaaaaaaaaaa54a');
		$this->assertEquals($new_token, $result, "Asserting access token returned");

	}
*/
	//todo fix after refactor
	/*public function test_get_access_token_from_sid_load_auth_data_refresh_fail(){
		$time_now = time();
		$refresh_token ='eyJjdHkiO.refresh.token.ffffff.U2R0NNIiwi-';
		$cognito_username = 'u000101';
		$phpbb_user_id = 1991;
		$row = array (
			'session_token' => 'NtMQHaaaaaaaaaaaa.refresh.aaaaa1',
			'expires' => $time_now + 299,
			'uuid' => 'aaaaaaaa-bbbb-xxxx-dddd-eeeeeeeeeeee',
			'username' => $cognito_username,
			'preferred_username' => '',
			'nickname' => '',
			'email' => '',
			'phpbb_user_id' => $phpbb_user_id,
			'sid' => 'a652e8feaaaaa.refresh.aaaaaaa54a',
			'access_token' =>'eyJraWQiOiJndlwvcmNDQTBMWUhMd2-piUlVmMU.Fwe',
			'refresh_token' => $refresh_token
		);

		$auth = new \mrfg\cogauth\tests\cognito\authentication_test_functions(
			$this->web_token, $this->db,'cogauth_authentication');
		$time_now = time();
		$auth->set_time_now($time_now);

		// Is he SQL query formed correctly
		$this->db->expects($this->once())
			->method('sql_fetchrow')
			->willReturn($row);

		//Assert no refresh required
		$this->cognito->expects($this->once())
			->method('refresh_access_token_for_username')
			->with($refresh_token, $cognito_username, $phpbb_user_id)
			->willReturn(false);

		$result = $auth->get_access_token_from_sid('a652e8feaaaaaaaaaaaaaaaaaaaaa54a');
		$this->assertFalse($result, "Asserting access refresh fail");

	}
*/
	public function test_get_access_token_from_sid_load_auth_data_null(){
		$time_now = time();

		$row = array ();

		$auth = new \mrfg\cogauth\tests\cognito\auth_result_test_functions(
			$this->web_token, $this->db,'cogauth_authentication');
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

