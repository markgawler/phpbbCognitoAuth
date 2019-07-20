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
 * Authentication Class Twsts
 */

namespace mrfg\cogauth\tests\cognito;

class authentication_test extends \phpbb_test_case
{
	/** @var $web_token \mrfg\cogauth\cognito\web_token_phpbb|\PHPUnit_Framework_MockObject_MockObject */
	protected $web_token;

	/** @var $db \phpbb\db\driver\driver_interface|\PHPUnit_Framework_MockObject_MockObject */
	protected $db;

	/** @var $web_token \mrfg\cogauth\cognito\authentication */
	protected $auth;


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

		//$this->auth = $this->getMockBuilder('\mrfg\cogauth\cognito\authentication')
		//	->setMethods(array('authenticated'));

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
			$this->web_token, $this->db,'cogauth_authentication');


		// Validate the Database Store
		$sql_fields = array(
			'session_token' => $auth->get_session_token(),
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

		$this->db->expects($this->once())
			->method('sql_build_array')
			->with($this->equalTo('INSERT'), $this->equalTo($sql_fields));

		$this->db->expects($this->once())->method('sql_query');


    	$result = $auth->validate_and_store_auth_response($encoded_response);

    	$this->assertTrue($result,'Asserting validate_and_store_auth_response is True');


		$session_token = $auth->authenticated($phpbb_user_id, $sid);
		$this->assertEquals($sql_fields['session_token'],$session_token,
			'Sesion_Token returned correctly');
	}

	public function test_authenticated_no_access_token()
	{
		$this->db->expects($this->never())
			->method('sql_build_array');

		$this->setExpectedException('\mrfg\cogauth\cognito\exception\cogauth_authentication_exception');

		$auth = new \mrfg\cogauth\cognito\authentication(
			$this->web_token, $this->db,'cogauth_authentication');

		$auth->authenticated('1234', 'dddd');

	}

	public function test_authenticated_no_sid()
	{
		$dummy_access_token = 'Dummy Access token';
		$dummy_id_token = 'Dummy ID token';
		$encoded_response = json_encode((array(
			'id_token'=> $dummy_id_token,
			'access_token' => $dummy_access_token,
			'refresh_token' => '')));

		$id_token_decoded = array(
			'sub' =>  'aaaaaaaa-xxxx-yyyy-zzzz-eeeeeeeeeeee',
			'cognito:username' => '',
			'nickname' => '',
			'expires' => '',
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

		$auth = new \mrfg\cogauth\cognito\authentication(
			$this->web_token, $this->db,'cogauth_authentication');

		$result = $auth->validate_and_store_auth_response($encoded_response);
		$this->assertTrue($result,'Validating responce');

		$auth->authenticated('1234', '');

	}


}

