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

namespace mrfg\cogauth\tests\event_listener;

class cognito_db_test extends \phpbb_database_test_case
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

    /** @var $web_token \mrfg\cogauth\cognito\web_token|\PHPUnit_Framework_MockObject_MockObject */
    protected $web_token;

    /** @var $client  \mrfg\cogauth\cognito\cognito_client_wrapper| \PHPUnit_Framework_MockObject_MockObject */
	protected $client;

	/** @var $cognito \mrfg\cogauth\cognito\cognito */
	protected $cognito;



	/** @var $log \phpbb\log\log_interface |\PHPUnit_Framework_MockObject_MockObject */
	protected $log;

	static protected function setup_extensions()
	{
		return array('mrfg/cogauth');
	}

	public function getDataSet()
	{
		return $this->createXMLDataSet(dirname(__FILE__) . '/fixtures/user_data.xml');
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
			->getMock();

		$this->config = $this->getMockBuilder('\phpbb\config\config')
            ->disableOriginalConstructor()
            ->getMock();

        $this->web_token = $this->getMockBuilder('\mrfg\cogauth\cognito\web_token')
            ->disableOriginalConstructor()
            ->setMethods(array('verify_access_token'))
            ->getMock();

		$this->client = $this->getMockBuilder('\mrfg\cogauth\cognito\cognito_client_wrapper')
			->disableOriginalConstructor()
			->getMock();

		$this->log = $this->getMockBuilder('\phpbb\log\log_interface')
			->disableOriginalConstructor()
			->getMock();

        $map = array(
            array('cogauth_pool_id', 'eu-west-1_T0xxxxx1'),
            array('cogauth_client_id', 'faaaaaaaaaaaaaaaaaaaaaav7'),
            array('cogauth_client_secret', '110aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaai'),
            array('cogauth_aws_key', 'AKAAAAAAAAAAAAAAAAAQ'),
            array('cogauth_aws_secret', 'BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAG'),
            array('cogauth_aws_region', 'eu-west-1')
        );
        $this->config->method('offsetGet')->will($this->returnValueMap($map));

		/** @var $cognito \mrfg\cogauth\cognito\cognito_client_wrapper */
		$this->cognito = new \mrfg\cogauth\cognito\cognito($this->db, $this->config, $this->user, $this->log, $this->client, $this->web_token, $this->table_prefix . 'cogauth_session');

	}


	public function test_db_columns()
	{
		$columns = array('sid', 'access_token', 'expires_at', 'id_token', 'refresh_token', 'token_type');
		foreach ($columns as $c) {
			$this->assertTrue($this->db_tools->sql_column_exists($this->table_prefix . 'cogauth_session', $c), 'Asserting that column "' . $c . '" exists');
		}
	}

	public function test_get_token()
	{
		$this->user->session_id = 'a652e8fe432c7b6d6e42eb134ae9054a';
		$token = $this->cognito->get_access_token();
		$this->assertEquals('eyJraWQiOiJndlwvcmNDQTBMWUhMd2piUlVmMUFweEJESVRlRlwvbHRrTUFzNXRjTUJJUzQ9IiwiYWxnIjoiUlMyNTYifQ.eyJzdWIiOiJlZDgzYTkxMi04ZTUwLTRhOWYtYjVhNi1kOGJhNjVmMTYzZjciLCJldmVudF9pZCI6ImQ3YjgwOWNmLWI0NjEtMTFlOC05M2I2LTYzNThkYThlMTJiOSIsInRva2VuX3VzZSI6ImFjY2VzcyIsInNjb3BlIjoiYXdzLmNvZ25pdG8uc2lnbmluLnVzZXIuYWRtaW4iLCJhdXRoX3RpbWUiOjE1MzY1MTkyOTYsImlzcyI6Imh0dHBzOlwvXC9jb2duaXRvLWlkcC5ldS13ZXN0LTEuYW1hem9uYXdzLmNvbVwvZXUtd2VzdC0xX1Q3emptcXhhMSIsImV4cCI6MTUzNjUyMjg5NiwiaWF0IjoxNTM2NTE5Mjk2LCJqdGkiOiI0MjljNTY0OC05YTk4LTRmOGItOWRiMS1kMWFiYjZiZDM3NDEiLCJjbGllbnRfaWQiOiJmMjRhcXBkZjNhYnMyazFiMGc4bXRkdHY3IiwidXNlcm5hbWUiOiJ1MDAwMDQ5In0.i9BGWE3tgO7OjQM44cOrKK_uynq5r7vH_27IjZ747f5U7_iwQLUquxKMdU7NFg12dU264xbP3hbW_xXIPtC0IckEef1fM-V_9JQdr2iBEibugPXSME51-6KqUnzYidedFUswdZ_xvURDgZZehjD08e7V_0BNqFzmiCohBjV7i5JR-bJmhsE33bWOE1qBXFbR47x8iaI558O8ZG_06zvgQHFP08BRkwVSVyUqfv_hDkwObHGNES3eCvqLqzw0_yMr21_U52dNZE9oIWe7z01GFxiKcXB02TFHxiPFtG_Fkcv053OGBmNsY1ARVPafifSOIn6_pN-WU6aoCcaqjV63hg',
			$token,'Asserting correct access token returned for SID');
	}

	public function test_phpbb_session_killed_01()
	{
		$session_id = 'a652e8fe432c7b6d6e42eb134ae9054a';
		$rows = $this->cognito->phpbb_session_killed($session_id);
		$this->assertEquals(1,$rows, 'Asserting one row is effected.');
	}

	public function test_phpbb_session_killed_02()
	{
		$session_id = '1';
		$rows = $this->cognito->phpbb_session_killed($session_id);
		$this->assertEquals(0,$rows, 'Asserting no rows effected.');
	}

	public function test_session_expired_01()
	{
		$rows = $this->cognito->delete_expired_sessions();
		$this->assertEquals(1,$rows, 'Asserting no rows effected.');
	}

	public function test_session_expired_02()
	{
		// Add an expired token
		$this->client->expects($this->once())
			->method('admin_initiate_auth')
			->willReturn(array('AuthenticationResult' => array(
				'AccessToken' => 'xxxxxxx',
				'ExpiresIn' => -1,
				'IdToken' => 'fred',
				'RefreshToken' => 'yyyyyyy',
				'TokenType' => 'fakeNews'
			)));
		$this->cognito->authenticate(1234,'password');
		$this->cognito->store_auth_result('A1234567890');


		$rows = $this->cognito->delete_expired_sessions();
		$this->assertEquals(2,$rows, 'Asserting no rows effected.');
	}
	public function test_session_expired_03()
	{
		// Add ata token that will expire in one hour
		$this->client->expects($this->once())
			->method('admin_initiate_auth')
			->willReturn(array('AuthenticationResult' => array(
				'AccessToken' => 'xxxxxxx',
				'ExpiresIn' => 3600,
				'IdToken' => 'fred',
				'RefreshToken' => 'yyyyyyy',
				'TokenType' => 'fakeNews'
			)));
		$this->cognito->authenticate(1233,'password');
		$this->cognito->store_auth_result('A1234567891');


		$rows = $this->cognito->delete_expired_sessions();
		$this->assertEquals(1,$rows, 'Asserting no rows effected.');
	}

}