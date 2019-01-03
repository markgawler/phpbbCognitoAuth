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

class cognito_test_functions extends \mrfg\cogauth\cognito\cognito
{
	public function set_time_now($time_now)
	{
		$this->time_now = $time_now;
	}
}

class cognito_access_token_management_test extends \phpbb_database_test_case
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

	/** @noinspection PhpUndefinedClassInspection */
	/** @var $web_token \mrfg\cogauth\cognito\web_token_phpbb|\PHPUnit_Framework_MockObject_MockObject */
	protected $web_token;

	/** @noinspection PhpUndefinedClassInspection */
	/** @var $client  \mrfg\cogauth\cognito\cognito_client_wrapper| \PHPUnit_Framework_MockObject_MockObject */
	protected $client;

	/** @noinspection PhpUndefinedClassInspection */
	/** @var $cognito \mrfg\cogauth\tests\dbal\cognito_test_functions | \PHPUnit_Framework_MockObject_MockObject  */
	protected $cognito;

	/** @var $request \phpbb\request\request_interface */
	protected $request;

	protected $log;

	protected $refresh_token = "eyJjdHkiOiJKV1QiLCJlbmMiOiJBMjU2R0NNIiwiYWxnIjoiUlNBLU9BRVAifQ.b45aQ1hvBu8uPN9nzj8xHg37varujz3PbUKO9cXJ5n-Hpu7Xqmy_04pmI-rxeiuAu5IwyQUUQYyPP2A5IlOSxfWOb0aPlf9IV-wBwIWU90JgJUie48FTpJUNdAPKQ_dUCwhMYmXb87409TbTHwiCvjZiB_0vTAcVt45YwaI1gALb7mXDr4pdO3Z11g57tAFV5eT4TCtu4BJ_qsBxnv_6bUqQLUPBhbb4VuAIMDmw4SB15ZuhqYATZZSOLZeoU3rHsaxLkJgBdZRFNiTGqKTL3NMyawkHwyqMi7m_NXVX1kVuKuZhtD_lloFniCs3_ZJMVTe4TTq-XjimQ7_s6POkGA.TZS3MlediJOooBqX.1bYXQOfzkyQElWvdISqHk9LCrUu__d5nCPvQ6pJgeUAG_hrc0YO1ULUOxgUQQW84czZnPy-gdtMgES-hq8x7_CS7q22b6Xz8JbjUrIBzYQj4HxlcSUMvSh06SLiqvHwD16WGwm6t4m0ft4skjPI0UzdvnwK039qCj9d2Wd0Q85BsN_1Sg3OJOCbGJoYEkiIOKUEdB4tNZ42Dqq_JKKX45h9OZ3zQ9dIjlwDAEfgSbZwVhDejKhmpSYOwieQBJtb_ZjHxbt1CN6uCCfc41sT8XIzEu06ytq9jjD4TvuxTJX89oJdXr6bqXPSvceXx7GEL8xYapJZwyMzQocRZYj3sjvqH1CogEAII1VG97y0TaFIayR5Nk4makwgiop5FiN3YkCotVPRNWj_P469Aw-BHMgx6BarIEifIG2ZIGRF0sO8N5ayx0FE89yqOqhBeoyYtHoDG3MLqWBkVjiQEZWJrGx2Lk1NqkcVbd2FrwIT5pFnDaP4A2CrCiJ1QYxEbVub9s1vdxv7KS0Q4EjDhUHRPPuI5Gju4goRcv80UADNyu04SrcCEcqblYymZBeeQC1-WsiYoZkjpv6w8FOoe-_bbJx3Lz1DCiwOSwCrca4U9yiYuDtnJwKvAMcdvs4JIvNmxiv9BZc7SdPg6oEIKUvQ6xo3ioPNOWe3OClJuXhW8B4BG47CqGmteVSCx-_03j0bdYlhP4JwS92KMCDBhrEgGNk7EYcqO_7npMkuSB1kMEa3H6B4aLz1cRBnG_J2nlsLMQH-nXftbiVwjme4P_cnInBA-P1f9eS2DnAh1xGOzo5Hr87F8War_HK7L--vyb993Auq8btA89CXhAdu6M3YFZqHVnKBCHJc7HPwwBu6rbvrm7b6FOkzd6LySSJJ1SP0ztXgUzjsMIYZvqRjxeJTS_dtZvIdi6Cy0BqVPvbrNvjA9Fx590ejyYs_xJf2VaG_hFmvtpZ8S36fHTe5LqE1fbIv-Hlav8Aws0zjGxK4UaS-_zc-aRiBvqPPfkTrJfdcX7U27qANcmT_sGmxn4VyFuoxpins4Vrlgne_DUWEmHTMohZHizGykr9pNI44Zxa1uXR7GR6YFkKgex8fIjlPYIEs9A4T9EhGaWkltTWWOi1h4Ebdlg1g2aDmjDHzphiATM-kGeYpFrE-mC4TGkYNLLQ7O9n12bFSt9n017pEsTerenf2zpSw4Bu5TwhPkaGiZinvWpECThJSa-XY0CXShW0bpnPteWgQG9MaGc3kSruP84EHwnoDln3TPCox9Vi3FAkMx.fxhoOTjjVLO2S7NXM0qYcA";


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
			->getMock()
		;

		$this->config = $this->getMockBuilder('\phpbb\config\config')
			->disableOriginalConstructor()
			->getMock()
		;

		$this->web_token = $this->getMockBuilder('\mrfg\cogauth\cognito\web_token_phpbb')
			->disableOriginalConstructor()
			->setMethods(array('verify_access_token'))
			->getMock()
		;

		$this->client = $this->getMockBuilder('\mrfg\cogauth\cognito\cognito_client_wrapper')
			->disableOriginalConstructor()
			->getMock()
		;

		$this->log = $this->getMockBuilder('\phpbb\log\log_interface')
			->disableOriginalConstructor()
			->getMock()
		;

		$this->request = $this->getMockBuilder('\phpbb\request\request_interface')
			->disableOriginalConstructor()
			->getMock()
		;

		//$this->cognito = new cognito_test_functions($this->db, $this->config, $this->user, $this->request, $this->log, $this->client, $this->web_token, $this->table_prefix . 'cogauth_session');

		$construct_args = array($this->db, $this->config, $this->user, $this->request, $this->log, $this->client, $this->web_token, $this->table_prefix . 'cogauth_session');

		$this->cognito = $this->getMockBuilder('\mrfg\cogauth\tests\dbal\cognito_test_functions')
			->setMethods(array('refresh_access_token','handleCognitoIdentityProviderException'))
			->setConstructorArgs($construct_args)
			->getMock();
	}

	public function test_get_access_token()
	{
		$this->cognito->expects($this->never())
			->method('refresh_access_token')
		;
		$this->cognito->set_time_now(1546345800-301);
		$this->user->session_id = 'a652e8fe432c7b6d6e42eb134ae9054a';
		$token = $this->cognito->get_access_token();
		$this->assertEquals('eyJraWQiOiJndlwvcmNDQTBMWUhMd2piUlVmMUFweEJESVRlRlwvbHRrTUFzNXRjTUJJUzQ9IiwiYWxnIjoiUlMyNTYifQ.eyJzdWIiOiJlZDgzYTkxMi04ZTUwLTRhOWYtYjVhNi1kOGJhNjVmMTYzZjciLCJldmVudF9pZCI6ImQ3YjgwOWNmLWI0NjEtMTFlOC05M2I2LTYzNThkYThlMTJiOSIsInRva2VuX3VzZSI6ImFjY2VzcyIsInNjb3BlIjoiYXdzLmNvZ25pdG8uc2lnbmluLnVzZXIuYWRtaW4iLCJhdXRoX3RpbWUiOjE1MzY1MTkyOTYsImlzcyI6Imh0dHBzOlwvXC9jb2duaXRvLWlkcC5ldS13ZXN0LTEuYW1hem9uYXdzLmNvbVwvZXUtd2VzdC0xX1Q3emptcXhhMSIsImV4cCI6MTUzNjUyMjg5NiwiaWF0IjoxNTM2NTE5Mjk2LCJqdGkiOiI0MjljNTY0OC05YTk4LTRmOGItOWRiMS1kMWFiYjZiZDM3NDEiLCJjbGllbnRfaWQiOiJmMjRhcXBkZjNhYnMyazFiMGc4bXRkdHY3IiwidXNlcm5hbWUiOiJ1MDAwMDQ5In0.i9BGWE3tgO7OjQM44cOrKK_uynq5r7vH_27IjZ747f5U7_iwQLUquxKMdU7NFg12dU264xbP3hbW_xXIPtC0IckEef1fM-V_9JQdr2iBEibugPXSME51-6KqUnzYidedFUswdZ_xvURDgZZehjD08e7V_0BNqFzmiCohBjV7i5JR-bJmhsE33bWOE1qBXFbR47x8iaI558O8ZG_06zvgQHFP08BRkwVSVyUqfv_hDkwObHGNES3eCvqLqzw0_yMr21_U52dNZE9oIWe7z01GFxiKcXB02TFHxiPFtG_Fkcv053OGBmNsY1ARVPafifSOIn6_pN-WU6aoCcaqjV63hg',
			$token, 'Asserting correct access token returned for SID');
	}
	public function test_get_access_token_session_token()
	{
		$this->cognito->expects($this->never())
			->method('refresh_access_token')
		;
		$this->cognito->set_time_now(1546345800-301);
		$token = $this->cognito->get_access_token('NtMQHz2q89Bjc4HEjq82brEJ6zmXD6u1');
		$this->assertEquals('eyJraWQiOiJndlwvcmNDQTBMWUhMd2piUlVmMUFweEJESVRlRlwvbHRrTUFzNXRjTUJJUzQ9IiwiYWxnIjoiUlMyNTYifQ.eyJzdWIiOiJlZDgzYTkxMi04ZTUwLTRhOWYtYjVhNi1kOGJhNjVmMTYzZjciLCJldmVudF9pZCI6ImQ3YjgwOWNmLWI0NjEtMTFlOC05M2I2LTYzNThkYThlMTJiOSIsInRva2VuX3VzZSI6ImFjY2VzcyIsInNjb3BlIjoiYXdzLmNvZ25pdG8uc2lnbmluLnVzZXIuYWRtaW4iLCJhdXRoX3RpbWUiOjE1MzY1MTkyOTYsImlzcyI6Imh0dHBzOlwvXC9jb2duaXRvLWlkcC5ldS13ZXN0LTEuYW1hem9uYXdzLmNvbVwvZXUtd2VzdC0xX1Q3emptcXhhMSIsImV4cCI6MTUzNjUyMjg5NiwiaWF0IjoxNTM2NTE5Mjk2LCJqdGkiOiI0MjljNTY0OC05YTk4LTRmOGItOWRiMS1kMWFiYjZiZDM3NDEiLCJjbGllbnRfaWQiOiJmMjRhcXBkZjNhYnMyazFiMGc4bXRkdHY3IiwidXNlcm5hbWUiOiJ1MDAwMDQ5In0.i9BGWE3tgO7OjQM44cOrKK_uynq5r7vH_27IjZ747f5U7_iwQLUquxKMdU7NFg12dU264xbP3hbW_xXIPtC0IckEef1fM-V_9JQdr2iBEibugPXSME51-6KqUnzYidedFUswdZ_xvURDgZZehjD08e7V_0BNqFzmiCohBjV7i5JR-bJmhsE33bWOE1qBXFbR47x8iaI558O8ZG_06zvgQHFP08BRkwVSVyUqfv_hDkwObHGNES3eCvqLqzw0_yMr21_U52dNZE9oIWe7z01GFxiKcXB02TFHxiPFtG_Fkcv053OGBmNsY1ARVPafifSOIn6_pN-WU6aoCcaqjV63hg',
			$token, 'Asserting correct access token returned for Session-token');
	}

	public function test_get_access_token_expired()
	{
		$this->cognito->expects($this->once())
			->method('refresh_access_token')
			->with($this->refresh_token, 99)
			->willReturn(array('AuthenticationResult' => array('AccessToken' => 'AnewToken')));
		;

		$this->cognito->set_time_now(1546345800-299);

		$this->user->session_id = 'a652e8fe432c7b6d6e42eb134ae9054a';
		$token = $this->cognito->get_access_token();
		$this->assertEquals('AnewToken',
			$token, 'Asserting new access token returned token_expired');
	}

	public function test_get_access_token_no_session()
	{
		$this->cognito->expects($this->never())
			->method('refresh_access_token')
		;

		$this->user->session_id = '0000'; // invalid SID
		$token = $this->cognito->get_access_token();
		$this->assertEquals(false,
			$token, 'Asserting correct access token returned for SID no_session');
	}

	public function test_get_access_token_exception()
	{
		/* @var $aws_exception \Aws\CognitoIdentityProvider\Exception\CognitoIdentityProviderException */
		$aws_exception = $this->getMockBuilder('\Aws\CognitoIdentityProvider\Exception\CognitoIdentityProviderException')
			->disableOriginalConstructor()
			->getMock();

		$this->cognito->expects($this->once())
			->willThrowException($aws_exception)
			->method('refresh_access_token')
		;
		$this->cognito->expects($this->never())
			->method('store_auth_result')
		;
		$this->cognito->set_time_now(1546345800-299);
		$this->user->session_id = 'a652e8fe432c7b6d6e42eb134ae9054a';

		$this->cognito->expects($this->once())
			->method('handleCognitoIdentityProviderException');

		$token = $this->cognito->get_access_token();
		$this->assertEquals(false,
			$token, 'Asserting correct access token returned for token exception');
	}

}