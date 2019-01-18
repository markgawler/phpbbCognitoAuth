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

    /** @var $web_token \mrfg\cogauth\cognito\web_token_phpbb|\PHPUnit_Framework_MockObject_MockObject */
    protected $web_token;

    /** @var $client  \mrfg\cogauth\cognito\cognito_client_wrapper| \PHPUnit_Framework_MockObject_MockObject */
	protected $client;

	/** @var $cognito \mrfg\cogauth\cognito\cognito */
	protected $cognito;

	/** @var $request \phpbb\request\request_interface */
	protected $request;



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

        $this->web_token = $this->getMockBuilder('\mrfg\cogauth\cognito\web_token_phpbb')
            ->disableOriginalConstructor()
            ->setMethods(array('verify_access_token'))
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
		$this->cognito = new \mrfg\cogauth\cognito\cognito($this->db, $this->config, $this->user, $this->request, $this->log, $this->client, $this->web_token, $this->table_prefix . 'cogauth_session');

	}


	public function test_db_columns()
	{
		$columns = array('sid', 'access_token', 'expires_at', 'id_token', 'refresh_token');
		foreach ($columns as $c) {
			$this->assertTrue($this->db_tools->sql_column_exists($this->table_prefix . 'cogauth_session', $c), 'Asserting that column "' . $c . '" exists');
		}
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

}