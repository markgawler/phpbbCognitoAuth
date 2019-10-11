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


class cognito_db_user_test extends \phpbb_database_test_case
{
	/** @var $db \phpbb\db\driver\driver_interface */
	protected $db;

	/** @var \phpbb\db\tools\tools */
	protected $db_tools;

	/** @var string */
	protected $table_prefix;

	/** @var  \phpbb\user $user */
	protected $phpbb_user;

	/** @var  \phpbb\auth\auth $auth */
	protected $auth;

	/** @var  \phpbb\config\config $config */
	protected $config;

	/** @var  \phpbb\passwords\manager $passwords_manager */
	protected $password_manager;

	/** @var \mrfg\cogauth\cognito\user $user */
	protected $user;

	static protected function setup_extensions()
	{
		return array('mrfg/cogauth');
	}

	public function getDataSet()
	{
		return $this->createXMLDataSet(dirname(__FILE__) . '/fixtures/cogauth_usermap_data.xml');
	}

	public function setUp()
	{
		parent::setUp();

		global $table_prefix;

		$this->table_prefix = $table_prefix;
		$this->db = $this->new_dbal();
		$this->db_tools = new \phpbb\db\tools\tools($this->db);

		$this->phpbb_user = $this->getMockBuilder('\phpbb\user')
			->disableOriginalConstructor()
			->getMock();

		$this->auth = $this->getMockBuilder('\phpbb\auth\auth')
			->disableOriginalConstructor()
			->getMock();

		$this->config = $this->getMockBuilder('\phpbb\config\config')
			->disableOriginalConstructor()
			->getMock();

		$this->password_manager = $this->getMockBuilder('\phpbb\passwords\manager')
			->disableOriginalConstructor()
			->getMock();

		$this->user = new \mrfg\cogauth\cognito\user(
			$this->phpbb_user,
			$this->auth,
			$this->db,
			$this->config,
			$this->password_manager,
			'phpBB/ext/mrfg/cogauth/tests/dbal/stubs/','php',$this->table_prefix.'cogauth_usermap');
	}

	public function test_get_cognito_user_01()
	{
		$username = $this->user->get_cognito_username(12);
		$this->assertEquals('Frank', $username, 'Asserting username lookup from DB is correct');

		$username = $this->user->get_cognito_username(33);
		$this->assertEquals('u000033', $username, 'Asserting username lookup generated is correct');

		$attr = $this->user->get_cognito_usermap_attributes(12);
		$this->assertEquals(array('cognito_username' => 'Frank','phpbb_password_valid' => false), $attr,
			'Asserting attributes, name, not phpbb_password_valid');

		$attr = $this->user->get_cognito_usermap_attributes(15);
		$this->assertEquals(array('cognito_username' => 'Ben','phpbb_password_valid' => true), $attr,
			'Asserting attributes, name, phpbb_password_valid ');

		$attr = $this->user->get_cognito_usermap_attributes(44);
		$this->assertEquals(array('cognito_username' => 'u000044','phpbb_password_valid' => true), $attr,
			'Asserting attributes, name, phpbb_password_valid');

		// Set phpBB password to be valid
		$this->user->set_phpbb_password_status(12,true);
		$attr = $this->user->get_cognito_usermap_attributes(12);
		$this->assertEquals(array('cognito_username' => 'Frank','phpbb_password_valid' => true), $attr,
			'Asserting attributes, name, not phpbb_password_valid following setting to valid');

	}

	public function test_get_cognito_add_user()
	{
		$attr = array(
			'cognito:username' => 'FredTheFlint',
			'email' => 'fred@flint.stone');

		$this->user->add_user($attr);

		$result = $this->user->get_cognito_usermap_attributes(6543);
		$this->assertEquals(array(
			'cognito_username' => $attr['cognito:username'],
			'phpbb_password_valid' => false),$result,'Verify creation of usermap entry');
	}

}
