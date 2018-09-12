<?php
/**
 *
 * AWS Cognito Authentication. An extension for the phpBB Forum Software package.
 *
 * @copyright (c) 2018, Mark Gawler
 * @license GNU General Public License, version 2 (GPL-2.0)
 *
 */

namespace mrfg\cogauth\tests\cognito;

class main_test extends \phpbb_database_test_case
{
    /** @var \phpbb\db\tools\tools */
    protected $db_tools;

    /** @var string */
    protected $table_prefix;

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
        $db = $this->new_dbal();
        $this->db_tools = new \phpbb\db\tools\tools($db);
	}
	

    public function test_db_columns()
    {
        $columns = array('sid', 'access_token', 'expires_in', 'id_token', 'refresh_token', 'token_type');
        foreach ($columns as $c) {
            $this->assertTrue($this->db_tools->sql_column_exists($this->table_prefix . 'cogauth_session', $c), 'Asserting that column "' . $c . '" exists');
        }
    }

}
