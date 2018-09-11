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

class config_test extends \phpbb_database_test_case
{
    /** @var \phpbb\db\tools\tools */
    protected $db_tools;

    /** @var string */
    protected $table;

    /** @var \phpbb\config\config */
    protected $config;

    /** @var \phpbb\db\driver\driver_interface */
    protected $db;

    /** @var \phpbb\user */
    protected $user;

    public function getDataSet()
    {
        return $this->createXMLDataSet(dirname(__FILE__) . '/fixtures/user_date.xml');
    }



    public function setUp()
    {

        parent::setUp();

        global $table_prefix;

        $this->table = $table_prefix . 'ukrgb_images';
        $this->db = $this->new_dbal();
        $this->db_tools = new \phpbb\db\tools\tools($this->db);


        $this->config = $this->getMockBuilder('\phpbb\config\config')
            ->disableOriginalConstructor()
            ->getMock();

        $this->user = $this->getMockBuilder('\phpbb\user')
            ->disableOriginalConstructor()
            ->getMock();

        $this->user = $this->getMockBuilder('\phpbb\user')
            ->disableOriginalConstructor()
            ->getMock();
	}

    public function test_config()
    {
        $this->assertTrue(1 === 1, 'Dummy');


    }



}
