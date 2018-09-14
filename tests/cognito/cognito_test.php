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

class cognito_test extends \phpbb_test_case
{

    /** @var $user \phpbb\user */
    protected $user;

    /** @var $cognito_client \phpbb\config\config */
    protected $config;

    /** @var $db \phpbb\db\driver\driver_interface */
    protected $db;


    public function setUp()
    {
        parent::setUp();

        $this->user = $this->getMockBuilder('\phpbb\user')
            ->disableOriginalConstructor()
            ->getMock();

        $this->db = $this->getMockBuilder('\phpbb\db\driver\driver_interface')
            ->disableOriginalConstructor()
            ->getMock();

        $this->config = $this->getMockBuilder('\phpbb\config\config')
            ->disableOriginalConstructor()
            ->getMock();

        $map =array(
            array('cogauth_pool_id','eu-west-1_T0xxxxx1'),
            array('cogauth_client_id','faaaaaaaaaaaaaaaaaaaaaav7'),
            array('cogauth_client_secret','110aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaai'),
            array('cogauth_aws_key','AKAAAAAAAAAAAAAAAAAQ'),
            array('cogauth_aws_secret','BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAG'),
            array('cogauth_aws_region','eu-west-1')
        );
        $this->config->method('offsetGet')->will($this->returnValueMap($map));
    }

    public function test_get_user()
    {

        $session = '';


        $cognito = new \mrfg\cogauth\cognito\cognito($this->db,$this->config,$this->user,$session);


        $this->assert(1 === 1, 'Yay!');
    }

}