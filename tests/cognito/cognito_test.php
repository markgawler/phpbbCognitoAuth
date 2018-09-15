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

    public function test_get_user_valid()
    {
        $client = $this->getMockBuilder('\mrfg\cogauth\cognito\cognito_client_wrapper')
            ->disableOriginalConstructor()
            ->setMethods(array('create_client', 'admin_get_user'))
            ->getMock();

        /** @var $client \mrfg\cogauth\cognito\cognito_client_wrapper */
        $cognito = new \mrfg\cogauth\cognito\cognito($this->db,$this->config,$this->user,$client,'');

        $attr = array(
            array(
                'Name' => 'preferred_username',
                'Value' => 'frederick'),
            array(
                'Name' => 'nickname',
                'Value' => 'fred')
        );
        $client->method('admin_get_user')
            ->willReturn(array(
                'UserStatus' => 'CONFIRMED',
                'UserAttributes' => $attr));

        $client->expects($this->once())
            ->method('admin_get_user')
            ->with(array(
                "Username"   => 'u001234',
                "UserPoolId" => 'eu-west-1_T0xxxxx1'));

        $response = $cognito->get_user('1234');
        $this->assertTrue($response['status'] == COG_USER_FOUND, 'Asserting status is COG_USER_FOUND');
        $this->assertTrue($response['user_status'] == 'CONFIRMED', 'Asserting user_status is CONFIRMED');
        $this->assertTrue($response['user_attributes'] == $attr, 'Asserting user attributes are correct');

    }

}