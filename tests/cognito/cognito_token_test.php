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

namespace mrfg\cogauth\tests\cognito;

class cognito_token_test extends \phpbb_test_case
{

    /** @var $user \phpbb\user */
    protected $user;

    /** @var $cognito_client \phpbb\config\config */
    protected $config;

    /** @var $db \phpbb\db\driver\driver_interface */
    protected $db;

    /** @var $web_token \mrfg\cogauth\cognito\web_token*/
    protected $web_token;


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

        $this->web_token = $this->getMockBuilder('\mrfg\cogauth\cognito\web_token')
            ->disableOriginalConstructor()
            ->setMethods(array('verify_access_token'))
            ->getMock();

        $map =array(
            array('cogauth_pool_id','eu-west-1_T0xxxxx1'),
            array('cogauth_aws_region','eu-west-1')
        );
        $this->config->method('offsetGet')->will($this->returnValueMap($map));
    }

    public function test_download_jwt_keys()
    {
        $client = $this->getMockBuilder('\mrfg\cogauth\cognito\cognito_client_wrapper')
            ->disableOriginalConstructor()
            ->setMethods(array('create_client'))
            ->getMock();

        /** @var $client \mrfg\cogauth\cognito\cognito */
    /*    //$cognito = new \mrfg\cogauth\cognito\cognito($this->db,$this->config,$this->user,$client,'');
        $args = array($this->db,$this->config,$this->user,$client,'');
        $cognito = $this->getMockBuilder('\mrfg\cogauth\cognito\cognito')
            ->setConstructorArgs($args)
            ->setMethods(array('download_jwt_web_keys'))
            ->getMock();

        $cognito->expects($this->once())
            ->method('download_jwt_web_keys');

        $cognito->getJwtWebKeys();
*/
    }
}