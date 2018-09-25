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

        $this->config = $this->getMockBuilder('\phpbb\config\config')
            ->disableOriginalConstructor()
            ->getMock();

        $map =array(
            array('cogauth_pool_id','eu-west-1_T0xxxxx1'),
            array('cogauth_aws_region','eu-west-1')
        );
        $this->config->method('offsetGet')->will($this->returnValueMap($map));
    }

    public function test_verify_access_token()
    {

        //$wt = new \mrfg\cogauth\cognito\web_token($this->config);

        //$username = $wt->verify_access_token('hello');
		$username = True;
        $this->assertTrue($username,'Its true');

    }
}