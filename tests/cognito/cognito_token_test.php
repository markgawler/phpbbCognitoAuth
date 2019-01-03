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
	/** @noinspection PhpUndefinedClassInspection */
	/* @var $config \phpbb\config\config|\PHPUnit_Framework_MockObject_MockObject */
	protected $config;

	/** @noinspection PhpUndefinedClassInspection */
	/* @var $cache \phpbb\cache\driver\driver_interface|\PHPUnit_Framework_MockObject_MockObject */
	protected $cache;


	public function setUp()
    {
        parent::setUp();

        $this->config = $this->getMockBuilder('\phpbb\config\config')
            ->disableOriginalConstructor()
            ->getMock();

		$this->cache = $this->getMockForAbstractClass('\phpbb\cache\driver\driver_interface');

        $map =array(
            array('cogauth_pool_id','eu-west-1_T0xxxxx1'),
            array('cogauth_aws_region','eu-west-1')
        );
        $this->config->method('offsetGet')->will($this->returnValueMap($map));
    }

    public function test_download_jwt_web_keys_cached()
    {

    	$test_keys = file_get_contents(__DIR__ . '/.well-known/jwks.json');
    	$this->cache->method('get')
			->willReturn($test_keys);

    	$this->cache->expects($this->once())
			->method('get')
			->with('_cogauth_jwt_web_keys');

		$this->cache->expects($this->never())
			->method('put');

        $wt = new \mrfg\cogauth\cognito\web_token_phpbb($this->config, $this->cache, '');

        $keys = $wt->download_jwt_web_keys();
        $this->assertEquals($test_keys, $keys, 'Asserting correct return of cached jwks key');
    }

	public function test_download_jwt_web_keys()
	{
		$test_keys = file_get_contents(__DIR__ . '/.well-known/jwks.json');
		$this->cache->method('get')
			->willReturn(false);

		$this->cache->expects($this->once())
			->method('get')
			->with('_cogauth_jwt_web_keys');

		$this->cache->expects($this->once())
			->method('put')
			->with('_cogauth_jwt_web_keys',$test_keys);

		$this->config->expects($this->at(0))
			->method('offsetGet')
			->with('cogauth_aws_region');

		$this->config->expects($this->at(1))
			->method('offsetGet')
			->with('cogauth_pool_id');

		$this->config->expects($this->exactly(2))
			->method('offsetGet');

		$wt = new \mrfg\cogauth\cognito\web_token_phpbb($this->config, $this->cache, __DIR__ . '');

		$keys = $wt->download_jwt_web_keys();
		$this->assertEquals($test_keys, $keys, 'Asserting correct return of non-cached jwks key');
	}

	public function test_decode_token_invalid_token_01()
	{
		$token = null;
		$this->cache->expects($this->never())
			->method('get');
		$wt = new \mrfg\cogauth\cognito\web_token_phpbb($this->config, $this->cache, __DIR__ . '');
		$this->assertTrue($wt->decode_token($token) === false, 'Asserting decoding invalid token returns False');
	}

	public function test_decode_token_invalid_token_02()
	{
		/** @var $token \Jose\Component\Signature\Serializer\string */
		$token = 'invalid string';
		$this->cache->expects($this->never())
			->method('get');
		$wt = new \mrfg\cogauth\cognito\web_token_phpbb($this->config, $this->cache, __DIR__ . '');
		$this->assertTrue($wt->decode_token($token) === false, 'Asserting decoding invalid token returns False');
	}
}

