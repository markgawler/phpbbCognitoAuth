<?php
/**
 *
 * AWS Cognito Authentication. An extension for the phpBB Forum Software package.
 *
 * @copyright (c) 2018, Mark Gawler
 * @license GNU General Public License, version 2 (GPL-2.0)
 *
 * Date: 20/09/18
 *
 */

namespace mrfg\cogauth\cognito;

class web_token_phpbb extends web_token
{
	/** @var \phpbb\config\config */
	protected $config;

	/** @var /phpbb/ */
	protected $cache;

	/** @var string $jwsk_url_template
	 *     jwsk_url_template: 'https://cognito-idp.%%s.amazonaws.com/%%s'
	 */
	protected $jwsk_url_template;

	/**
	 * web_token constructor.
	 * @param \phpbb\config\config  $config
	 * @param \phpbb\cache\driver\driver_interface $cache
	 * @param string $jwsk_url_template
	 */
	public function __construct(
		\phpbb\config\config $config,
		\phpbb\cache\driver\driver_interface $cache,
		$jwsk_url_template)
	{
		$this->jwsk_url_template = $jwsk_url_template;
		$this->config = $config;
		$this->cache = $cache;
	}

	/**
	 * @return string uri of web keys
	 */
	protected function get_uri()
	{
		return sprintf($this->jwsk_url_template,
			$this->config['cogauth_aws_region'],
			$this->config['cogauth_pool_id']);
	}

	/**
	 * Download or retrieve from cache jwt web keys
	 * @param boolean $refresh refresh the cache
	 * @return \Jose\Component\Core\string
	 *
	 */
	public function download_jwt_web_keys($refresh = false)
	{
		$keys = false;
		if (!$refresh)
		{
			$keys = $this->get_cached_web_key();
		}
		if ($keys === false)
		{
			$url = $this->get_uri();
			$keys = @file_get_contents($url . '/.well-known/jwks.json');
			$this->cache_web_keys($keys);
		}
		return $keys;
	}

	/**
	 * Store the downloaded key in cache
	 * @@return  string cached Key
	 */
	protected function get_cached_web_key()
	{
		return $this->cache->get('_cogauth_jwt_web_keys');
	}

	/**
	 * Store the downloaded key in cache
	 * @param string Key to be cached.
	 */
	protected function cache_web_keys($keys)
	{
		$this->cache->put('_cogauth_jwt_web_keys', $keys);
	}


}