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

use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\Converter\StandardConverter;
use Jose\Component\Core\JWKSet;
use Jose\Component\Signature\Algorithm\RS256;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\Serializer\CompactSerializer;
use mrfg\cogauth\cognito\exception\TokenVerificationException;

class web_token
{
    /** @var \phpbb\config\config */
    protected $config;


    /** @var /phpbb/ */
    protected $cache;

    /**
     * web_token constructor.
     * @param \phpbb\config\config  $config
	 * @param \phpbb\cache\driver\driver_interface $cache
     */
    public function __construct(
    	\phpbb\config\config $config,
		\phpbb\cache\driver\driver_interface $cache)
    {
		$this->config = $config;
		$this->cache = $cache;
    }

    /**
     * @param $access_token
     * @return boolean false is decode fails
	 * @return array os claims if decode succeeds
     */
    public function decode_token($access_token)
    {
        $algorithmManager = AlgorithmManager::create(array(new RS256()));
        $serializerManager = new CompactSerializer(new StandardConverter());
        try {
            $jws = $serializerManager->unserialize($access_token);
        } catch (\Exception $e)     // \LogicException  | InvalidArgumentException
        {
        	return false;
        }
        $jwsVerifier = new JWSVerifier(
            $algorithmManager
        );
		$json = $this->download_jwt_web_keys();
		if ($json === false)
		{
			return false;
		}
		$keySet = JWKSet::createFromJson($json);

        /** @var \Jose\Component\Signature\int $sig */
        $sig = 0;
        if (!$jwsVerifier->verifyWithKeySet($jws, $keySet, $sig)) {
			return false;
        }
        return json_decode($jws->getPayload(), true);
    }

    /**
     * Verifies the given access token and returns the username
     *
     * @param string $accessToken
     * @throws TokenVerificationException
     * @return string
     */
    public function verify_access_token($accessToken)
    {
        error_log('verify_access_token');
        $jwt_payload = $this->decode_token($accessToken);
        if ($jwt_payload === false)
		{
			throw new TokenVerificationException('token decode failed');
		}
        $expectedIss = $this->get_uri();

        if ($jwt_payload['iss'] !== $expectedIss) {
            throw new TokenVerificationException('invalid iss');
        }

        if ($jwt_payload['token_use'] !== 'access') {
            throw new TokenVerificationException('invalid token_use');
        }

        if ($jwt_payload['exp'] < time()) {
            throw new TokenVerificationException('token expired');
        }

        return $jwt_payload['username'];
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
			$keys = $this->cache->get('_cogauth_jwt_web_keys');
		}
		if ($keys === false)
		{
			$keys = @file_get_contents($this->get_uri() . '/.well-known/jwks.json');
			$this->cache->put('_cogauth_jwt_web_keys', $keys);
		}
		else {
			error_log('use cache');
		}
		return $keys;
	}

	private function get_uri()
	{
		return sprintf('https://cognito-idp.%s.amazonaws.com/%s',
			$this->config['cogauth_aws_region'],
			$this->config['cogauth_pool_id']);
	}
}