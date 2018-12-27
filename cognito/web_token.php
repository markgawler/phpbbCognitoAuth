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

abstract class web_token
{
	/**
	 * @param string $access_token
	 * @return boolean false is decode fails
	 * @return array os claims if decode succeeds
	 */
	public function decode_token($access_token)
	{
		$algorithmManager = AlgorithmManager::create(array(new RS256()));
		$serializerManager = new CompactSerializer(new StandardConverter());
		try {
			if (is_string($access_token))
			{
				/** @var $access_token \Jose\Component\Signature\Serializer\string */
				$jws = $serializerManager->unserialize($access_token);
			} else {
				return false;
			}
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
	 * @param \Jose\Component\Signature\Serializer\string $access_token
	 * @throws TokenVerificationException
	 * @return string
	 */
	public function verify_access_token($access_token)
	{
		$jwt_payload = $this->decode_token($access_token);
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




	abstract public function download_jwt_web_keys($refresh = false);
	abstract protected function get_uri();

}