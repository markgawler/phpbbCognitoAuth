<?php
/**
 * @package phpBB Extension - AWS Cognito Authentication phpBB Extension
 * @copyright (c) 2019 Mark Gawler
 * @license GNU General Public License v2
 */

namespace mrfg\cogauth\jwt;

use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWKSet;
use Jose\Component\Signature\Algorithm\RS256;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\Serializer\JWSSerializerManager;
use Jose\Component\Signature\Serializer\CompactSerializer;
use mrfg\cogauth\jwt\exception\TokenVerificationException;

abstract class web_token
{

	/**
	 * @var \Jose\Component\Core\AlgorithmManager
	 * @since 1.0
	 */
	protected $algorithmManager;

	/**
	 * @var \Jose\Component\Signature\JWSVerifier
	 * @since 1.0
	 */
	protected $jwsVerifier;

	/**
	 * @var \Jose\Component\Signature\Serializer\JWSSerializerManager
	 * @since version
	 */
	protected $serializerManager;

	public  function __construct()
	{
		// The algorithm manager with the RS256 algorithm.
		$this->algorithmManager = new AlgorithmManager(array(
			new RS256(),
		));

		// We instantiate our JWS Verifier.
		$this->jwsVerifier = new JWSVerifier(
			$this->algorithmManager
		);

		$this->serializerManager = new JWSSerializerManager(array(
			new CompactSerializer(),
		));
	}

	/**
	 * @param $token \Jose\Component\Signature\Serializer\string
	 * @return bool | \Jose\Component\Signature\JWS
	 *
	 * @since 1.0
	 */
	protected function deserialize($token)
	{

		try {
			if (is_string($token))
			{
				$jws = $this->serializerManager->unserialize($token);
			} else {
				return false;
			}
		} catch (\Exception $e)     // \LogicException  | InvalidArgumentException
		{
			return false;
		}
		return $jws;
	}

	/**
	 * @param $jws    \Jose\Component\Signature\JWS
	 * @param $jwkSet \Jose\Component\Core\JWKSet
	 *
	 * @return bool
	 * @since version
	 */
	protected function verify_signature($jws,$jwkSet)
	{
		/** @var \Jose\Component\Signature\int $signature */
		$signature = 0;
		$isVerified = $this->jwsVerifier->verifyWithKeySet($jws, $jwkSet, $signature);
		return $isVerified;
	}


	/**
	 *
	 * @return bool|\Jose\Component\Core\JWKSet
	 *
	 * @since 1,0
	 */
	protected function load_JWKSet()
	{
		$json = $this->download_jwt_web_keys();
		if ($json === false)
		{
			return false;
		}
		$keySet = JWKSet::createFromJson($json);
		return $keySet;
	}

	/**
	 * @param $token \Jose\Component\Signature\Serializer\string
	 *
	 * @return mixed
	 *
	 * @throws \mrfg\cogauth\jwt\exception\TokenVerificationException
	 * @since 1.0
	 */
	public function decode_token($token)
	{
		//todo header check
		$jws = $this->deserialize($token);
		if ($jws === false)
		{
			throw new TokenVerificationException('Token deserialize failed.');
		}
		$jwkSet = $this->load_JWKSet();
		if ($jwkSet === false)
		{
			throw new TokenVerificationException('JWKSet load failed.');
		}

		if (!$this->verify_signature($jws, $jwkSet))
		{
			throw new TokenVerificationException('JWS signature failed to verify.');
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

	//abstract protected function verify_claims();


}
