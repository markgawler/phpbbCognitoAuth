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
use mrfg\cogauth\cognito\exception\TokenExpiryException;
use mrfg\cogauth\cognito\exception\TokenVerificationException;

class web_token
{
    /** @var JWKSet */
    protected $jwt_web_keys;

    /** @var string */
    protected $access_token;

    /** @var string */
    protected $region;

    /** @var string */
    protected $user_pool_id;

    /**
     * web_token constructor.
     * @param \phpbb\config\config  $config
     */
    public function __construct($config)
    {
        $this->region = $config['cogauth_aws_region'];
        $this->user_pool_id = $config['cogauth_pool_id'];
        $this->jwt_web_keys = $this->get_jwt_web_keys();
    }

    /**
     * @param $access_token
     * @return mixed
     * @throws TokenVerificationException
     */
    public function decode_token($access_token)
    {
        $algorithmManager = AlgorithmManager::create(array(new RS256()));
        $serializerManager = new CompactSerializer(new StandardConverter());
        try {
            $jws = $serializerManager->unserialize($access_token);
        } catch (\Exception $e)     // \LogicException  | InvalidArgumentException
        {
            throw new TokenVerificationException('failed to unserialize token');
        }
        $jwsVerifier = new JWSVerifier(
            $algorithmManager
        );
        //$keySet = $this->get_jwt_web keys();
        /** @var \Jose\Component\Signature\int $sig */
        $sig = 0;
        if (!$jwsVerifier->verifyWithKeySet($jws, $this->jwt_web_keys, $sig)) {
            throw new TokenVerificationException('could not verify token');
        }
        return json_decode($jws->getPayload(), true);
    }

    /**
     * Verifies the given access token and returns the username
     *
     * @param string $accessToken
     *
     * @throws TokenExpiryException
     * @throws TokenVerificationException
     *
     * @return string
     */
    public function verify_access_token($accessToken)
    {
        $jwtPayload = $this->decode_token($accessToken);

        $expectedIss = sprintf('https://cognito-idp.%s.amazonaws.com/%s', $this->region, $this->user_pool_id);
        if ($jwtPayload['iss'] !== $expectedIss) {
            throw new TokenVerificationException('invalid iss');
        }

        if ($jwtPayload['token_use'] !== 'access') {
            throw new TokenVerificationException('invalid token_use');
        }

        if ($jwtPayload['exp'] < time()) {
            throw new TokenExpiryException('invalid exp');
        }

        return $jwtPayload['username'];
    }

    /**
     * @return JWKSet
     */
    public function get_jwt_web_keys()
    {
        if (!$this->jwt_web_keys) {
            $json = $this->download_jwt_web_keys();
            $this->jwt_web_keys = JWKSet::createFromJson($json);
        }
        return $this->jwt_web_keys;
    }

    /**
     * @return \Jose\Component\Core\string
     */
    protected function download_jwt_web_keys()
    {
        $url = sprintf(
            'https://cognito-idp.%s.amazonaws.com/%s/.well-known/jwks.json',
            $this->region,
            $this->user_pool_id
        );

        $keys = file_get_contents($url);
        return $keys;
    }
}