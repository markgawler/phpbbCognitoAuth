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
 * Wrapper for AWS CognitoIdentityProviderClient
 */
namespace mrfg\cogauth\cognito;


class cognito_client_wrapper
{
    /**
     * @var  \Aws\CognitoIdentityProvider\CognitoIdentityProviderClient
     */
    protected $client;
    /**
     * @var \Aws\Sdk $aws_sdk
     */
    private $aws_sdk;

    /**
     * Constructs a new Aws\Sdk object
     */
    public function __construct()
    {
        $this->aws_sdk = new \Aws\Sdk();
    }

    /**
     * Create Cognito Identity Providerby client using an array of constructor options.
     *
     * @param array  $args Arguments to configure the client.
     *
     * @throws \InvalidArgumentException if any required options are missing or
     *                                   the service is not supported.
     * @see \Aws\AwsClient::__construct for a list of available options for args.
     */
    public function create_client(array $args)
    {
        $this->client = $this->aws_sdk->createCognitoIdentityProvider($args);
    }

    /**
     * @param $args
     * @return \Aws\Result
     */
    public function admin_create_user($args)
    {
        return $this->client->adminCreateUser($args);
    }

    /**
     * @param $args
     * @return \Aws\Result
     */
    public function admin_respond_to_auth_challenge($args)
    {
        return $this->client->adminRespondToAuthChallenge($args);
    }

    /**
     * @param $args
     * @return \Aws\Result
     */
    public function admin_initiate_auth($args)
    {
        return $this->client->adminInitiateAuth($args);
    }

    /**
     * @param $args
     * @return \Aws\Result
     */
    public function admin_disable_user($args)
    {
        return $this->client->adminDisableUser($args);
    }

	/**
	 * @param $args
	 * @return \Aws\Result
	 */
	public function admin_delete_user($args)
	{
		return $this->client->AdminDeleteUser($args);
	}

	/**
	 * @param $args
	 * @return \Aws\Result
	 */
	public function admin_enable_user($args)
	{
		return $this->client->adminEnableUser($args);
	}

    /**
     * @param $args
     * @return \Aws\Result
     */
    public function admin_update_user_attributes($args)
    {
        return $this->client->AdminUpdateUserAttributes($args);
    }

    /**
     * @param $args
     * @return \Aws\Result
     */
    public function admin_get_user($args)
    {
        return $this->client->AdminGetUser($args);
    }

    /**
     * @param $args
     * @return \Aws\Result
     */
    public function change_password($args)
    {
        return $this->client->changePassword($args);
    }

    /**
     * @param $args
     * @return \Aws\Result
     */
    public function update_user_attributes($args)
    {
        return $this->client->UpdateUserAttributes($args);
    }

	/**
	 * @param $args
	 * @return \Aws\Result
	 */
	public function initiate_auth($args)
	{
		return $this->client->adminInitiateAuth($args);
	}

}