<?php
/**
 * @package phpBB Extension - AWS Cognito Authentication phpBB Extension
 * @copyright (c) 2019 Mark Gawler
 * @license GNU General Public License v2
 */

namespace mrfg\cogauth\controller;

class main
{
	/* @var \phpbb\config\config */
	protected $config;

	/* @var \phpbb\request\request 	phpBB request object */
	protected $request;

	/* @var \phpbb\language\language $language */
	protected $language;

	/* @var \phpbb\controller\helper */
	protected $helper;

	/* @var \mrfg\cogauth\cognito\auth_result */
	protected $auth_result;

	/**
	 * Constructor
	 *
	 * @param \phpbb\config\config      		$config
	 * @param \phpbb\request\request_interface  $request
	 * @param \mrfg\cogauth\cognito\auth_result $auth_result
	 * @param \phpbb\language\language 			$language
   	 * @param   \phpbb\controller\helper $helper

	 */
	public function __construct(
		\phpbb\config\config $config,
		\phpbb\request\request_interface $request,
		\mrfg\cogauth\cognito\auth_result $auth_result,
		\phpbb\language\language $language,
		\phpbb\controller\helper $helper)
	{
		$this->config   = $config;
		$this->request = $request;
		$this->auth_result = $auth_result;
		$this->language = $language;
		$this->helper =$helper;

	}

	/**
	 * Demo controller for route /demo/{name}
	 *
	 * @param string $command
	 * @throws \phpbb\exception\http_exception | \Exception
	 * @return \Symfony\Component\HttpFoundation\Response A Symfony Response object
	 */
	public function handle($command)
	{
		$this->language->add_lang(array('ucp'));

		if ($command === 'callback')
		{
			$client_id = $this->config['cogauth_client_id'];
			$client_secret = $this->config['cogauth_client_secret'];
			$code = $this->request->variable('code', '');
			if ($code != '')
			{
				$url = 'https://' . $this->config['cogauth_hosted_ui_domain'] . '/oauth2/token';
				$prefix = $this->config['server_protocol'] . $this->config['server_name'] . $this->config['script_path'];
				$data = array(
					'grant_type'   => 'authorization_code',
					'client_id'    => $client_id,
					'code'         => $code,
					'redirect_uri' => $prefix . '/app.php/cogauth/auth/callback');

				$handle = curl_init($url);
				curl_setopt($handle, CURLOPT_FOLLOWLOCATION, true);
				curl_setopt($handle, CURLOPT_USERPWD, $client_id . ":" . $client_secret);
				curl_setopt($handle, CURLOPT_RETURNTRANSFER, true);
				$field_string = http_build_query($data);

				curl_setopt($handle, CURLOPT_POSTFIELDS, $field_string);
				$resp = curl_exec($handle);

				if (!curl_errno($handle))
				{
					switch ($http_code = curl_getinfo($handle, CURLINFO_HTTP_CODE))
					{
						case 200:  # OK
							$token = $this->validate_response(json_decode($resp, true));
							if ($token)
							{
								// Success
								$this->helper->assign_meta_refresh_var(2, generate_board_url());
								return $this->helper->message('LOGIN_REDIRECT');
							}
						break;
						default:
							// Unexpected http code
							return $this->helper->message('COGAUTH_HOSTED_UI_STATUS_FAIL',array($http_code));
					}
				}
				else
				{
					// curl error
					return $this->helper->message('COGAUTH_HOSTED_UI_FAIL',array(curl_error($handle)));
				}
			}
			// Missing 'code' in callback
			return $this->helper->message('COGAUTH_HOSTED_UI_INVALID',array(),'INFORMATION',500);

		} elseif ($command === 'signout')
		{
			error_log('signout - not implemented');
			$this->helper->assign_meta_refresh_var(2,generate_board_url());
			return $this->helper->message('LOGOUT_REDIRECT');
		}
		else {
			// Invalid command parameter (invalid url)
			return $this->helper->message('COGAUTH_HOSTED_UI_404',array(),'INFORMATION',404);
		}
	}

	protected function validate_response($response)
	{
		$cogauth_token = $this->auth_result->validate_and_store_auth_response(
			array('IdToken' => $response['id_token'],
				  'AccessToken' => $response['access_token'],
				  'RefreshToken' => $response['refresh_token'],
		));

		return $cogauth_token;
	}

}
