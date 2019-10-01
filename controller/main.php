<?php
/**
 * @package phpBB Extension - AWS Cognito Authentication phpBB Extension
 * @copyright (c) 2019 Mark Gawler
 * @license GNU General Public License v2
 */

namespace mrfg\cogauth\controller;

class main
{
	/** @var \phpbb\config\config */
	protected $config;

	/** @var \phpbb\request\request 	phpBB request object */
	protected $request;

	/** @var \phpbb\language\language $language */
	protected $language;

	/** @var \phpbb\controller\helper */
	protected $helper;

	/** @var  \mrfg\cogauth\cognito\user $controller*/
	protected $controller;

	/**
	 * Constructor
	 *
	 * @param \phpbb\config\config      		$config
	 * @param \phpbb\request\request_interface  $request
	 * param \mrfg\cogauth\cognito\auth_result $auth_result
	 * @param \phpbb\language\language 			$language
   	 * @param \phpbb\controller\helper $helper
	 * @param \mrfg\cogauth\cognito\controller $controller
	 * param \mrfg\cogauth\cognito\user $user


	 */
	public function __construct(
		\phpbb\config\config $config,
		\phpbb\request\request_interface $request,
		\phpbb\language\language $language,
		\phpbb\controller\helper $helper,
		\mrfg\cogauth\cognito\controller $controller
		)
	{
		$this->config   = $config;
		$this->request = $request;
		$this->language = $language;
		$this->helper =$helper;
		$this->controller = $controller;

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
							$tokens = $this->format_response(json_decode($resp, true));
							$result = $this->controller->login($tokens);
							if ($result)
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
			// Missing 'code' in callback, or validate response returned false
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

	protected function format_response($response)
	{
		return array('IdToken' => $response['id_token'],
			  'AccessToken' => $response['access_token'],
			  'RefreshToken' => $response['refresh_token'],
		);
	}

}
