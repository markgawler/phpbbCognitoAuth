<?php
/**
 * @package phpBB Extension - AWS Cognito Authentication phpBB Extension
 * @copyright (c) 2019 Mark Gawler
 * @license GNU General Public License v2
 */

namespace mrfg\cogauth\controller;

use \Symfony\Component\HttpFoundation\Response;

class main
{
	/* @var \phpbb\config\config */
	protected $config;

	/* @var \phpbb\request\request 	phpBB request object */
	protected $request;

	/* @var \phpbb\language\language $language */
	protected $language;

	/* @var \mrfg\cogauth\cognito\cognito */
	protected $cognito;

	/** @var \mrfg\cogauth\cognito\web_token_phpbb */
	protected $web_token;
	/**
	 * Constructor
	 *
	 * @param \phpbb\config\config      		$config
	 * @param \phpbb\request\request_interface  $request
	 * @param \mrfg\cogauth\cognito\cognito 	$cognito
	 * @param \mrfg\cogauth\cognito\web_token_phpbb $web_token
	 * @param \phpbb\language\language 			$language
 */
	public function __construct(
		\phpbb\config\config $config,
		\phpbb\request\request_interface $request,
		\mrfg\cogauth\cognito\cognito $cognito,
		\mrfg\cogauth\cognito\web_token_phpbb $web_token,
		\phpbb\language\language $language)
	{
		$this->config   = $config;
		$this->request = $request;
		$this->cognito = $cognito;
		$this->language = $language;
		$this->web_token = $web_token;

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
		$client_id = $this->config['cogauth_client_id'];
		//$client_id  = '13h3u2ie5tvvf4ot20p316n822';
		$client_secret = $this->config['cogauth_client_secret'];
		//$client_secret = 'o2d9423m32aijr63l83t38rl9hga55hq82nq5r747onmikrnips';
		$code = $this->request->variable('code','');
		$result_text = '';
		error_log('handle ' . $code);

		if ($code != '')
		{
			$url = 'https://auth.ukriversguidebook.co.uk/oauth2/token';
			$data = array(
				'grant_type'   => 'authorization_code',
				'client_id'    => $client_id,
				'code'         => $code,
				'redirect_uri' => 'https://area51.ukriversguidebook.co.uk/forum/app.php/cogauth/auth/callback');

			$handle = curl_init($url);
			curl_setopt($handle, CURLOPT_VERBOSE, true);
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
						$this->validate_response(json_decode($resp,true));

						$result_text  = 'OK';
					break;
					default:
						$result_text  =  'Unexpected HTTP code: ' . $http_code;
				}
			}
		}


		$result = array('re' => $result_text);

		$content = json_encode((object) $result );
		return new \Symfony\Component\HttpFoundation\Response($content, Response::HTTP_OK);
	}

	protected function validate_response($response)
	{
		$decode_id = $this->web_token->decode_token($response['id_token']);
		$decode_access = $this->web_token->decode_token($response['access_token']);

		var_dump($response);
		var_dump($decode_id);
		var_dump($decode_access);
	}

}
