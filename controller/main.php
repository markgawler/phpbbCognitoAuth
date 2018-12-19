<?php
/**
 * Created by PhpStorm.
 * User: mrfg
 * Date: 09/12/18
 * Time: 16:05
 */

namespace mrfg\cogauth\controller;

use \Symfony\Component\HttpFoundation\Response;

class main
{
	/* @var \phpbb\config\config */
	protected $config;

	/* @var \phpbb\controller\helper */
	protected $helper;

	/* @var \phpbb\user */
	protected $user;

	/* @var \phpbb\request\request 	phpBB request object */
	protected $request;

	/* @var \mrfg\cogauth\auth\provider\cogauth */
	protected $auth;

	/* @var \phpbb\language\language $language */
	protected $language;

	/* @var \mrfg\cogauth\cognito\cognito */
	protected $cognito;

	/**
	 * Constructor
	 *
	 * @param \phpbb\user               $user
	 * @param \phpbb\config\config      $config
	 * @param \phpbb\request\request_interface  $request
	 * @param \mrfg\cogauth\auth\provider\cogauth $auth
	 * @param \mrfg\cogauth\cognito\cognito $cognito
	 * @param \phpbb\language\language $language
 */
	public function __construct(
		\phpbb\config\config $config,
		\phpbb\user $user,
     	\phpbb\request\request_interface $request,
		\mrfg\cogauth\auth\provider\cogauth $auth,
		\mrfg\cogauth\cognito\cognito $cognito,
		\phpbb\language\language $language)
	{
		$this->config   = $config;
		$this->user     = $user;
		$this->request = $request;
		$this->auth = $auth;
		$this->cognito = $cognito;
		$this->language = $language;
	}

	/**
	 * Demo controller for route /demo/{name}
	 *
	 * @param string $command
	 * @param string $payload
	 * @throws \phpbb\exception\http_exception
	 * @return \Symfony\Component\HttpFoundation\Response A Symfony Response object
	 */
	public function handle($command,$payload)
	{
		//TODO	validate request
		if ($command === 'bertie')
		{
			throw new \phpbb\exception\http_exception(Response::HTTP_FORBIDDEN, 'NO_AUTH_SPEAKING', array($command));
		}

		$command = strtolower($command);
		switch ($command)
		{
			//case 'username_clean':
			//	$username = $this->request->variable('username','');
			//	$result = $this->username_clean($username);
			//break;
			case 'authenticate':
				$result = $this->authenticate(
					$this->request->variable('username',''),
					$this->request->variable('password','')
				);
			break;
			case 'active_session':
				$session_token = $this->request->variable('session_token','');
				$result = $this->is_session_active($session_token);
			break;
			default:
				$result = array('error' => 'unknown command');
		}

		$content = json_encode((object) $result );
		error_log('Result: ' .$content);
		return new \Symfony\Component\HttpFoundation\Response($content, Response::HTTP_OK);
	}

	/**
	 * @param $username
	 * @return array content to return, 'username_clean => 'username'
	 */
	//private function username_clean($username)
	//{
	//	return array ('username_clean' => utf8_clean_string($username));
	//}

	/**
	 * @param string $username
	 * @param string $password
	 * @return array user_id, username_clean, authenticated (bool), error
	 */
	private function authenticate($username, $password)
	{
		$result = $this->auth->login($username, $password);
		//TODO need to handle %s in error_msg string

		$user_row = $result['user_row'];
		$response = array(
			'status' => $result['status'],
			'error' => $this->language->lang($result['error_msg']),
			'user_row' => array(
				'user_id' => $user_row['user_id'],
				'user_type' => $user_row['user_type'],
				'group_id' => $user_row['group_id'],
				'username' => $user_row['username'],
				'username_clean' => $user_row['username_clean'],
				'user_email' => $user_row['user_email']
			),
			'session_token' => $result['session_token']);
		return $response;
	}

	/**
	 * @param $session_token
	 * @return array
	 *
	 */
	private function is_session_active($session_token)
	{
		error_log('is_session_active');
		if ($session_token !== '')
		{
			$result = $this->cognito->validate_session($session_token);
			return $result;
		}
		return array('error' => 'invalid token');
	}
}
