<?php
/**
 *
 * AWS Cognito Authentication. An extension for the phpBB Forum Software package.
 *
 * @copyright (c) 2018, Mark Gawler
 * @license GNU General Public License, version 2 (GPL-2.0)
 *
 */

namespace mrfg\cogauth\event;

/**
 * @ignore
 */
use Symfony\Component\EventDispatcher\EventSubscriberInterface;

/**
 * AWS Cognito Authentication Event listener.
 */
class main_listener implements EventSubscriberInterface
{
	static public function getSubscribedEvents()
	{
		return array(
			'core.user_setup'				=> 'load_language_on_setup',
			'core.ucp_profile_reg_details_validate' => 'ucp_profile_update',
			'core.session_create_after' 	=> 'session_create_after',
			'core.session_gc_after' 		=> 'session_gc_after',
		);
	}

	/* @var \phpbb\controller\helper */
	protected $helper;

	/* @var \phpbb\template\template */
	protected $template;

	/* @var \phpbb\user */
	protected $user;

	/* @var \mrfg\cogauth\cognito\cognito */
	protected $client;

	/* @var string */
	protected $session_table;

	/**
	 * Constructor
	 *
	 * @param \phpbb\controller\helper	$helper		Controller helper object
	 * @param \phpbb\template\template	$template	Template object
	 * @param \phpbb\user               $user       User object
	 * @param \mrfg\cogauth\cognito\cognito $client
	 * @param string $session_table
	 */
	public function __construct(
		\phpbb\controller\helper $helper,
		\phpbb\template\template $template,
		\phpbb\user $user,
		\mrfg\cogauth\cognito\cognito $client,
		$session_table)
	{
		$this->helper   = $helper;
		$this->template = $template;
		$this->user     = $user;
		$this->client = $client;
		$this->session_table = $session_table;
	}

	/**
	 * Load common language files during user setup
	 *
	 * @param \phpbb\event\data	$event	Event object
	 */
	public function load_language_on_setup($event)
	{
		$lang_set_ext = $event['lang_set_ext'];
		$lang_set_ext[] = array(
			'ext_name' => 'mrfg/cogauth',
			'lang_set' => 'common',
		);
		$event['lang_set_ext'] = $lang_set_ext;
	}

	public function session_gc_after($event)
	{
		error_log('session_gc_after - has run');
		//TODO Tidy sesions
	}


	public function session_create_after($event)
	{
		$data = $event['session_data'];
		if ($data['session_user_id'] !== 1)
		{
			error_log('Store access token');
			// Store the Cognito access token in the DB now we hae the SID for the logged in session.
			$this->client->store_auth_result($data['session_id']);
		}
	}

	public function ucp_profile_update($event)
	{
		if ($event['submit'] &&  !sizeof($event['error']))
		{
			error_log('ucp_profile_update, no errors submit ');
			$data = $event['data'];

			error_log('Password Change: ' . $event['data']['new_password']);
			$access_token = $this->client->get_access_token();
			if (isset($access_token))
			{
				try
				{
					$this->client->changePassword($access_token, $data['cur_password'], $data['new_password']);
					error_log('Success');
				}
				catch  (\Exception $e)  //TODO error handling
				{
					error_log('Fail');
					$event['error'] = array('COGAUTH_PASSWORD_ERROR');
				}
			}
			else
			{
				error_log('No Access token found');
				$event['error'] = array('COGAUTH_PASSWORD_ERROR');
			}
		}
	}
}
