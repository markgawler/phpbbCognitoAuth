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
			'core.session_kill_after'		=> 'session_kill_after',
			'core.user_setup'				=> 'load_language_on_setup',
			'core.user_setup_after'			=> 'user_setup_after',
			'core.ucp_profile_reg_details_validate' => 'ucp_profile_update',
			'core.session_create_after' 	=> 'session_create_after',
			'core.acp_users_overview_modify_data' => 'acp_profile_update',
			'core.delete_user_after' 		=> 'delete_users',
			'core.user_active_flip_after' 	=> 'user_active_flip',
			'core.session_gc_after' 		=> 'session_gc_after',
		);
	}

	/* @var \phpbb\user */
	protected $user;

	/* @var \phpbb\auth\auth */
	protected $auth;

	/* @var \phpbb\request\request 	phpBB request object */
	protected $request;

	/* @var \phpbb\config\config */
	protected $config;

	/* @var \mrfg\cogauth\cognito\cognito */
	protected $client;

	/* @var string */
	protected $session_table;

	/**
	 * Constructor
	 *
	 * @param \phpbb\user               $user       User object
	 * @param \phpbb\auth\auth $auth
	 * @param \phpbb\request\request_interface  $request
	 * @param \phpbb\config\config      $config
	 * @param \mrfg\cogauth\cognito\cognito $client
	 * @param string $session_table
	 */
	public function __construct(
		\phpbb\user $user,
		\phpbb\auth\auth $auth,
		\phpbb\request\request_interface $request,
		\phpbb\config\config $config,
		\mrfg\cogauth\cognito\cognito $client,
		$session_table)
	{
		$this->user = $user;
		$this->auth = $auth;
		$this->request = $request;
		$this->config = $config;
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

	/**
	 * Sesion synchronisation
	 *
	 * @since version
	 */
	public function user_setup_after()
	{
		$mode = $this->request->variable('mode','');
		if (!$this->user->data['is_bot'] &&  $mode != 'login' && $mode != 'logout')
		{
			$user_id = $this->user->data['user_id'];
			$session_token = $this->request->variable($this->config['cookie_name'] . '_cogauth', '', false, \phpbb\request\request_interface::COOKIE);
			if ($session_token == '')
			{
				if ($user_id != ANONYMOUS)
				{
					$this->user->session_kill(true);
					$this->auth->acl($this->user->data);
					$this->user->session_begin();
				}
			}
			else
			{
				// Check session is valid
				$cognito_session = $this->client->validate_session($session_token);
				$session_active = $cognito_session['active'];

				if ($user_id == ANONYMOUS && $session_active)
				{
					$this->client->store_session_token($session_token);  // save the token so that it gets put back in the cookie
					// Not Logged In - attempt to login / start session
					$this->user->session_kill();
					$this->user->session_create($cognito_session['user_id'], false, false, true);  //todo  remember me
					$this->auth->acl($this->user->data);
					$this->user->setup();
				}

				if ($user_id != ANONYMOUS && !$session_active)
				{
					// Logged in - Log out / end session
					$this->user->session_kill(true);
					$this->auth->acl($this->user->data);
					$this->user->session_begin();

				}
			}
		}
	}

	/**
	 * @param \phpbb\event\data	$event	Event object
	 */
	public function session_gc_after(/** @noinspection PhpUnusedParameterInspection */ $event)
	{
		$this->client->delete_expired_sessions();
	}

	/**
	 * @param \phpbb\event\data	$event	Event object
	 */
	public function session_create_after($event)
	{
		//error_log('session_create_after');
		$data = $event['session_data'];
		if ($data['session_user_id'] !== 1)  // user_id of 1 = Guest
        {
			// Now we have the SID we can stor it in the cogauth_session table..
            $this->client->store_sid($data['session_id']);

            // Set the cookie to the new cognito session token.
			$this->user->set_cookie('cogauth', $this->client->get_session_token(), 0);
		}
    }

	/**
	 * @param \phpbb\event\data	$event	Event object
	 */
	public function session_kill_after($event)
	{
		$session = $event['session_id'];
		$this->client->phpbb_session_killed($session);

		// Destroy the session cookie to force logout of bridged app
		$this->user->set_cookie('cogauth', '', 0);
	}

	/**
   	 * @param \phpbb\event\data	$event	Event object
	 */
	public function ucp_profile_update($event)
	{

		if ($event['submit'] &&  !sizeof($event['error']))
		{
			$data = $event['data'];

			$access_token = $this->client->get_access_token();
			if (isset($access_token))
			{
				$user_id = $this->user->data['user_id'];
				if (!empty($data['email']))
				{
					if (! $this->client->update_user_email($user_id, $data['email'], $access_token))
					{
						$event['error'] = array('COGAUTH_EMAIL_CHANGE_ERROR');
					}
				}
				if (!empty($data['new_password']))
				{
					error_log('Password Change: ' . $event['data']['new_password']);
					if (! $this->client->change_password($user_id, $access_token, $data['cur_password'], $data['new_password']))
					{
						$event['error'] = array('COGAUTH_PASSWORD_ERROR');
					}
				}
			}
			else
			{
				//TODO this is not an error if the user has not been migrated, we should migrate the user and set the password.
				//error_log('No Access token found');
				$event['error'] = array('COGAUTH_PASSWORD_ERROR');
			}
		}
	}

	/**
	 * @param \phpbb\event\data	$event	Event object
	 */
	public function acp_profile_update($event)
	{
		$data = $event['data'];
		$user_row = $event['user_row'];
		$user_id = $event['user_row']['user_id'];

		if (!empty($data['email']) && $data['email'] != $user_row['user_email'])
		{
			$this->client->admin_update_email($user_id,$data['email']);
		}

		if (!empty($data['new_password']))
		{
			$this->client->admin_change_password($user_id,$data['new_password']);
		}

		$username_clean = utf8_clean_string($data['username']);
		if (!empty($username_clean) && $username_clean != $user_row['username_clean'])
		{
			$this->client->admin_update_username($user_id,$data['username']);
		}
	}

	/**
	 * @param \phpbb\event\data	$event	Event object
	 */
	public function delete_users($event)
	{
		foreach ($event['user_ids'] as $user_id)
		{
			$this->client->admin_delete_user($user_id);
		}
	}

	public function user_active_flip($event)
	{
		foreach ($event['user_id_ary'] as $user_id)
		{
			$activated = $event['activated'];
			$deactivated = $event['deactivated'];

			switch ($event['mode'])
			{
				case 'flip':
					if ($activated && $deactivated)
					{
						//TODO error handling
						error_log('Ambiguous activation/deactivation');
					}
					elseif ($activated)
					{
						$this->client->admin_enable_user($user_id);
					}
					else
					{
						$this->client->admin_disable_user($user_id);
					}
				break;
				case 'activate':
					$this->client->admin_enable_user($user_id);
				break;
				case 'deactivate':
					$this->client->admin_disable_user($user_id);
				break;
			}
		}
	}
}

