<?php

/**
 *
 * AWS Cognito Authentication. An extension for the phpBB Forum Software package.
 *
 * @copyright (c) 2018, Mark Gawler
 * @license GNU General Public License, version 2 (GPL-2.0)
 *
 */
/** @noinspection PhpUnused */

namespace mrfg\cogauth\event;

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
			'core.ucp_profile_reg_details_validate' => 'ucp_profile_update',
			'core.session_create_after' 	=> 'session_create_after',
			'core.acp_users_overview_modify_data' => 'acp_profile_update',
			'core.delete_user_after' 		=> 'delete_users',
			'core.user_active_flip_after' 	=> 'user_active_flip',
			'core.auth_login_session_create_before' => 'auth_login_session_create_before',
			'core.acp_board_config_edit_add' => 'acp_board_config_edit_add'
		);
	}

	/** @var \phpbb\user */
	protected $user;

	/** @var \mrfg\cogauth\cognito\cognito */
	protected $client;

	/** @var \phpbb\event\dispatcher_interface */
	protected $dispatcher;

	/** @var \mrfg\cogauth\cognito\auth_result $auth_result */
	protected $auth_result;

	/** @var \mrfg\cogauth\cognito\controller $controller */
	protected $controller;

	/* @var \phpbb\request\request 	phpBB request object */
	protected $request;

	/**@var \phpbb\config\config $config Config object */
	protected $config;

	/**
	 * Constructor
	 *
	 * @param \phpbb\user                       $user       User object
	 * @param \mrfg\cogauth\cognito\cognito     $client
	 * @param \mrfg\cogauth\cognito\auth_result $auth_result
	 * @param \mrfg\cogauth\cognito\controller  $controller
	 * @param \phpbb\event\dispatcher_interface $dispatcher Event dispatcher
	 * @param \phpbb\request\request            $request
	 * @param \phpbb\config\config              $config
	 */
	public function __construct(
		\phpbb\user $user,
		\mrfg\cogauth\cognito\cognito $client,
		\mrfg\cogauth\cognito\auth_result $auth_result,
		\mrfg\cogauth\cognito\controller $controller,
		\phpbb\event\dispatcher_interface $dispatcher,
		\phpbb\request\request $request,
		\phpbb\config\config $config)
	{
		$this->auth_result = $auth_result;
		$this->user = $user;
		$this->client = $client;
		$this->controller = $controller;
		$this->dispatcher = $dispatcher;
		$this->request = $request;
		$this->config   = $config;

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
	 * @param \phpbb\event\data	$event	Event object
	 *
	 * @since 1.0
	 */
	public function auth_login_session_create_before($event)
	{
		if ($event['admin'])
		{
			// This is a login to the ACP so copy autologin from user session
			$this->auth_result->set_autologin($this->user->data['session_autologin'] == true);
		}
		else
		{
			$this->auth_result->set_autologin($event['autologin'] == true);
		}
	}

	/**
	 * @param \phpbb\event\data $event Event object
	 * @throws \mrfg\cogauth\cognito\exception\cogauth_authentication_exception
	 */
	public function session_create_after($event)
	{
		$data = $event['session_data'];
		if ($data['session_user_id'] !== 1)  // user_id of 1 = Guest
        {
			// Now we have the SID we can store it in the cogauth_authentication table..
			/** @noinspection PhpUnusedLocalVariableInspection */
			$session_token = $this->auth_result->authenticated(
				$data['session_user_id'], $data['session_id']);

			/**
			 * Cogauth session after create event
			 *
			 * @event mrfg.cogauth.session_create_after
			 * @var  string  session_token
			 * @since 1.1
			 */
			$vars = array('session_token',);
			extract($this->dispatcher->trigger_event('mrfg.cogauth.session_create_after', compact($vars)));
		}
    }

	/**
	 * @param \phpbb\event\data	$event	Event object
	 */
	public function session_kill_after($event)
	{
		/*
		 * 'user_id' => int 2
		 * 'session_id' => string '3ba5603a695a1bd1b32ab5a698e65468' (length=32)
		 * 'new_session' => boolean true
		 */

		$session = $event['session_id'];
		/** @noinspection PhpUnusedLocalVariableInspection */
		$session_token = $this->auth_result->get_session_token(false);

		$this->auth_result->kill_session($session);

		if ($session_token)
		{
			/**
			 * Cogauth session kill after event
			 *
			 * @event mrfg.cogauth.session_kill_after
			 * @var  string  session_token
			 * @since 1.1
			 */
			$vars = array('session_token',);
			extract($this->dispatcher->trigger_event('mrfg.cogauth.session_kill_after', compact($vars)));
		}
	}

	/**
	 * @param \phpbb\event\data $event Event object
	 * @throws \mrfg\cogauth\cognito\exception\cogauth_internal_exception
	 */
	public function ucp_profile_update($event)
	{

		if ($event['submit'] &&  !sizeof($event['error']))
		{
			$data = $event['data'];

			$access_token = $this->controller->get_access_token();
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
				// this may be because the SID was not found in the cogauth_authentication table
				// or the access token was invalid and failed to refresh.
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

	public function acp_board_config_edit_add($event)
	{
		// Ensure the APC  max_autologin_time is within the valid range for Cognito refresh token validity,
		if ($event['mode'] == 'security' )
		{
			if ($event['submit'] == true)
			{
				// todo: is there a better way of triggering an action when the config changes?
				$new_config = $this->request->variable('config', array('' => ''), true);
				$max_autologin_time = $new_config['max_autologin_time'];
				if ($max_autologin_time >= 1 && $max_autologin_time <= 3560 && $max_autologin_time != $this->config['max_autologin_time'])
				{
					$this->client->update_user_pool_client($max_autologin_time);
				}
			}
			else
			{
				// this seems long hand, but didn't work until the local $display_vars was used.
				$display_vars = $event['display_vars'];
				$display_vars['vars']['max_autologin_time']['validate'] = 'int:1:3650';
				$display_vars['vars']['max_autologin_time']['type'] = 'number:1:3650';
				$display_vars['vars']['max_autologin_time']['lang'] = 'CA_AUTOLOGIN_LENGTH';
				$event['display_vars'] = $display_vars;
			}
		}
	}
}
