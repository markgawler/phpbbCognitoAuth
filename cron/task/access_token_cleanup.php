<?php
/**
 * @package     mrfg\cogauth\cron\task
 * @subpackage
 *
 * @copyright   A copyright
 * @license     A "Slug" license name e.g. GPL2
 */

namespace mrfg\cogauth\cron\task;

/** @noinspection PhpUnused */

class access_token_cleanup extends \phpbb\cron\task\base
{
	/** @var \phpbb\config\config $config */
	protected $config;

	/** @var \phpbb\db\driver\driver_interface $db */
	protected $db;

	/* @var \mrfg\cogauth\cognito\auth_result */
	protected $auth_result;

	/**
	 * Constructor - cleanup
	 *
	 * @param \phpbb\config\config              $config              The config
	 * @param \mrfg\cogauth\cognito\auth_result     $auth_result
 */
	public function __construct(
		\phpbb\config\config $config,
		\mrfg\cogauth\cognito\auth_result $auth_result)
	{
		$this->config = $config;
		$this->auth_result = $auth_result;
	}

	/**
	 * Runs this cron task.
	 *
	 */
	public function run()
	{
		error_log('Cron Run - cogauth_token_cleanup');
		$this->config->set('cogauth_token_cleanup_last_gc', time());
		$this->auth_result->cleanup_session_tokens($this->config['cogauth_max_session_hours'] );
	}

	/**
	 * Returns whether this cron task can run, given current board configuration.
	 *
	 * @return bool
	 */
	public function is_runnable()
	{
		return true;
	}

	/**
	 * Returns whether this cron task should run now, because enough time
	 * has passed since it was last run.
	 *
	 * @return bool
	 */
	public function should_run()
	{
		return ((time() - $this->config['cogauth_token_cleanup_last_gc']) >  $this->config['cogauth_token_cleanup_gc'] * 60);
	}
}
