<?php
/**
 * @package     mrfg\cogauth\cron\task
 * @subpackage
 *
 * @copyright   A copyright
 * @license     A "Slug" license name e.g. GPL2
 */

namespace mrfg\cogauth\cron\task;

class access_token_refresh extends \phpbb\cron\task\base
{
	/** @var \phpbb\config\config $config */
	protected $config;

	/** @var \phpbb\db\driver\driver_interface $db */
	protected $db;

	/* @var \mrfg\cogauth\cognito\cognito */
	protected $cognito;

	/**
	 * Constructor - cleanup
	 *
	 * @param \phpbb\config\config              $config              The config
	 * @param \phpbb\db\driver\driver_interface $db     The db connection
	 * @param \mrfg\cogauth\cognito\cognito     $cognito
 */
	public function __construct(
		\phpbb\config\config $config,
		\phpbb\db\driver\driver_interface $db,
		\mrfg\cogauth\cognito\cognito $cognito)
	{
		$this->config = $config;
		$this->db = $db;
		$this->cognito = $cognito;
	}

	/**
	 * Runs this cron task.
	 *
	 */
	public function run()
	{
		error_log('Cron Run - token Refresh');

		$this->config->set('cogauth_token_refresh_last_gc', time());
		$this->cognito->refresh_access_tokens();
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
		return ((time() - $this->config['cogauth_token_refresh_last_gc']) >  $this->config['cogauth_token_refresh_gc']);
	}
}