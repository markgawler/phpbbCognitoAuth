<?php
/**
 * @package     mrfg\cogauth\cognito
 * @subpackage
 *
 * @copyright   A copyright
 * @license     A "Slug" license name e.g. GPL2
 */

namespace mrfg\cogauth\cognito;


class validation_result
{
	/** @var string $cogauth_token */
	public $cogauth_token;

	/** @var integer $phpbb_user_id */
	public $phpbb_user_id;

	public function __construct($cogauth_token = '', $phpbb_user_id = 0)
	{
		$this->cogauth_token = $cogauth_token;
		$this->phpbb_user_id = $phpbb_user_id;
	}

	public function is_new_user()
	{
		return ($this->cogauth_token !== '' && $this->phpbb_user_id == 0);
	}
}
