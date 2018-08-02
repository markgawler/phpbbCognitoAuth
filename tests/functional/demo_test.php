<?php
/**
 *
 * AWS Cognito Authentication. An extension for the phpBB Forum Software package.
 *
 * @copyright (c) 2018, Mark Gawler
 * @license GNU General Public License, version 2 (GPL-2.0)
 *
 */

namespace mrfg\cogauth\tests\functional;

/**
 * @group functional
 */
class demo_test extends \phpbb_functional_test_case
{
	static protected function setup_extensions()
	{
		return array('mrfg/cogauth');
	}

	public function test_demo_cogauth()
	{
		$crawler = self::request('GET', 'app.php/demo/cogauth');
		$this->assertContains('cogauth', $crawler->filter('h2')->text());

		$this->add_lang_ext('mrfg/cogauth', 'common');
		$this->assertContains($this->lang('DEMO_HELLO', 'cogauth'), $crawler->filter('h2')->text());
		$this->assertNotContains($this->lang('DEMO_GOODBYE', 'cogauth'), $crawler->filter('h2')->text());

		$this->assertNotContainsLang('ACP_COGAUTH', $crawler->filter('h2')->text());
	}

	public function test_demo_world()
	{
		$crawler = self::request('GET', 'app.php/demo/world');
		$this->assertNotContains('cogauth', $crawler->filter('h2')->text());
		$this->assertContains('world', $crawler->filter('h2')->text());
	}
}
