<?php
/**
 *
 * AWS Cognito Authentication. An extension for the phpBB Forum Software package.
 *
 * @copyright (c) 2018, Mark Gawler
 * @license GNU General Public License, version 2 (GPL-2.0)
 *
 * Date: 12/09/18
 *
 * Event Listener tests
 */

namespace mrfg\cogauth\tests\event_listener;


class simple_event_test extends \phpbb_test_case
{

    public function test_config3()
    {
        $this->assertTrue(1 === 1, 'Dummy 1');
    }


}