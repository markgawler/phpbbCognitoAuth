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
    /** @var $user \phpbb\user*/
    protected $user;

	/** @noinspection PhpUndefinedClassInspection */
	/** @var $cognito_client \mrfg\cogauth\cognito\cognito | \PHPUnit_Framework_MockObject_MockObject */
    protected $cognito_client;

    /** @var \phpbb\request\request_interface $request */
    protected $request;

    /** @var array  */
    protected $config;

    /** @var \mrfg\cogauth\event\main_listener $listener*/
    protected $listener ;

	/** @noinspection PhpUndefinedClassInspection */
	/** @var \phpbb\event\dispatcher_interface | \PHPUnit_Framework_MockObject_MockObject */
    protected $dispatcher;

    public function setUp()
    {
        parent::setUp();

		$this->user = $this->getMockBuilder('\phpbb\user')
			->disableOriginalConstructor()
			->getMock();

		$this->request = $this->getMockBuilder('\phpbb\request\request_interface')
			->disableOriginalConstructor()
			->getMock();

		$this->config = $this->getMockBuilder('\phpbb\config\config')
			->disableOriginalConstructor()
			->getMock();

        $this->cognito_client = $this->getMockBuilder('\mrfg\cogauth\cognito\cognito')
            ->setMethods(array('store_sid','get_session_token'))
            ->disableOriginalConstructor()
            ->getMock();

		$this->dispatcher = $this->getMockBuilder('\phpbb\event\dispatcher_interface')
			->disableOriginalConstructor()
			->getMock();

        $this->listener = new \mrfg\cogauth\event\main_listener(
            $this->user,
            $this->cognito_client,
			$this->dispatcher);
    }
    
    
    public function test_session_create_after()
    {
        /** @var \phpbb\event\data $event */
        $event = array('session_data' => array(
            'session_user_id' => 1234567,
            'session_id' => '1f7efc7a5a163338f30bbdcc66001de5'));

		$this->dispatcher->method('trigger_event')
			->willReturn(array('session_token' => '1234567AAA'));

		$this->cognito_client->method('get_session_token')
			->willReturn('Hello_I_am_a_token');

		$this->cognito_client->expects($this->once())
			->method('get_session_token');

        $this->cognito_client->expects($this->once())
            ->method('store_sid')
            ->with('1f7efc7a5a163338f30bbdcc66001de5');

        $this->listener->session_create_after($event);
    }

    public function test_session_create_after_guest()
    {
        /** @var \phpbb\event\data $event */
        $event = array('session_data' => array(
            'session_user_id' => 1,
            'session_id' => '1f7efc7a5abbdcc66001de5163338f30'));

		$this->cognito_client->expects($this->never())
			->method('get_session_token');

		$this->dispatcher->expects($this->never())
		->method('trigger_event');

		$this->listener->session_create_after($event);
    }

}