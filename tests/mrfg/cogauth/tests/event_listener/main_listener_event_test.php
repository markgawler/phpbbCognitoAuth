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


use phpbb\event\data;

class main_listener_event_test extends \phpbb_test_case
{
    /** @var $user \phpbb\user*/
    protected $user;

	/** @noinspection PhpUndefinedClassInspection */
	/** @var $cognito_client \mrfg\cogauth\cognito\cognito | \PHPUnit_Framework_MockObject_MockObject */
    protected $cognito_client;

    /** @var $request \phpbb\request\request | \PHPUnit_Framework_MockObject_MockObject  */
    protected $request;

    /** @var $config \phpbb\config\config  */
    protected $config;

    /** @var \mrfg\cogauth\event\main_listener $listener*/
    protected $listener ;

	/** @noinspection PhpUndefinedClassInspection */
	/** @var \phpbb\event\dispatcher_interface | \PHPUnit_Framework_MockObject_MockObject */
    protected $dispatcher;

    /** @var \mrfg\cogauth\cognito\auth_result| \PHPUnit_Framework_MockObject_MockObject */
    protected $auth_result;

	/** @var \mrfg\cogauth\cognito\controller $controller \PHPUnit_Framework_MockObject_MockObject */
	protected $controller;

	/** @var \phpbb\template\template $template */
	protected $template;

    public function setUp()
    {
        parent::setUp();

		$this->user = $this->getMockBuilder('\phpbb\user')
			->disableOriginalConstructor()
			->getMock();

		$this->request = $this->getMockBuilder('\phpbb\request\request')
			->disableOriginalConstructor()
			->getMock();

		$this->config = $this->getMockBuilder('\phpbb\config\config')
			->disableOriginalConstructor()
			->getMock();

        $this->cognito_client = $this->getMockBuilder('\mrfg\cogauth\cognito\cognito')
            ->setMethods(array('store_sid','get_session_token'))
            ->disableOriginalConstructor()
            ->getMock();

		$this->auth_result = $this->getMockBuilder('\mrfg\cogauth\cognito\auth_result')
			->setMethods(array('authenticated','get_session_token','kill_session'))
			->disableOriginalConstructor()
			->getMock();

		$this->controller = $this->getMockBuilder('\mrfg\cogauth\cognito\controller')
			->setMethods(array('get_access_token'))
			->disableOriginalConstructor()
			->getMock();

		$this->dispatcher = $this->getMockBuilder('\phpbb\event\dispatcher_interface')
			->disableOriginalConstructor()
			->getMock();

		$this->template = $this->getMockBuilder('\phpbb\template\template')
		->disableOriginalConstructor()
		->getMock();

        $this->listener = new \mrfg\cogauth\event\main_listener(
            $this->user,
            $this->cognito_client,
			$this->auth_result,
			$this->controller,
			$this->dispatcher,
			$this->request,
			$this->config,
			$this->template);
    }


    public function test_session_create_after()
    {
		$sid = '1f7efc7a5a163338f30bbdcc66001de5';
		$token = '1f7aaaaaaaasessiontokenaaaa01de5';

	   /** @var \phpbb\event\data $event */
        $event = new data(array('session_data' => array(
            'session_user_id' => 1234567,
            'session_id' => $sid)));

		$this->dispatcher->expects(($this->once()))
			->method('trigger_event')
			->with('mrfg.cogauth.session_create_after',array('session_token' => $token))
			->willReturn(array());

		$this->auth_result->expects($this->once())
			->method('authenticated')
			->with(1234567,$sid)
			->willReturn($token);

		/** @noinspection PhpUnhandledExceptionInspection */
		$this->listener->session_create_after($event);
    }

    public function test_session_create_after_guest()
    {
        /** @var \phpbb\event\data $event */
        $event = new data(array('session_data' => array(
            'session_user_id' => 1,
            'session_id' => '1f7efc7a5abbdcc66001de5163338f30')));

		$this->auth_result->expects($this->never())
			->method('authenticated');

		$this->dispatcher->expects($this->never())
		->method('trigger_event');

		/** @noinspection PhpUnhandledExceptionInspection */
		$this->listener->session_create_after($event);
    }

    public function test_session_kill_after()
	{
		$token = 'tttttttttttttttttokennnnnnnnnn8';
		$sid = '3ba5603a695aaaaaaaaaaaaaaaaaaa68';

		/** @var \phpbb\event\data $event */
		$event = new data(array(
			'user_id'     => 2,
			'session_id'  => $sid,
			'new_session' => true));

		$this->auth_result->expects($this->once())
			->method('get_session_token')
			->with(false)
			->willReturn($token)
		;

		$this->auth_result->expects($this->once())
			->method('kill_session')
			->with($sid)
		;

		$this->dispatcher->expects($this->once())
			->method('trigger_event')
			->with('mrfg.cogauth.session_kill_after', array('session_token' => $token))
			->willReturn(array());
		;

		$this->listener->session_kill_after($event);

	}

	public function test_session_kill_after_no_session()
	{
		$token =  null;
		$sid = '3ba5603a695aaaaaaaaaaaaaaaaaaa68';

		/** @var \phpbb\event\data $event */
		$event = new data(array(
			'user_id'     => 2,
			'session_id'  => $sid,
			'new_session' => true));

		$this->auth_result->expects($this->once())
			->method('get_session_token')
			->with(false)
			->willReturn($token)
		;

		$this->auth_result->expects($this->once())
			->method('kill_session')
			->with($sid)
		;

		$this->dispatcher->expects($this->never())
			->method('trigger_event')
		;

		$this->listener->session_kill_after($event);

	}
}
