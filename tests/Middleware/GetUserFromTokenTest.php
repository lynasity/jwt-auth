<?php

/*
 * This file is part of jwt-auth.
 *
 * (c) Sean ManyHong <ManyHong148@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace ManyHong\JWTAuth\Test;

use Mockery;
use ManyHong\JWTAuth\Middleware\GetUserFromToken;
use ManyHong\JWTAuth\Exceptions\TokenExpiredException;
use ManyHong\JWTAuth\Exceptions\TokenInvalidException;

class GetUserFromTokenTest extends \PHPUnit_Framework_TestCase
{
    public function setUp()
    {
        $this->events = Mockery::mock('Illuminate\Contracts\Events\Dispatcher');
        $this->auth = Mockery::mock('ManyHong\JWTAuth\JWTAuth');

        $this->request = Mockery::mock('Illuminate\Http\Request');
        $this->response = Mockery::mock('Illuminate\Contracts\Routing\ResponseFactory');

        $this->middleware = new GetUserFromToken($this->response, $this->events, $this->auth);

        $this->auth->shouldReceive('setRequest')->once()->with($this->request)->andReturn($this->auth);
    }

    public function tearDown()
    {
        Mockery::close();
    }

    /** @test */
    public function it_should_fire_an_event_when_no_token_is_available()
    {
        $this->auth->shouldReceive('getToken')->once()->andReturn(false);

        $this->events->shouldReceive('fire')->once()->with('ManyHong.jwt.absent', [], true);
        $this->response->shouldReceive('json')->with(['error' => 'token_not_provided'], 400);

        $this->middleware->handle($this->request, function () {
        });
    }

    /** @test */
    public function it_should_fire_an_event_when_the_token_has_expired()
    {
        $exception = new TokenExpiredException;

        $this->auth->shouldReceive('getToken')->once()->andReturn('foo');
        $this->auth->shouldReceive('authenticate')->once()->with('foo')->andThrow($exception);

        $this->events->shouldReceive('fire')->once()->with('ManyHong.jwt.expired', [$exception], true);
        $this->response->shouldReceive('json')->with(['error' => 'token_expired'], 401);

        $this->middleware->handle($this->request, function () {
        });
    }

    /** @test */
    public function it_should_fire_an_event_when_the_token_is_invalid()
    {
        $exception = new TokenInvalidException;

        $this->auth->shouldReceive('getToken')->once()->andReturn('foo');
        $this->auth->shouldReceive('authenticate')->once()->with('foo')->andThrow($exception);

        $this->events->shouldReceive('fire')->once()->with('ManyHong.jwt.invalid', [$exception], true);
        $this->response->shouldReceive('json')->with(['error' => 'token_invalid'], 400);

        $this->middleware->handle($this->request, function () {
        });
    }

    /** @test */
    public function it_should_fire_an_event_when_no_user_is_found()
    {
        $this->auth->shouldReceive('getToken')->once()->andReturn('foo');
        $this->auth->shouldReceive('authenticate')->once()->with('foo')->andReturn(false);

        $this->events->shouldReceive('fire')->once()->with('ManyHong.jwt.user_not_found', [], true);
        $this->response->shouldReceive('json')->with(['error' => 'user_not_found'], 404);

        $this->middleware->handle($this->request, function () {
        });
    }

    /** @test */
    public function it_should_fire_an_event_when_the_token_has_been_decoded_and_user_is_found()
    {
        $user = (object) ['id' => 1];

        $this->auth->shouldReceive('getToken')->once()->andReturn('foo');
        $this->auth->shouldReceive('authenticate')->once()->with('foo')->andReturn($user);

        $this->events->shouldReceive('fire')->once()->with('ManyHong.jwt.valid', $user);
        $this->response->shouldReceive('json')->never();

        $this->middleware->handle($this->request, function () {
        });
    }
}
