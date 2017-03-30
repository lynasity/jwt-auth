<?php

/*
 * This file is part of jwt-auth.
 *
 * (c) Sean Tymon <tymon148@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace ManyHong\JWTAuth;

use ManyHong\JWTAuth\Exceptions\JWTException;
use ManyHong\JWTAuth\Providers\JWT\JWTInterface;
use ManyHong\JWTAuth\Exceptions\TokenBlacklistedException;

class JWTManager
{
    /**
     * @var \ManyHong\JWTAuth\Providers\JWT\JWTInterface
     */
    protected $jwt;

    /**
     * @var \ManyHong\JWTAuth\Blacklist
     */
    protected $blacklist;

    /**
     * @var \ManyHong\JWTAuth\PayloadFactory
     */
    protected $payloadFactory;

    /**
     * @var bool
     */
    protected $blacklistEnabled = true;

    /**
     * @var bool
     */
    protected $refreshFlow = false;

    /**
     *  @param \ManyHong\JWTAuth\Providers\JWT\JWTInterface  $jwt
     *  @param \ManyHong\JWTAuth\Blacklist  $blacklist
     *  @param \ManyHong\JWTAuth\PayloadFactory  $payloadFactory
     */
    public function __construct(JWTInterface $jwt, Blacklist $blacklist, PayloadFactory $payloadFactory)
    {
        $this->jwt = $jwt;
        $this->blacklist = $blacklist;
        $this->payloadFactory = $payloadFactory;
    }

    /**
     * Encode a Payload and return the Token.
     *
     * @param  \ManyHong\JWTAuth\Payload  $payload
     * @return \ManyHong\JWTAuth\Token
     */
    public function encode(Payload $payload)
    {
        $token = $this->jwt->encode($payload->get());

        return new Token($token);
    }

    /**
     * Decode a Token and return the Payload.
     *
     * @param  \ManyHong\JWTAuth\Token $token
     * @return Payload
     * @throws TokenBlacklistedException
     */
    public function decode(Token $token)
    {
        $payloadArray = $this->jwt->decode($token->get());

        $payload = $this->payloadFactory->setRefreshFlow($this->refreshFlow)->make($payloadArray);

        if ($this->blacklistEnabled && $this->blacklist->has($payload)) {
            throw new TokenBlacklistedException('The token has been blacklisted');
        }

        return $payload;
    }

    /**
     * Refresh a Token and return a new Token.
     *
     * @param  \ManyHong\JWTAuth\Token  $token
     * @return \ManyHong\JWTAuth\Token
     */
    public function refresh(Token $token)
    {
        $payload = $this->setRefreshFlow()->decode($token);

        if ($this->blacklistEnabled) {
            // invalidate old token
            $this->blacklist->add($payload);
        }

        // return the new token
        return $this->encode(
            $this->payloadFactory->make([
                'sub' => $payload['sub'],
                'iat' => $payload['iat'],
            ])
        );
    }

    /**
     * Invalidate a Token by adding it to the blacklist.
     *
     * @param  Token  $token
     * @return bool
     */
    public function invalidate(Token $token)
    {
        if (! $this->blacklistEnabled) {
            throw new JWTException('You must have the blacklist enabled to invalidate a token.');
        }

        return $this->blacklist->add($this->decode($token));
    }

    /**
     * Get the PayloadFactory instance.
     *
     * @return \ManyHong\JWTAuth\PayloadFactory
     */
    public function getPayloadFactory()
    {
        return $this->payloadFactory;
    }

    /**
     * Get the JWTProvider instance.
     *
     * @return \ManyHong\JWTAuth\Providers\JWT\JWTInterface
     */
    public function getJWTProvider()
    {
        return $this->jwt;
    }

    /**
     * Get the Blacklist instance.
     *
     * @return \ManyHong\JWTAuth\Blacklist
     */
    public function getBlacklist()
    {
        return $this->blacklist;
    }

    /**
     * Set whether the blacklist is enabled.
     *
     * @param bool  $enabled
     */
    public function setBlacklistEnabled($enabled)
    {
        $this->blacklistEnabled = $enabled;

        return $this;
    }

    /**
     * Set the refresh flow.
     *
     * @param bool $refreshFlow
     * @return $this
     */
    public function setRefreshFlow($refreshFlow = true)
    {
        $this->refreshFlow = $refreshFlow;

        return $this;
    }
}
