<?php

/*
 * This file is part of jwt-auth.
 *
 * (c) Sean Tymon <tymon148@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace ManyHong\JWTAuth\Claims;

class Factory
{
    /**
     * @var array
     */
    private static $classMap = [
        'aud' => 'ManyHong\JWTAuth\Claims\Audience',
        'exp' => 'ManyHong\JWTAuth\Claims\Expiration',
        'iat' => 'ManyHong\JWTAuth\Claims\IssuedAt',
        'iss' => 'ManyHong\JWTAuth\Claims\Issuer',
        'jti' => 'ManyHong\JWTAuth\Claims\JwtId',
        'nbf' => 'ManyHong\JWTAuth\Claims\NotBefore',
        'sub' => 'ManyHong\JWTAuth\Claims\Subject',
    ];

    /**
     * Get the instance of the claim when passing the name and value.
     *
     * @param  string  $name
     * @param  mixed   $value
     * @return \ManyHong\JWTAuth\Claims\Claim
     */
    public function get($name, $value)
    {
        if ($this->has($name)) {
            return new self::$classMap[$name]($value);
        }

        return new Custom($name, $value);
    }

    /**
     * Check whether the claim exists.
     *
     * @param  string  $name
     * @return bool
     */
    public function has($name)
    {
        return array_key_exists($name, self::$classMap);
    }
}
