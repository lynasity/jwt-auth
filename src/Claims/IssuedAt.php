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

class IssuedAt extends Claim
{
    /**
     * The claim name.
     *
     * @var string
     */
    protected $name = 'iat';

    /**
     * Validate the issued at claim.
     *
     * @param  mixed  $value
     * @return bool
     */
    protected function validate($value)
    {
        return is_numeric($value);
    }
}
