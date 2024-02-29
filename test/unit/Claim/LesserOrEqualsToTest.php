<?php
/**
 * This file is part of v1n2e7t\JWT, a simple library to handle JWT and JWS
 *
 * @license http://opensource.org/licenses/BSD-3-Clause BSD-3-Clause
 */

namespace v1n2e7t\JWT\Claim;

use v1n2e7t\JWT\ValidationData;

/**
 * @author Luís Otávio Cobucci Oblonczyk <lcobucci@gmail.com>
 * @since 2.0.0
 */
class LesserOrEqualsToTest extends \PHPUnit\Framework\TestCase
{
    /**
     * @test
     *
     * @uses v1n2e7t\JWT\Claim\Basic::__construct
     * @uses v1n2e7t\JWT\Claim\Basic::getName
     * @uses v1n2e7t\JWT\ValidationData::__construct
     * @uses v1n2e7t\JWT\ValidationData::has
     * @uses v1n2e7t\JWT\ValidationData::setCurrentTime
     *
     * @covers v1n2e7t\JWT\Claim\LesserOrEqualsTo::validate
     */
    public function validateShouldReturnTrueWhenValidationDontHaveTheClaim()
    {
        $claim = new LesserOrEqualsTo('iss', 10);

        $this->assertTrue($claim->validate(new ValidationData()));
    }

    /**
     * @test
     *
     * @uses v1n2e7t\JWT\Claim\Basic::__construct
     * @uses v1n2e7t\JWT\Claim\Basic::getName
     * @uses v1n2e7t\JWT\Claim\Basic::getValue
     * @uses v1n2e7t\JWT\ValidationData::__construct
     * @uses v1n2e7t\JWT\ValidationData::setIssuer
     * @uses v1n2e7t\JWT\ValidationData::has
     * @uses v1n2e7t\JWT\ValidationData::get
     * @uses v1n2e7t\JWT\ValidationData::setCurrentTime
     *
     * @covers v1n2e7t\JWT\Claim\LesserOrEqualsTo::validate
     */
    public function validateShouldReturnTrueWhenValueIsLesserThanValidationData()
    {
        $claim = new LesserOrEqualsTo('iss', 10);

        $data = new ValidationData();
        $data->setIssuer(11);

        $this->assertTrue($claim->validate($data));
    }

    /**
     * @test
     *
     * @uses v1n2e7t\JWT\Claim\Basic::__construct
     * @uses v1n2e7t\JWT\Claim\Basic::getName
     * @uses v1n2e7t\JWT\Claim\Basic::getValue
     * @uses v1n2e7t\JWT\ValidationData::__construct
     * @uses v1n2e7t\JWT\ValidationData::setIssuer
     * @uses v1n2e7t\JWT\ValidationData::has
     * @uses v1n2e7t\JWT\ValidationData::get
     * @uses v1n2e7t\JWT\ValidationData::setCurrentTime
     *
     * @covers v1n2e7t\JWT\Claim\LesserOrEqualsTo::validate
     */
    public function validateShouldReturnTrueWhenValueIsEqualsToValidationData()
    {
        $claim = new LesserOrEqualsTo('iss', 10);

        $data = new ValidationData();
        $data->setIssuer(10);

        $this->assertTrue($claim->validate($data));
    }

    /**
     * @test
     *
     * @uses v1n2e7t\JWT\Claim\Basic::__construct
     * @uses v1n2e7t\JWT\Claim\Basic::getName
     * @uses v1n2e7t\JWT\Claim\Basic::getValue
     * @uses v1n2e7t\JWT\ValidationData::__construct
     * @uses v1n2e7t\JWT\ValidationData::setIssuer
     * @uses v1n2e7t\JWT\ValidationData::has
     * @uses v1n2e7t\JWT\ValidationData::get
     * @uses v1n2e7t\JWT\ValidationData::setCurrentTime
     *
     * @covers v1n2e7t\JWT\Claim\LesserOrEqualsTo::validate
     */
    public function validateShouldReturnFalseWhenValueIsGreaterThanValidationData()
    {
        $claim = new LesserOrEqualsTo('iss', 11);

        $data = new ValidationData();
        $data->setIssuer(10);

        $this->assertFalse($claim->validate($data));
    }
}
