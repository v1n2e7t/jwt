<?php
/**
 * This file is part of v1n2e7t\JWT, a simple library to handle JWT and JWS
 *
 * @license http://opensource.org/licenses/BSD-3-Clause BSD-3-Clause
 */

namespace v1n2e7t\JWT\FunctionalTests;

use v1n2e7t\JWT\Builder;
use v1n2e7t\JWT\Parser;
use v1n2e7t\JWT\Token;
use v1n2e7t\JWT\ValidationData;

/**
 * @author Luís Otávio Cobucci Oblonczyk <lcobucci@gmail.com>
 * @since 2.1.0
 */
class UnsignedTokenTest extends \PHPUnit\Framework\TestCase
{
    const CURRENT_TIME = 100000;

    /**
     * @test
     *
     * @covers v1n2e7t\JWT\Builder
     * @covers v1n2e7t\JWT\Token
     * @covers v1n2e7t\JWT\Claim\Factory
     * @covers v1n2e7t\JWT\Claim\Basic
     * @covers v1n2e7t\JWT\Parsing\Encoder
     */
    public function builderCanGenerateAToken()
    {
        $user = (object) ['name' => 'testing', 'email' => 'testing@abc.com'];

        $token = (new Builder())->setId(1)
                              ->setAudience('http://client.abc.com')
                              ->setIssuer('http://api.abc.com')
                              ->setExpiration(self::CURRENT_TIME + 3000)
                              ->set('user', $user)
                              ->getToken();

        $this->assertAttributeEquals(null, 'signature', $token);
        $this->assertEquals('http://client.abc.com', $token->getClaim('aud'));
        $this->assertEquals('http://api.abc.com', $token->getClaim('iss'));
        $this->assertEquals(self::CURRENT_TIME + 3000, $token->getClaim('exp'));
        $this->assertEquals($user, $token->getClaim('user'));

        return $token;
    }

    /**
     * @test
     *
     * @depends builderCanGenerateAToken
     *
     * @covers v1n2e7t\JWT\Builder
     * @covers v1n2e7t\JWT\Parser
     * @covers v1n2e7t\JWT\Token
     * @covers v1n2e7t\JWT\Claim\Factory
     * @covers v1n2e7t\JWT\Claim\Basic
     * @covers v1n2e7t\JWT\Parsing\Encoder
     * @covers v1n2e7t\JWT\Parsing\Decoder
     */
    public function parserCanReadAToken(Token $generated)
    {
        $read = (new Parser())->parse((string) $generated);

        $this->assertEquals($generated, $read);
        $this->assertEquals('testing', $read->getClaim('user')->name);
    }

    /**
     * @test
     *
     * @depends builderCanGenerateAToken
     *
     * @covers v1n2e7t\JWT\Builder
     * @covers v1n2e7t\JWT\Parser
     * @covers v1n2e7t\JWT\Token
     * @covers v1n2e7t\JWT\ValidationData
     * @covers v1n2e7t\JWT\Claim\Factory
     * @covers v1n2e7t\JWT\Claim\Basic
     * @covers v1n2e7t\JWT\Claim\EqualsTo
     * @covers v1n2e7t\JWT\Claim\GreaterOrEqualsTo
     * @covers v1n2e7t\JWT\Parsing\Encoder
     * @covers v1n2e7t\JWT\Parsing\Decoder
     */
    public function tokenValidationShouldReturnWhenEverythingIsFine(Token $generated)
    {
        $data = new ValidationData(self::CURRENT_TIME - 10);
        $data->setAudience('http://client.abc.com');
        $data->setIssuer('http://api.abc.com');

        $this->assertTrue($generated->validate($data));
    }

    /**
     * @test
     *
     * @dataProvider invalidValidationData
     *
     * @depends builderCanGenerateAToken
     *
     * @covers v1n2e7t\JWT\Builder
     * @covers v1n2e7t\JWT\Parser
     * @covers v1n2e7t\JWT\Token
     * @covers v1n2e7t\JWT\ValidationData
     * @covers v1n2e7t\JWT\Claim\Factory
     * @covers v1n2e7t\JWT\Claim\Basic
     * @covers v1n2e7t\JWT\Claim\EqualsTo
     * @covers v1n2e7t\JWT\Claim\GreaterOrEqualsTo
     * @covers v1n2e7t\JWT\Parsing\Encoder
     * @covers v1n2e7t\JWT\Parsing\Decoder
     */
    public function tokenValidationShouldReturnFalseWhenExpectedDataDontMatch(ValidationData $data, Token $generated)
    {
        $this->assertFalse($generated->validate($data));
    }

    /**
     * @test
     *
     * @depends builderCanGenerateAToken
     *
     * @covers v1n2e7t\JWT\Builder
     * @covers v1n2e7t\JWT\Parser
     * @covers v1n2e7t\JWT\Token
     * @covers v1n2e7t\JWT\ValidationData
     * @covers v1n2e7t\JWT\Claim\Factory
     * @covers v1n2e7t\JWT\Claim\Basic
     * @covers v1n2e7t\JWT\Claim\EqualsTo
     * @covers v1n2e7t\JWT\Claim\GreaterOrEqualsTo
     * @covers v1n2e7t\JWT\Parsing\Encoder
     * @covers v1n2e7t\JWT\Parsing\Decoder
     */
    public function tokenValidationShouldReturnTrueWhenExpectedDataMatchBecauseOfLeeway(Token $generated)
    {
        $notExpiredDueToLeeway = new ValidationData(self::CURRENT_TIME + 3020, 50);
        $notExpiredDueToLeeway->setAudience('http://client.abc.com');
        $notExpiredDueToLeeway->setIssuer('http://api.abc.com');
        $this->assertTrue($generated->validate($notExpiredDueToLeeway));
    }

    public function invalidValidationData()
    {
        $expired = new ValidationData(self::CURRENT_TIME + 3020);
        $expired->setAudience('http://client.abc.com');
        $expired->setIssuer('http://api.abc.com');

        $invalidAudience = new ValidationData(self::CURRENT_TIME - 10);
        $invalidAudience->setAudience('http://cclient.abc.com');
        $invalidAudience->setIssuer('http://api.abc.com');

        $invalidIssuer = new ValidationData(self::CURRENT_TIME - 10);
        $invalidIssuer->setAudience('http://client.abc.com');
        $invalidIssuer->setIssuer('http://aapi.abc.com');

        return [[$expired], [$invalidAudience], [$invalidIssuer]];
    }
}
