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
use v1n2e7t\JWT\Signature;
use v1n2e7t\JWT\Signer\Hmac\Sha256;
use v1n2e7t\JWT\Signer\Hmac\Sha512;

/**
 * @author Luís Otávio Cobucci Oblonczyk <lcobucci@gmail.com>
 * @since 2.1.0
 */
class HmacTokenTest extends \PHPUnit\Framework\TestCase
{
    /**
     * @var Sha256
     */
    private $signer;

    /**
     * @before
     */
    public function createSigner()
    {
        $this->signer = new Sha256();
    }

    /**
     * @test
     *
     * @covers v1n2e7t\JWT\Builder
     * @covers v1n2e7t\JWT\Token
     * @covers v1n2e7t\JWT\Signature
     * @covers v1n2e7t\JWT\Claim\Factory
     * @covers v1n2e7t\JWT\Claim\Basic
     * @covers v1n2e7t\JWT\Parsing\Encoder
     * @covers v1n2e7t\JWT\Signer\Key
     * @covers v1n2e7t\JWT\Signer\BaseSigner
     * @covers v1n2e7t\JWT\Signer\Hmac
     * @covers v1n2e7t\JWT\Signer\Hmac\Sha256
     */
    public function builderCanGenerateAToken()
    {
        $user = (object) ['name' => 'testing', 'email' => 'testing@abc.com'];

        $token = (new Builder())->setId(1)
                              ->setAudience('http://client.abc.com')
                              ->setIssuer('http://api.abc.com')
                              ->set('user', $user)
                              ->setHeader('jki', '1234')
                              ->sign($this->signer, 'testing')
                              ->getToken();

        $this->assertAttributeInstanceOf(Signature::class, 'signature', $token);
        $this->assertEquals('1234', $token->getHeader('jki'));
        $this->assertEquals('http://client.abc.com', $token->getClaim('aud'));
        $this->assertEquals('http://api.abc.com', $token->getClaim('iss'));
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
     * @covers v1n2e7t\JWT\Signature
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
     * @covers v1n2e7t\JWT\Signature
     * @covers v1n2e7t\JWT\Parsing\Encoder
     * @covers v1n2e7t\JWT\Claim\Factory
     * @covers v1n2e7t\JWT\Claim\Basic
     * @covers v1n2e7t\JWT\Signer\Key
     * @covers v1n2e7t\JWT\Signer\BaseSigner
     * @covers v1n2e7t\JWT\Signer\Hmac
     * @covers v1n2e7t\JWT\Signer\Hmac\Sha256
     */
    public function verifyShouldReturnFalseWhenKeyIsNotRight(Token $token)
    {
        $this->assertFalse($token->verify($this->signer, 'testing1'));
    }

    /**
     * @test
     *
     * @depends builderCanGenerateAToken
     *
     * @covers v1n2e7t\JWT\Builder
     * @covers v1n2e7t\JWT\Parser
     * @covers v1n2e7t\JWT\Token
     * @covers v1n2e7t\JWT\Signature
     * @covers v1n2e7t\JWT\Parsing\Encoder
     * @covers v1n2e7t\JWT\Claim\Factory
     * @covers v1n2e7t\JWT\Claim\Basic
     * @covers v1n2e7t\JWT\Signer\Key
     * @covers v1n2e7t\JWT\Signer\BaseSigner
     * @covers v1n2e7t\JWT\Signer\Hmac
     * @covers v1n2e7t\JWT\Signer\Hmac\Sha256
     * @covers v1n2e7t\JWT\Signer\Hmac\Sha512
     */
    public function verifyShouldReturnFalseWhenAlgorithmIsDifferent(Token $token)
    {
        $this->assertFalse($token->verify(new Sha512(), 'testing'));
    }

    /**
     * @test
     *
     * @depends builderCanGenerateAToken
     *
     * @covers v1n2e7t\JWT\Builder
     * @covers v1n2e7t\JWT\Parser
     * @covers v1n2e7t\JWT\Token
     * @covers v1n2e7t\JWT\Signature
     * @covers v1n2e7t\JWT\Parsing\Encoder
     * @covers v1n2e7t\JWT\Claim\Factory
     * @covers v1n2e7t\JWT\Claim\Basic
     * @covers v1n2e7t\JWT\Signer\Key
     * @covers v1n2e7t\JWT\Signer\BaseSigner
     * @covers v1n2e7t\JWT\Signer\Hmac
     * @covers v1n2e7t\JWT\Signer\Hmac\Sha256
     */
    public function verifyShouldReturnTrueWhenKeyIsRight(Token $token)
    {
        $this->assertTrue($token->verify($this->signer, 'testing'));
    }

    /**
     * @test
     *
     * @covers v1n2e7t\JWT\Builder
     * @covers v1n2e7t\JWT\Parser
     * @covers v1n2e7t\JWT\Token
     * @covers v1n2e7t\JWT\Signature
     * @covers v1n2e7t\JWT\Signer\Key
     * @covers v1n2e7t\JWT\Signer\BaseSigner
     * @covers v1n2e7t\JWT\Signer\Hmac
     * @covers v1n2e7t\JWT\Signer\Hmac\Sha256
     * @covers v1n2e7t\JWT\Claim\Factory
     * @covers v1n2e7t\JWT\Claim\Basic
     * @covers v1n2e7t\JWT\Parsing\Encoder
     * @covers v1n2e7t\JWT\Parsing\Decoder
     */
    public function everythingShouldWorkWhenUsingATokenGeneratedByOtherLibs()
    {
        $data = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXUyJ9.eyJoZWxsbyI6IndvcmxkIn0.Rh'
                . '7AEgqCB7zae1PkgIlvOpeyw9Ab8NGTbeOH7heHO0o';

        $token = (new Parser())->parse((string) $data);

        $this->assertEquals('world', $token->getClaim('hello'));
        $this->assertTrue($token->verify($this->signer, 'testing'));
    }
}
