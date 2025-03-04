<?php
/**
 * This file is part of v1n2e7t\JWT, a simple library to handle JWT and JWS
 *
 * @license http://opensource.org/licenses/BSD-3-Clause BSD-3-Clause
 */

namespace v1n2e7t\JWT;

use DateInterval;
use DateTime;
use v1n2e7t\JWT\Claim\Basic;
use v1n2e7t\JWT\Claim\EqualsTo;
use v1n2e7t\JWT\Claim\GreaterOrEqualsTo;
use v1n2e7t\JWT\Claim\LesserOrEqualsTo;

/**
 * @author Luís Otávio Cobucci Oblonczyk <lcobucci@gmail.com>
 * @since 0.1.0
 */
class TokenTest extends \PHPUnit\Framework\TestCase
{
    /**
     * @test
     *
     * @covers v1n2e7t\JWT\Token::__construct
     */
    public function constructMustInitializeAnEmptyPlainTextTokenWhenNoArgumentsArePassed()
    {
        $token = new Token();

        $this->assertAttributeEquals(['alg' => 'none'], 'headers', $token);
        $this->assertAttributeEquals([], 'claims', $token);
        $this->assertAttributeEquals(null, 'signature', $token);
        $this->assertAttributeEquals(['', ''], 'payload', $token);
    }

    /**
     * @test
     *
     * @uses v1n2e7t\JWT\Token::__construct
     *
     * @covers v1n2e7t\JWT\Token::hasHeader
     */
    public function hasHeaderMustReturnTrueWhenItIsConfigured()
    {
        $token = new Token(['test' => 'testing']);

        $this->assertTrue($token->hasHeader('test'));
    }

    /**
     * @test
     *
     * @uses v1n2e7t\JWT\Token::__construct
     *
     * @covers v1n2e7t\JWT\Token::hasHeader
     */
    public function hasHeaderMustReturnFalseWhenItIsNotConfigured()
    {
        $token = new Token(['test' => 'testing']);

        $this->assertFalse($token->hasHeader('testing'));
    }

    /**
     * @test
     *
     * @uses v1n2e7t\JWT\Token::__construct
     * @uses v1n2e7t\JWT\Token::hasHeader
     *
     * @covers v1n2e7t\JWT\Token::getHeader
     *
     * @expectedException \OutOfBoundsException
     */
    public function getHeaderMustRaiseExceptionWhenHeaderIsNotConfigured()
    {
        $token = new Token(['test' => 'testing']);

        $token->getHeader('testing');
    }

    /**
     * @test
     *
     * @uses v1n2e7t\JWT\Token::__construct
     * @uses v1n2e7t\JWT\Token::hasHeader
     *
     * @covers v1n2e7t\JWT\Token::getHeader
     */
    public function getHeaderMustReturnTheDefaultValueWhenIsNotConfigured()
    {
        $token = new Token(['test' => 'testing']);

        $this->assertEquals('blah', $token->getHeader('testing', 'blah'));
    }

    /**
     * @test
     *
     * @uses v1n2e7t\JWT\Token::__construct
     * @uses v1n2e7t\JWT\Token::hasHeader
     *
     * @covers v1n2e7t\JWT\Token::getHeader
     * @covers v1n2e7t\JWT\Token::getHeaderValue
     */
    public function getHeaderMustReturnTheRequestedHeader()
    {
        $token = new Token(['test' => 'testing']);

        $this->assertEquals('testing', $token->getHeader('test'));
    }

    /**
     * @test
     *
     * @uses v1n2e7t\JWT\Token::__construct
     * @uses v1n2e7t\JWT\Token::hasHeader
     * @uses v1n2e7t\JWT\Claim\Basic
     *
     * @covers v1n2e7t\JWT\Token::getHeader
     * @covers v1n2e7t\JWT\Token::getHeaderValue
     */
    public function getHeaderMustReturnValueWhenItIsAReplicatedClaim()
    {
        $token = new Token(['jti' => new EqualsTo('jti', 1)]);

        $this->assertEquals(1, $token->getHeader('jti'));
    }

    /**
     * @test
     *
     * @uses v1n2e7t\JWT\Token::__construct
     *
     * @covers v1n2e7t\JWT\Token::getHeaders
     */
    public function getHeadersMustReturnTheConfiguredHeader()
    {
        $token = new Token(['test' => 'testing']);

        $this->assertEquals(['test' => 'testing'], $token->getHeaders());
    }

    /**
     * @test
     *
     * @uses v1n2e7t\JWT\Token::__construct
     *
     * @covers v1n2e7t\JWT\Token::getClaims
     */
    public function getClaimsMustReturnTheConfiguredClaims()
    {
        $token = new Token([], ['test' => 'testing']);

        $this->assertEquals(['test' => 'testing'], $token->getClaims());
    }

    /**
     * @test
     *
     * @uses v1n2e7t\JWT\Token::__construct
     * @uses v1n2e7t\JWT\Claim\Basic
     *
     * @covers v1n2e7t\JWT\Token::hasClaim
     */
    public function hasClaimMustReturnTrueWhenItIsConfigured()
    {
        $token = new Token([], ['test' => new Basic('test', 'testing')]);

        $this->assertTrue($token->hasClaim('test'));
    }

    /**
     * @test
     *
     * @uses v1n2e7t\JWT\Token::__construct
     * @uses v1n2e7t\JWT\Claim\Basic
     *
     * @covers v1n2e7t\JWT\Token::hasClaim
     */
    public function hasClaimMustReturnFalseWhenItIsNotConfigured()
    {
        $token = new Token([], ['test' => new Basic('test', 'testing')]);

        $this->assertFalse($token->hasClaim('testing'));
    }

    /**
     * @test
     *
     * @uses v1n2e7t\JWT\Token::__construct
     * @uses v1n2e7t\JWT\Token::hasClaim
     * @uses v1n2e7t\JWT\Claim\Basic
     *
     * @covers v1n2e7t\JWT\Token::getClaim
     */
    public function getClaimMustReturnTheDefaultValueWhenIsNotConfigured()
    {
        $token = new Token([], ['test' => new Basic('test', 'testing')]);

        $this->assertEquals('blah', $token->getClaim('testing', 'blah'));
    }

    /**
     * @test
     *
     * @uses v1n2e7t\JWT\Token::__construct
     * @uses v1n2e7t\JWT\Token::hasClaim
     * @uses v1n2e7t\JWT\Claim\Basic
     *
     * @covers v1n2e7t\JWT\Token::getClaim
     *
     * @expectedException \OutOfBoundsException
     */
    public function getClaimShouldRaiseExceptionWhenClaimIsNotConfigured()
    {
        $token = new Token();
        $token->getClaim('testing');
    }

    /**
     * @test
     *
     * @uses v1n2e7t\JWT\Token::__construct
     * @uses v1n2e7t\JWT\Token::hasClaim
     * @uses v1n2e7t\JWT\Claim\Basic
     *
     * @covers v1n2e7t\JWT\Token::getClaim
     */
    public function getClaimShouldReturnTheClaimValueWhenItExists()
    {
        $token = new Token([], ['testing' => new Basic('testing', 'test')]);

        $this->assertEquals('test', $token->getClaim('testing'));
    }

    /**
     * @test
     *
     * @uses v1n2e7t\JWT\Token::__construct
     *
     * @covers v1n2e7t\JWT\Token::verify
     *
     * @expectedException BadMethodCallException
     */
    public function verifyMustRaiseExceptionWhenTokenIsUnsigned()
    {
        $signer = $this->createMock(Signer::class);

        $token = new Token();
        $token->verify($signer, 'test');
    }

    /**
     * @test
     *
     * @uses v1n2e7t\JWT\Token::__construct
     *
     * @covers v1n2e7t\JWT\Token::verify
     * @covers v1n2e7t\JWT\Token::getPayload
     */
    public function verifyShouldReturnFalseWhenTokenAlgorithmIsDifferent()
    {
        $signer = $this->createMock(Signer::class);
        $signature = $this->createMock(Signature::class, [], [], '', false);

        $signer->expects($this->any())
               ->method('getAlgorithmId')
               ->willReturn('HS256');

        $signature->expects($this->never())
                  ->method('verify');

        $token = new Token(['alg' => 'RS256'], [], $signature);

        $this->assertFalse($token->verify($signer, 'test'));
    }

    /**
     * @test
     *
     * @uses v1n2e7t\JWT\Token::__construct
     *
     * @covers v1n2e7t\JWT\Token::verify
     * @covers v1n2e7t\JWT\Token::getPayload
     */
    public function verifyMustDelegateTheValidationToSignature()
    {
        $signer = $this->createMock(Signer::class);
        $signature = $this->createMock(Signature::class, [], [], '', false);

        $signer->expects($this->any())
               ->method('getAlgorithmId')
               ->willReturn('HS256');

        $signature->expects($this->once())
                  ->method('verify')
                  ->with($signer, $this->isType('string'), 'test')
                  ->willReturn(true);

        $token = new Token(['alg' => 'HS256'], [], $signature);

        $this->assertTrue($token->verify($signer, 'test'));
    }

    /**
     * @test
     *
     * @uses v1n2e7t\JWT\Token::__construct
     * @uses v1n2e7t\JWT\ValidationData::__construct
     * @uses v1n2e7t\JWT\ValidationData::setCurrentTime
     *
     * @covers v1n2e7t\JWT\Token::validate
     * @covers v1n2e7t\JWT\Token::getValidatableClaims
     */
    public function validateShouldReturnTrueWhenClaimsAreEmpty()
    {
        $token = new Token();

        $this->assertTrue($token->validate(new ValidationData()));
    }

    /**
     * @test
     *
     * @uses v1n2e7t\JWT\Token::__construct
     * @uses v1n2e7t\JWT\ValidationData::__construct
     * @uses v1n2e7t\JWT\ValidationData::setCurrentTime
     * @uses v1n2e7t\JWT\Claim\Basic::__construct
     *
     * @covers v1n2e7t\JWT\Token::validate
     * @covers v1n2e7t\JWT\Token::getValidatableClaims
     */
    public function validateShouldReturnTrueWhenThereAreNoValidatableClaims()
    {
        $token = new Token([], ['testing' => new Basic('testing', 'test')]);

        $this->assertTrue($token->validate(new ValidationData()));
    }

    /**
     * @test
     *
     * @uses v1n2e7t\JWT\Token::__construct
     * @uses v1n2e7t\JWT\ValidationData
     * @uses v1n2e7t\JWT\Claim\Basic
     * @uses v1n2e7t\JWT\Claim\EqualsTo
     *
     * @covers v1n2e7t\JWT\Token::validate
     * @covers v1n2e7t\JWT\Token::getValidatableClaims
     */
    public function validateShouldReturnFalseWhenThereIsAtLeastOneFailedValidatableClaim()
    {
        $token = new Token(
            [],
            [
                'iss' => new EqualsTo('iss', 'test'),
                'testing' => new Basic('testing', 'test')
            ]
        );

        $data = new ValidationData();
        $data->setIssuer('test1');

        $this->assertFalse($token->validate($data));
    }

    /**
     * @test
     *
     * @uses v1n2e7t\JWT\Token::__construct
     * @uses v1n2e7t\JWT\ValidationData
     * @uses v1n2e7t\JWT\Claim\Basic
     * @uses v1n2e7t\JWT\Claim\EqualsTo
     * @uses v1n2e7t\JWT\Claim\LesserOrEqualsTo
     * @uses v1n2e7t\JWT\Claim\GreaterOrEqualsTo
     *
     * @covers v1n2e7t\JWT\Token::validate
     * @covers v1n2e7t\JWT\Token::getValidatableClaims
     */
    public function validateShouldReturnFalseWhenATimeBasedClaimFails()
    {
        $now = time();

        $token = new Token(
            [],
            [
                'iss' => new EqualsTo('iss', 'test'),
                'iat' => new LesserOrEqualsTo('iat', $now),
                'nbf' => new LesserOrEqualsTo('nbf', $now + 20),
                'exp' => new GreaterOrEqualsTo('exp', $now + 500),
                'testing' => new Basic('testing', 'test')
            ]
        );

        $data = new ValidationData($now + 10);
        $data->setIssuer('test');

        $this->assertFalse($token->validate($data));
    }

    /**
     * @test
     *
     * @uses v1n2e7t\JWT\Token::__construct
     * @uses v1n2e7t\JWT\ValidationData
     * @uses v1n2e7t\JWT\Claim\Basic
     * @uses v1n2e7t\JWT\Claim\EqualsTo
     * @uses v1n2e7t\JWT\Claim\LesserOrEqualsTo
     * @uses v1n2e7t\JWT\Claim\GreaterOrEqualsTo
     *
     * @covers v1n2e7t\JWT\Token::validate
     * @covers v1n2e7t\JWT\Token::getValidatableClaims
     */
    public function validateShouldReturnTrueWhenThereAreNoFailedValidatableClaims()
    {
        $now = time();

        $token = new Token(
            [],
            [
                'iss' => new EqualsTo('iss', 'test'),
                'iat' => new LesserOrEqualsTo('iat', $now),
                'exp' => new GreaterOrEqualsTo('exp', $now + 500),
                'testing' => new Basic('testing', 'test')
            ]
        );

        $data = new ValidationData($now + 10);
        $data->setIssuer('test');

        $this->assertTrue($token->validate($data));
    }

    /**
     * @test
     *
     * @uses v1n2e7t\JWT\Token::__construct
     * @uses v1n2e7t\JWT\ValidationData
     * @uses v1n2e7t\JWT\Claim\Basic
     * @uses v1n2e7t\JWT\Claim\EqualsTo
     * @uses v1n2e7t\JWT\Claim\LesserOrEqualsTo
     * @uses v1n2e7t\JWT\Claim\GreaterOrEqualsTo
     *
     * @covers v1n2e7t\JWT\Token::validate
     * @covers v1n2e7t\JWT\Token::getValidatableClaims
     */
    public function validateShouldReturnTrueWhenLeewayMakesAllTimeBasedClaimsTrueAndOtherClaimsAreTrue()
    {
        $now = time();

        $token = new Token(
            [],
            [
                'iss' => new EqualsTo('iss', 'test'),
                'iat' => new LesserOrEqualsTo('iat', $now),
                'nbf' => new LesserOrEqualsTo('nbf', $now + 20),
                'exp' => new GreaterOrEqualsTo('exp', $now + 500),
                'testing' => new Basic('testing', 'test')
            ]
        );

        $data = new ValidationData($now + 10, 20);
        $data->setIssuer('test');

        $this->assertTrue($token->validate($data));
    }

    /**
     * @test
     *
     * @covers v1n2e7t\JWT\Token::isExpired
     *
     * @uses v1n2e7t\JWT\Token::__construct
     * @uses v1n2e7t\JWT\Token::getClaim
     * @uses v1n2e7t\JWT\Token::hasClaim
     */
    public function isExpiredShouldReturnFalseWhenTokenDoesNotExpires()
    {
        $token = new Token(['alg' => 'none']);

        $this->assertFalse($token->isExpired());
    }

    /**
     * @test
     *
     * @covers v1n2e7t\JWT\Token::isExpired
     *
     * @uses v1n2e7t\JWT\Token::__construct
     * @uses v1n2e7t\JWT\Token::getClaim
     * @uses v1n2e7t\JWT\Token::hasClaim
     * @uses v1n2e7t\JWT\Claim\Basic
     * @uses v1n2e7t\JWT\Claim\GreaterOrEqualsTo
     */
    public function isExpiredShouldReturnFalseWhenTokenIsNotExpired()
    {
        $token = new Token(
            ['alg' => 'none'],
            ['exp' => new GreaterOrEqualsTo('exp', time() + 500)]
        );

        $this->assertFalse($token->isExpired());
    }

    /**
     * @test
     *
     * @covers v1n2e7t\JWT\Token::isExpired
     *
     * @uses v1n2e7t\JWT\Token::__construct
     * @uses v1n2e7t\JWT\Token::getClaim
     * @uses v1n2e7t\JWT\Token::hasClaim
     * @uses v1n2e7t\JWT\Claim\Basic
     * @uses v1n2e7t\JWT\Claim\GreaterOrEqualsTo
     */
    public function isExpiredShouldReturnTrueAfterTokenExpires()
    {
        $token = new Token(
            ['alg' => 'none'],
            ['exp' => new GreaterOrEqualsTo('exp', time())]
        );

        $this->assertTrue($token->isExpired(new DateTime('+10 days')));
    }

    /**
     * @test
     *
     * @uses v1n2e7t\JWT\Token::__construct
     *
     * @covers v1n2e7t\JWT\Token::getPayload
     */
    public function getPayloadShouldReturnAStringWithTheTwoEncodePartsThatGeneratedTheToken()
    {
        $token = new Token(['alg' => 'none'], [], null, ['test1', 'test2', 'test3']);

        $this->assertEquals('test1.test2', $token->getPayload());
    }

    /**
     * @test
     *
     * @uses v1n2e7t\JWT\Token::__construct
     * @uses v1n2e7t\JWT\Token::getPayload
     *
     * @covers v1n2e7t\JWT\Token::__toString
     */
    public function toStringMustReturnEncodedDataWithEmptySignature()
    {
        $token = new Token(['alg' => 'none'], [], null, ['test', 'test']);

        $this->assertEquals('test.test.', (string) $token);
    }

    /**
     * @test
     *
     * @uses v1n2e7t\JWT\Token::__construct
     * @uses v1n2e7t\JWT\Token::getPayload
     *
     * @covers v1n2e7t\JWT\Token::__toString
     */
    public function toStringMustReturnEncodedData()
    {
        $signature = $this->createMock(Signature::class, [], [], '', false);

        $token = new Token(['alg' => 'none'], [], $signature, ['test', 'test', 'test']);

        $this->assertEquals('test.test.test', (string) $token);
    }
}
