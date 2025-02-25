<?php
/**
 * This file is part of v1n2e7t\JWT, a simple library to handle JWT and JWS
 *
 * @license http://opensource.org/licenses/BSD-3-Clause BSD-3-Clause
 */

namespace v1n2e7t\JWT;

use v1n2e7t\JWT\Claim\Factory as ClaimFactory;
use v1n2e7t\JWT\Parsing\Decoder;
use RuntimeException;

/**
 * @author Luís Otávio Cobucci Oblonczyk <lcobucci@gmail.com>
 * @since 0.1.0
 */
class ParserTest extends \PHPUnit\Framework\TestCase
{
    /**
     * @var Decoder|\PHPUnit_Framework_MockObject_MockObject
     */
    protected $decoder;

    /**
     * @var ClaimFactory|\PHPUnit_Framework_MockObject_MockObject
     */
    protected $claimFactory;

    /**
     * @var Claim|\PHPUnit_Framework_MockObject_MockObject
     */
    protected $defaultClaim;

    /**
     * {@inheritdoc}
     */
    protected function setUp()
    {
        $this->decoder = $this->createMock(Decoder::class);
        $this->claimFactory = $this->createMock(ClaimFactory::class, [], [], '', false);
        $this->defaultClaim = $this->createMock(Claim::class);

        $this->claimFactory->expects($this->any())
                           ->method('create')
                           ->willReturn($this->defaultClaim);
    }

    /**
     * @return Parser
     */
    private function createParser()
    {
        return new Parser($this->decoder, $this->claimFactory);
    }

    /**
     * @test
     *
     * @covers v1n2e7t\JWT\Parser::__construct
     */
    public function constructMustConfigureTheAttributes()
    {
        $parser = $this->createParser();

        $this->assertAttributeSame($this->decoder, 'decoder', $parser);
        $this->assertAttributeSame($this->claimFactory, 'claimFactory', $parser);
    }

    /**
     * @test
     *
     * @uses v1n2e7t\JWT\Parser::__construct
     *
     * @covers v1n2e7t\JWT\Parser::parse
     * @covers v1n2e7t\JWT\Parser::splitJwt
     *
     * @expectedException InvalidArgumentException
     */
    public function parseMustRaiseExceptionWhenJWSIsNotAString()
    {
        $parser = $this->createParser();
        $parser->parse(['asdasd']);
    }

    /**
     * @test
     *
     * @uses v1n2e7t\JWT\Parser::__construct
     *
     * @covers v1n2e7t\JWT\Parser::parse
     * @covers v1n2e7t\JWT\Parser::splitJwt
     *
     * @expectedException InvalidArgumentException
     */
    public function parseMustRaiseExceptionWhenJWSDontHaveThreeParts()
    {
        $parser = $this->createParser();
        $parser->parse('');
    }

    /**
     * @test
     *
     * @uses v1n2e7t\JWT\Parser::__construct
     *
     * @covers v1n2e7t\JWT\Parser::parse
     * @covers v1n2e7t\JWT\Parser::splitJwt
     * @covers v1n2e7t\JWT\Parser::parseHeader
     *
     * @expectedException RuntimeException
     */
    public function parseMustRaiseExceptionWhenHeaderCannotBeDecoded()
    {
        $this->decoder->expects($this->any())
                      ->method('jsonDecode')
                      ->willThrowException(new RuntimeException());

        $parser = $this->createParser();
        $parser->parse('asdfad.asdfasdf.');
    }

    /**
     * @test
     *
     * @uses v1n2e7t\JWT\Parser::__construct
     *
     * @covers v1n2e7t\JWT\Parser::parse
     * @covers v1n2e7t\JWT\Parser::splitJwt
     * @covers v1n2e7t\JWT\Parser::parseHeader
     *
     * @expectedException InvalidArgumentException
     */
    public function parseMustRaiseExceptionWhenHeaderIsFromAnEncryptedToken()
    {
        $this->decoder->expects($this->any())
                      ->method('jsonDecode')
                      ->willReturn(['enc' => 'AAA']);

        $parser = $this->createParser();
        $parser->parse('a.a.');
    }

    /**
     * @test
     *
     * @uses v1n2e7t\JWT\Parser::__construct
     * @uses v1n2e7t\JWT\Token::__construct
     *
     * @covers v1n2e7t\JWT\Parser::parse
     * @covers v1n2e7t\JWT\Parser::splitJwt
     * @covers v1n2e7t\JWT\Parser::parseHeader
     * @covers v1n2e7t\JWT\Parser::parseClaims
     * @covers v1n2e7t\JWT\Parser::parseSignature
     *
     */
    public function parseMustReturnANonSignedTokenWhenSignatureIsNotInformed()
    {
        $this->decoder->expects($this->at(1))
                      ->method('jsonDecode')
                      ->willReturn(['typ' => 'JWT', 'alg' => 'none']);

        $this->decoder->expects($this->at(3))
                      ->method('jsonDecode')
                      ->willReturn(['aud' => 'test']);

        $parser = $this->createParser();
        $token = $parser->parse('a.a.');

        $this->assertAttributeEquals(['typ' => 'JWT', 'alg' => 'none'], 'headers', $token);
        $this->assertAttributeEquals(['aud' => $this->defaultClaim], 'claims', $token);
        $this->assertAttributeEquals(null, 'signature', $token);
    }

    /**
     * @test
     *
     * @uses v1n2e7t\JWT\Parser::__construct
     * @uses v1n2e7t\JWT\Token::__construct
     *
     * @covers v1n2e7t\JWT\Parser::parse
     * @covers v1n2e7t\JWT\Parser::splitJwt
     * @covers v1n2e7t\JWT\Parser::parseHeader
     * @covers v1n2e7t\JWT\Parser::parseClaims
     * @covers v1n2e7t\JWT\Parser::parseSignature
     */
    public function parseShouldReplicateClaimValueOnHeaderWhenNeeded()
    {
        $this->decoder->expects($this->at(1))
                      ->method('jsonDecode')
                      ->willReturn(['typ' => 'JWT', 'alg' => 'none', 'aud' => 'test']);

        $this->decoder->expects($this->at(3))
                      ->method('jsonDecode')
                      ->willReturn(['aud' => 'test']);

        $parser = $this->createParser();
        $token = $parser->parse('a.a.');

        $this->assertAttributeEquals(
            ['typ' => 'JWT', 'alg' => 'none', 'aud' => $this->defaultClaim],
            'headers',
            $token
        );

        $this->assertAttributeEquals(['aud' => $this->defaultClaim], 'claims', $token);
        $this->assertAttributeEquals(null, 'signature', $token);
    }

    /**
     * @test
     *
     * @uses v1n2e7t\JWT\Parser::__construct
     * @uses v1n2e7t\JWT\Token::__construct
     * @uses v1n2e7t\JWT\Signature::__construct
     *
     * @covers v1n2e7t\JWT\Parser::parse
     * @covers v1n2e7t\JWT\Parser::splitJwt
     * @covers v1n2e7t\JWT\Parser::parseHeader
     * @covers v1n2e7t\JWT\Parser::parseClaims
     * @covers v1n2e7t\JWT\Parser::parseSignature
     */
    public function parseMustReturnASignedTokenWhenSignatureIsInformed()
    {
        $this->decoder->expects($this->at(1))
                      ->method('jsonDecode')
                      ->willReturn(['typ' => 'JWT', 'alg' => 'HS256']);

        $this->decoder->expects($this->at(3))
                      ->method('jsonDecode')
                      ->willReturn(['aud' => 'test']);

        $this->decoder->expects($this->at(4))
                      ->method('base64UrlDecode')
                      ->willReturn('aaa');

        $parser = $this->createParser();
        $token = $parser->parse('a.a.a');

        $this->assertAttributeEquals(['typ' => 'JWT', 'alg' => 'HS256'], 'headers', $token);
        $this->assertAttributeEquals(['aud' => $this->defaultClaim], 'claims', $token);
        $this->assertAttributeEquals(new Signature('aaa'), 'signature', $token);
    }
}
