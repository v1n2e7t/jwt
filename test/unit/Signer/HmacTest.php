<?php
/**
 * This file is part of v1n2e7t\JWT, a simple library to handle JWT and JWS
 *
 * @license http://opensource.org/licenses/BSD-3-Clause BSD-3-Clause
 */

namespace v1n2e7t\JWT\Signer;

/**
 * @author Luís Otávio Cobucci Oblonczyk <lcobucci@gmail.com>
 * @since 0.1.0
 */
class HmacTest extends \PHPUnit\Framework\TestCase
{
    /**
     * @var Hmac|\PHPUnit_Framework_MockObject_MockObject
     */
    protected $signer;

    /**
     * {@inheritdoc}
     */
    protected function setUp()
    {
        $this->signer = $this->getMockForAbstractClass(Hmac::class);

        $this->signer->expects($this->any())
                     ->method('getAlgorithmId')
                     ->willReturn('TEST123');

        $this->signer->expects($this->any())
                     ->method('getAlgorithm')
                     ->willReturn('sha256');
    }

    /**
     * @test
     *
     * @uses v1n2e7t\JWT\Signer\Key
     *
     * @covers v1n2e7t\JWT\Signer\Hmac::createHash
     */
    public function createHashMustReturnAHashAccordingWithTheAlgorithm()
    {
        $hash = hash_hmac('sha256', 'test', '123', true);

        $this->assertEquals($hash, $this->signer->createHash('test', new Key('123')));

        return $hash;
    }

    /**
     * @test
     *
     * @depends createHashMustReturnAHashAccordingWithTheAlgorithm
     *
     * @uses v1n2e7t\JWT\Signer\Hmac::createHash
     * @uses v1n2e7t\JWT\Signer\Key
     *
     * @covers v1n2e7t\JWT\Signer\Hmac::doVerify
     */
    public function doVerifyShouldReturnTrueWhenExpectedHashWasCreatedWithSameInformation($expected)
    {
        $this->assertTrue($this->signer->doVerify($expected, 'test', new Key('123')));
    }

    /**
     * @test
     *
     * @depends createHashMustReturnAHashAccordingWithTheAlgorithm
     *
     * @uses v1n2e7t\JWT\Signer\Hmac::createHash
     * @uses v1n2e7t\JWT\Signer\Key
     *
     * @covers v1n2e7t\JWT\Signer\Hmac::doVerify
     */
    public function doVerifyShouldReturnFalseWhenExpectedHashWasNotCreatedWithSameInformation($expected)
    {
        $this->assertFalse($this->signer->doVerify($expected, 'test', new Key('1234')));
    }

    /**
     * @test
     *
     * @uses v1n2e7t\JWT\Signer\Key
     *
     * @covers v1n2e7t\JWT\Signer\Hmac::doVerify
     */
    public function doVerifyShouldReturnFalseWhenExpectedHashIsNotString()
    {
        $this->assertFalse($this->signer->doVerify(false, 'test', new Key('1234')));
    }

    /**
     * @test
     *
     * @covers v1n2e7t\JWT\Signer\Hmac::hashEquals
     */
    public function hashEqualsShouldReturnFalseWhenExpectedHashHasDifferentLengthThanGenerated()
    {
        $this->assertFalse($this->signer->hashEquals('123', '1234'));
    }

    /**
     * @test
     *
     * @depends createHashMustReturnAHashAccordingWithTheAlgorithm
     *
     * @uses v1n2e7t\JWT\Signer\Hmac::createHash
     * @uses v1n2e7t\JWT\Signer\Key
     *
     * @covers v1n2e7t\JWT\Signer\Hmac::hashEquals
     */
    public function hashEqualsShouldReturnFalseWhenExpectedHashIsDifferentThanGenerated($expected)
    {
        $this->assertFalse($this->signer->hashEquals($expected, $this->signer->createHash('test', new Key('1234'))));
    }

    /**
     * @test
     *
     * @depends createHashMustReturnAHashAccordingWithTheAlgorithm
     *
     * @uses v1n2e7t\JWT\Signer\Hmac::createHash
     * @uses v1n2e7t\JWT\Signer\Key
     *
     * @covers v1n2e7t\JWT\Signer\Hmac::hashEquals
     */
    public function hashEqualsShouldReturnTrueWhenExpectedHashIsEqualsThanGenerated($expected)
    {
        $this->assertTrue($this->signer->hashEquals($expected, $this->signer->createHash('test', new Key('123'))));
    }
}
