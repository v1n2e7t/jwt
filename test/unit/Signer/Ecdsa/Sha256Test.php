<?php
/**
 * This file is part of v1n2e7t\JWT, a simple library to handle JWT and JWS
 *
 * @license http://opensource.org/licenses/BSD-3-Clause BSD-3-Clause
 */

namespace v1n2e7t\JWT\Signer\Ecdsa;

/**
 * @author Luís Otávio Cobucci Oblonczyk <lcobucci@gmail.com>
 * @since 2.1.0
 */
class Sha256Test extends \PHPUnit\Framework\TestCase
{
    /**
     * @test
     *
     * @uses v1n2e7t\JWT\Signer\Ecdsa
     * @uses v1n2e7t\JWT\Signer\OpenSSL
     *
     * @covers v1n2e7t\JWT\Signer\Ecdsa\Sha256::getAlgorithmId
     */
    public function getAlgorithmIdMustBeCorrect()
    {
        $signer = new Sha256();

        $this->assertEquals('ES256', $signer->getAlgorithmId());
    }

    /**
     * @test
     *
     * @uses v1n2e7t\JWT\Signer\Ecdsa
     * @uses v1n2e7t\JWT\Signer\OpenSSL
     *
     * @covers v1n2e7t\JWT\Signer\Ecdsa\Sha256::getAlgorithm
     */
    public function getAlgorithmMustBeCorrect()
    {
        $signer = new Sha256();

        $this->assertEquals('sha256', $signer->getAlgorithm());
    }

    /**
     * @test
     *
     * @uses v1n2e7t\JWT\Signer\Ecdsa
     * @uses v1n2e7t\JWT\Signer\OpenSSL
     *
     * @covers v1n2e7t\JWT\Signer\Ecdsa\Sha256::getKeyLength
     */
    public function getKeyLengthMustBeCorrect()
    {
        $signer = new Sha256();

        $this->assertEquals(64, $signer->getKeyLength());
    }
}
