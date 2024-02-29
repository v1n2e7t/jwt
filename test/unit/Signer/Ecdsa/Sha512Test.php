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
class Sha512Test extends \PHPUnit\Framework\TestCase
{
    /**
     * @test
     *
     * @uses v1n2e7t\JWT\Signer\Ecdsa
     * @uses v1n2e7t\JWT\Signer\OpenSSL
     *
     * @covers v1n2e7t\JWT\Signer\Ecdsa\Sha512::getAlgorithmId
     */
    public function getAlgorithmIdMustBeCorrect()
    {
        $signer = new Sha512();

        $this->assertEquals('ES512', $signer->getAlgorithmId());
    }

    /**
     * @test
     *
     * @uses v1n2e7t\JWT\Signer\Ecdsa
     * @uses v1n2e7t\JWT\Signer\OpenSSL
     *
     * @covers v1n2e7t\JWT\Signer\Ecdsa\Sha512::getAlgorithm
     */
    public function getAlgorithmMustBeCorrect()
    {
        $signer = new Sha512();

        $this->assertEquals('sha512', $signer->getAlgorithm());
    }

    /**
     * @test
     *
     * @uses v1n2e7t\JWT\Signer\Ecdsa
     * @uses v1n2e7t\JWT\Signer\OpenSSL
     *
     * @covers v1n2e7t\JWT\Signer\Ecdsa\Sha512::getKeyLength
     */
    public function getKeyLengthMustBeCorrect()
    {
        $signer = new Sha512();

        $this->assertEquals(132, $signer->getKeyLength());
    }
}
