<?php
/**
 * This file is part of v1n2e7t\JWT, a simple library to handle JWT and JWS
 *
 * @license http://opensource.org/licenses/BSD-3-Clause BSD-3-Clause
 */

namespace v1n2e7t\JWT\Signer\Rsa;

/**
 * @author Luís Otávio Cobucci Oblonczyk <lcobucci@gmail.com>
 * @since 2.1.0
 */
class Sha384Test extends \PHPUnit\Framework\TestCase
{
    /**
     * @test
     *
     * @covers v1n2e7t\JWT\Signer\Rsa\Sha384::getAlgorithmId
     */
    public function getAlgorithmIdMustBeCorrect()
    {
        $signer = new Sha384();

        $this->assertEquals('RS384', $signer->getAlgorithmId());
    }

    /**
     * @test
     *
     * @covers v1n2e7t\JWT\Signer\Rsa\Sha384::getAlgorithm
     */
    public function getAlgorithmMustBeCorrect()
    {
        $signer = new Sha384();

        $this->assertEquals(OPENSSL_ALGO_SHA384, $signer->getAlgorithm());
    }
}
