<?php
/**
 * This file is part of v1n2e7t\JWT, a simple library to handle JWT and JWS
 *
 * @license http://opensource.org/licenses/BSD-3-Clause BSD-3-Clause
 */

namespace v1n2e7t\JWT;

/**
 * @author Luís Otávio Cobucci Oblonczyk <lcobucci@gmail.com>
 * @since 2.0.0
 */
class ValidationDataTest extends \PHPUnit\Framework\TestCase
{
    /**
     * @test
     *
     * @covers v1n2e7t\JWT\ValidationData::__construct
     * @covers v1n2e7t\JWT\ValidationData::setCurrentTime
     */
    public function constructorShouldConfigureTheItems()
    {
        $expected = $this->createExpectedData();
        $data = new ValidationData(1);

        $this->assertAttributeSame($expected, 'items', $data);
    }

    /**
     * @test
     *
     * @covers v1n2e7t\JWT\ValidationData::__construct
     * @covers v1n2e7t\JWT\ValidationData::setCurrentTime
     */
    public function constructorWithLeewayShouldConfigureTheItems()
    {
        $expected = $this->createExpectedData(null, null, null, null, 111, 111, 89);
        $data = new ValidationData(100, 11);

        $this->assertAttributeSame($expected, 'items', $data);
    }

    /**
     * @test
     *
     * @dataProvider claimValues
     *
     * @uses v1n2e7t\JWT\ValidationData::__construct
     * @uses v1n2e7t\JWT\ValidationData::setCurrentTime
     *
     * @covers v1n2e7t\JWT\ValidationData::setId
     */
    public function setIdShouldChangeTheId($id)
    {
        $expected = $this->createExpectedData($id);
        $data = new ValidationData(1);
        $data->setId($id);

        $this->assertAttributeSame($expected, 'items', $data);
    }

    /**
     * @test
     *
     * @dataProvider claimValues
     *
     * @uses v1n2e7t\JWT\ValidationData::__construct
     * @uses v1n2e7t\JWT\ValidationData::setCurrentTime
     *
     * @covers v1n2e7t\JWT\ValidationData::setIssuer
     */
    public function setIssuerShouldChangeTheIssuer($iss)
    {
        $expected = $this->createExpectedData(null, null, $iss);
        $data = new ValidationData(1);
        $data->setIssuer($iss);

        $this->assertAttributeSame($expected, 'items', $data);
    }

    /**
     * @test
     *
     * @dataProvider claimValues
     *
     * @uses v1n2e7t\JWT\ValidationData::__construct
     * @uses v1n2e7t\JWT\ValidationData::setCurrentTime
     *
     * @covers v1n2e7t\JWT\ValidationData::setAudience
     */
    public function setAudienceShouldChangeTheAudience($aud)
    {
        $expected = $this->createExpectedData(null, null, null, $aud);
        $data = new ValidationData(1);
        $data->setAudience($aud);

        $this->assertAttributeSame($expected, 'items', $data);
    }

    /**
     * @test
     *
     * @dataProvider claimValues
     *
     * @uses v1n2e7t\JWT\ValidationData::__construct
     * @uses v1n2e7t\JWT\ValidationData::setCurrentTime
     *
     * @covers v1n2e7t\JWT\ValidationData::setSubject
     */
    public function setSubjectShouldChangeTheSubject($sub)
    {
        $expected = $this->createExpectedData(null, $sub);
        $data = new ValidationData(1);
        $data->setSubject($sub);

        $this->assertAttributeSame($expected, 'items', $data);
    }

    /**
     * @test
     *
     * @uses v1n2e7t\JWT\ValidationData::__construct
     * @uses v1n2e7t\JWT\ValidationData::setCurrentTime
     *
     * @covers v1n2e7t\JWT\ValidationData::setCurrentTime
     */
    public function setCurrentTimeShouldChangeTheTimeBasedValues()
    {
        $expected = $this->createExpectedData(null, null, null, null, 2);
        $data = new ValidationData(1);
        $data->setCurrentTime(2);

        $this->assertAttributeSame($expected, 'items', $data);
    }

    /**
     * @test
     *
     * @uses   v1n2e7t\JWT\ValidationData::__construct
     * @uses v1n2e7t\JWT\ValidationData::setCurrentTime
     *
     * @covers v1n2e7t\JWT\ValidationData::setCurrentTime
     */
    public function setCurrentTimeShouldChangeTheTimeBasedValuesUsingLeeway()
    {
        $expected = $this->createExpectedData(null, null, null, null, 30, 30, 10);
        $data = new ValidationData(15, 10);
        $data->setCurrentTime(20);

        $this->assertAttributeSame($expected, 'items', $data);
    }

    /**
     * @test
     *
     * @uses v1n2e7t\JWT\ValidationData::__construct
     * @uses v1n2e7t\JWT\ValidationData::setCurrentTime
     *
     * @covers v1n2e7t\JWT\ValidationData::has
     */
    public function hasShouldReturnTrueWhenItemIsNotEmpty()
    {
        $data = new ValidationData(1);

        $this->assertTrue($data->has('iat'));
    }

    /**
     * @test
     *
     * @uses v1n2e7t\JWT\ValidationData::__construct
     * @uses v1n2e7t\JWT\ValidationData::setCurrentTime
     *
     * @covers v1n2e7t\JWT\ValidationData::has
     */
    public function hasShouldReturnFalseWhenItemIsEmpty()
    {
        $data = new ValidationData(1);

        $this->assertFalse($data->has('jti'));
    }

    /**
     * @test
     *
     * @uses v1n2e7t\JWT\ValidationData::__construct
     * @uses v1n2e7t\JWT\ValidationData::setCurrentTime
     *
     * @covers v1n2e7t\JWT\ValidationData::has
     */
    public function hasShouldReturnFalseWhenItemIsNotDefined()
    {
        $data = new ValidationData(1);

        $this->assertFalse($data->has('test'));
    }

    /**
     * @test
     *
     * @uses v1n2e7t\JWT\ValidationData::__construct
     * @uses v1n2e7t\JWT\ValidationData::setCurrentTime
     *
     * @covers v1n2e7t\JWT\ValidationData::get
     */
    public function getShouldReturnTheItemValue()
    {
        $data = new ValidationData(1);

        $this->assertEquals(1, $data->get('iat'));
    }

    /**
     * @test
     *
     * @uses v1n2e7t\JWT\ValidationData::__construct
     * @uses v1n2e7t\JWT\ValidationData::setCurrentTime
     *
     * @covers v1n2e7t\JWT\ValidationData::get
     */
    public function getShouldReturnNullWhenItemIsNotDefined()
    {
        $data = new ValidationData(1);

        $this->assertNull($data->get('test'));
    }

    /**
     * @return array
     */
    public function claimValues()
    {
        return [
            [1],
            ['test']
        ];
    }

    /**
     * @param string|null $id
     * @param string|null $sub
     * @param string|null $iss
     * @param string|null $aud
     * @param int $iat
     * @param int|null $nbf
     * @param int|null $exp
     *
     * @return array
     */
    private function createExpectedData(
        $id = null,
        $sub = null,
        $iss = null,
        $aud = null,
        $iat = 1,
        $nbf = null,
        $exp = null
    ) {
        return [
            'jti' => $id !== null ? (string) $id : null,
            'iss' => $iss !== null ? (string) $iss : null,
            'aud' => $aud !== null ? (string) $aud : null,
            'sub' => $sub !== null ? (string) $sub : null,
            'iat' => $iat,
            'nbf' => $nbf !== null ? $nbf: $iat,
            'exp' => $exp !== null ? $exp: $iat
        ];
    }
}
