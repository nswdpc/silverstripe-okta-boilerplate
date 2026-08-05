<?php

namespace NSWDPC\Authentication\Okta\Tests;

use SilverStripe\Dev\SapphireTest;
use SilverStripe\Security\Member;

/**
 * Run tests for the Okta Profile Value
 */
class OktaProfileValueTest extends SapphireTest
{
    /**
     * @inheritdoc
     */
    protected $usesDatabase = true;

    /**
     * Test write and retrieve okta profile value
     */
    public function testOktaProfileValue(): void
    {
        $member = Member::create([
            'FirstName' => 'Jason',
            'Surname' => 'Text',
            'Email' => 'json@example.com'
        ]);
        $member->write();

        $this->assertNull($member->OktaProfileValue);

        $profileValue = [
            'firstName' => 'Jason',
            'lastName' => 'Text',
            'middleName' => 'Lint',
            'secondEmail' => 'secondary@example.com',
            'city' => 'Test town'
        ];
        $member->OktaProfileValue = $profileValue;
        $member->write();

        $get = $member->getOktaProfileValueAsArray();
        foreach ($profileValue as $k => $v) {
            $this->assertEquals($v, $get[$k]);
        }
    }

    /**
     * Test write and retrieve okta profile value
     */
    public function testStringOktaProfileValue(): void
    {
        $member = Member::create([
            'FirstName' => 'Jason',
            'Surname' => 'Text',
            'Email' => 'json@example.com'
        ]);
        $member->write();

        $this->assertNull($member->OktaProfileValue);

        $profileValue = [
            'firstName' => 'Jason',
            'lastName' => 'Text',
            'middleName' => 'String',
            'secondEmail' => 'secondary@example.com',
            'city' => 'Test town'
        ];
        $member->OktaProfileValue = json_encode($profileValue);
        $member->write();

        $get = $member->getOktaProfileValueAsArray();
        foreach ($profileValue as $k => $v) {
            $this->assertEquals($v, $get[$k]);
        }
    }

    /**
     * Test write and retrieve okta profile value
     */
    public function testInvalidOktaProfileValue(): void
    {
        $member = Member::create([
            'FirstName' => 'Jason',
            'Surname' => 'Text',
            'Email' => 'json@example.com'
        ]);
        $member->write();
        $this->assertNull($member->OktaProfileValue);
        $member->OktaProfileValue = 'Not a json string';
        $member->write();

        try {
            $assert = false;
            $get = $member->getOktaProfileValueAsArray();
        } catch (\JsonException $jsonException) {
            $assert = true;
        }

        $this->assertTrue($assert);
    }

}
