<?php

namespace NSWDPC\Authentication\Okta\Tests;

use NSWDPC\Authentication\Okta\OktaAppUserSync;
use SilverStripe\Dev\SapphireTest;
use SilverStripe\Security\Member;

/**
 * Unlink member testing
 */
class OktaUnlinkMemberTest extends SapphireTest
{

    protected $usesDatabase = true;

    protected static $fixture_file = './support/staleUserRemoval.yml';

    /**
     * Test stale member query
     */
    public function testStaleMemberList() {

        $sync = new OktaAppUserSync(false);
        $beforeDays = 2;
        $before = new \DateTime();
        $before->modify("-{$beforeDays} day");
        $list = $sync->getStaleMemberList($before);

        // no users have been marked stale in the fixture
        $this->assertEquals(0, $list->count());

        // not stale
        $oktaUser5Sync = new \DateTime();
        $oktaUser5Sync->modify("-{$beforeDays} day");
        $oktaUser5 = $this->objFromFixture(Member::class, 'oktauser5');
        $oktaUser5->OktaLastSync = $oktaUser5Sync->format('Y-m-d H:i:s');
        $oktaUser5->write();

        // stale
        $syncDays = $beforeDays + 5;
        $oktaUser6Sync = new \DateTime();
        $oktaUser6Sync->modify("-{$syncDays} day");
        $oktaUser6 = $this->objFromFixture(Member::class, 'oktauser6');
        $oktaUser6->OktaLastSync = $oktaUser6Sync->format('Y-m-d H:i:s');
        $oktaUser6->write();

        // stale
        $syncDays = $beforeDays + 1;
        $oktaUser7Sync = new \DateTime();
        $oktaUser7Sync->modify("-{$syncDays} day");
        $oktaUser7 = $this->objFromFixture(Member::class, 'oktauser7');
        $oktaUser7->OktaLastSync = $oktaUser7Sync->format('Y-m-d H:i:s');
        $oktaUser7->write();

        $list = $sync->getStaleMemberList($before);
        $this->assertEquals(2, $list->count());
        $this->assertNotNull( $list->filter(['OktaProfileLogin' => 'oktauser7@example.com'])->first() );
        $this->assertNotNull( $list->filter(['OktaProfileLogin' => 'oktauser6@sub.example.com'])->first() );

    }

}
