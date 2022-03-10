<?php

namespace NSWDPC\Authentication\Okta\Tests;

use Bigfork\SilverStripeOAuth\Client\Model\Passport;
use NSWDPC\Authentication\Okta\OktaAppUserSync;
use SilverStripe\Core\Config\Config;
use SilverStripe\Dev\SapphireTest;
use SilverStripe\ORM\DataList;
use SilverStripe\Security\Member;
use SilverStripe\Security\Group;
use SilverStripe\Security\Permission;
use SilverStripe\Security\PermissionRole;

/**
 * Run test related to the Okta API using `okta/sdk`
 */
class SyncTest extends SapphireTest
{
    protected $usesDatabase = true;

    protected static $fixture_file = [
        './support/staleUserRemoval.yml'
    ];

    public static function setupBeforeClass()
    {
        parent::setupBeforeClass();
        Config::inst()->update(Member::class, 'okta_lockout_after_days', 30);
    }

    protected function getLastOktaSyncDate($modifier)
    {
        $dt = new \DateTime();
        $dt->modify($modifier);
        return $dt->format('Y-m-d H:i:s');
    }

    protected function getUserList() : array {
        $members = [
            'admin1' => '-40 days',// no remove, even though expired and okta group member
            'admin2' => null,// no remove only admin
            'contenteditor1' => null,// no remove, no okta group, no sync date
            'contenteditor2' => '-80 days',//no remove, expoired but content group member
            'oktauser1' => '-60 days',//remove
            'oktauser2' => '-40 days',//remove
            'oktauser3' => '-5 days',//no remove, not expired
            'oktauser4' => '-28 days',// no remove, admin plus date
            'oktauser5' => null,// no remove
            'oktauser6' => '-31 days',// remove (no groups)
            'oktauser7' => '-32 days',// no remove, expired but admin
        ];

        foreach ($members as $memberIndex => $syncDateOffset) {
            $member = $this->objFromFixture(Member::class, $memberIndex);
            $member->OktaLastSync = is_null($syncDateOffset) ? null : $this->getLastOktaSyncDate($syncDateOffset);
            $member->write();
        }

        return $members;
    }

    public function testStaleUserRemoval()
    {
        $this->assertEquals(30, Config::inst()->get(Member::class, 'okta_lockout_after_days'));
        $members = $this->getUserList();

        $sync = new OktaAppUserSync();
        $list = $sync->getStaleOktaMembers();
        $expected = [
            'oktauser1@example.com',
            'oktauser2@example.com',
            'oktauser6@example.com',
        ];

        $emails = [];
        $removedMemberIds = [];
        foreach ($list as $memberToBeRemoved) {
            $emails[] = $memberToBeRemoved->Email;
            $removedMemberIds[] = $memberToBeRemoved->ID;
        }
        sort($emails);
        sort($expected);

        $this->assertEquals($expected, $emails);

        $deleted = $sync->removeStaleOktaMembers(false);

        $this->assertEquals(count($removedMemberIds), $deleted);

        // get all members remaining
        $allMemberIds = Member::get()->column("ID");

        $this->assertEmpty(array_intersect($allMemberIds, $removedMemberIds), "Some members still exist in the DB");

        $remainingMemberIds = array_diff($allMemberIds, $removedMemberIds);

        // check for passports of expired members
        $passports = Passport::get()->filter('MemberID', $removedMemberIds);

        $this->assertEquals(0, $passports->count(), "Some passports remain for deleted members");

        $remainingPassports = Passport::get()
            ->filter('MemberID', $remainingMemberIds);

        //based on fixture passport/member linkage, we should have 7 passports remaining
        $this->assertEquals(7, $remainingPassports->count());
    }

    public function testLimitedStaleUserRemoval()
    {
        $this->assertEquals(30, Config::inst()->get(Member::class, 'okta_lockout_after_days'));
        $dt = new \DateTime();
        $members = $this->getUserList();
        $sync = new OktaAppUserSync();
        $list = $sync->getStaleOktaMembers(1);
        $this->assertEquals(1, $list->count());
        $member = $list->first();
        $member->OktaLastSync = $dt->format('Y-m-d H:i:s');
        $member->write();
        $list = $sync->getStaleOktaMembers(1);
        $this->assertEquals(1, $list->count());
        $nextMember = $list->first();
        $this->assertNotEquals($member->ID, $nextMember->ID);
    }

}
