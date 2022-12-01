<?php

namespace NSWDPC\Authentication\Okta\Tests;

use Bigfork\SilverStripeOAuth\Client\Model\Passport;
use NSWDPC\Authentication\Okta\PassportCleanupJob;
use SilverStripe\Core\Config\Config;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\Dev\SapphireTest;
use SilverStripe\ORM\DB;

/**
 * Test for verification of passport cleanup
 */
class PassportCleanUpJobTest extends SapphireTest
{

    /**
     * @inheritdoc
     */
    protected $usesDatabase = true;

    /**
     * @inheritdoc
     */
    protected static $fixture_file = "./support/passports.yml";

    /**
     * Test passport clean up
     */
    public function testPassportCleanup() {

        $passports = Passport::get();
        $ids = $passports->column('ID');
        $staleIds = $okIds = [];
        foreach($ids as $id) {
            if($id % 2 == 0) {
                $staleIds[] = $id;
            } else {
                $okIds[] = $id;
            }
        }
        $totalCount = $passports->count();
        $staleness = 30;
        $interval = $staleness+1;
        // mark stale records with a stale last edited date beyond the limit
        $result = DB::query(
            "UPDATE \"SS_OAuth_Passport\""
            . " SET \"LastEdited\" = CURDATE() - INTERVAL {$interval} DAY "
            . " WHERE ID IN (" . implode(",", $staleIds) . ")"
        );
        $job = new PassportCleanupJob(30, 0);
        $result = $job->process();

        $removedPassports = Passport::get()->filter(['ID' => $staleIds]);
        $keptPassports = Passport::get()->filter(['ID' => $okIds]);

        $this->assertEquals( 0, $removedPassports->count() );
        $this->assertEquals( count($okIds), $keptPassports->count() );

    }

}
