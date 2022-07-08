<?php

namespace NSWDPC\Authentication\Okta;

use SilverStripe\Control\Director;
use SilverStripe\Dev\BuildTask;
use SilverStripe\ORM\DB;

class OktaAppUserSyncTask extends BuildTask
{
    protected $title = 'Okta App User Sync Task';

    protected $description = 'Retrieve application user information from Okta and sync to local DB';

    /**
     * {@inheritDoc}
     * @var string
     */
    private static $segment = 'OktaAppUserSyncTask';

    /**
     * Run the task
     * When commit=1 is provided, the changes found are committed
     * This task gets all users by paging through all results
     */
    public function run($request)
    {
        try {
            if (!Director::is_cli()) {
                print "This task can only be run via CLI\n";
                return false;
            }

            $commitChanges = $request->getVar('commit');
            $limit = $request->getVar('limit');
            $verbose = $request->getVar('verbose') == 1;
            $cursorAfter = $request->getVar('after');
            $dryRun = ($commitChanges != 1);
            $sync = new OktaAppUserSync($dryRun);
            $sync->setIsSinglePage(true);

            $queryOptions = [];
            $queryOptions['limit'] = ($limit > 0 ? $limit : 50);
            if($cursorAfter) {
                $queryOptions['after'] = $cursorAfter;
            }
            print "Running with limit {$queryOptions['limit']}\n";
            $sync->run($queryOptions);

            if ($verbose) {
                print "DRY RUN report:\n";
                print_r($sync->getReport());
            }

            print "SUCCESS: " . count($sync->getSuccesses()) . "\n";
            print "FAIL: " . count($sync->getFailures()) . "\n";
            print "UNLINK: " . $sync->getUnlinkedMemberCount() . "\n";
            print "AFTER: " . $sync->getCursorAfter() . "\n";// for next task run

            return true;
        } catch (\Exception $e) {
            print $e->getMessage();
            print "\n";
            exit(1);
        }
    }
}
