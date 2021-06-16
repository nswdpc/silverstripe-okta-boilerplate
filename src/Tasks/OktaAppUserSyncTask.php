<?php

namespace NSWDPC\Authentication\Okta;

use SilverStripe\Control\Director;
use SilverStripe\Dev\BuildTask;

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
     * Run the task - given a group id, get all users
     * When commit=1 is provided, the changes found are committed
     */
    public function run($request)
    {
        try {
            if (!Director::is_cli()) {
                print "This task can only be run via CLI\n";
                return false;
            }
            
            $commitChanges = $request->getVar('commit');
            $dryRun = ($commitChanges != 1);
            $sync = new OktaAppUserSync();
            $sync->run($dryRun);
            
            if ($dryRun) {
                print "DRY RUN report:\n";
                print_r($sync->getReport());
            }
            
            print "SUCCESS\n";
            print_r($sync->getSuccesses());
            print "FAIL\n";
            print_r($sync->getFailures());
            
            return true;
        } catch (\Exception $e) {
            print $e->getMessage();
            print "\n";
            exit(1);
        }
    }
}
