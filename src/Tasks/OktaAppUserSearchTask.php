<?php

namespace NSWDPC\Authentication\Okta;

use SilverStripe\Control\Director;
use SilverStripe\Dev\BuildTask;
use SilverStripe\ORM\DB;

class OktaAppUserSearchTask extends BuildTask
{
    protected $title = 'Okta App User Search Task';

    protected $description = 'Search for users via Okta API';

    /**
     * {@inheritDoc}
     * @var string
     */
    private static $segment = 'OktaAppUserSearchTask';

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

            $queryOptions = $request->getVars();
            unset($queryOptions['url']);

            $client = new OktaAppUserSearch();
            if($results = $client->search($queryOptions)) {
                DB::alteration_message("Found:" . $results->count() . " record(s)","success");
            } else {
                DB::alteration_message("Invalid result from search", "error");
            }
        } catch (\Exception $e) {
            DB::alteration_message("Failed: " . $e->getMessage(), "error");
        }
    }
}
