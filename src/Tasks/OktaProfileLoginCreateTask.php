<?php

namespace NSWDPC\Authentication\Okta;

use SilverStripe\Control\Director;
use SilverStripe\Dev\BuildTask;
use SilverStripe\ORM\DB;

/**
 * This is a one-off task to copy Member.Email values to Member.OktaProfileLogin
 * Can be used if the Okta login is the member email
 * @author James
 */
class OktaProfileLoginCreateTask extends BuildTask
{

    protected $title = 'Okta profile login create task';

    protected $description = 'Migrates email to okta profile login value. Use when upgrading to v0.1';

    /**
     * {@inheritDoc}
     * @var string
     */
    private static $segment = 'OktaProfileLoginCreateTask';

    /**
     * Run the task
     * When commit=1 is provided, the changes found are committed
     * This task gets all users by paging through all results
     */
    public function run($request)
    {
        try {
            if (!Director::is_cli()) {
                throw new \Exception("This task can only be run via CLI");
            }

            DB::get_conn()->transactionStart();
            $commitChanges = $request->getVar('commit');

            $conditional = "(`OktaProfileLogin` IS NULL OR `OktaProfileLogin` = '') AND `Email` LIKE '%@%'";
            $sqlSelect = "SELECT COUNT(`ID`) AS RecordCount FROM `Member` WHERE {$conditional}";

            $result = DB::query($sqlSelect);
            $recordCount = 0;
            if($result) {
                $row = $result->nextRecord();
                $recordCount = $row['RecordCount'];
            }
            DB::alteration_message("Found {$recordCount} matching member records", "changed");

            $sql = "UPDATE `Member` "
                . " SET `OktaProfileLogin` = `Email`"
                . " WHERE {$conditional}";
            $result = DB::query($sql);
            $affectedRows = DB::affected_rows();

            DB::alteration_message("Changed {$affectedRows} member records", "changed");

            if($commitChanges) {
                DB::alteration_message("Commit", "changed");
                DB::get_conn()->transactionEnd();
            } else {
                DB::alteration_message("Rolling back", "changed");
                DB::get_conn()->transactionRollback();
            }
            return true;
        } catch (\Exception $e) {
            print $e->getMessage();
            print "\n";
            exit(1);
        }
    }
}
