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
     */
    private static string $segment = 'OktaProfileLoginCreateTask';

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

            $conditional = "(\"OktaProfileLogin\" IS NULL OR \"OktaProfileLogin\" = '') AND \"Email\" LIKE '%@%'";
            $sqlSelect = "SELECT COUNT(\"ID\") AS RecordCount FROM \"Member\" WHERE {$conditional}";

            $result = DB::query($sqlSelect);
            $recordCount = 0;
            if ($result) {
                $row = $result->record();
                $recordCount = $row['RecordCount'] ?? 0;
            }

            DB::alteration_message("Found {$recordCount} matching member records", "changed");

            if ($recordCount > 0) {

                $sqlUpdate = 'UPDATE "Member" '
                    . ' SET "OktaProfileLogin" = "Email"'
                    . " WHERE {$conditional}";
                $result = DB::query($sqlUpdate);
                $affectedRows = DB::affected_rows();

                DB::alteration_message("Changed {$affectedRows} member records", "changed");

                if ($commitChanges) {
                    DB::alteration_message("Commit", "changed");
                    DB::get_conn()->transactionEnd();
                } else {
                    DB::alteration_message("Rolling back", "changed");
                    DB::get_conn()->transactionRollback();
                }
            } else {
                DB::alteration_message("Done", "changed");
            }
        } catch (\Exception $exception) {
            print $exception->getMessage();
            print "\n";
            exit(1);
        }
    }
}
