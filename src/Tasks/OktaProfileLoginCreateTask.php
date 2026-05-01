<?php

declare(strict_types=1);

namespace NSWDPC\Authentication\Okta;

use SilverStripe\Control\Director;
use SilverStripe\Dev\BuildTask;
use SilverStripe\ORM\DB;
use SilverStripe\PolyExecution\PolyOutput;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;

/**
 * This is a one-off task to copy Member.Email values to Member.OktaProfileLogin
 * Can be used if the Okta login is the member email
 * @author James
 */
class OktaProfileLoginCreateTask extends BuildTask
{
    protected string $title = 'Okta profile login create task';

    protected static string $description = 'Migrates email to okta profile login value. Use when upgrading to v0.1';

    protected static string $commandName = 'OktaProfileLoginCreateTask';

    private bool $commit = false;

    #[\Override]
    public function getOptions(): array
    {
        return [
            new InputOption('commit', null, InputOption::VALUE_NONE, 'Commit the change'),
        ];
    }

    /**
     * Run the task
     * When commit=1 is provided, the changes found are committed
     */
    protected function execute(InputInterface $input, PolyOutput $output): int
    {
        try {

            $this->commit = $input->getOption('commit') == 1;

            if (!Director::is_cli()) {
                throw new \Exception("This task can only be run via CLI");
            }

            DB::get_conn()->withTransaction(
                function () use ($output): void {

                    $conditional = "(\"OktaProfileLogin\" IS NULL OR \"OktaProfileLogin\" = '') AND \"Email\" LIKE '%@%'";
                    $sqlSelect = "SELECT COUNT(\"ID\") AS RecordCount FROM \"Member\" WHERE {$conditional}";

                    $result = DB::query($sqlSelect);
                    $recordCount = 0;
                    if ($result) {
                        $row = $result->record();
                        $recordCount = $row['RecordCount'] ?? 0;
                    }

                    $output->writeln("Found {$recordCount} matching member records");

                    if ($recordCount > 0) {

                        $sqlUpdate = 'UPDATE "Member" '
                            . ' SET "OktaProfileLogin" = "Email"'
                            . " WHERE {$conditional}";
                        $result = DB::query($sqlUpdate);
                        $affectedRows = DB::affected_rows();

                        $output->writeln("Changed {$affectedRows} member records");

                        if (!$this->commit) {
                            throw new \Exception("Not committing changes");
                        }
                    } else {
                        $output->writeln("No changes to be made");
                    }
                },
                function () use ($output): void {
                    // Error callback
                    $output->writeln("Rollback: error or not committing changes");
                }
            );

            return Command::SUCCESS;
        } catch (\Exception $exception) {
            // Task threw an error or not committing
            $output->writeln($exception->getMessage());
            return Command::FAILURE;
        }
    }
}
