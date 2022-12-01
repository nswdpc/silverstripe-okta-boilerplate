<?php

namespace NSWDPC\Authentication\Okta;

use SilverStripe\Core\Config\Configurable;
use SilverStripe\Core\Convert;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\ORM\DB;
use Symbiote\QueuedJobs\Services\QueuedJobService;
use Symbiote\QueuedJobs\Services\AbstractQueuedJob;
use Symbiote\QueuedJobs\Services\QueuedJob;

/**
 * Handle cleaning up stale passports
 */
class PassportCleanupJob extends AbstractQueuedJob
{
    use Configurable;

    /**
     * @var int
     */
    private static $requeue_in_seconds = 86400;

    /**
     * Create the job with args
     */
    public function __construct($staleness_in_days = 30, $report_only = 0)
    {
        $this->report_only = $report_only;
        $this->staleness_in_days = $staleness_in_days;
    }

    /**
     * There is one step in this job
     */
    public function setup()
    {
        parent::setup();
        $this->totalSteps = 1;//there is one step in this job
    }

    public function getJobType()
    {
        return QueuedJob::QUEUED;
    }

    public function getTitle()
    {
        return _t(
            'OKTA.PASSPORT_CLEANUP_JOB',
            'Passport Cleanup Job staleness={staleness_in_days} report_only={report_only}',
            [
                'report_only' => $this->report_only,
                'staleness_in_days' => $this->staleness_in_days
            ]
        );
    }

    /**
     * Run the job
     */
    public function process()
    {
        try {
            if($this->staleness_in_days <= 0 ) {
                throw new \Exception("Invalid value for staleness_in_days.. must be > 0");
            }
            // increment number of steps
            $this->currentStep++;
            /**
             * @var bool
             */
            $dryRun = ($this->report_only != 0);
            $dt = new \DateTime();
            $dt->modify("-{$this->staleness_in_days} days");

            DB::get_conn()->transactionStart();
            $sql = "DELETE FROM \"SS_OAuth_Passport\""
                . " WHERE \"LastEdited\" < '" . Convert::raw2sql($dt->format('Y-m-d H:i:s')) . "'"
                . " AND OAuthSource = 'Okta'";
            $result = DB::query($sql);
            $affectedRows = DB::affected_rows();
            if($dryRun) {
                $this->addMessage("Report only: would delete {$affectedRows} records");
                DB::get_conn()->transactionRollback();
            } else {
                DB::get_conn()->transactionEnd();
                $this->addMessage("Deleted {$affectedRows} records");
            }
            $this->isComplete = true;
        } catch (\Exception $e) {
            $this->addMessage($e->getMessage(), "ERROR");
        }
    }

    /**
     * Recreate the job for the next run
     */
    public function afterComplete()
    {
        $seconds = (int)$this->config()->get('requeue_in_seconds');
        if ($seconds <= 0) {
            // default every 1 day if not configured
            $seconds = 86400;
        }
        $rdt = new \DateTime();
        $rdt->modify("+{$seconds} seconds");
        Injector::inst()->get(QueuedJobService::class)->queueJob(
            new self($this->report_only, $this->staleness_in_days),
            $rdt->format('Y-m-d H:i:s')
        );
    }
}
