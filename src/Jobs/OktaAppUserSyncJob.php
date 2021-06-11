<?php

namespace NSWDPC\Authentication\Okta;

use SilverStripe\Core\Config\Configurable;
use SilverStripe\Core\Injector\Injector;
use Symbiote\QueuedJobs\Services\QueuedJobService;
use Symbiote\QueuedJobs\Services\AbstractQueuedJob;
use Symbiote\QueuedJobs\Services\QueuedJob;

/**
 * Queued Job to handle Okta application user sync
 */
class OktaAppUserSyncJob extends AbstractQueuedJob
{
    
    use Configurable;

    /**
     * @var int
     */
    private static $requeue_in_seconds = 86400;

    public function __construct($per_page = 100, $report_only = 0)
    {
        $this->per_page = $per_page;
        $this->report_only = $report_only;
    }
    
    public function getJobType()
    {
        return QueuedJob::QUEUED;
    }
    
    public function getTitle() {
        return _t(
            'OKTA.APP_USER_SYNC_JOB',
            'Okta App User Sync Job report_only={report_only}, per_page={per_page}',
            [
                'report_only' => $this->report_only,
                'per_page' => $this->per_page
            ]
        );
    }

    /**
     * Run the job
     */
    public function process() {
        try {
            $sync = new OktaAppUserSync();
            $sync->run( $this->report_only != 0 );
            $successes = $sync->getSuccesses();
            $failures = $sync->getFailures();
            $this->addMessage("Successes=" . count($success), "INFO");
            $this->addMessage("Failures=" . count($failures), "INFO");
            foreach($successes as $k=>$v) {
                $this->addMessage("Success: {$k}/{$v}", "INFO");
            }
            foreach($failures as $v) {
                $this->addMessage("Fail: {$v}", "INFO");
            }
            $this->isComplete = 1;
        } catch (\Exception $e) {
            $this->addMessage($e->getMessage(), "ERROR");
        }
    }
    
    /**
     * Recreate the job for the next run, at the time determined by configuration
     */
    public function afterComplete()
    {
        $seconds = (int)$this->config()->get('requeue_in_seconds');
        if ($seconds <= 1800) {
            // min every 30min
            $seconds = 1800;
        }
        $run_datetime = new \DateTime();
        $run_datetime->modify("+{$seconds} seconds");
        Injector::inst()->get(QueuedJobService::class)->queueJob(
            new self($this->per_page, $this->report_only),
            $run_datetime->format('Y-m-d H:i:s')
        );
    }


}
