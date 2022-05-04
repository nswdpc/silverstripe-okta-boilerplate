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
    private static $requeue_in_seconds = 300;

    /**
     * Create the job with args
     */
    public function __construct($per_page = 100, $report_only = 0, $cursor_after = '')
    {
        $this->per_page = $per_page;
        $this->report_only = $report_only;
        $this->cursor_after = $cursor_after;
    }

    /**
     * There is one step in this job, a step involves multiple users
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
            'OKTA.APP_USER_SYNC_JOB',
            'Okta App User Sync Job report_only={report_only}, per_page={per_page}, after=' . $this->cursor_after,
            [
                'report_only' => $this->report_only,
                'per_page' => $this->per_page,
                'cursor_after' => $this->cursor_after
            ]
        );
    }

    /**
     * Run the job
     */
    public function process()
    {
        try {

            // increment number of steps
            $this->currentStep++;

            /**
             * @var bool
             */
            $dryRun = ($this->report_only != 0);

            /**
             * @var int
             */
            $limit = intval($this->per_page);
            // set sensible limit
            $queryOptions = [
                'limit' => ($limit > 0 ? $limit : 50)
            ];
            // if starting a job from the last run's cursor position
            if($this->cursor_after) {
                $this->addMessage("(Start) After=" . $this->cursor_after, "INFO");
                $queryOptions['after'] = $this->cursor_after;
            }

            $sync = new OktaAppUserSync($dryRun);
            $sync->setIsSinglePage(true);// job handles a single page of results
            $sync->run($queryOptions);

            $successes = $sync->getSuccesses();
            $failures = $sync->getFailures();
            $this->addMessage("Successes=" . count($successes), "INFO");
            $this->addMessage("Failures=" . count($failures), "INFO");
            /*
            foreach ($successes as $k=>$v) {
                $this->addMessage("Success: {$k}/{$v}", "INFO");
            }
            foreach ($failures as $v) {
                $this->addMessage("Fail: {$v}", "INFO");
            }
            */

            // store a cursor for the next batch
            $this->cursor_after = $sync->getCursorAfter();
            $this->isComplete = true;

        } catch (\Exception $e) {
            $this->addMessage($e->getMessage(), "ERROR");
        }
    }

    /**
     * Recreate the job for the next run, at the time determined by configuration
     * If a cursor is present, this is passed to the new job as an argument
     */
    public function afterComplete()
    {
        $seconds = (int)$this->config()->get('requeue_in_seconds');
        if ($seconds <= 0) {
            // default every 5mins if not configured
            $seconds = 300;
        }
        $run_datetime = new \DateTime();
        $run_datetime->modify("+{$seconds} seconds");
        Injector::inst()->get(QueuedJobService::class)->queueJob(
            new self($this->per_page, $this->report_only, $this->cursor_after),
            $run_datetime->format('Y-m-d H:i:s')
        );
    }
}
