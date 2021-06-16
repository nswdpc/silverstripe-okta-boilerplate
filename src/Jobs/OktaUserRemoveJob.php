<?php

namespace NSWDPC\Authentication\Okta;

use SilverStripe\Core\Config\Configurable;
use SilverStripe\Core\Injector\Injector;
use Symbiote\QueuedJobs\Services\QueuedJobService;
use Symbiote\QueuedJobs\Services\AbstractQueuedJob;
use Symbiote\QueuedJobs\Services\QueuedJob;

/**
 * Queued Job to handle removal of users who are not syncing from Okta via the
 * {@link NSWDPC\Authentication\Okta\OktaAppUserSyncJob}
 *
 * Members with:
 * - CMS_ACCESS permissions
 * - no last Okta sync date
 * ... are not removed
 *
 * You can add this as a default job to your project by following the queued job documentation
 * https://github.com/symbiote/silverstripe-queuedjobs#default-jobs
 * Alternately, add it to the queued jobs administration area, it will requeue after each run
 * using the configured $requeue_in_seconds value
 *
 * If a removed Okta user/Member is re-added to the Okta application
 * they will automatically sign-in without issue,
 * provided they meet the authentication requirements.
 * In this case they will be assigned a new Member record
 *
 */
class OktaUserRemoveJob extends AbstractQueuedJob
{
    use Configurable;

    /**
     * @var int
     */
    private static $requeue_in_seconds = 86400;

    public function __construct($report_only = 0)
    {
        $this->report_only = $report_only;
    }
    
    public function getJobType()
    {
        return QueuedJob::QUEUED;
    }
    
    public function getTitle()
    {
        return _t(
            'OKTA.APP_USER_REMOVAL_JOB',
            'Okta App User Removal Job report_only={report_only}',
            [
                'report_only' => $this->report_only
            ]
        );
    }

    /**
     * Run the job
     */
    public function process()
    {
        try {
            $sync = new OktaAppUserSync();
            $deleted = $sync->removeStaleOktaMembers($this->report_only != 0);
            $this->addMessage("Removed {$deleted} members");
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
            new self($this->report_only),
            $run_datetime->format('Y-m-d H:i:s')
        );
    }
}
