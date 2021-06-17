<?php

namespace NSWDPC\Authentication\Okta;

use SilverStripe\ORM\DataObject;
use SilverStripe\ORM\DB;
use SilverStripe\Security\Member;
use SilverStripe\Security\Permission;
use SilverStripe\Security\PermissionProvider;

/**
 * Stores OAuth failures for inspection
 * @author James
 */
class OAuthLog extends DataObject implements PermissionProvider
{

    /**
     * @var string
     */
    private static $table_name = 'OAuthLog';

    /**
     * @var string
     */
    private static $singular_name = 'OAuth log';

    /**
     * @var string
     */
    private static $plural_name = 'OAuth logs';

    /**
     * @var string
     */
    private static $default_sort = 'Created DESC';

    /**
     * @var int
     */
    private static $log_truncation_age = 7;//days

    /**
     * @var array
     */
    private static $db = [
        'Code' => 'Varchar(3)',
        'MessageId' => 'Int',
        'OAuthSource' => 'Varchar(255)',
        'Identifier' => 'Varchar(255)'
    ];

    /**
     * @var array
     */
    private static $indexes = [
        'Code' => true,
        'OAuthSource' => true,
        'MessageId' => true,
        'Identifier' => true,
        'Created' => true
    ];

    /**
     * @var array
     */
    private static $summary_fields = [
        'Created.Nice' => 'Created',
        'MessageId' => 'Message Id',
        'Code' => 'Code',
        'Meaning' => 'Meaning',
        'OAuthSource' => 'OAuth provider',
        'Identifier' => 'Identifier',
    ];

    /**
     * Retrieve code meaning
     */
    public function getMeaning() : string
    {
        return OktaLoginHandler::getFailMessageForCode($this->Code);
    }

    /**
     * Quick add record
     */
    public static function add($code, int $messageId, $providerName, $identifier = '') : self
    {
        $record = self::create([
            'Code' => $code,
            'MessageId' => $messageId,
            'OAuthSource' => $providerName,
            'Identifier' => $identifier
        ]);
        $record->write();
        return $record;
    }

    /**
     * @return string
     */
    public function getTitle()
    {
        return $this->MessageId;
    }

    /**
     * Truncate logs
     */
    public static function truncate()
    {
        $day = intval(self::config()->get('log_truncation_age'));
        if ($day <= 0) {
            $day = 7;
        }
        $sql = "DELETE FROM `OAuthLog` WHERE Created < CURDATE() - INTERVAL {$day} DAY";
        DB::query($sql);
    }

    /**
     * Who can edit
     */
    public function canEdit($member = null)
    {
        return false;
    }

    /**
     * Who can create
     */
    public function canCreate($member = null, $context = [])
    {
        return false;
    }

    /**
     * Who can delete
     */
    public function canDelete($member = null)
    {
        return Permission::checkMember($member, 'OAUTH_LOG_DELETE');
    }

    /**
     * Who can view
     */
    public function canView($member = null)
    {
        return Permission::checkMember($member, 'OAUTH_LOG_VIEW');
    }

    /**
     * Provide permissions for passports
     */
    public function providePermissions()
    {
        return [
            'OAUTH_LOG_DELETE' => [
                'name' => _t('OAUTH.LOG_DELETE', 'Delete OAuth logs'),
                'category' => 'OAuth',
            ],
            'OAUTH_LOG_VIEW' => [
                'name' => _t('OAUTH.LOG_VIEW', 'View OAuth logs'),
                'category' => 'OAuth',
            ]
        ];
    }

    /**
     * Update fields
     */
    public function getCmsFields()
    {
        $fields = parent::getCmsFields();
        if ($codeField = $fields->dataFieldByName('Code')) {
            $codeField->setRightTitle(
                OktaLoginHandler::getFailMessageForCode($this->Code)
            );
        }
        if ($oauthSourceField = $fields->dataFieldByName('OAuthSource')) {
            $oauthSourceField->setTitle(_t('OAUTH.SOURCE_TITLE', 'OAuth provider'));
        }
        return $fields;
    }
}
