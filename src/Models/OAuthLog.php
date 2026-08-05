<?php

namespace NSWDPC\Authentication\Okta;

use SilverStripe\ORM\DataObject;
use SilverStripe\ORM\DB;
use SilverStripe\Security\Permission;
use SilverStripe\Security\PermissionProvider;

/**
 * Stores OAuth failures for inspection
 * @author James
 * @property ?string $Code
 * @property int $MessageId
 * @property ?string $OAuthSource
 * @property ?string $Identifier
 */
class OAuthLog extends DataObject implements PermissionProvider
{
    private static string $table_name = 'OAuthLog';

    private static string $singular_name = 'OAuth log';

    private static string $plural_name = 'OAuth logs';

    private static string $default_sort = 'Created DESC';

    private static int $log_truncation_age = 7;

    //days
    private static array $db = [
        'Code' => 'Varchar(3)',
        'MessageId' => 'Int',
        'OAuthSource' => 'Varchar(255)',
        'Identifier' => 'Varchar(255)'
    ];

    private static array $indexes = [
        'Code' => true,
        'OAuthSource' => true,
        'MessageId' => true,
        'Identifier' => true,
        'Created' => true
    ];

    private static array $summary_fields = [
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
    public function getMeaning(): string
    {
        return OktaLoginHandler::getFailMessageForCode($this->Code);
    }

    /**
     * Quick add record
     */
    public static function add(string $code, int $messageId, string $providerName, string $identifier = ''): self
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

    #[\Override]
    public function getTitle()
    {
        return (string) $this->MessageId;
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

        $sql = 'DELETE FROM "OAuthLog" WHERE Created < CURDATE() - INTERVAL ? DAY';
        DB::prepared_query($sql, [$day]);
    }

    /**
     * Who can edit
     */
    #[\Override]
    public function canEdit($member = null)
    {
        return false;
    }

    /**
     * Who can create
     */
    #[\Override]
    public function canCreate($member = null, $context = [])
    {
        return false;
    }

    /**
     * Who can delete
     */
    #[\Override]
    public function canDelete($member = null)
    {
        return Permission::checkMember($member, 'OAUTH_LOG_DELETE');
    }

    /**
     * Who can view
     */
    #[\Override]
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
    #[\Override]
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
