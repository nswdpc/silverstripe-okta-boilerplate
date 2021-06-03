<?php
namespace NSWDPC\Authentication\Okta;

use SilverStripe\ORM\DataExtension;
use SilverStripe\Security\Permission;
use SilverStripe\Security\PermissionProvider;

/**
 * Adds the OauthSource to the Identifier to avoid collisions when
 * multiple Oauth providers are used
 *
 * Adds unique indexes to the DB
 * @author James
 */
class PassportExtension extends DataExtension implements PermissionProvider {

    /**
     * @var array
     */
    private static $db = [
        'OAuthSource' => 'Varchar(255)'
    ];

    /**
     * @var array
     */
    private static $indexes = [
        'IdentifierProvider' => [
            'type' => 'unique',
            'columns' => [
                'Identifier',
                'OAuthSource'
            ]
        ]
    ];

    /**
     * @var array
     */
    private static $summary_fields = [
        'Identifier' => 'Identifier',
        'OAuthSource' => 'OAuth provider',
        'Member.Email' => 'Member',
        'Created' => 'Created',
        'LastEdited' => 'Edited'
    ];

    /**
     * @var array
     */
    private static $searchable_fields = [
        'Identifier' => 'PartialMatchFilter',
        'OAuthSource' => 'ExactMatchFilter',
        'Member.Email' => 'PartialMatchFilter'
    ];

    public function getTitle() {
        if($this->owner->exists()) {
            return _t(
                'OAUTH.PASSPORT_TITLE',
                '{Identifier} @ {OAuthSource}',
                [
                    'Identifier' => $this->owner->Identifier,
                    'OAuthSource' => $this->owner->OAuthSource
                ]
            );
        } else {
            return _t('OKTA.NEW_PASSPORT', 'New OAuth Passport');
        }
    }

    /**
     * These fields are readonly and can only be deleted or viewed
     */
    public function canEdit($member) {
        return false;
    }

    /**
     * These fields are readonly and can only be deleted or viewed
     */
    public function canCreate($member) {
        return false;
    }

    /**
     * These fields are readonly and can only be deleted or viewed
     */
    public function canDelete($member) {
        return Permission::checkMember($member, 'OAUTH_PASSPORT_DELETE');
    }

    /**
     * These fields are readonly and can only be deleted or viewed
     */
    public function canView($member) {
        return Permission::checkMember($member, 'OAUTH_PASSPORT_VIEW');
    }

    /**
     * Update fields for CMS
     */
    public function updateCmsFields($fields) {
        if($sourceField = $fields->dataFieldByName('OAuthSource')) {
            $sourceField->setTitle(_t('OAUTH.SOURCE_TITLE', 'OAuth provider'));
        }
    }

    /**
     * Provide permissions for passports
     */
    public function providePermissions()
    {
        return [
            'OAUTH_PASSPORT_VIEW' => [
                'name' => _t('OAUTH.PERMISSION_VIEW', 'View OAuth passports'),
                'category' => 'OAuth',
            ],
            'OAUTH_PASSPORT_DELETE' => [
                'name' => _t('OAUTH.PERMISSION_DELETE', 'Delete OAuth passports'),
                'category' => 'OAuth',
            ]
        ];
    }


}
