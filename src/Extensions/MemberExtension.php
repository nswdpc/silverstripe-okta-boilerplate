<?php

namespace NSWDPC\Authentication\Okta;

use SilverStripe\ORM\DataExtension;
use SilverStripe\ORM\ManyManyList;
use SilverStripe\ORM\ValidationResult;
use SilverStripe\Forms\ReadonlyField;
use SilverStripe\Forms\CompositeField;
use SilverStripe\Forms\CheckboxField;
use SilverStripe\Forms\LabelField;
use SilverStripe\Forms\LiteralField;
use SilverStripe\Security\Member;
use SilverStripe\Security\Permission;
use SilverStripe\Security\PermissionProvider;
use SilverStripe\Security\Security;

/**
 * Updates member view in administration area
 */
class MemberExtension extends DataExtension implements PermissionProvider
{

    /**
     * @var array
     */
    private static $db = [
        'OktaProfile' => 'MultiValueField',
        // see https://developer.okta.com/docs/reference/api/users/#profile-object
        'OktaProfileLogin' => 'Varchar(100)',
        'OktaLastSync' => 'DBDatetime'
    ];

    /**
     * @var array
     */
    private static $indexes = [
        'OktaLastSync' => true,
        'OktaProfileLogin' => [
            'type' => 'unique',
            'columns' => [
                'OktaProfileLogin'
            ]
        ]
    ];

    /**
     * Handle member okta operations on write
     */
    public function onBeforeWrite()
    {
        parent::onBeforeWrite();
        if ($this->owner->OktaLastSyncClear) {
            $this->owner->OktaLastSync = null;
        }
    }

    /**
     * Reset values after write
     */
    public function onAfterWrite()
    {
        parent::onAfterWrite();
        $this->owner->OktaLastSyncClear = null;
    }

    /**
     * Get a passport for the member
     * @param string $provider the provider name
     */
    public function getPassport(string $provider)
    {
        if ($passports = $this->owner->Passports()) {
            return $passports->filter('OAuthSource', $provider)->first();
        } else {
            return null;
        }
    }

    public function updateCmsFields($fields)
    {
        $fields->removeByName([
            'Passports',
            'Okta',
            'OAuthSource',
            'OktaProfileLogin',
            'OktaProfile',
            'OktaLastSync'
        ]);

        try {
            $profileFieldsValue = json_encode(
                $this->owner->OktaProfile->getValue(),
                JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES|JSON_THROW_ON_ERROR
            );
        } catch (\Exception $e) {
            $profileFieldsValue = '';
        }

        if( Permission::checkMember( Security::getCurrentUser(), 'ADMIN') ) {
            $fields->addFieldToTab(
                'Root.Okta',
                CompositeField::create(
                    ReadonlyField::create(
                        'OktaProfileLogin',
                        _t('OKTA.PROFILE_LOGIN', 'Okta login')
                    ),
                    LabelField::create(
                        'OktaProfileLabel',
                        _t('OKTA.PROFILE_FIELD_TITLE', 'Latest profile data')
                    ),
                    LiteralField::create(
                        'OktaProfile',
                        '<pre>'
                        . htmlspecialchars($profileFieldsValue)
                        . '</pre>'
                    ),
                    ReadonlyField::create(
                        'OktaLastSync',
                        _t('OKTA.LAST_SYNC_DATETIME', 'Last sync. date'),
                        $this->owner->OktaLastSync
                    ),
                    CheckboxField::create(
                        'OktaLastSyncClear',
                        _t(
                            'OKTA.CLEAR_SYNC_DATETIME',
                            'Clear this value'
                        )
                    )
                )->setTitle(
                    _t('OKTA.OKTA_HEADING', 'Okta')
                )
            );
        }
    }

    /**
     * Extend {@link Member::validateCanLogin()} to block logins for anyone whose account has become stale
     * @return void
     */
    public function canLogIn(ValidationResult &$result)
    {

        /**
         * If the validation result is already a fail, go no further
         */
        if (!$result->isValid()) {
            return false;
        }

        $days = intval($this->owner->config()->get('okta_lockout_after_days'));
        if ($days <= 0) {
            // if the configured days is 0 or less, OK
            return true;
        }
        if (!$this->owner->OktaLastSync) {
            // If the member has never been sync'd, allow
            return;
        }

        // calculate datetime comparison
        try {
            $dt = new \DateTime();
            $odt = new \DateTime($this->owner->OktaLastSync);
            $odt->modify("+1 {$days} day");
            if ($odt < $dt) {
                // still not on or after today
                $result->addError(
                    _t(
                        'OKTA.ACCOUNT_TOO_OLD',
                        'Sorry, you cannot sign in to this website as your account has not been used recently.'
                        . ' Please contact a website administrator for further assistance.'
                    )
                );
                return false;
            }
        } catch (\Exception $e) {
            // noop
        }
        return true;
    }

    /**
     * Get a Member's *direct* Okta groups, which excludes the root Okta group
     */
    public function getOktaGroups() : ManyManyList
    {
        return $this->owner->DirectGroups()->filter(['IsOktaGroup' => 1]);
    }

    /**
     * Provide permissions
     */
    public function providePermissions()
    {
        return [
            'OKTA_LOCAL_PASSWORD_RESET' => [
                'name' => _t('OKTA.ALLOW_LOCAL_PASSWORD_RESET', 'Allow local password reset'),
                'category' => _t(
                    'SilverStripe\\Security\\Permission.PERMISSIONS_CATEGORY',
                    'Roles and access permissions'
                ),
            ]
        ];
    }

}
