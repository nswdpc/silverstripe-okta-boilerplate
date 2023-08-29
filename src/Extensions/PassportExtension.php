<?php

namespace NSWDPC\Authentication\Okta;

use Bigfork\SilverStripeOAuth\Client\Model\Passport;
use Bigfork\SilverStripeOAuth\Client\Factory\ProviderFactory;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\Forms\DropdownField;
use SilverStripe\ORM\DataExtension;
use SilverStripe\ORM\ValidationException;
use SilverStripe\Security\Member;
use SilverStripe\Security\Permission;
use SilverStripe\Security\PermissionProvider;
use SilverStripe\Security\Security;

/**
 * Adds the OauthSource to the Identifier to avoid collisions when
 * multiple Oauth providers are used
 *
 * Adds unique indexes to the DB
 * @author James
 */
class PassportExtension extends DataExtension implements PermissionProvider
{

    /**
     * @var array
     */
    private static $db = [
        'OAuthSource' => 'Varchar(255)'
    ];

    /**
     * @var array
     */
    private static $has_one = [
        'CreatedByMember' => Member::class
    ];

    /**
     * @var array
     */
    private static $indexes = [
        'Created' => true,
        'LastEdited' => true,
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
        'LastEdited' => 'Edited',
        'CreatedByMember.Email' => 'Created by'
    ];

    /**
     * @var array
     */
    private static $searchable_fields = [
        'Identifier' => 'PartialMatchFilter',
        'OAuthSource' => 'ExactMatchFilter',
        'Member.Email' => 'PartialMatchFilter'
    ];

    /**
     * Validate the values provided prior to allowing write
     */
    public function validatePassportWrite()
    {

        // Validate: the Identifier/OAuthSource is unique
        if ($this->owner->Identifier && $this->owner->OAuthSource) {
            $existing = Passport::get()->filter([
                'Identifier' => $this->owner->Identifier,
                'OAuthSource' => $this->owner->OAuthSource
            ]);
            if ($this->owner->isInDB()) {
                // exclude current record if it exists
                $existing = $existing->exclude([ "ID" => $this->owner->ID ]);
            }
            $existing = $existing->first();
            if ($existing && $existing->exists()) {
                throw new ValidationException(
                    OktaLoginHandler::getFailMessageForCode(OktaLoginHandler::FAIL_PASSPORT_CREATE_IDENT_COLLISION),
                    OktaLoginHandler::FAIL_PASSPORT_CREATE_IDENT_COLLISION
                );
            }
        }

        // Validate: the MemberID/OAuthSource is unique
        if ($this->owner->MemberID && $this->owner->OAuthSource) {
            // validate member/provider passport does not exist
            $existing = Passport::get()->filter([
                'MemberID' => $this->owner->MemberID,
                'OAuthSource' => $this->owner->OAuthSource
            ]);
            if ($this->owner->isInDB()) {
                // exclude current record if it exists (updating current record)
                $existing = $existing->exclude(["ID" => $this->owner->ID ]);
            }
            $existing = $existing->first();
            if ($existing && $existing->exists()) {
                throw new ValidationException(
                    OktaLoginHandler::getFailMessageForCode(OktaLoginHandler::FAIL_USER_MEMBER_PASSPORT_MISMATCH),
                    OktaLoginHandler::FAIL_USER_MEMBER_PASSPORT_MISMATCH
                );
            }
        }

        return true;
    }

    public function onBeforeWrite()
    {
        parent::onBeforeWrite();
        if (!$this->owner->isInDB()) {
            $member = Security::getCurrentUser();
            $this->owner->CreatedByMemberID = $member->ID ?? 0;
        }
        // validate that the passport can be written
        $this->validatePassportWrite();
    }

    public function getTitle()
    {
        if ($this->owner->exists()) {
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
     * Members cannot edit a passport record
     */
    public function canEdit($member)
    {
        return false;
    }

    /**
     * Members cannot create a passport record
     */
    public function canCreate($member)
    {
        return false;
    }

    /**
     * Who can delete a passport
     */
    public function canDelete($member)
    {
        return Permission::checkMember($member, 'OAUTH_PASSPORT_EDIT');
    }

    /**
     * Who can view a passport
     */
    public function canView($member)
    {
        return Permission::checkMember($member, 'OAUTH_PASSPORT_VIEW');
    }

    /**
     * Update fields for CMS
     */
    public function updateCmsFields($fields)
    {
        if ($sourceField = $fields->dataFieldByName('OAuthSource')) {
            $providerFactory = Injector::inst()->get(ProviderFactory::class);
            $providers = $providerFactory->getProviders();
            $listProviders = [];
            if($this->owner->OAuthSource) {
                $listProviders[ $this->owner->OAuthSource ] = _t(
                    'OKTA.PROVIDER_' . $this->owner->OAuthSource,
                    $this->owner->OAuthSource
                );
            }
            if (is_array($providers)) {
                foreach ($providers as $providerName => $provider) {
                    $listProviders[ $providerName ] = _t(
                        'OKTA.PROVIDER_' . $providerName,
                        $providerName
                    );
                }
            }
            $fields->replaceField(
                'OAuthSource',
                DropdownField::create(
                    'OAuthSource',
                    _t('OAUTH.SOURCE_TITLE', 'OAuth provider'),
                    $listProviders,
                    $this->owner->OAuthSource
                )->setEmptyString('')
            );
        }

        if (!$this->owner->isInDB()) {
            $fields->removeByName('CreatedByMemberID');
        } elseif ($createdByMemberField = $fields->dataFieldByName('CreatedByMemberID')) {
            $createdByMemberField->setTitle(_t('OAUTH.CREATED_BY_MEMBER', 'Created by'));
            $fields->makeFieldReadonly('CreatedByMemberID');
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
            'OAUTH_PASSPORT_EDIT' => [
                'name' => _t('OAUTH.PERMISSION_CED', 'Create and delete OAuth passports'),
                'category' => 'OAuth',
            ],
            'OAUTH_SYNC_REPORT_VIEW' => [
                'name' => _t('OAUTH.SYNC_REPORT_VIEW', 'View sync report'),
                'category' => 'OAuth',
            ]
        ];
    }
}
