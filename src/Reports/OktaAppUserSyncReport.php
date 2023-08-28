<?php

namespace NSWDPC\Authentication\Okta;

use SilverStripe\Admin\SecurityAdmin;
use SilverStripe\Control\Controller;
use SilverStripe\Forms\CheckboxField;
use SilverStripe\Forms\DropdownField;
use SilverStripe\Forms\FieldList;
use SilverStripe\Forms\DateField;
use SilverStripe\Reports\Report;
use SilverStripe\Security\Member;
use SilverStripe\Security\Permission;

/**
 * Display report of Okta App users sync information
 */
class OktaAppUserSyncReport extends Report
{
    public function title()
    {
        return _t('OKTA.TITLE', 'Member/Okta user sync report');
    }

    /**
     * Members with passport view permissions can view these
     * @inheritdoc
     */
    public function canView($member = null)
    {
        if (!$member && $member !== false) {
            $member = Member::currentUser();
        }
        return Permission::checkMember($member, 'OAUTH_SYNC_REPORT_VIEW');
    }

    /**
     * Get source records based on filters, or lack of filters
     */
    public function sourceRecords($params, $sort, $limit)
    {

        $list = Member::get()->sort([ 'OktaLastSync' => 'DESC' ]);
        if (empty($params['OktaLastSyncFilter'])) {
            $params['OktaLastSyncFilter'] = 'recent';
        }

        // filter those members marked as unlinked
        if(!empty($params['WasUnlinkedFromOkta'])) {
            $list = $list->where('OktaUnlinkedWhen IS NOT NULL');
        }

        // filter the list
        if ($params['OktaLastSyncFilter'] == 'never') {
            // never sync
            $list = $list->where("OktaLastSync IS NULL OR OktaLastSync = ''");
        } elseif ($params['OktaLastSyncFilter'] == 'recent') {
            // recent sync
            $list = $list->where("OktaLastSync >= CURDATE() - INTERVAL 2 DAY");
        } elseif ($params['OktaLastSyncFilter'] == 'range') {
            if (!empty($params['OktaLastSyncStart']) && !empty($params['OktaLastSyncEnd'])) {
                // between these dates
                $list = $list->filter([
                    "OktaLastSync:GreaterThanOrEqual" => $params['OktaLastSyncStart'],
                    "OktaLastSync:LessThanOrEqual" => $params['OktaLastSyncEnd'],
                ]);
            } elseif (!empty($params['OktaLastSyncStart'])) {
                // on or after a date
                $list = $list->filter([
                    "OktaLastSync:GreaterThanOrEqual" => $params['OktaLastSyncStart']
                ]);
            } elseif (!empty($params['OktaLastSyncEnd'])) {
                // on or before a date
                $list = $list->filter([
                    "OktaLastSync:LessThanOrEqual" => $params['OktaLastSyncEnd']
                ]);
            } else {
                $list = $list->filter('ID:LessThan', 0);
            }
        } else {
            $list = $list->filter('ID:LessThan', 0);
        }
        return $list;
    }

    /**
     * Return filtering fields
     */
    public function parameterFields()
    {
        return FieldList::create(
            DropdownField::create(
                'OktaLastSyncFilter',
                _t('OKTA.SYNC_FILTER_SELECT', 'Select a filter'),
                [
                    'never' => _t('OKTA.SYNC_DATE_NEVER', 'No sync recorded'),
                    'recent' => _t('OKTA.SYNC_DATE_RECENT', 'Sync in the last 2 days'),
                    'range' =>  _t('OKTA.SYNC_DATE_RECENT', 'Select a date range (below)')
                ]
            )->setEmptyString(''),
            DateField::create(
                'OktaLastSyncStart',
                _t('OKTA.SYNC_DATE_LOWER_BOUND', 'Last sync is on or after this date')
            ),
            DateField::create(
                'OktaLastSyncEnd',
                _t('OKTA.SYNC_DATE_UPPER_BOUND', 'Last sync is on or before this date')
            ),
            CheckboxField::create(
                'WasUnlinkedFromOkta',
                _t('OKTA.SYNC_WAS_UNLINKED', 'The member was unlinked from Okta')
            )
        );
    }

    public function columns()
    {
        $fields = [
            "ID" => [
                "title" => _t('OKTA.ID', 'ID')
            ],
            "OktaLastSync" => [
                "title" => _t('OKTA.OKTA_LAST_SYNC', 'Last Okta Sync'),
                'formatting' => function ($value, $item) {
                    try {
                        if (!$value) {
                            return "";
                        }
                        $dt = new \DateTime($value);
                        return $dt->format('Y-m-d H:i:s');
                    } catch (\Exception $e) {
                        return "";
                    }
                }
            ],
            "HasOktaPassport" => [
                "title" => _t('OKTA.HAS_OKTA_PASSPORT', 'Has Okta Passport?'),
                'formatting' => function ($value, $item) {
                    try {
                        $passport = $item->getPassport('Okta');
                        return $passport && $passport->isInDB()
                            ? _t('OKTA.YES', 'Yes')
                            : _t('OKTA.NO', 'No');
                    } catch (\Exception $e) {
                        return _t('OKTA.NO', 'No');
                    }
                }
            ],
            "Surname" => [
                "title" => _t('OKTA.SURNAME', 'Surname'),
            ],
            "FirstName" => [
                "title" => _t('OKTA.FIRSTNAME', 'First name'),
            ],
            "Email" => [
                "title" => _t('OKTA.EMAIL', 'Email'),
                'formatting' => function ($value, $item) {
                    $controller = SecurityAdmin::create();
                    $link = Controller::join_links(
                        $controller->Link(),
                        'EditForm',
                        'field',
                        'Members',
                        'item',
                        $item->ID,
                        'edit'
                    );
                    return sprintf('<a href="%s">%s</a>', $link, htmlspecialchars($item->Email));
                }
            ]
        ];

        return $fields;
    }
}
