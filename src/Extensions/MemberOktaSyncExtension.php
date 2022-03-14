<?php

namespace NSWDPC\Authentication\Okta;

use SilverStripe\Control\Controller;
use SilverStripe\Core\Extension;
use SilverStripe\Forms\FormAction;
use SilverStripe\Security\Member;
use SilverStripe\ORM\ValidationException;

/**
 * Provide synchronisation action for Member admin
 * This extension is applied to the GridFieldDetailForm_ItemRequest class
 * @author James
 */
class MemberOktaSyncExtension extends Extension
{

    /**
     * Create an Okta Sync job for this Member
     */
    public function doOktaSync($data, $form) {
        $member = $this->owner->getRecord();
        if(
            ($member instanceof Member)
            &&
            $member->isInDB()
            &&
            $member->OktaProfileLogin
        ) {
            try {
                $client = new OktaUserUpdate();
                $client->updateMember( $member );
                $form->sessionMessage(
                    _t(
                        'OKTA.MEMBER_UPDATED',
                        'The record was updated using information from Okta'
                    ),
                    'good'
                );
            } catch ( ValidationException $e) {
                $form->sessionMessage($e->getMessage(), 'bad');
            } catch (\Exception $e) {
                Logger::log($e->getMessage(), "NOTICE");
                $form->sessionMessage(
                    _t(
                        'OKTA.MEMBER_CANNOT_BE_UPDATED',
                        'Sorry, an error occurred and this record could not be updated'
                    ),
                    'bad'
                );
            }
        }

        return $this->owner->edit(Controller::curr()->getRequest());
    }

    /**
     * Add an Okta sync button to a Member record when the login value is available
     * and the member exists
     */
    public function updateFormActions($actions) {
        $record = $this->owner->getRecord();
        if(
            ($record instanceof Member)
            &&
            $record->isInDB()
            &&
            $record->OktaProfileLogin
        ) {
            $action = FormAction::create(
                'doOktaSync',
                _t(
                    'OKTA.SYNC_USER_TITLE',
                    'Update from Okta'
                )
            )->addExtraClass('btn-hide-outline font-icon-sync')
            ->setUseButtonTag(true);

            $hasDelete = $actions->fieldByName('action_doDelete');
            if($hasDelete) {
                $actions->insertAfter('action_doDelete', $action);
            } else {
                $actions->insertAfter('MajorActions', $action);
            }

        }
    }
}
