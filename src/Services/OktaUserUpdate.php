<?php

namespace NSWDPC\Authentication\Okta;

use SilverStripe\ORM\ValidationException;
use SilverStripe\Security\Member;

/**
 * Single user/member update
 * @see https://developer.okta.com/docs/reference/api/users/#get-user
 * @author James
 */
class OktaUserUpdate extends OktaClient
{

    /**
     * Update a Member based on their external data
     * @param Member $member
     * @throws ValidationException
     */
    public function updateMember(Member $member) : bool {

        if(!$member->isInDB()) {
            throw new ValidationException(_t(
                "OKTA.UPDATE_MEMBER_NOT_IN_DB",
                "This record must be saved before an Okta update can occur"
            ));
        }

        if(!$member->OktaProfileLogin) {
            throw new ValidationException(_t(
                "OKTA.UPDATE_MEMBER_NO_LOGIN",
                "This record does not have a valid Okta identifier"
            ));
        }

        // Get user from Okta, using their login
        $user = $this->getUser($member->OktaProfileLogin);
        if(!$user) {
            throw new ValidationException(_t(
                "OKTA.UPDATE_MEMBER_NO_LOGIN",
                "The user could not be found at Okta"
            ));
        }

        try {

            $userProfile = $this->getUserProfile($user);

            // Update member from profile
            $dt = new \DateTime();
            $member->FirstName = $userProfile->getFirstName();
            $member->Surname = $userProfile->getLastName();
            $member->OktaProfile->setValue( $userProfile->__toString() );
            $member->OktaLastSync = $dt->format('Y-m-d H:i:s');
            $member->write();

            return true;

        } catch ( \Exception $e ) {
            throw new ValidationException(_t(
                "OKTA.UPDATE_MEMBER_FAILED",
                "This record could not be updated"
            ));
        }
    }

}
