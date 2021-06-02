# Considerations

The following extensions and handlers modify or add functionality to the default OAuth process in Silverstripe. If you have other OAuth2 providers configured you should be aware of these changes:

## Group extension

The module adds an 'IsOktaGroup' field to the `Group` table.

## Passport extension

The module adds the OAuthSource value to the Passport and creates a unique index on Identifier + OAuthSource. See OktaLoginHandler for usage.


## Okta Login Handler

Configuration adds this handler as the OAuth login handler. It overrides Passport and Member handling.

The following configuration values are available on the Okta Login Handler.

### link_existing_member

`bool` - if true, existing members will be linked to authenticated Okta users based on their email address. This is useful if you have a existing table of Silverstripe members.

If false, authenticated Okta users whose email value exists for a current Silverstripe member will not be able to complete the sign-in process unless they have a Passport record linked to that member.

If you are switching to Okta authentication and the Okta user.email + Silverstripe Member.Email are owned by the same person, this can be set to true.

### apply_group_restriction

`bool` - whether to further restrict access based on the Okta groups returned for an authenticate user. When false, any user authenticated by your Okta OAuth app may gain access

### site_restricted_groups

`array` - Okta group titles. The site can specify these groups. Okta users authenticating must exist in all groups specified. If `apply_group_restriction` is false, this value is ignored.
