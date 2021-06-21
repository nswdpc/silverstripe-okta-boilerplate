# Considerations

## Other providers

You may have success using this module with other OAuth provider clients configured. If you do so, pay attention to the changes documented below.

The Okta login handler provided in this module works on the basis that:

1. The Okta user's preferred username is returned during the authentication process
1. Some or all of the Okta user's groups are returned during the authentication process
1. One person is the owner of the Okta account and Silverstripe Member record, and that the Okta preferred_username is matched with the Silverstripe Member.Email value

## Extensions

The following extensions and handlers modify or add functionality to the default OAuth process in Silverstripe. If you have other OAuth2 providers configured you should be aware of these changes:

### Group extension

The module adds an `IsOktaGroup` field.

Groups with `IsOktaGroup` toggled 'on' will not be able to have permissions or roles assigned. Okta groups can be used for targeted content, for instance.

All groups synchronised this way will be given a parent based on the configured root group.

### Member extension

Adds OktaProfile and OktaLastSync fields.

### Passport extension

The module adds the OAuthSource value to the Passport and creates a unique index on Identifier + OAuthSource.

See OktaLoginHandler for usage.

## Okta Login Handler

Configuration adds this handler as the OAuth login handler when enabled. It overrides Passport and Member handling.

The following configuration values are available on the Okta Login Handler:

### link_existing_member

`bool` - if true, existing members will be linked to authenticated Okta users based on their email address. This is useful if you have an existing table of Silverstripe members.

If false, authenticated Okta users whose email value exists for a current Silverstripe member will not be able to complete the sign-in process unless they have a Passport record linked to that member.

If you are switching to Okta authentication and the Okta user.email + Silverstripe Member.Email are owned by the same person, this can be set to true.

### apply_group_restriction

`bool` - whether to further restrict access based on the Okta groups returned for an authenticate user. When false, any user authenticated by your Okta OAuth app may gain access. You can control user access to the app via the Okta administration dashboard.

### site_restricted_groups

`array` - Okta group name.

The site can specify these groups. Okta users authenticating must exist in all groups specified. If `apply_group_restriction` is false, this value is ignored.
