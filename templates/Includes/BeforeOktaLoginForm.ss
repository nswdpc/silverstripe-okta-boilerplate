<p>
<% if not $CurrentMember %>
<%t OAUTH.SIGN_IN_WITH_A_PROVIDER "To access this website, sign in using one of the providers listed below" %>
<% else %>
<%t OAUTH.SIGNED_IN_SIGN_OUT "You are signed in to this website. Sign out below." %>
<% end_if %>
</p>
