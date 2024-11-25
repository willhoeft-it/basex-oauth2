(:~
 : Simple example to demonstrate OAuth2 permission checks.
 : Requires the following environment variables to be set:
 : - RESTXQ_BASE_URL: the base URL of the RESTXQ server, accessible from the browser.
 :)

module namespace page = 'http://basex.org/modules/web-page';
import module namespace session = "http://basex.org/modules/session";
import module namespace oa = "oauth2" at "oauth2.xqm";

(: ========= Permission handling ============ :)

declare variable $page:rolesToPermissions := map {
  "admin": ("systemSettings", "viewItem", "editItem"),
  "viewer": "viewItem",
  "editor": ("viewItem", "editItem")
};

declare variable $page:oauthLandingPage := environment-variable("RESTXQ_BASE_URL") || "/oauth-redirect";

(:~
 : Permission check: all internal urls need logged-in user, and some also need specific roles.
 : A user can have multiple roles, and each role can have multiple permissions. Check expects a single necessary permission per request.
 : @param $perm map with permission data
 :)

declare
  %perm:check('internal/', '{$perm}')
function page:checkInternal($perm as map(*)) {
  let $permission := $perm?allow
  let $path := $perm?path
  let $userId := session:get('userId')
  let $roles := session:get('oa:roles')
  return (
    message("Permission check, path: " || $path || ", permission: " || $permission || ", userId: " || $userId || ", roles: " || $roles),
    if (empty($userId)) then (
      (: Not logged in, redirect to authorization :)
      (: Save the path the user wanted :)
      (: TODO: unfortunately we cannot access, check and/or save the requested URL-Parameters, etc. in this context :)
      session:set('requestedPathForAuth', $path),
      oa:redirectAuthorize($page:oauthLandingPage)
    )
    (: functional map parameter requires BaseX 11 and above  :)
    else if (not(empty($permission) or not(map:empty(map:filter($page:rolesToPermissions, fn($k, $v) { $roles = $k and $permission = $v }))))) then (
      (: Request requires a permission that is not assigned to any of the user's roles :)
      web:error(403, "You do not have the required permissions to access this page.")
    ) else ()
  )
};

(:~
 : We received a redirect from the OAuth2 server. Validate request and code directly with the OAuth2 server.
 : FusionAuth also returns a userState parameter, but currently we don't use it.
 :)
declare
  %rest:path("oauth-redirect")
  %output:method("html")
  %rest:query-param("code", "{$code}")
  %rest:query-param("state", "{$state}")
function page:oauthRedirect($code as xs:string, $state as xs:string) {
  (: TODO: On error, we might better redirect to a try again page. E.g. expired or invalid code on error status 400 may happen regularly on a
       slow redirect or when paging back :)
  oa:completeAuthorizationCodeGrant($code, $state, $page:oauthLandingPage),
  <html>
    <head>
      <title>Login Success</title>
    </head>
    <body>
      <h1>OAuth Login Success Page</h1>
      <p>You have been successfully logged in.</p>
      <p>Please go on to the requested <a href="{session:get('requestedPathForAuth')}">page</a>.</p>
      <p>You can also go to:</p>
      <li><a href="/">Main page</a></li>
      <li><a href="internal/mydata">Internal page (requires login)</a></li>
    </body>
  </html>
};

(:~
 : Logout the user.
 :)
declare
  %rest:path("logout")
  %output:method("html")
function page:logout() { (
  oa:logout(),
  <html>
    You have been successfully logged out.

    Go back to the <a href="/">main page</a>.
  </html>
)};


(: ========= The actual pages ============ :)

(:~
 : Welcome page.
 : @return HTML page
 :)
declare
  %rest:path("")
  %output:method("html")
function page:start() {
  <html>
    <head>
      <title>BaseX Main Page</title>
    </head>
    <body>
      <h1>BaseX Main Page</h1>
      <h3>Links:</h3>
      <li><a href="internal/mydata">My data page (requires login)</a></li>
      <li><a href="internal/admin">Administration page (requires permission "systemSettings" / role "admin")</a></li>
      <li><a href="internal/viewer">View item page (requires permission "viewItem" / role "admin", "viewer", "editor")</a></li>
      <li><a href="internal/editor">Edit item page (requires permission "editItem" / role "admin", "editor")</a></li>
      <li><a href="logout">Log out</a></li>
      <h3>Environment</h3>
{
  for $v in available-environment-variables()
  return <li>{$v} = {environment-variable($v)}</li>
}   
    </body>
  </html>
};

(:~
 : My internal page, no special permissions required.
 : @return HTML page
 :)
declare
  %rest:path("internal/mydata")
  %output:method("html")
function page:mydata() {
  <html>
    <head>
      <title>BaseX My Data</title>
    </head>
    <body>
      <h1>My Session Data</h1>
{
  for $k in session:names()
  return <li>{$k} = <pre>{serialize(session:get($k), map {"indent": "yes"})}</pre></li>
}
    </body>
  </html>
};

(:~ Admin page. :)
declare
  %rest:path("internal/admin")
  %output:method("html")
  %perm:allow("systemSettings")
function page:admin() {
  <html>
    Welcome to the admin page.
  </html>
};

(:~ Viewer page :)
declare
  %rest:path("internal/viewer")
  %output:method("html")
  %perm:allow("viewItem")
function page:viewer() {
  <html>
    Welcome to the viewer page.
  </html>
};

(:~ Editor page :)
declare
  %rest:path("internal/editor")
  %output:method("html")
  %perm:allow("editItem")
function page:editor() {
  <html>
    Welcome to the editor page.
  </html>
};

