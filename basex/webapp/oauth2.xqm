(:
: OAuth2 permission implementation for BaseX.
:
: Requires the following environment variables to be set:
: - OAUTH2_SERVER_AUTH_URL: the url of the OAuth2 server's authorization endpoint, which must be accessible from the user's browser.
:     E.g. "http://localhost:9011/oauth2/authorize" for FusionAuth or
:     "http://localhost:8080/auth/realms/myrealm/protocol/openid-connect/auth" for Keycloak.
: - OAUTH2_SERVER_LOGOUT_URL: the url of the OAuth2 server's logout endpoint, which must be accessible from RestXQ (not necessarily the browser).
: - OAUTH2_SERVER_TOKEN_URL: the url of the OAuth2 server's token endpoint, which must be accessible from RestXQ (not necessarily the browser).
:     E.g. "http://localhost:9011/oauth2/token" for FusionAuth or "http://localhost:8080/auth/realms/myrealm/protocol/openid-connect/token"
:     for Keycloak.
: - OAUTH2_SERVER_TENANT_ID: the tenant id of the OAuth2 server
: - OAUTH2_CLIENT_ID: this application's client id as configured in the OAuth2 server
: - OAUTH2_CLIENT_SECRET: this application's client secret as configured in the OAuth2 server
:)

module namespace oa = "oauth2";
import module namespace session = "http://basex.org/modules/session";

(:~
 : Redirect to the OAuth2 server authorization endpoint.
 : @param $redirectUri the uri of our page to redirect to after the authorization has been completed. Must be an absolute uri that can be resolved
 :   by the user's browser. Valid redirectUris must have been registered in the OAuth2 server beforehand.
 :)
declare function oa:redirectAuthorize($redirectUri as xs:string) as element(rest:response) {
    let $baseUrl := environment-variable("OAUTH2_SERVER_AUTH_URL")
    let $clientId := environment-variable("OAUTH2_CLIENT_ID")
    let $state := random:uuid()
    let $url := web:create-url($baseUrl, map {
      "response_type": "code",
      "scope": "openid profile email",
      "client_id": $clientId,
      "state": $state,
      "redirect_uri": $redirectUri })
    return (
      session:set('oa:oauth2State', $state),
      web:redirect($url)
    )
};

(:~
 : Decodes the special base64 url encoding, which is used in JWT. It is similar to base64, but uses two different characters and lacks the padding.
 : @param $input the base64 url encoded string
 : @return the base64 string
 :)
declare function oa:base64UrlToUtf8($input as xs:string) as xs:string {
  let $chReplaced := replace(replace($input, '-', '+'), '_', '/')
  let $lm := string-length($input) mod 4
  let $padding :=
    if ($lm = 2) then '=='
    else if ($lm = 3) then '='
    else ''
  return
    bin:decode-string(xs:base64Binary($chReplaced || $padding), 'UTF-8')
};

(:~
 : Decodes a JWT token, but does not verify the signature.
 : @param $input the JWT token
 : @return the decoded JWT token
 :)
declare function oa:parse-jwt($input as xs:string) as element(oa:jwt){
  let $parts := tokenize($input, '\.')
  let $encodedHeader := $parts[1]
  let $encodedContent := $parts[2]
  (: let $signature := $parts[3]  signature is optional :)
  let $jsonHeader := oa:base64UrlToUtf8($encodedHeader)
  let $jsonContent := oa:base64UrlToUtf8($encodedContent)
  return
    <oa:jwt>
      <header>{json:parse($jsonHeader)/*/*}</header>
      <content>{json:parse($jsonContent)/*/*}</content>
    </oa:jwt>
};

(:~
 : After receiving a browser redirect from the OAuth2 server, we validate the incoming request directly with the OAuth2 server's token endpoint
 : and store the resulting user data in the session.
 : @param $code the authorization code received from the OAuth2 server
 : @param $state the state parameter received from the OAuth2 server
 : @param $redirectUri the uri that actually received the incoming request from the OAuth2 server. This should be the same as the one used in
 :   the redirectAuthorize call function, otherwise the OAuth2 server will reject the request.
 :)
declare function oa:completeAuthorizationCodeGrant($code as xs:string, $state as xs:string, $redirectUri as xs:string) as empty-sequence() {
  let $stateSession := session:get('oa:oauth2State')
  return
    if ($state = "" or $state != $stateSession) then
      error(xs:QName("oa:completeAuthorization"), "State mismatch")
    else
      let $requri := environment-variable("OAUTH2_SERVER_TOKEN_URL") 
      let $clientId := environment-variable("OAUTH2_CLIENT_ID")
      let $clientSecret := environment-variable("OAUTH2_CLIENT_SECRET")
      let $request :=
        <http:request method = "post">
          <http:body media-type='application/x-www-form-urlencoded'/>
        </http:request>
      let $body := "grant_type=authorization_code&amp;code=" || encode-for-uri($code)
        || "&amp;redirect_uri=" || encode-for-uri($redirectUri)
        || "&amp;client_id=" || $clientId
        || "&amp;client_secret=" || $clientSecret
      let $response := http:send-request($request, $requri, $body)
      return
        if (not(string($response[1]/@status) = "200")) then
          error(xs:QName("oa:completeAuthorization"), "Unsuccessful http status: " || serialize($response))
        else if (not($response[1]/http:body/@media-type = "application/json")) then
          error(xs:QName("oa:completeAuthorization"), "Unexpected response content type: " || $response[1]/@media-type)
        else
          (: because the response content mime type is application/json, it has been automatically parsed as JSON :)
          let $json := tail($response) 
          let $accessToken := oa:parse-jwt($json/json/access__token)
          let $idToken := oa:parse-jwt($json/json/id__token)
          let $userId := $idToken/content/email/text()
          return (
            session:set('userId', $userId),
            session:set('oa:accessToken', $accessToken),
            session:set('oa:idToken', $idToken),
            session:set('oa:roles', $accessToken/content/roles/*/text())
          )
};

(:~
 : Closes the session and tells the OAuth2 server to invalidate its tokens. We do not use the OAuth2 server's logout redirect but rather do it ourselves.
 :)
declare function oa:logout() as empty-sequence() {
(
  session:close(),
  let $tenantId := environment-variable("OAUTH2_SERVER_TENANT_ID")
  let $clientId := environment-variable("OAUTH2_CLIENT_ID")
  let $baseUrl := environment-variable("OAUTH2_SERVER_LOGOUT_URL")
  let $request :=
    <http:request method = "post" />
  let $url := web:create-url($baseUrl, map {
    "tenantId": $tenantId,
    "client_id": $clientId })
  let $response := http:send-request($request, $url)
  return
    if (xs:integer($response[1]/@status) >= 400) then
      message(("Failed loging out from OAuth2 server: ", $response))
) => void()
};
