# OAuth2 permission checks for BaseX RESTXQ
This is an implementation of OAuth2 permission checking in BaseX' RESTXQ with a fully working docker compose example. Instead of reinventing the wheel all over again, it is convenient to reuse one of the many services available to handle user accounts and registration workflows. This could be a self-hosted service as shown in this example setup, an external trusted (social) ID provider like Google, Facebook or Github or a mix of both for which your self-hosted instance forwards the request to a social provider if the user has one, but also offers a registration of its own.
If you are in an environment with multiple different services, OAuth will also allow you to authenticate with a single sign on (SSO) into your application.
There are many freely available OAuth providers, e.g. [Keycloak](https://www.keycloak.org/), [SuperTokens](https://supertokens.com) or [Authentik](https://goauthentik.io/). Some are more open source / free like Keycloak, others might provide better (paid) support. For this example setup, we have chosen [FusionAuth](https://fusionauth.io) because it is well documented and maintained, offers all basic functionality we need for free, but also  offers paid enterprise features that may come in handy if the infrastructure grows. Since OAuth2 / OpenID is standardized, the shown approach should work with other authentication providers, too, but currently it is only tested in the given combination. 

## Setup

We use roughly the same setup as in [FusionAuth's 5-Minute Guide](https://fusionauth.io/docs/quickstarts/5-minute-docker). But instead of a Node application, we provide our own RestXQ app.

* Copy the sample.env file to .env. Leave the values as they are for now.
* Startup the docker compose file. The initial startup may take a while:
```
sudo docker compose up -d
```
* Access FusionAuth via http://localhost:9011
* Accept the license agreement and setup the FusionAuth instance with an admin account
* Create an application in FusionAuth's admin panel.
  * Name it "basex-auth-example" or as you like.
  * Add the following roles: "admin" (super role), "viewer", "editor"
  * In the "OAuth" tab, set
    * Authorized redirect URLs: "http://localhost:8884/oauth-redirect"
    * Enabled grants: "Authorization Code" (should be active already)
    * Require registration: True
  * In the "Registration" tab
    * Self-service registration: True
    * Login type: email
    * Registration Fields: First name, last name
  * Save the application
* Register the admin account for the application: Users / admin user / action "manage" / tab "Registrations" / "add registration". Select role "admin" and save the user.
* Edit the .env file and set the following values from the admin panel: OAUTH2_SERVER_TENANT_ID, OAUTH2_CLIENT_ID, OAUTH2_CLIENT_SECRET
* Restart the docker compose file ("restart" will not suffice):
```
sudo docker compose down
sudo docker compose up -d
```
* With a different browser or in incognito mode access the RestXQ site at http://localhost:8884
* Click "Create an account" and register a new user.
* You now have access to the "My data page" but not to the "View item" or "Edit item" pages.
* With your logged in admin user in the FusionAuth admin panel edit the other user's registration and add the role "viewer".
* Log the other user out and back in. Now you can access the "View item" page.

