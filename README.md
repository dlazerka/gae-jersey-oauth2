# GAE Jersey OAuth2.0

Authentication using OAuth2.0, integrated with Google App Engine and Jersey servlet container. 


# Set up
1. Add project dependency on `me.lazerka.gae-jersey-oauth2:gae-jersey-oauth2:1.0-beta2`.
2. In your Guice module: add `install(new OauthModule());`. See available OauthModule constructors.
3. In your Jersey parameters: add
`parameters.put(ResourceConfig.PROPERTY_RESOURCE_FILTER_FACTORIES, AuthFilterFactory.class.getName())`.


# Usage
Annotate your resources with standard javax.annotation.security.*:
* `@RolesAllowed(Role.USER)`
* `@RolesAllowed(Role.ADMIN)`,
* `@PermitAll`
* `@DenyAll`

To get current user credentials:

	import javax.ws.rs.core.SecurityContext;
	import me.lazerka.gae.jersey.oauth2.UserPrincipal;

	public class UserService {
		@Inject
		SecurityContext securityContext;

		private UserPrincipal getCurrentOauthUser() {
			return (UserPrincipal) checkNotNull(securityContext.getUserPrincipal());
        }

        public MyUser getCurrentUser() {
            UserPrincipal oauthUser = getCurrentOauthUser();
            ...
        }
    }


Note that resources annotated with `@PermitAll` do not get any principal set.
