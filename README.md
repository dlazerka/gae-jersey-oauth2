# GAE Jersey OAuth2.0

Authentication using OAuth, integrated with Google App Engine and Jersey 1.x servlet container.

Includes token verifiers for <b>Google Sign In</b> and <b>Facebook Login</b>, but you can specify your own
implementation.

Extensible as much as possible, so you can swap any class with your own implementation.



# Set up
1. Add project dependency.

	* Maven:
	```xml
		<dependency>
			<groupId>me.lazerka.gae-jersey-oauth2</groupId>
			<artifactId>gae-jersey-oauth2</artifactId>
			<version>2.2</version>
		</dependency>
	```
	* Gradle:
	```groovy
		compile 'me.lazerka.gae-jersey-oauth2:gae-jersey-oauth2:2.2'
	```
2. Install Guice module:

	```java
	install(new OauthModule());
	```
	See available OauthModule constructors.
3. Add Jersey parameter:

	```java
	parameters.put(ResourceConfig.PROPERTY_RESOURCE_FILTER_FACTORIES, AuthFilterFactory.class.getName())
	```


# Usage
Annotate your resources with one of standard `javax.annotation.security.*` annotations:
* `@RolesAllowed(Role.USER)`
* `@RolesAllowed(Role.ADMIN)`
* `@RolesAllowed(Role.OPTIONAL)`
* `@PermitAll`
* `@DenyAll`

To get current user credentials:
```java
import me.lazerka.gae.jersey.oauth2.UserPrincipal;
import javax.annotation.Nullable;
import javax.ws.rs.core.SecurityContext;

public class UserService {
	@Inject
	SecurityContext securityContext;

	@Nullable
	public UserPrincipal getCurrentUserPrincipal() {
		return (UserPrincipal) securityContext.getUserPrincipal();
	}
}
```

Resources annotated with `@PermitAll` do not even check authentication,
so resources annotated with it will not get any `SecurityContext` even if user is
authenticated. See `Role.OPTIONAL`.

# Customize
You can swap pretty much anything with your own implementation:
* `OauthModule` is optional, feel free to use your own. 
* `AuthFilterFactory` can be customized by providing your own implementation to Jersey parameters.
* `AuthFilter` can be customized by binding your own implementation in Guice module: 
`bind(AuthFilter.class).to(MyAuthFilter.class);`.
* You can add other providers by adding your own `TokenVerifier`s using Guice Multibindings 
(see example `OauthModule`). 
