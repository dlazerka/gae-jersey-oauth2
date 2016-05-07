# GAE Jersey OAuth2.0

Authentication using OAuth2.0, integrated with Google App Engine and Jersey servlet container. 


# Set up
1. Add project dependency.

	* Maven:
	```xml
		<dependency>
			<groupId>me.lazerka.gae-jersey-oauth2</groupId>
			<artifactId>gae-jersey-oauth2</artifactId>
			<version>1.2</version>
		</dependency>
	```
	* Gradle:
	```groovy
		compile 'me.lazerka.gae-jersey-oauth2:gae-jersey-oauth2:1.2'
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
