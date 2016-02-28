# GAE Jersey OAuth2.0

Authentication using OAuth2.0, integrated with Google App Engine and Jersey servlet container. 


# Set up
1. Add project dependency.

	* Maven: 
	```xml 
		<dependency>
			<groupId>me.lazerka.gae-jersey-oauth2</groupId>
			<artifactId>gae-jersey-oauth2</artifactId>
			<version>1.0-beta2</version>
		</dependency>
	```
	* Gradle: 
	```groovy
		compile 'me.lazerka.gae-jersey-oauth2:gae-jersey-oauth2:1.0-beta2'
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
Annotate your resources with standard javax.annotation.security.*:
* `@RolesAllowed(Role.USER)`
* `@RolesAllowed(Role.ADMIN)`,
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

Note that resources annotated with `@PermitAll` do not get any principal set.
