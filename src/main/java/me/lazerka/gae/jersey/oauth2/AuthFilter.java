/*
 * Copyright (c) 2016 Dzmitry Lazerka
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package me.lazerka.gae.jersey.oauth2;

import com.google.appengine.api.users.User;
import com.google.appengine.api.users.UserService;
import com.google.appengine.api.utils.SystemProperty;
import com.google.appengine.api.utils.SystemProperty.Environment.Value;
import com.google.common.base.MoreObjects;
import com.google.common.collect.ImmutableSet;
import com.sun.jersey.spi.container.ContainerRequest;
import com.sun.jersey.spi.container.ContainerRequestFilter;
import com.sun.jersey.spi.container.ContainerResponseFilter;
import com.sun.jersey.spi.container.ResourceFilter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.inject.Inject;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;
import java.io.IOException;
import java.net.URI;
import java.security.GeneralSecurityException;
import java.util.List;
import java.util.Set;

import static com.google.appengine.api.utils.SystemProperty.Environment.Value.Development;
import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.base.Preconditions.checkState;

/**
 * Checks requests whether they are authenticated using either GAE or OAuth authentication.
 *
 * @see <a href="https://developers.google.com/identity/sign-in/android/backend-auth">documentation</a>.
 * @author Dzmitry Lazerka
 */
public class AuthFilter implements ResourceFilter, ContainerRequestFilter {
	private static final Logger logger = LoggerFactory.getLogger(AuthFilter.class);

	public static final String PROVIDER_HEADER = "X-Authorization-Provider";

	@Inject
	Set<TokenVerifier> tokenVerifiers;

	@Inject
	UserService userService;

	Set<String> rolesAllowed;

	protected void setRolesAllowed(Set<String> rolesAllowed) {
		this.rolesAllowed = rolesAllowed;
	}

	private boolean isDevServer() {
		Value env = SystemProperty.environment.value();
		return env.equals(Development);
	}

	@Override
	@Nonnull
	public ContainerRequest filter(ContainerRequest request) {
		checkNotNull(rolesAllowed);
		checkState(!tokenVerifiers.isEmpty(), "No tokenVerifiers configured");

		AuthSecurityContext securityContext = getSecurityContext(request);

		for(String roleAllowed : rolesAllowed) {
			if (securityContext.isUserInRole(roleAllowed)) {
				request.setSecurityContext(securityContext);
				return request;
			}
		}

		UserPrincipal principal = securityContext.getUserPrincipal();
		logger.warn("User {} not in roles {}", principal, rolesAllowed);

		throw new WebApplicationException(getForbiddenResponse("Not Authorized"));
	}

	private AuthSecurityContext getSecurityContext(ContainerRequest request) {
		// Deny all insecure requests on production (@PermitAll requests do not come here at all).
		if (!request.isSecure() && !isDevServer()) {
			logger.warn("Insecure auth, Deny: " + request);
			return throwUnauthenticatedIfNotOptional(request, "Request insecure", null);
		}

		// Check regular GAE authentication.
		if (userService.isUserLoggedIn()) {
			return useGaeAuthentication(request);
		}

		// Check OAuth authentication.
		String authorizationHeader = request.getHeaderValue("Authorization");
		if (authorizationHeader == null) {
			logger.warn("No credentials provided for {}", request.getPath());
			return throwUnauthenticatedIfNotOptional(request, "No credentials provided", null);
		}

		if (authorizationHeader.startsWith("Bearer ")) {
			String token = authorizationHeader.substring("Bearer ".length());
			return useOauthAuthentication(request, token);
		} else {
			logger.warn("Authorization should use Bearer protocol {}", request.getPath());
			return throwUnauthenticatedIfNotOptional(request, "Not Bearer Authorization", null);
		}
	}

	private AuthSecurityContext useOauthAuthentication(ContainerRequest request, String token) {
		TokenVerifier tokenVerifier = findTokenVerifier(request);

		if (tokenVerifier == null) {
			return throwUnauthenticatedIfNotOptional(request, "Cannot found suitable TokenVerifier", null);
		}

		logger.trace("Authenticating OAuth2.0 user...");
		try {
			UserPrincipal userPrincipal = tokenVerifier.verify(token);
			return new AuthSecurityContext(
					userPrincipal,
					request.isSecure(),
					ImmutableSet.of(Role.USER, Role.OPTIONAL),
					tokenVerifier.getAuthenticationScheme()
			);
		} catch (GeneralSecurityException e) {
			logger.info(e.getClass().getName() + ": " + e.getMessage());
			return throwUnauthenticatedIfNotOptional(request, "Invalid OAuth2.0 token", e);
		} catch (IOException e) {
			logger.error("IOException verifying OAuth token", e);
			return throwUnauthenticatedIfNotOptional(request, "Error verifying OAuth2.0 token", e);
		}
	}

	private TokenVerifier findTokenVerifier(ContainerRequest request) {
		String provider = request.getHeaderValue(PROVIDER_HEADER);
		for (TokenVerifier tokenVerifier : tokenVerifiers) {
			if (tokenVerifier.canHandle(provider)) {
				return tokenVerifier;
			}
		}

		logger.warn("No TokenVerifier for provider {}", provider);
		return null;
	}

	private AuthSecurityContext useGaeAuthentication(ContainerRequest request) {
		Set<String> roles = userService.isUserAdmin()
				? ImmutableSet.of(Role.USER, Role.ADMIN, Role.OPTIONAL)
				: ImmutableSet.of(Role.USER, Role.OPTIONAL);

		User user = userService.getCurrentUser();
		UserPrincipal userPrincipal = new UserPrincipal(user.getUserId(), user.getEmail());
		return new AuthSecurityContext(
				userPrincipal,
				request.isSecure(),
				roles,
				"GAE"
		);
	}

	/**
	 * Throws 401 Unauthorized, or, if {@link #rolesAllowed} contains {@link Role#OPTIONAL}, returns context.
	 *
	 * @throws WebApplicationException with Status.UNAUTHORIZED (401).
	 */
	protected AuthSecurityContext throwUnauthenticatedIfNotOptional(
			ContainerRequest request,
			String reason,
			@Nullable Exception cause
	) {
		// In case request is AJAX, we want to tell client how to authenticate user.
		String loginUrl = composeLoginUrl(request);

		Response response = Response
				.status(Status.UNAUTHORIZED)
				.type(MediaType.TEXT_PLAIN_TYPE)
				.header("X-Login-URL", loginUrl)
				.entity(reason)
				.build();

		if (rolesAllowed.contains(Role.OPTIONAL)) {
			return new AuthSecurityContext(
								null,
								request.isSecure(),
								ImmutableSet.of(Role.OPTIONAL),
								"OAuth2.0"
						);
		}

		throw new WebApplicationException(cause, response);
	}

	protected Response getForbiddenResponse(String reason) {
		return Response
				.status(Status.FORBIDDEN)
				.type(MediaType.TEXT_PLAIN_TYPE)
				.entity(reason)
				.build();
	}

	protected String composeLoginUrl(ContainerRequest request) {
		List<String> loginReturnUrls = request.getRequestHeader("X-Login-Return-Url");
		String loginReturnUrl;
		if (loginReturnUrls == null || loginReturnUrls.isEmpty()) {
			loginReturnUrl = request.getRequestUri().toASCIIString();
		} else {
			loginReturnUrl = URI.create(loginReturnUrls.get(0)).toASCIIString();
		}
		return userService.createLoginURL(loginReturnUrl);
	}

	@Override
	public ContainerRequestFilter getRequestFilter() {
		return this;
	}

	@Override
	public ContainerResponseFilter getResponseFilter() {
		return null;
	}

	@Override
	public String toString() {
		return MoreObjects.toStringHelper(this)
				.add("rolesAllowed", rolesAllowed)
				.toString();
	}
}
