package name.dlazerka.gae.jersey.oauth2;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.api.client.extensions.appengine.http.UrlFetchTransport;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdTokenVerifier;
import com.google.api.client.json.gson.GsonFactory;
import com.google.appengine.api.urlfetch.URLFetchService;
import com.google.appengine.api.users.UserService;
import com.google.appengine.api.utils.SystemProperty;
import com.google.appengine.api.utils.SystemProperty.Environment.Value;
import com.google.appengine.repackaged.com.google.common.collect.Sets;
import com.google.appengine.repackaged.com.google.common.collect.Sets.SetView;
import com.google.common.collect.ImmutableSet;
import com.sun.jersey.spi.container.ContainerRequest;
import com.sun.jersey.spi.container.ContainerRequestFilter;
import com.sun.jersey.spi.container.ContainerResponseFilter;
import com.sun.jersey.spi.container.ResourceFilter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nonnull;
import javax.inject.Inject;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.Cookie;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URI;
import java.security.GeneralSecurityException;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static com.google.appengine.api.utils.SystemProperty.Environment.Value.Development;

public class AuthFilter implements ResourceFilter, ContainerRequestFilter {
	private static final String COOKIE_NAME_AUTH_TOKEN = "authToken";
	private final Logger logger = LoggerFactory.getLogger(AuthFilterFactory.class);

	/**
	 * Allow if user is admin, according to default GAE authentication.
	 */
	public static final String ADMIN_ROLE = "admin";

	/**
	 * Allow if on development server.
	 */
	public static final String DEV_ROLE = "dev";

	@Inject
	UserService userService;

	@Inject
	URLFetchService urlFetchService;

	@Inject
	ObjectMapper objectMapper;

	GoogleIdTokenVerifier tokenVerifier = new GoogleIdTokenVerifier(
			new UrlFetchTransport(), GsonFactory.getDefaultInstance());

	private Set<String> roles;

	protected void setRoles(Set<String> roles) {
		this.roles = roles;
	}

	private boolean isAdminAllowed() {
		return this.roles.contains(ADMIN_ROLE);
	}

	// Development server
	private boolean isDevAllowed() {
		return this.roles.contains(DEV_ROLE);
	}

	@Override
	@Nonnull
	public ContainerRequest filter(ContainerRequest request) {
		// Don't allow HTTP, unless on local.
		Value env = SystemProperty.environment.value();
		if (isDevAllowed() && env.equals(Development)) {
			logger.info("Dev auth, OK: " + request);
			return request;
		}

		// Deny all HTTP requests (@PermitAll requests do not come here at all).
		if (!request.isSecure() && !env.equals(Development)) {
			logger.warn("Insecure auth, Deny: " + request);
			throw getForbiddenException(request, "Request insecure");
		}

		if (isAdminAllowed() && userService.isUserLoggedIn() && userService.isUserAdmin()) {
			logger.info("Admin auth, OK: " + request);
			return request;
		}

		if (roles.isEmpty()) {
			throw getForbiddenException(request, "Forbidden");
		}

		return request;
		//return checkCookie(request);
	}

	private ContainerRequest checkCookie(ContainerRequest request) {
		Map<String,Cookie> cookies = request.getCookies();
		Cookie cookie = cookies.get(COOKIE_NAME_AUTH_TOKEN);
		if (cookie == null) {
			logger.warn("No authToken auth, Deny: " + request);
			throw getForbiddenException(request, "No Auth Token");
		}
		String authToken = cookie.getValue();
		try {
			return verify(authToken, request);
		} catch (MalformedURLException e) {
			logger.error("Hacker's sent malformed token: {}", authToken, e);
		} catch (IOException e) {
			logger.error("Error fetching url", e);
		}

		throw getForbiddenException(request, "Error verifying token");
	}

	private ContainerRequest verify(String authToken, ContainerRequest request) throws IOException {
		GoogleIdToken token;
		try {
			token = tokenVerifier.verify(authToken);
		} catch (GeneralSecurityException e) {
			logger.warn("Excepting while verifying token", e);
			throw getForbiddenException(request, "Excepting while verifying token");
		}
		if (token == null) {
			logger.info("Token invalid");
			throw getForbiddenException(request, "Token invalid");
		}
		List<String> audiences = token.getPayload().getAudienceAsList();
		SetView<String> intersection = Sets.intersection(roles, ImmutableSet.copyOf(audiences));
		if (intersection.isEmpty()) {
			throw getForbiddenException(request, "Token audiences in not in allowed roles list: " + audiences);
		}

		addUserContextToRequest(request, token);

		return request;
	}

	private void addUserContextToRequest(ContainerRequest request, GoogleIdToken token) {
		request.setSecurityContext(new ProSecurityContext(token));
	}

	/*
	private verifyHttp() {
		// You can also verify with "/tokeninfo"
		//URL url = new URL("https://www.googleapis.com/auth/userinfo.email?access_token=" + authToken);
		URL tokenInfoUrl = new URL("https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=" + authToken);
		Future<HTTPResponse> tokenInfoFuture = urlFetchService.fetchAsync(tokenInfoUrl);

		URL url = new URL("https://www.googleapis.com/oauth2/v1/userinfo?alt=json&access_token=" + authToken);
		HTTPResponse response = urlFetchService.fetch(url);
		int responseCode = response.getResponseCode();
		String content = new String(response.getContent(), Charsets.UTF_8);
		logger.debug("{}: {}", responseCode, content);

		if (responseCode != 200) {
			throw getForbiddenException(request, content);
		}

		JsonNode tree = objectMapper.readTree(content);
		checkState(!tree.hasNonNull("error"));
		String email = tree.get("email").asText();
		request.setSecurityContext(new );
	}
	*/

	private WebApplicationException getForbiddenException(ContainerRequest request, String reason) {
		List<String> loginReturnUrls = request.getRequestHeader("X-Login-Return-Url");
		String loginReturnUrl;
		if (loginReturnUrls == null || loginReturnUrls.isEmpty()) {
			loginReturnUrl = request.getRequestUri().toASCIIString();
		} else {
			loginReturnUrl = URI.create(loginReturnUrls.get(0)).toASCIIString();
		}
		String url = userService.createLoginURL(loginReturnUrl);

		Response response = Response
				.status(Status.FORBIDDEN)
				.type(MediaType.APPLICATION_JSON_TYPE)
				.entity(reason)
				.header("X-Login-URL", url)
				.build();
		return new WebApplicationException(response);
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
		return roles.isEmpty() ? "FORBIDDEN" : roles.toString();
	}
}
