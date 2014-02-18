package name.dlazerka.gae.jersey.oauth2;

import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;

import javax.ws.rs.core.SecurityContext;
import java.security.Principal;

public class ProSecurityContext implements SecurityContext {
	private final GoogleIdToken token;

	public ProSecurityContext(GoogleIdToken token) {
		this.token = token;
	}

	@Override
	public Principal getUserPrincipal() {
		return new ProOAuthPrincipal(token);
	}

	@Override
	public boolean isUserInRole(String role) {
		return token.getPayload().getAudienceAsList().contains(role);
	}

	@Override
	public boolean isSecure() {
		// AuthFilter rejects insecure requests.
		return true;
	}

	@Override
	public String getAuthenticationScheme() {
		return "name.dlazerka.pro.gae";
	}

}
