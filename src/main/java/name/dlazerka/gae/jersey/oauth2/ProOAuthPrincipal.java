package name.dlazerka.gae.jersey.oauth2;

import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;

import java.security.Principal;

public class ProOAuthPrincipal implements Principal {
	private final GoogleIdToken token;

	public ProOAuthPrincipal(GoogleIdToken token) {
		this.token = token;
	}

	@Override
	public String getName() {
		// Not email, because it's not recommended to count on email.
		return token.getPayload().getSubject();
	}

	public GoogleIdToken getToken() {
		return token;
	}

	public String getEmail() {
		return token.getPayload().getEmail();
	}
}
