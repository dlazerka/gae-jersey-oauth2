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

package me.lazerka.gae.jersey.oauth2.google;

import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken.Payload;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdTokenVerifier;
import me.lazerka.gae.jersey.oauth2.facebook.BasicTokenVerifier;
import org.joda.time.DateTime;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Provider;
import javax.inject.Singleton;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;

/**
 * Verifies OAuth token using public key signature check.
 *
 * Utilizes google-api-client for that.
 *
 * @see <a href="https://developers.google.com/identity/sign-in/android/backend-auth">documentation</a>.
 * @author Dzmitry Lazerka
 */
@Singleton
public class TokenVerifierGoogleSignature extends BasicTokenVerifier {
	private static final Logger logger = LoggerFactory.getLogger(TokenVerifierGoogleSignature.class);

	public static final String AUTH_SCHEME = "GoogleSignIn/Signature";

	final GoogleIdTokenVerifier verifier;
	final Provider<DateTime> nowProvider;

	public TokenVerifierGoogleSignature(
			GoogleIdTokenVerifier verifier,
			Provider<DateTime> nowProvider
	) {
		this.verifier = verifier;
		this.nowProvider = nowProvider;
	}

	@Override
	public GoogleUserPrincipal verify(String token) throws IOException, GeneralSecurityException {

		GoogleIdToken idToken;
		try {
			idToken = GoogleIdToken.parse(verifier.getJsonFactory(), token);
		} catch (IllegalArgumentException e) {
			throw new InvalidKeyException("Cannot parse token as JWS");
		}

		if (!verifier.verify(idToken)) {
			String email = idToken.getPayload().getEmail();

			// Give meaningful message for the most common case.
			DateTime now = nowProvider.get();
			if (!idToken.verifyTime(now.getMillis(), verifier.getAcceptableTimeSkewSeconds())) {
				throw new InvalidKeyException("Token expired for allegedly " + email);
			}

			throw new InvalidKeyException("Invalid token for allegedly " + email);
		}

		Payload payload = idToken.getPayload();
		return new GoogleUserPrincipal(payload.getSubject(), payload.getEmail());
	}

	@Override
	public String getAuthenticationScheme() {
		return AUTH_SCHEME;
	}
}
