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

import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken.Payload;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdTokenVerifier;
import org.joda.time.DateTime;

import javax.inject.Inject;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;

import static org.joda.time.DateTimeZone.UTC;

/**
 * Filter that verifies OAuth token using public key signature check.
 *
 * Utilizes google-api-client for that.
 *
 * @see <a href="https://developers.google.com/identity/sign-in/android/backend-auth">documentation</a>.
 * @author Dzmitry Lazerka
 */
public class TokenVerifierSignature implements TokenVerifier {
	@Inject
	GoogleIdTokenVerifier tokenVerifier;

	DateTime now = DateTime.now(UTC);

	@Override
	public UserPrincipal verify(String token) throws IOException, GeneralSecurityException {

		GoogleIdToken idToken;
		try {
			idToken = GoogleIdToken.parse(tokenVerifier.getJsonFactory(), token);
		} catch (IllegalArgumentException e) {
			throw new InvalidKeyException("Cannot parse token as JWS");
		}

		if (!tokenVerifier.verify(idToken)) {
			String email = idToken.getPayload().getEmail();

			// Give meaningful message for the most common case.
			if (!idToken.verifyTime(now.getMillis(), tokenVerifier.getAcceptableTimeSkewSeconds())) {
				throw new InvalidKeyException("Token expired for allegedly " + email);
			}

			throw new InvalidKeyException("Invalid token for allegedly " + email);
		}

		Payload payload = idToken.getPayload();
		return new UserPrincipal(payload.getSubject(), payload.getEmail());
	}
}
