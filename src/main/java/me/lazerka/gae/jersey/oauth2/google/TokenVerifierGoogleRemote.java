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

import com.google.api.client.auth.oauth2.TokenErrorResponse;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken.Payload;
import com.google.api.client.json.JsonFactory;
import com.google.appengine.api.urlfetch.HTTPRequest;
import com.google.appengine.api.urlfetch.HTTPResponse;
import com.google.appengine.api.urlfetch.URLFetchService;
import com.google.common.base.Stopwatch;
import me.lazerka.gae.jersey.oauth2.facebook.BasicTokenVerifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Singleton;
import javax.ws.rs.core.UriBuilder;
import java.io.IOException;
import java.net.URI;
import java.net.URL;
import java.security.InvalidKeyException;
import java.util.Collections;
import java.util.Set;
import java.util.concurrent.TimeUnit;

import static com.google.appengine.api.urlfetch.FetchOptions.Builder.validateCertificate;
import static com.google.appengine.api.urlfetch.HTTPMethod.GET;
import static java.nio.charset.StandardCharsets.UTF_8;

/**
 * Filter that verifies token by making HTTPS call to Google endpoint, so Google servers verify it.
 *
 * This MUST be done through HTTPS.
 *
 * Documentation: https://developers.google.com/identity/sign-in/android/backend-auth
 *
 * @author Dzmitry Lazerka
 */
@Singleton
public class TokenVerifierGoogleRemote extends BasicTokenVerifier {
	private static final Logger logger = LoggerFactory.getLogger(TokenVerifierGoogleRemote.class);

	public static final String AUTH_SCHEME = "GoogleSignIn/Remote";

	private static final URI TOKEN_INFO = URI.create("https://www.googleapis.com/oauth2/v3/tokeninfo");

	final URLFetchService urlFetchService;
	final JsonFactory jsonFactory;
	final String oauthClientId;

	public TokenVerifierGoogleRemote(URLFetchService urlFetchService, JsonFactory jsonFactory, String oauthClientId) {
		this.urlFetchService = urlFetchService;
		this.jsonFactory = jsonFactory;
		this.oauthClientId = oauthClientId;
	}

	@Override
	public GoogleUserPrincipal verify(String authToken) throws IOException, InvalidKeyException {
		logger.trace("Requesting endpoint to validate token");

		URL url = UriBuilder.fromUri(TOKEN_INFO)
				.queryParam("id_token", authToken)
				.build()
				.toURL();

		HTTPRequest httpRequest = new HTTPRequest(url, GET, validateCertificate());

		Stopwatch stopwatch = Stopwatch.createStarted();
		HTTPResponse response = urlFetchService.fetch(httpRequest);
		logger.debug("Remote call took {}ms", stopwatch.elapsed(TimeUnit.MILLISECONDS));

		int responseCode = response.getResponseCode();
		String content = new String(response.getContent(), UTF_8);

		if (responseCode != 200) {
			logger.warn("{}: {}", responseCode, content);

			String msg = "Endpoint response code " + responseCode;

			// Something is wrong with our request.
			// If signature is invalid, then response code is 403.
			if (responseCode >= 400 && responseCode < 500) {
				try {
					TokenErrorResponse tokenErrorResponse = jsonFactory.fromString(content, TokenErrorResponse.class);
					msg += ": " + tokenErrorResponse.getErrorDescription();
				} catch (IOException e) {
					logger.warn("Cannot parse response as " + TokenErrorResponse.class.getSimpleName());
				}
			}

			throw new InvalidKeyException(msg);
		}

		// Signature verification is done remotely (the whole point of this class).
		// Expiration verification is done

		Payload payload = jsonFactory.fromString(content, Payload.class);

		// Issuers verification have been done remotely.

		Set<String> trustedClientIds = Collections.singleton(oauthClientId);
		// Note containsAll.
		if (!trustedClientIds.containsAll(payload.getAudienceAsList())) {
			throw new InvalidKeyException("Audience invalid");
		}

		if (!payload.getEmailVerified()) {
			throw new InvalidKeyException("Email not verified");
		}

		return new GoogleUserPrincipal(payload.getSubject(), payload.getEmail());
	}

	@Override
	public String getAuthenticationScheme() {
		return AUTH_SCHEME;
	}
}
