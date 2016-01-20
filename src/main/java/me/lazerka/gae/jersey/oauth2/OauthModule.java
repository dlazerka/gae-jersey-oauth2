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

import com.google.api.client.extensions.appengine.http.UrlFetchTransport;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdTokenVerifier;
import com.google.api.client.json.JsonFactory;
import com.google.api.client.json.jackson2.JacksonFactory;
import com.google.common.collect.ImmutableSet;
import com.google.common.io.Files;
import com.google.inject.AbstractModule;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.Set;

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;
import static java.nio.charset.StandardCharsets.UTF_8;

/**
 * Configuration needed for OAuth web authentication.
 *
 * @author Dzmitry Lazerka
 */
public class OauthModule extends AbstractModule {
	private static final Logger logger = LoggerFactory.getLogger(OauthModule.class);

	private static final Set<String> ALLOWED_ISSUERS = ImmutableSet.of(
			"accounts.google.com",
			"https://accounts.google.com");

	/** Default location of Client ID */
	private static final String CLIENT_ID_FILE_PATH = "WEB-INF/keys/oauth.client_id.key";

	private String clientId;
	private Method method;

	public enum Method {
		/** Verifies token signature using Google public key. */
		SIGNATURE,
		/** Verifies token signature by making HTTPS call to Google servers. */
		REMOTE
	}

	/** Reads Client ID from file {@link #CLIENT_ID_FILE_PATH}. */
	public OauthModule() {
		this(new File(CLIENT_ID_FILE_PATH));
	}

	/** Reads Client ID from file {@link #CLIENT_ID_FILE_PATH}. */
	public OauthModule(File file) {
		this(readClientIdFile(file), Method.SIGNATURE);
	}

	/**
	 * @param clientId Issued by authorization server.
	 */
	public OauthModule(String clientId, Method method) {
		checkArgument(clientId.endsWith(".apps.googleusercontent.com"), "Must end with '.apps.googleusercontent.com'");
		this.clientId = checkNotNull(clientId);
		this.method = checkNotNull(method);
	}

	@Override
	protected void configure() {
		if (method == Method.SIGNATURE) {

			GoogleIdTokenVerifier tokenVerifier = createTokenVerifier(clientId, JacksonFactory.getDefaultInstance());
			bind(GoogleIdTokenVerifier.class).toInstance(tokenVerifier);

			bind(TokenVerifier.class).to(TokenVerifierSignature.class);

		} else if (method == Method.REMOTE) {

			bind(String.class)
					.annotatedWith(OauthClientId.class)
					.toInstance(clientId);

			bind(JsonFactory.class).toInstance(JacksonFactory.getDefaultInstance());
			bind(TokenVerifier.class).to(TokenVerifierRemote.class);

		} else {
			throw new IllegalArgumentException(method.toString());
		}
	}

	private GoogleIdTokenVerifier createTokenVerifier(String oauthClientId, JsonFactory jsonFactory) {
		logger.trace("Creating " + GoogleIdTokenVerifier.class.getSimpleName());
		UrlFetchTransport transport = new UrlFetchTransport.Builder()
				.validateCertificate()
				.build();
		return new GoogleIdTokenVerifier.Builder(transport, jsonFactory)
				.setAudience(ImmutableSet.of(oauthClientId))
				.setIssuers(ALLOWED_ISSUERS)
				.build();
	}

	/**
	 * Reads whole file as a string.
	 */
	static String readClientIdFile(File file) {
		logger.trace("Reading {}", file.getAbsolutePath());

		String notFoundMsg = "Put there OAuth2.0 Client ID obtained as described here " +
				"https://developers.google.com/identity/sign-in/android/";

		try {
			String result = Files.toString(file, UTF_8)
					.trim();
			if (result.isEmpty()) {
				throw new RuntimeException("File is empty: " + file.getAbsolutePath() + " " + notFoundMsg);
			}

			return result;
		} catch (FileNotFoundException e) {
			throw new RuntimeException("File " + file.getAbsolutePath() + " not found. " + notFoundMsg);
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}
}
