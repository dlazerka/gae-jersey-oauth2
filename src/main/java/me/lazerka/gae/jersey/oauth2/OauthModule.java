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
import com.google.api.client.googleapis.auth.oauth2.GoogleIdTokenVerifier.Builder;
import com.google.api.client.json.JsonFactory;
import com.google.api.client.json.jackson2.JacksonFactory;
import com.google.common.collect.ImmutableSet;
import com.google.common.io.Files;
import com.google.inject.AbstractModule;
import com.google.inject.Key;
import com.google.inject.Provides;
import com.google.inject.name.Names;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Singleton;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.Set;

import static java.nio.charset.StandardCharsets.UTF_8;

/**
 * Configuration needed for OAuth web authentication.
 *
 * @author Dzmitry Lazerka
 */
public class OauthModule extends AbstractModule {
	private static final Logger logger = LoggerFactory.getLogger(OauthModule.class);

	public static final String OAUTH_CLIENT_ID = "oauth.client.id";
	public static final Set<String> ALLOWED_ISSUERS = ImmutableSet.of(
			"accounts.google.com",
			"https://accounts.google.com");

	@Override
	protected void configure() {
		// Read config files early, so that errors would pop up on startup.
		bind(Key.get(String.class, Names.named(OAUTH_CLIENT_ID)))
				.toInstance(readOauthClientId());

		// Choose between verification methods.
		bind(TokenVerifier.class).to(TokenVerifierSignature.class);
		//bind(AuthFilter.class).to(TokenVerifierRemote.class);
	}

	@Inject
	@Provides
	@Singleton
	GoogleIdTokenVerifier createTokenVerifier(
			@Named(OAUTH_CLIENT_ID) String oauthClientId,
			JsonFactory jsonFactory
	) {
		logger.trace("Creating " + GoogleIdTokenVerifier.class.getSimpleName());
		UrlFetchTransport transport = new UrlFetchTransport.Builder()
				.validateCertificate()
				.build();
		return new Builder(transport, jsonFactory)
				.setAudience(ImmutableSet.of(oauthClientId))
				.setIssuers(ALLOWED_ISSUERS)
				.build();
	}

	@Provides
	@Singleton
	JsonFactory getJsonFactory() {
		return JacksonFactory.getDefaultInstance();
	}

	String readOauthClientId() {
		File file = new File("WEB-INF/keys/oauth.client_id.key");
		String notFoundMsg = "Put there OAuth2.0 Client ID obtained as described here " +
				"https://developers.google.com/identity/sign-in/android/";

		String result = readKeyFile(file, notFoundMsg);

		if (!result.endsWith(".apps.googleusercontent.com")) {
			throw new RuntimeException("Must end with '.apps.googleusercontent.com'");
		}

		return result;
	}

	/**
	 * Reads whole file as a string.
	 */
	static String readKeyFile(File file, String notFoundMsg) {
		logger.trace("Reading {}", file.getAbsolutePath());
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
