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

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.api.client.extensions.appengine.http.UrlFetchTransport;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdTokenVerifier;
import com.google.api.client.googleapis.auth.oauth2.GooglePublicKeysManager;
import com.google.api.client.json.jackson2.JacksonFactory;
import com.google.appengine.api.urlfetch.URLFetchServiceFactory;
import com.google.common.collect.ImmutableSet;
import com.google.common.io.Files;
import com.google.inject.AbstractModule;
import com.google.inject.multibindings.Multibinder;
import com.google.inject.name.Names;
import me.lazerka.gae.jersey.oauth2.facebook.TokenVerifierFacebookDebugToken;
import me.lazerka.gae.jersey.oauth2.google.TokenVerifierGoogleSignature;
import org.joda.time.DateTime;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nonnull;
import javax.inject.Provider;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.Set;

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.joda.time.DateTimeZone.UTC;

/**
 * Configures Google and Facebook token verifiers.
 *
 * You do not have to use this module.
 * Here's only one important binding: `Set<TokenVerifier>` -- you can bind your own.
 *
 * @author Dzmitry Lazerka
 */
public class OauthModule extends AbstractModule {
	private static final Logger logger = LoggerFactory.getLogger(OauthModule.class);

	private static final Set<String> ALLOWED_ISSUERS = ImmutableSet.of(
			"accounts.google.com",
			"https://accounts.google.com");

	private final String googleClientId;
	private final String facebookAppId;
	private final String facebookAppSecret;

	public OauthModule(
			@Nonnull File googleClientId,
			@Nonnull File facebookAppId,
			@Nonnull File facebookAppSecret
	) {
		this(
				readKey(googleClientId),
				readKey(facebookAppId),
				readKey(facebookAppSecret)
		);
	}

	/**
	 * @param googleClientId Issued by authorization server.
	 */
	public OauthModule(
			@Nonnull String googleClientId,
			@Nonnull String facebookAppId,
			@Nonnull String facebookAppSecret
	) {
		checkArgument(googleClientId.endsWith(".apps.googleusercontent.com"), "Must end with '.apps.googleusercontent.com'");
		this.googleClientId = checkNotNull(googleClientId);
		this.facebookAppId = checkNotNull(facebookAppId);
		this.facebookAppSecret = checkNotNull(facebookAppSecret);
	}

	@Override
	protected void configure() {

		// This guy is recommended to be a singleton, because it keeps a shared store of Google's public keys.
		GooglePublicKeysManager googlePublicKeysManager = getGooglePublicKeysManager();
		bind(GooglePublicKeysManager.class).toInstance(googlePublicKeysManager);
		TokenVerifier googleVerifier = new TokenVerifierGoogleSignature(
				getGoogleIdTokenVerifier(googlePublicKeysManager, googleClientId),
				new NowProvider()
		);

		ObjectMapper jackson = new ObjectMapper();

		bind(String.class).annotatedWith(Names.named("facebook.app.id")).toInstance(facebookAppId);
		bind(String.class).annotatedWith(Names.named("facebook.app.secret")).toInstance(facebookAppSecret);
		TokenVerifier facebookVerifierSignedRequest = new TokenVerifierFacebookDebugToken(
				URLFetchServiceFactory.getURLFetchService(),
				jackson,
				facebookAppId,
				facebookAppSecret,
				new NowProvider()
		);

		Multibinder<TokenVerifier> multibinder = Multibinder.newSetBinder(binder(), TokenVerifier.class);
		multibinder.addBinding().toInstance(googleVerifier);
		multibinder.addBinding().toInstance(facebookVerifierSignedRequest);

		bind(TokenVerifier.class).annotatedWith(Names.named("default")).toInstance(googleVerifier);
	}

	private GooglePublicKeysManager getGooglePublicKeysManager() {
		logger.trace("Creating " + GooglePublicKeysManager.class.getSimpleName());

		UrlFetchTransport transport = new UrlFetchTransport.Builder()
				.validateCertificate()
				.build();

		// This guy should be singleton.
		return new GooglePublicKeysManager(transport, JacksonFactory.getDefaultInstance());
	}

	private GoogleIdTokenVerifier getGoogleIdTokenVerifier(GooglePublicKeysManager publicKeysManager, String clientId) {
		return new GoogleIdTokenVerifier.Builder(publicKeysManager)
				.setAudience(ImmutableSet.of(clientId))
				.setIssuers(ALLOWED_ISSUERS)
				.build();
	}

	/**
	 * Reads whole file as a string.
	 */
	static String readKey(File file) {
		logger.trace("Reading {}", file.getAbsolutePath());

		try {
			String result = Files.toString(file, UTF_8)
					.trim();
			if (result.isEmpty()) {
				throw new RuntimeException("File is empty: " + file.getAbsolutePath());
			}

			return result;
		} catch (FileNotFoundException e) {
			throw new RuntimeException("File " + file.getAbsolutePath() + " not found.");
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}

	/**
	 * Simply returns current time. Helps mocking in unit-tests.
	 */
	static class NowProvider implements Provider<DateTime> {
		@Override
		public DateTime get() {
			return DateTime.now(UTC);
		}
	}
}
