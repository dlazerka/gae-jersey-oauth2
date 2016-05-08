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

package me.lazerka.gae.jersey.oauth2.facebook;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.api.client.auth.oauth2.TokenErrorResponse;
import com.google.appengine.api.urlfetch.HTTPRequest;
import com.google.appengine.api.urlfetch.HTTPResponse;
import com.google.appengine.api.urlfetch.URLFetchService;
import com.google.common.base.Stopwatch;
import com.google.common.collect.ImmutableMap;
import me.lazerka.gae.jersey.oauth2.TokenVerifier;
import org.joda.time.DateTime;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nullable;
import javax.inject.Provider;
import javax.ws.rs.core.UriBuilder;
import java.io.IOException;
import java.net.URL;
import java.security.InvalidKeyException;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import static com.google.appengine.api.urlfetch.FetchOptions.Builder.validateCertificate;
import static com.google.appengine.api.urlfetch.HTTPMethod.GET;
import static java.nio.charset.StandardCharsets.UTF_8;

/**
 * Filter that verifies token by making HTTPS call to Facebook endpoint.
 *
 * Documentation on token verification:
 * https://developers.facebook.com/docs/facebook-login/manually-build-a-login-flow#confirm
 * https://developers.facebook.com/docs/facebook-login/manually-build-a-login-flow#checktoken
 *
 * Documentation on parsing signed_request: https://developers.facebook.com/docs/games/gamesonfacebook/login#parsingsr
 *
 * @author Dzmitry Lazerka
 */
public class TokenVerifierFacebookInspectToken implements TokenVerifier {
	private static final Logger logger = LoggerFactory.getLogger(TokenVerifierFacebookInspectToken.class);

	public static final String AUTH_SCHEME = "Facebook/InspectToken";

	private static final UriBuilder accessTokenEndpoint =
			UriBuilder.fromUri("https://graph.facebook.com/oauth/access_token")
					.queryParam("client_id", "{appId}")
					.queryParam("client_secret", "{clientSecret}")
					.queryParam("grant_type", "client_credentials");
//					.queryParam("redirect_uri={redirect-uri}");
//					.queryParam("code={code-parameter}");

	protected static final UriBuilder accessTokenEndpoint2 =
			UriBuilder.fromUri("https://graph.facebook.com//oauth/access_token")
					.queryParam("client_id", "{appId}")
					.queryParam("client_secret", "{clientSecret}")
					.queryParam("grant_type", "fb_exchange_token")
					.queryParam("fb_exchange_token", "{short-lived-token}");


	private static final UriBuilder debugTokenEndpoint =
			UriBuilder.fromUri("https://graph.facebook.com/v2.6/debug_token")
					.queryParam("input_token", "{inputToken}")
					.queryParam("access_token", "{appId}|{appSecret}");

	final URLFetchService urlFetchService;
	final ObjectMapper jackson;
	final String appId;
	final String appSecret;
	final Provider<DateTime> nowProvider;

	public TokenVerifierFacebookInspectToken(
			URLFetchService urlFetchService,
			ObjectMapper jackson,
			String appId,
			String appSecret,
			Provider<DateTime> nowProvider
	) {
		this.urlFetchService = urlFetchService;
		this.jackson = jackson;
		this.appId = appId;
		this.appSecret = appSecret;
		this.nowProvider = nowProvider;
	}

	@Override
	public boolean canHandle(@Nullable String authProvider) {
		return "facebook".equals(authProvider);
	}

	@Override
	public FacebookUserPrincipal verify(String userAccessToken) throws IOException, InvalidKeyException {
		logger.trace("Requesting endpoint to validate token");

		Map<String, String> params = ImmutableMap.of(
				"inputToken", userAccessToken,
				"appId", appId,
				"appSecret", appSecret
		);

		URL url = debugTokenEndpoint.buildFromMap(params).toURL();

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
					JsonNode tree = jackson.readTree(content);
					JsonNode error = tree.findPath("error");
					if (!error.isMissingNode()) {
						msg += ": " + error.findPath("message").textValue();
					}
				} catch (IOException e) {
					logger.warn("Cannot parse response as " + TokenErrorResponse.class.getSimpleName());
				}
			}

			throw new InvalidKeyException(msg);
		}

		DebugTokenResponse payload = jackson.readValue(content, DebugTokenResponse.class);

		if (!appId.equals(payload.data.appId)) {
			// Token is issued for another application.
			throw new InvalidKeyException("Invalid appId: " + payload.data.appId);
		}

		DateTime now = nowProvider.get();
		if (now.getMillis() / 1000 > payload.data.expiresAt) {
			throw new InvalidKeyException("Token expired: " + payload.data.expiresAt);
		}

		if (!payload.data.isValid) {
			throw new InvalidKeyException("Token invalid");
		}

		if (payload.data.userId == null || payload.data.userId.isEmpty()) {
			throw new InvalidKeyException("No userId");
		}

		return new FacebookUserPrincipal(payload.data.userId, null); // TODO
	}

	@Override
	public String getAuthenticationScheme() {
		return AUTH_SCHEME;
	}
}
