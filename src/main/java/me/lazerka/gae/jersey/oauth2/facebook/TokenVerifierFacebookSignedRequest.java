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

import com.fasterxml.jackson.core.Base64Variants;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.api.client.auth.oauth2.TokenErrorResponse;
import com.google.appengine.api.urlfetch.HTTPRequest;
import com.google.appengine.api.urlfetch.HTTPResponse;
import com.google.appengine.api.urlfetch.URLFetchService;
import com.google.common.base.Splitter;
import com.google.common.base.Stopwatch;
import com.google.common.base.Throwables;
import com.google.common.collect.ImmutableMap;
import me.lazerka.gae.jersey.oauth2.TokenVerifier;
import org.joda.time.DateTime;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nullable;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.inject.Provider;
import javax.ws.rs.core.UriBuilder;
import java.io.IOException;
import java.net.URL;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import static com.google.appengine.api.urlfetch.FetchOptions.Builder.validateCertificate;
import static com.google.appengine.api.urlfetch.HTTPMethod.GET;
import static com.google.common.base.Preconditions.checkArgument;
import static java.nio.charset.StandardCharsets.UTF_8;

/**
 * Filter that verifies signed_request.
 *
 * Documentation on token verification:
 * https://developers.facebook.com/docs/facebook-login/manually-build-a-login-flow#confirm
 * https://developers.facebook.com/docs/facebook-login/manually-build-a-login-flow#checktoken
 *
 * Documentation on parsing signed_request: https://developers.facebook.com/docs/games/gamesonfacebook/login#parsingsr
 *
 * @author Dzmitry Lazerka
 */
public class TokenVerifierFacebookSignedRequest implements TokenVerifier {
	private static final Logger logger = LoggerFactory.getLogger(TokenVerifierFacebookSignedRequest.class);

	public static final String AUTH_SCHEME = "Facebook/SignedRequest";

	protected static final UriBuilder accessTokenEndpoint =
			UriBuilder.fromUri("https://graph.facebook.com/v2.6/oauth/access_token")
					.queryParam("client_id", "{appId}")
					.queryParam("client_secret", "{appSecret}")
					.queryParam("code", "{code}")
					.queryParam("grant_type", "client_credentials");
//					.queryParam("redirect_uri={redirect-uri}");

//	protected static final UriBuilder userEndpoint =
//			UriBuilder.fromUri("https://graph.facebook.com/v2.6/user")
//					.segment("{userId}")
//					.queryParam("access_token", "{appId}");


	private final Mac hmac;

	final URLFetchService urlFetchService;
	final ObjectMapper jackson;
	final String appId;
	final String appSecret;
	final Provider<DateTime> nowProvider;

	public TokenVerifierFacebookSignedRequest(
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

		try {
			SecretKeySpec signingKey = new SecretKeySpec(appSecret.getBytes(UTF_8), "HmacSHA1");
			hmac = Mac.getInstance("HmacSHA256");
			hmac.init(signingKey);
		} catch (NoSuchAlgorithmException | InvalidKeyException e) {
			throw Throwables.propagate(e);
		}
	}

	@Override
	public boolean canHandle(@Nullable String authProvider) {
		return "facebook".equals(authProvider);
	}

	@Override
	public FacebookUserPrincipal verify(String signedRequestToken) throws IOException, InvalidKeyException {
		logger.trace("Requesting endpoint to validate token");

		List<String> parts = Splitter.on('.').splitToList(signedRequestToken);

		checkArgument(parts.size() == 2, "Signed request must have two parts separated by period.");

		byte[] providedSignature = Base64Variants.MODIFIED_FOR_URL.decode(parts.get(0));
		String signedRequestJsonEncoded = parts.get(1);
		byte[] signedRequestJson = Base64Variants.MODIFIED_FOR_URL.decode(signedRequestJsonEncoded);

		SignedRequest signedRequest = jackson.readValue(signedRequestJson, SignedRequest.class);

		if (!"HMAC-SHA256".equals(signedRequest.algorithm)) {
			throw new InvalidKeyException("Unsupported signing method: " + signedRequest.algorithm);
		}

		byte[] expectedSignature = hmac.doFinal(signedRequestJsonEncoded.getBytes(UTF_8));
		if (!Arrays.equals(providedSignature, expectedSignature)) {
			throw new InvalidKeyException("Signature invalid");
		}

		String accessToken = exchangeCodeForAppAccessToken(signedRequest.code);

		// Not fetching email, because maybe we won't need to, if ID is enough.

		return new FacebookUserPrincipal(signedRequest.userId, accessToken);
	}

	/**
	 * Exchange `code` for long-lived access token. This serves as verification for `code` expiration too.
	 */
	protected String exchangeCodeForAppAccessToken(String code) throws IOException, InvalidKeyException {
		Map<String, String> params = ImmutableMap.of(
				"appId", appId,
				"appSecret", appSecret,
				"code", code
		);

		URL url = accessTokenEndpoint.buildFromMap(params).toURL();

		HTTPRequest httpRequest = new HTTPRequest(url, GET, validateCertificate());

		Stopwatch stopwatch = Stopwatch.createStarted();
		HTTPResponse response = urlFetchService.fetch(httpRequest);
		logger.debug("Call to /access_token took {}ms", stopwatch.elapsed(TimeUnit.MILLISECONDS));

		int responseCode = response.getResponseCode();

		// Like "access_token=1753927518187309|AJNQIuA346773XeyTpPT27pcq2I"
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

		AccessTokenResponse accessTokenResponse = jackson.readValue(content, AccessTokenResponse.class);

		return accessTokenResponse.accessToken;
	}

	@Override
	public String getAuthenticationScheme() {
		return AUTH_SCHEME;
	}
}
