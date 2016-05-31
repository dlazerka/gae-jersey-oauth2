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
import com.google.api.client.util.Joiner;
import com.google.appengine.api.urlfetch.HTTPRequest;
import com.google.appengine.api.urlfetch.HTTPResponse;
import com.google.appengine.api.urlfetch.URLFetchService;
import com.google.common.base.Stopwatch;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.ws.rs.core.UriBuilder;
import java.io.IOException;
import java.net.URI;
import java.net.URL;
import java.security.InvalidKeyException;
import java.util.concurrent.TimeUnit;

import static com.google.appengine.api.urlfetch.FetchOptions.Builder.validateCertificate;
import static com.google.appengine.api.urlfetch.HTTPMethod.GET;
import static com.google.common.base.Preconditions.checkArgument;
import static java.nio.charset.StandardCharsets.UTF_8;

/**
 * Common functions for Facebook token verifiers (used as composition).
 *
 * @author Dzmitry Lazerka
 */
class FacebookFetcher {
	private static final Logger logger = LoggerFactory.getLogger(FacebookFetcher.class);

	private static final URI GRAPH_API = URI.create("https://graph.facebook.com/v2.6/");

	final String appId;
	final String appSecret;
	final ObjectMapper jackson;
	final URLFetchService urlFetchService;

	FacebookFetcher(String appId, String appSecret, ObjectMapper jackson, URLFetchService urlFetchService) {
		this.appId = appId;
		this.appSecret = appSecret;
		this.jackson = jackson;
		this.urlFetchService = urlFetchService;
	}

	String fetch(URL url) throws IOException, InvalidKeyException {
		logger.trace("Requesting endpoint to validate token");

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
					logger.warn("Cannot parse response as error");
				}
			}

			throw new InvalidKeyException(msg);
		}

		return content;
	}

	/**
	 * Not sure why we anyone would ever need this, because any requests accept client_id + client_secret as well.
	 */
	AccessTokenResponse fetchAppAccessToken() throws IOException, InvalidKeyException {
		logger.trace("Requesting {}/oauth/access_token ...", GRAPH_API);
		URL url = UriBuilder.fromUri(GRAPH_API).path("/oauth/access_token")
				.queryParam("client_id", appId)
				.queryParam("client_secret", appSecret)
				.queryParam("grant_type", "client_credentials")
				.build()
				.toURL();

		String content = fetch(url);

		return jackson.readValue(content, AccessTokenResponse.class);
	}

	AccessTokenResponse fetchUserAccessToken(String code, String redirectUri) throws IOException, InvalidKeyException {
		logger.trace("Requesting {}/oauth/access_token ...", GRAPH_API);
		URL url = UriBuilder.fromUri(GRAPH_API).path("/oauth/access_token")
				.queryParam("client_id", appId)
				.queryParam("client_secret", appSecret)
				.queryParam("code", code)
				.queryParam("scope", "email")
				.queryParam("redirect_uri", redirectUri)
				.build()
				.toURL();

		String content = fetch(url);

		return jackson.readValue(content, AccessTokenResponse.class);
	}

	FacebookUser fetchUser(String accessToken) throws IOException, InvalidKeyException {
		logger.trace("Requesting {}/me ...", GRAPH_API);

		checkArgument(!accessToken.contains("."), "This is signed_request, not access_token");

		String fields = Joiner.on(',').join(FacebookUser.FIELDS);
		URL url = UriBuilder.fromUri(GRAPH_API)
				.path("me")
				.queryParam("fields", fields)
				.queryParam("access_token", accessToken)
				.build()
				.toURL();

		String content = fetch(url);

		FacebookUser facebookUser = jackson.readValue(content, FacebookUser.class);
		logger.info("Fetched {}", facebookUser);

		return facebookUser;
	}

	DebugTokenResponse fetchDebugToken(String userAccessToken) throws IOException, InvalidKeyException {
		logger.trace("Requesting {}/oauth/access_token ...", GRAPH_API);

		checkArgument(!userAccessToken.contains("."), "This is signed_request, not access_token");

		URL url = UriBuilder.fromUri(GRAPH_API)
				.path("debug_token")
				.queryParam("input_token", userAccessToken)
				.queryParam("access_token", "{appId}|{appSecret}")
				.build(appId, appSecret)
				.toURL();

		String content = fetch(url);

		return jackson.readValue(content, DebugTokenResponse.class);
	}
}
