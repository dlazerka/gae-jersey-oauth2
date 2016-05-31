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
import static java.nio.charset.StandardCharsets.UTF_8;

/**
 * Filter that verifies token by making HTTPS call to Facebook endpoint.
 * <p>
 * Documentation on token verification:
 * https://developers.facebook.com/docs/facebook-login/manually-build-a-login-flow#confirm
 * https://developers.facebook.com/docs/facebook-login/manually-build-a-login-flow#checktoken
 * <p>
 * Documentation on parsing signed_request: https://developers.facebook.com/docs/games/gamesonfacebook/login#parsingsr
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

	public FacebookFetcher(String appId, String appSecret, ObjectMapper jackson, URLFetchService urlFetchService) {
		this.appId = appId;
		this.appSecret = appSecret;
		this.jackson = jackson;
		this.urlFetchService = urlFetchService;
	}

	public String fetch(URL url) throws IOException, InvalidKeyException {
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

	public AccessTokenResponse fetchAccessToken(String code) throws IOException, InvalidKeyException {
		URL url = UriBuilder.fromUri(GRAPH_API).path("/oauth/access_token")
				.queryParam("client_id", appId)
				.queryParam("client_secret", appSecret)
				.queryParam("code", code)
				.queryParam("grant_type", "client_credentials")
				// .queryParam("redirect_uri={redirect-uri}");
				.build()
				.toURL();

		String content = fetch(url);

		return jackson.readValue(content, AccessTokenResponse.class);
	}


	public FacebookUser fetchUser(String accessToken) throws IOException, InvalidKeyException {
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
}
