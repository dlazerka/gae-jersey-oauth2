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

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.appengine.api.urlfetch.URLFetchService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.security.InvalidKeyException;

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
public class TokenVerifierFacebookCode extends BasicTokenVerifier {
	private static final Logger logger = LoggerFactory.getLogger(TokenVerifierFacebookCode.class);

	public static final String AUTH_SCHEME = "Facebook/Code";

	final FacebookFetcher fetcher;
	final String redirectUri;

	public TokenVerifierFacebookCode(
			URLFetchService urlFetchService,
			ObjectMapper jackson,
			String appId,
			String appSecret,
			String redirectUri
	) {
		this.redirectUri = redirectUri;
		this.fetcher = new FacebookFetcher(appId, appSecret, jackson, urlFetchService);
	}

	@Override
	public FacebookUserPrincipal verify(String code) throws IOException, InvalidKeyException {
		logger.trace("Requesting endpoint to validate token");

		// This verifies expiration and audience (our app).
		AccessTokenResponse accessTokenResponse = fetcher.fetchUserAccessToken(code, redirectUri);

		// We still need to know User ID.

		FacebookUser facebookUser = fetcher.fetchUser(accessTokenResponse.accessToken);

		return new FacebookUserPrincipal(facebookUser.getId(), facebookUser, accessTokenResponse, null);
	}

	@Override
	public String getAuthenticationScheme() {
		return AUTH_SCHEME;
	}
}
