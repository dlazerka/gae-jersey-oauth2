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

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.appengine.api.urlfetch.URLFetchService;
import org.joda.time.DateTime;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Provider;
import java.io.IOException;
import java.security.InvalidKeyException;

/**
 * Checks User Access Token that was sent by user, by calling FB /debug_token endpoint.
 *
 * @author Dzmitry Lazerka
 */
public class TokenVerifierFacebookDebugToken extends BasicTokenVerifier {
	private static final Logger logger = LoggerFactory.getLogger(TokenVerifierFacebookDebugToken.class);

	public static final String AUTH_SCHEME = "Facebook/UserAccessToken";

	final String appId;
	final Provider<DateTime> nowProvider;
	final FacebookFetcher fetcher;

	public TokenVerifierFacebookDebugToken(
			URLFetchService urlFetchService,
			ObjectMapper jackson,
			String appId,
			String appSecret,
			Provider<DateTime> nowProvider
	) {
		this.appId = appId;
		this.nowProvider = nowProvider;
		this.fetcher = new FacebookFetcher(appId, appSecret, jackson, urlFetchService);
	}

	@Override
	public FacebookUserPrincipal verify(String userAccessToken) throws IOException, InvalidKeyException {
		logger.trace("Requesting endpoint to validate token");

		DebugTokenResponse response = fetcher.fetchDebugToken(userAccessToken);

		if (!response.data.isValid) {
			throw new InvalidKeyException("Token invalid: " + response.data.error.message);
		}

		if (!appId.equals(response.data.appId)) {
			// Token is issued for another application.
			throw new InvalidKeyException("Wrong appId: " + response.data.appId);
		}

		DateTime now = nowProvider.get();
		if (now.getMillis() / 1000 > response.data.expiresAt) {
			throw new InvalidKeyException("Token expired: " + response.data.expiresAt);
		}

		if (response.data.userId == null || response.data.userId.isEmpty()) {
			throw new InvalidKeyException("No userId");
		}

		return new FacebookUserPrincipal(response.data.userId, null, null, response);
	}

	@Override
	public String getAuthenticationScheme() {
		return AUTH_SCHEME;
	}
}
