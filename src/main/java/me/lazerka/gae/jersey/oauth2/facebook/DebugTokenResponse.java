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

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

/**
 * See https://developers.facebook.com/docs/facebook-login/manually-build-a-login-flow#checktoken
 *
 * Like:
 * <pre>
 *     {
 *       "data": {
 *           "app_id": 138483919580948,
 *           "application": "Social Cafe",
 *           "expires_at": 1352419328,
 *           "is_valid": true,
 *           "issued_at": 1347235328,
 *           "metadata": {
 *               "sso": "iphone-safari"
 *           },
 *           "scopes": [
 *               "email",
 *               "publish_actions"
 *           ],
 *           "user_id": 1207059
 *       }
 *   }
 * </pre>
 *
 *
 * @author Dzmitry Lazerka
 */
class DebugTokenResponse {
	@JsonProperty
	Data data;

	static class Data {
		@JsonProperty("app_id")
		String appId;

		@JsonProperty("application")
		String application;

		@JsonProperty("expires_at")
		long expiresAt;

		@JsonProperty("is_valid")
		boolean isValid;

		@JsonProperty("issued_at")
		long issuedAt;

		@JsonProperty("metadata")
		Metadata metadata;

		@JsonProperty("scopes")
		List<String> scopes;

		@JsonProperty("user_id")
		String userId;
	}

	static class Metadata {
		@JsonProperty("sso")
		String sso;
	}
}
