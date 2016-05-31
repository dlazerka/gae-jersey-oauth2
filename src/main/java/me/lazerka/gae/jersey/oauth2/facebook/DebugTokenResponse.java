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
import java.util.Objects;

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
public class DebugTokenResponse {
	@JsonProperty("data")
	Data data;

	static class Data {
		@JsonProperty("is_valid")
		boolean isValid;

		@JsonProperty("error")
		Error error;

		@JsonProperty("app_id")
		String appId;

		@JsonProperty("application")
		String application;

		@JsonProperty("expires_at")
		long expiresAt;

		@JsonProperty("issued_at")
		long issuedAt;

		@JsonProperty("metadata")
		Metadata metadata;

		@JsonProperty("scopes")
		List<String> scopes;

		@JsonProperty("user_id")
		String userId;

		@Override
		public boolean equals(Object o) {
			if (this == o) return true;
			if (!(o instanceof Data)) return false;
			Data data = (Data) o;
			return expiresAt == data.expiresAt &&
					isValid == data.isValid &&
					issuedAt == data.issuedAt &&
					Objects.equals(appId, data.appId) &&
					Objects.equals(application, data.application) &&
					Objects.equals(metadata, data.metadata) &&
					Objects.equals(scopes, data.scopes) &&
					Objects.equals(userId, data.userId);
		}

		@Override
		public int hashCode() {
			return Objects.hash(appId, application, expiresAt, isValid, issuedAt, metadata, scopes, userId);
		}
	}

	static class Metadata {
		@JsonProperty("sso")
		String sso;

		@Override
		public boolean equals(Object o) {
			if (this == o) return true;
			if (!(o instanceof Metadata)) return false;
			Metadata metadata = (Metadata) o;
			return Objects.equals(sso, metadata.sso);
		}

		@Override
		public int hashCode() {
			return Objects.hash(sso);
		}
	}

	static class Error {
		@JsonProperty("code")
		int code;

		@JsonProperty("message")
		String message;
	}

	public boolean isValid() {
		return data.isValid;
	}

	public String getAppId() {
		return data.appId;
	}

	public String getApplication() {
		return data.application;
	}

	public long getExpiresAt() {
		return data.expiresAt;
	}

	public long getIssuedAt() {
		return data.issuedAt;
	}

	public Metadata getMetadata() {
		return data.metadata;
	}

	public List<String> getScopes() {
		return data.scopes;
	}

	public String getUserId() {
		return data.userId;
	}

	public String getSso() {
		return data.metadata == null ? null : data.metadata.sso;
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		if (!(o instanceof DebugTokenResponse)) return false;
		DebugTokenResponse that = (DebugTokenResponse) o;
		return Objects.equals(data, that.data);
	}

	@Override
	public int hashCode() {
		return Objects.hash(data);
	}
}
