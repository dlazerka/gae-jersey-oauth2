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

/**
 * See https://developers.facebook.com/docs/facebook-login/manually-build-a-login-flow#checktoken
 *
 * Like:
 * <pre>
 *   {
 *     "access_token":"1753927518187309|AJNQIuZELLBZER834SEWxtcpq2I",
 *     "token_type":"bearer"
 *   }
 * </pre>
 *
 *
 * @author Dzmitry Lazerka
 */
class AccessTokenResponse {
	@JsonProperty("access_token")
	String accessToken;

	@JsonProperty("token_type")
	String tokenType;
}
