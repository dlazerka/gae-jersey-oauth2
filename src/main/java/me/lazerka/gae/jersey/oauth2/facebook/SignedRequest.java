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
 * @author Dzmitry Lazerka
 */
class SignedRequest {
	@JsonProperty(value = "algorithm", required = true)
	String algorithm;

	@JsonProperty(value = "code", required = true)
	String code;

	@JsonProperty(value = "issued_at", required = true)
	int issuedAt;

	@JsonProperty(value = "user_id", required = true)
	String userId;
}
