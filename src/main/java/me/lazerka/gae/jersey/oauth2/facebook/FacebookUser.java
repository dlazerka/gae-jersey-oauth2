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
import com.google.common.base.MoreObjects;
import com.google.common.collect.ImmutableSet;

import java.util.Set;

/**
 * https://developers.facebook.com/docs/graph-api/reference/v2.6/user
 * <p>
 * Only core fields.
 *
 * @author Dzmitry Lazerka
 */
public class FacebookUser {
	@JsonProperty
	String id;

	@JsonProperty
	String birthday;

	@JsonProperty
	String email;

	@JsonProperty("first_name")
	String firstName;

	@JsonProperty("last_name")
	String lastName;

	@JsonProperty("middle_name")
	String middleName;

	@JsonProperty("name")
	String name;

	@JsonProperty("timezone")
	int timezone;

	// All fields that are marked as "core" in FB API.
	static final Set<String> FIELDS = ImmutableSet.of(
			"id",
			"birthday",
			"email",
			"first_name",
			"last_name",
			"middle_name",
			"name",
			"timezone"
	);

	@Override
	public String toString() {
		return MoreObjects.toStringHelper(this)
				.add("id", id)
				.add("birthday", birthday)
				.add("email", email)
				.add("firstName", firstName)
				.add("lastName", lastName)
				.add("middleName", middleName)
				.add("name", name)
				.add("timezone", timezone)
				.toString();
	}
}
