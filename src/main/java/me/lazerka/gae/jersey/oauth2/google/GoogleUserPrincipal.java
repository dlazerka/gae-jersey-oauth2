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

package me.lazerka.gae.jersey.oauth2.google;

import me.lazerka.gae.jersey.oauth2.UserPrincipal;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;

/**
 * @author Dzmitry Lazerka
 */
public class GoogleUserPrincipal extends UserPrincipal {
	private final String email;

	public GoogleUserPrincipal(@Nonnull String id, @Nullable String email) {
		super(id);
		this.email = checkNotNull(email);
		checkArgument(email.contains("@"), "Email must contain @.");
	}

	public String getEmail() {
		return email;
	}

	@Override
	public String toString() {
		return super.toString() + ' ' + '<' + email + '>';
	}
}
