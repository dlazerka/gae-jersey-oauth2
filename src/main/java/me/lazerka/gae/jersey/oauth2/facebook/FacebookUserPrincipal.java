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

import com.google.common.base.Optional;
import me.lazerka.gae.jersey.oauth2.UserPrincipal;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import static com.google.common.base.Preconditions.checkNotNull;

/**
 * @author Dzmitry Lazerka
 */
public class FacebookUserPrincipal extends UserPrincipal {
	private final AccessTokenResponse accessTokenResponse;

	@Nullable
	private final FacebookUser facebookUser;

	public FacebookUserPrincipal(@Nonnull String id, @Nonnull AccessTokenResponse accessTokenResponse) {
		super(id);
		this.accessTokenResponse = checkNotNull(accessTokenResponse);
		facebookUser = null;
	}

	public FacebookUserPrincipal(@Nonnull FacebookUser user, @Nonnull AccessTokenResponse accessTokenResponse) {
		super(user.id);
		this.accessTokenResponse = checkNotNull(accessTokenResponse);
		facebookUser = user;
	}

	/**
	 * Exchanged access token in case you need to call Facebook API for this user info (like email).
	 */
	public AccessTokenResponse getAccessTokenResponse() {
		return accessTokenResponse;
	}

	public Optional<FacebookUser> getFacebookUser() {
		return Optional.fromNullable(facebookUser);
	}
}
