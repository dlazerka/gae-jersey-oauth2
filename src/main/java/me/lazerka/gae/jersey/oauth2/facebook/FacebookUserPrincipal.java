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

/**
 * @author Dzmitry Lazerka
 */
public class FacebookUserPrincipal extends UserPrincipal {

	private final FacebookUser facebookUser;
	private final AccessTokenResponse accessTokenResponse;
	private final DebugTokenResponse debugTokenResponse;

	public FacebookUserPrincipal(
			@Nonnull String id,
			@Nullable FacebookUser facebookUser,
			@Nullable AccessTokenResponse accessTokenResponse,
			@Nullable DebugTokenResponse debugTokenResponse
	) {
		super(id);
		this.facebookUser = facebookUser;
		this.accessTokenResponse = accessTokenResponse;
		this.debugTokenResponse = debugTokenResponse;
	}

	public Optional<FacebookUser> getFacebookUser() {
		return Optional.fromNullable(facebookUser);
	}

	public Optional<AccessTokenResponse> getAccessTokenResponse() {
		return Optional.fromNullable(accessTokenResponse);
	}

	public Optional<DebugTokenResponse> getDebugTokenResponse() {
		return Optional.fromNullable(debugTokenResponse);
	}

}
