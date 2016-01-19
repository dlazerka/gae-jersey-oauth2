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

package me.lazerka.gae.jersey.oauth2;

import javax.ws.rs.core.SecurityContext;
import java.util.Set;

import static com.google.common.base.Preconditions.checkNotNull;

/**
 * @author Dzmitry Lazerka
 */
public class AuthSecurityContext implements SecurityContext {
	private final UserPrincipal user;
	private final boolean secure;
	private final Set<String> roles;
	private final String authenticationScheme;

	public AuthSecurityContext(UserPrincipal user, boolean secure, Set<String> role, String authenticationScheme) {
		this.user = checkNotNull(user);
		this.secure = secure;
		this.roles = checkNotNull(role);
		this.authenticationScheme = checkNotNull(authenticationScheme);
	}

	@Override
	public UserPrincipal getUserPrincipal() {
		return user;
	}

	@Override
	public boolean isUserInRole(String role) {
		return roles.contains(role);
	}

	@Override
	public boolean isSecure() {
		return secure;
	}

	@Override
	public String getAuthenticationScheme() {
		return authenticationScheme;
	}
}
