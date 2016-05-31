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

import com.sun.jersey.spi.container.ContainerRequest;
import me.lazerka.gae.jersey.oauth2.TokenVerifier;

import javax.annotation.Nonnull;

/**
 * @author Dzmitry Lazerka
 */
public abstract class BasicTokenVerifier implements TokenVerifier {
	private static final String AUTH_SCHEME_HEADER = "X-Authorization-Scheme";

	@Override
	public boolean canHandle(@Nonnull ContainerRequest request) {
		String given = request.getHeaderValue(AUTH_SCHEME_HEADER);
		return getAuthenticationScheme().equals(given);
	}

	@Override
	public abstract String getAuthenticationScheme();
}
