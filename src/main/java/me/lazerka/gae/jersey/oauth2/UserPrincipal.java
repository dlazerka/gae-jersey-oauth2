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

import javax.annotation.Nonnull;
import java.security.Principal;

import static com.google.common.base.Preconditions.checkNotNull;

/**
 * @author Dzmitry Lazerka
 */
public abstract class UserPrincipal implements Principal {
	private final String id;

	public UserPrincipal(@Nonnull String id) {
		this.id = checkNotNull(id);
	}

	@Nonnull
	@Override
	public String getName() {
		return id;
	}

	@Nonnull
	public String getId() {
		return id;
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		if (o == null || getClass() != o.getClass()) return false;

		UserPrincipal that = (UserPrincipal) o;

		return id.equals(that.id);

	}

	@Override
	public int hashCode() {
		return id.hashCode();
	}

	@Override
	public String toString() {
		return id;
	}
}
