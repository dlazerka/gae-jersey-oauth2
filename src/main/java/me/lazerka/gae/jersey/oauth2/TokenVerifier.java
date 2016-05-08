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

import javax.annotation.Nullable;
import javax.ws.rs.core.SecurityContext;
import java.io.IOException;
import java.security.GeneralSecurityException;

/**
 * @author Dzmitry Lazerka
 */
public interface TokenVerifier {
	/**
	 * @param authProvider value of {@link AuthFilter#PROVIDER_HEADER} request header.
	 *                     `null` if request has no provider header.
	 */
	boolean canHandle(@Nullable String authProvider);

	UserPrincipal verify(String authToken) throws IOException, GeneralSecurityException;

	/** @return what should be returned from {@link SecurityContext#getAuthenticationScheme()}. */
	String getAuthenticationScheme();
}
