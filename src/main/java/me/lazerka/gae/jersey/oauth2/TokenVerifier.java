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

import com.sun.jersey.spi.container.ContainerRequest;

import javax.annotation.Nonnull;
import javax.ws.rs.core.SecurityContext;
import java.io.IOException;
import java.security.GeneralSecurityException;

/**
 * @author Dzmitry Lazerka
 */
public interface TokenVerifier {
	boolean canHandle(@Nonnull ContainerRequest request);

	UserPrincipal verify(String authToken) throws IOException, GeneralSecurityException;

	/** @return what should be returned from {@link SecurityContext#getAuthenticationScheme()}. */
	String getAuthenticationScheme();
}
