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

import com.google.appengine.api.users.User;
import com.google.appengine.api.users.UserService;
import com.google.appengine.api.utils.SystemProperty;
import com.google.appengine.api.utils.SystemProperty.Environment.Value;
import com.google.common.collect.ImmutableSet;
import com.sun.jersey.spi.container.ContainerRequest;
import me.lazerka.gae.jersey.oauth2.facebook.FacebookUserPrincipal;
import me.lazerka.gae.jersey.oauth2.google.GoogleUserPrincipal;
import org.mockito.ArgumentCaptor;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.SecurityContext;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.*;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.*;
import static org.testng.Assert.fail;

/**
 * @author Dzmitry Lazerka
 */
public class AuthFilterTest {
	String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" +
			".eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJzdWIiOiIxMTAxNjk0ODQ0NzQzODYyNzYzMzQiLCJhenAiOiIx" +
			"MDA4NzE5OTcwOTc4LWhiMjRuMmRzdGI0MG80NWQ0ZmV1bzJ1a3FtY2M2MzgxLmFwcHMuZ29vZ2xldXNlcmNvbnRlbnQuY29tIiwiZ" +
			"W1haWxfdmVyaWZpZWQiOiJ0cnVlIiwiZW1haWwiOiJiaWxsZDE2MDBAZ21haWwuY29tIiwibmFtZSI6IlRlc3QgVGVzdCIsImF1ZC" +
			"I6IjEwMDg3MTk5NzA5NzgtaGIyNG4yZHN0YjQwbzQ1ZDRmZXVvMnVrcW1jYzYzODEuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20" +
			"iLCJpYXQiOjE0MzM5NzgzNTMsImV4cCI6MTQzMzk4MTk1M30" +
			".GC1hAjr8DbAT5CkEL19wCUqZHsDH1SklFPL2ZJxezW8";

	ContainerRequest request;

	AuthFilter unit;
	private TokenVerifier verifierMock;

	@BeforeMethod
	public void setUp() throws URISyntaxException, IOException {
		request = mock(ContainerRequest.class);

		unit = new AuthFilter();
		verifierMock = mock(TokenVerifier.class);
		unit.tokenVerifiers = ImmutableSet.of(verifierMock);

		unit.setRolesAllowed(ImmutableSet.of(Role.USER));
		unit.userService = mock(UserService.class);

		when(request.getRequestUri())
				.thenReturn(URI.create("https://example.com"));

		SystemProperty.environment.set(Value.Production);
	}

	@Test
	public void testFilterOk() throws GeneralSecurityException, IOException {
		when(request.isSecure()).thenReturn(true);
		when(request.getHeaderValue("Authorization")).thenReturn("Bearer " + token);

		when(verifierMock.canHandle(null))
				.thenReturn(true);
		when(verifierMock.verify(token))
				.thenReturn(new FacebookUserPrincipal("123", "test@example.com"));
		when(verifierMock.getAuthenticationScheme())
				.thenReturn("TestScheme");

		unit.filter(request);

		ArgumentCaptor<SecurityContext> captor = ArgumentCaptor.forClass(SecurityContext.class);
		verify(request).setSecurityContext(captor.capture());

		SecurityContext securityContext = captor.getValue();
		UserPrincipal expectedPrincipal = new FacebookUserPrincipal("123", "test@example.com");
		assertThat((UserPrincipal) securityContext.getUserPrincipal(), is(expectedPrincipal));
		assertThat(securityContext.getAuthenticationScheme(), is("TestScheme"));
		assertThat(securityContext.isSecure(), is(true));
		assertThat(securityContext.isUserInRole(Role.OPTIONAL), is(true));
		assertThat(securityContext.isUserInRole(Role.USER), is(true));
		assertThat(securityContext.isUserInRole(Role.ADMIN), is(false));
	}


	@Test
	public void testFilterAdminOk() {
		unit.setRolesAllowed(ImmutableSet.of(Role.ADMIN));
		when(request.isSecure()).thenReturn(true);
		when(request.getHeaderValue("Authorization")).thenReturn(null);

		when(unit.userService.isUserLoggedIn()).thenReturn(true);
		when(unit.userService.isUserAdmin()).thenReturn(true);
		when(unit.userService.getCurrentUser()).thenReturn(new User("test@example.com", "google.com", "123"));

		try {
			unit.filter(request);
		} catch (WebApplicationException e) {
			fail("Should pass, but is: " + e.getResponse().getStatus(), e);
		}

		ArgumentCaptor<SecurityContext> captor = ArgumentCaptor.forClass(SecurityContext.class);
		verify(request).setSecurityContext(captor.capture());

		SecurityContext securityContext = captor.getValue();
		UserPrincipal expectedPrincipal = new GoogleUserPrincipal("123", "test@example.com");
		assertThat((UserPrincipal) securityContext.getUserPrincipal(), is(expectedPrincipal));
		assertThat(securityContext.getAuthenticationScheme(), is(AuthFilter.GAE_AUTH_SCHEME));
		assertThat(securityContext.isSecure(), is(true));
		assertThat(securityContext.isUserInRole(Role.OPTIONAL), is(true));
		assertThat(securityContext.isUserInRole(Role.USER), is(true));
		assertThat(securityContext.isUserInRole(Role.ADMIN), is(true));
	}

	@Test
	public void testFilterFail() throws GeneralSecurityException, IOException {
		when(request.isSecure()).thenReturn(true);
		when(request.getHeaderValue("Authorization")).thenReturn("Bearer " + token);

		when(verifierMock.canHandle(null))
				.thenReturn(true);
		when(verifierMock.verify(token))
				.thenThrow(new InvalidKeyException("Test msg"));

		try {
			unit.filter(request);
			fail();
		} catch (WebApplicationException e) {
			assertThat(e.getCause(), instanceOf(InvalidKeyException.class));
			assertThat(e.getResponse().getStatus(), is(401));
			verify(request, never()).setSecurityContext(any(AuthSecurityContext.class));
		}
	}

	@Test
	public void testFilterInsecure() {
		when(request.isSecure()).thenReturn(false);

		try {
			unit.filter(request);
		} catch (WebApplicationException e) {
			assertThat(e.getResponse().getStatus(), is(401));
			return;
		}

		fail();
	}

	@Test
	public void testRoleOptional() {
		unit.setRolesAllowed(ImmutableSet.of(Role.OPTIONAL));
		when(request.isSecure()).thenReturn(true);
		when(request.getHeaderValue("Authorization")).thenReturn(null);

		try {
			unit.filter(request);
		} catch (WebApplicationException e) {
			fail();
		}

		ArgumentCaptor<SecurityContext> captor = ArgumentCaptor.forClass(SecurityContext.class);
		verify(request).setSecurityContext(captor.capture());

		SecurityContext securityContext = captor.getValue();
		assertThat(securityContext.getUserPrincipal(), nullValue());
		assertThat(securityContext.getAuthenticationScheme(), is(AuthFilter.UNAUTHENTICATED_AUTH_SCHEME));
		assertThat(securityContext.isSecure(), is(true));
	}
}
