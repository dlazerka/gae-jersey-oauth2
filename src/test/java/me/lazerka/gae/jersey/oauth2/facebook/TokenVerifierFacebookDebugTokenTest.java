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

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.appengine.api.urlfetch.HTTPRequest;
import com.google.appengine.api.urlfetch.HTTPResponse;
import com.google.appengine.api.urlfetch.URLFetchService;
import com.google.common.io.Resources;
import com.sun.jersey.spi.container.ContainerRequest;
import org.joda.time.DateTime;
import org.mockito.ArgumentMatcher;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import javax.inject.Provider;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.security.InvalidKeyException;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.mockito.Matchers.argThat;
import static org.mockito.Mockito.*;
import static org.testng.Assert.fail;

/**
 * @author Dzmitry Lazerka
 */
public class TokenVerifierFacebookDebugTokenTest {
	String code = "ctestcopde123";

	static final ObjectMapper jackson = new ObjectMapper();

	ContainerRequest request = mock(ContainerRequest.class);

	@Mock
	Provider<DateTime> nowProvider;

	TokenVerifierFacebookDebugToken unit;

	@BeforeMethod
	public void setUp() throws URISyntaxException, IOException {
		MockitoAnnotations.initMocks(this);

		unit = new TokenVerifierFacebookDebugToken(
				mock(URLFetchService.class),
				jackson,
				"138483919580948",
				"secret",
				nowProvider
		);

		when(request.getRequestUri())
				.thenReturn(URI.create("https://example.com"));
	}

	@Test
	public void testVerifyOk() throws Exception {
		{
			HTTPResponse response = mock(HTTPResponse.class);
			URL url = getClass().getResource("debug_token.response.ok.json");
			when(response.getResponseCode()).thenReturn(200);
			when(response.getContent()).thenReturn(Resources.toByteArray(url));
			doReturn(response)
					.when(unit.fetcher.urlFetchService)
					.fetch(argThat(new MyRequestMatcher("/debug_token")));
		}

		when(nowProvider.get()).thenReturn(DateTime.parse("2016-05-31T21:00:00Z"));

		FacebookUserPrincipal principal = unit.verify(code);

		assertThat(principal.getId(), is("987654321"));
		DebugTokenResponse debugTokenResponse = principal.getDebugTokenResponse().get();
		assertThat(debugTokenResponse.getAppId(), is("138483919580948"));
		assertThat(debugTokenResponse.getUserId(), is("987654321"));
		assertThat(debugTokenResponse.isValid(), is(true));
	}

	@Test
	public void testVerify403() throws Exception {
		{
			HTTPResponse response = mock(HTTPResponse.class);
			URL resource = getClass().getResource("debug_token.response.invalid.json");
			when(response.getResponseCode()).thenReturn(403);
			when(response.getContent()).thenReturn(Resources.toByteArray(resource));
			when(unit.fetcher.urlFetchService.fetch(argThat(new MyRequestMatcher("/debug_token"))))
					.thenReturn(response);
		}

		try {
			unit.verify(code);
		} catch (InvalidKeyException e) {
			return;
		}
		fail();
	}

	private static class MyRequestMatcher extends ArgumentMatcher<HTTPRequest> {
		private final String urlPath;

		public MyRequestMatcher(String urlPath) {
			this.urlPath = urlPath;
		}

		@Override
		public boolean matches(Object argument) {
			if (!(argument instanceof HTTPRequest)) {
				return false;
			}
			String expected = ((HTTPRequest) argument).getURL().getPath();
			return expected.endsWith(urlPath);
		}
	}
}
