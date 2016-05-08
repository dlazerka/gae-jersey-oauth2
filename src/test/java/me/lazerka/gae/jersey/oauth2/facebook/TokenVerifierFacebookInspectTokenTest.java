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
import static org.hamcrest.Matchers.*;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.testng.Assert.fail;

/**
 * @author Dzmitry Lazerka
 */
public class TokenVerifierFacebookInspectTokenTest {
	String accessToken = "EAAY7MBKu7y0BAL7AU4oWP8yqjGnbc77uZC6TZCmWhubeUEoW5iVyCx7La0cQ35DIi6CZBT9dXYZCDcKA" +
			"vGtABVbJoNGOv2i3Rn0KL2p3bR3DBZC3yhDGiLtTrheUP4PQBbdSMsGRxcTQXRLeSrZCh0lS415rl7L9r2LpaR289dfgZDZD";

	final ObjectMapper jackson = new ObjectMapper();

	ContainerRequest request = mock(ContainerRequest.class);
	HTTPResponse remoteResponse = mock(HTTPResponse.class);

	TokenVerifierFacebookInspectToken unit;

	@Mock
	Provider<DateTime> nowProvider;

	@BeforeMethod
	public void setUp() throws URISyntaxException, IOException {
		MockitoAnnotations.initMocks(this);

		unit = new TokenVerifierFacebookInspectToken(
				mock(URLFetchService.class),
				jackson,
				"138483919580948",
				"secret",
				nowProvider
		);

		when(request.getRequestUri())
				.thenReturn(URI.create("https://example.com"));
		when(unit.urlFetchService.fetch(any(HTTPRequest.class)))
				.thenReturn(remoteResponse);
	}

	@Test
	public void testVerifyOk() throws Exception {
		URL resource = getClass().getResource("response.ok.json");
		byte[] content = Resources.toByteArray(resource);

		when(remoteResponse.getResponseCode()).thenReturn(200);
		when(remoteResponse.getContent()).thenReturn(content);
		when(unit.nowProvider.get()).thenReturn(DateTime.parse("2012-11-09T00:00:00Z"));

		FacebookUserPrincipal principal = unit.verify(accessToken);

		assertThat(principal.getId(), is("1207059"));
		assertThat(principal.getAccessToken(), nullValue());
	}

	@Test
	public void testVerifyExpired() throws Exception {
		URL resource = getClass().getResource("response.ok.json");
		byte[] content = Resources.toByteArray(resource);
		when(unit.nowProvider.get()).thenReturn(DateTime.parse("2012-11-09T00:05:00Z"));

		when(remoteResponse.getResponseCode()).thenReturn(200);
		when(remoteResponse.getContent()).thenReturn(content);

		try {
			unit.verify(accessToken);
		} catch (InvalidKeyException e) {
			assertThat(e.getMessage(), containsString("expired"));
		}
	}

	@Test
	public void testVerifyAppId() throws Exception {
		unit = new TokenVerifierFacebookInspectToken(
						mock(URLFetchService.class),
						jackson,
						"1234wrong",
						"secret",
						nowProvider
				);

		URL resource = getClass().getResource("response.ok.json");
		byte[] content = Resources.toByteArray(resource);
		when(unit.nowProvider.get()).thenReturn(DateTime.parse("2012-11-09T00:00:00Z"));

		when(remoteResponse.getResponseCode()).thenReturn(200);
		when(remoteResponse.getContent()).thenReturn(content);
		when(unit.urlFetchService.fetch(any(HTTPRequest.class)))
				.thenReturn(remoteResponse);

		try {
			unit.verify(accessToken);
		} catch (InvalidKeyException e) {
			assertThat(e.getMessage(), containsString("appId"));
		}
	}

	@Test
	public void testVerify403() throws Exception {
		URL resource = getClass().getResource("response.invalid.json");
		byte[] content = Resources.toByteArray(resource);
		when(remoteResponse.getResponseCode()).thenReturn(403);
		when(remoteResponse.getContent()).thenReturn(content);

		try {
			unit.verify(accessToken);
		} catch (InvalidKeyException e) {
			return;
		}
		fail();
	}
}