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

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * @author Dzmitry Lazerka
 */
public class TokenVerifierFacebookSignedRequestTest {
	String accessToken = "hX7QRE_Ipan373dPaMNv7jbIDGP-iQmIu-TPndEPmE8." +
			"eyJhbGdvcml0aG0iOiJITUFDLVNIQTI1NiIsImNvZGUiOiJBUUE1WmlhRWhxblpzS0xfY1NSUkFPM2cwaWl4WE5nSXB0Y0tZZExCWn" +
			"RPWDZPYThSWjFHc1V5QVJZTkR6SkszdENfdEZ3dVE1SVRaSDBYY1pHTE9naE1wUDFCeUNPZW9CRnZZaXJlOGZLNG1sLWxvZmU3eExm" +
			"czNsSFlIVHVXem9VQlVSaDVtalpad2hLR2dIWEgwcmh5QlVQZjRLeE5PWDhsQ3dVUm5OR2paR3NpYzhQS2sxN2NFUlJyRjdIcGg2bE" +
			"xVcmdSZFlsV3JxbTlqb0c5eFBDZURWcjZudzdxZ1lNRlFuVFdIRkF5X1h3QUQyZ2FJOW90VkE1azFRSlpzbVhWNW9kYm9IZVpfcUxN" +
			"YmtGLTF3YlRLVjBBSllvMW5BWXlZdmdZcUNHVkNKRXp1YXpUbHlWN0F1NVhXTzJVZEoxeE9nRGFWTTh1R2pJa1E0QlE0dGRlSmV5NE" +
			"UzWmR3SUtxQUtGSGFqU0pEckEiLCJpc3N1ZWRfYXQiOjE0NjMzNDQ3MzcsInVzZXJfaWQiOiIxMDE1MzM5MDEyNzE3MTA3NiJ9";

	final ObjectMapper jackson = new ObjectMapper();

	ContainerRequest request = mock(ContainerRequest.class);
	HTTPResponse remoteResponse = mock(HTTPResponse.class);

	TokenVerifierFacebookSignedRequest unit;

	@Mock
	Provider<DateTime> nowProvider;

	@BeforeMethod
	public void setUp() throws URISyntaxException, IOException {
		MockitoAnnotations.initMocks(this);

		unit = new TokenVerifierFacebookSignedRequest(
				mock(URLFetchService.class),
				jackson,
				"138483919580948",
				"secret",
				"http://local.host/test"
		);

		when(request.getRequestUri())
				.thenReturn(URI.create("https://example.com"));
		when(unit.fetcher.urlFetchService.fetch(any(HTTPRequest.class)))
				.thenReturn(remoteResponse);
	}

	@Test
	public void testVerifyOk() throws Exception {
		URL resource = getClass().getResource("access_token.response.ok.json");
		byte[] content = Resources.toByteArray(resource);

		when(remoteResponse.getResponseCode()).thenReturn(200);
		when(remoteResponse.getContent()).thenReturn(content);

		FacebookUserPrincipal principal = unit.verify(accessToken);

		assertThat(principal.getId(), is("10153390127171076"));
		assertThat(principal.getAccessTokenResponse().get().getAccessToken(), is("01234|testToken"));
	}
}
