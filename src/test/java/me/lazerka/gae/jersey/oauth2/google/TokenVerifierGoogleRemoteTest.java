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

package me.lazerka.gae.jersey.oauth2.google;

import com.google.api.client.json.jackson2.JacksonFactory;
import com.google.appengine.api.urlfetch.HTTPRequest;
import com.google.appengine.api.urlfetch.HTTPResponse;
import com.google.appengine.api.urlfetch.URLFetchService;
import com.google.common.io.Resources;
import com.sun.jersey.spi.container.ContainerRequest;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.security.InvalidKeyException;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.testng.Assert.fail;

/**
 * @author Dzmitry Lazerka
 */
public class TokenVerifierGoogleRemoteTest {
	String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJzdWIiOiIxMTAxNjk0ODQ0NzQzODYyNzYzMzQiLCJhenAiOiIxMDA4NzE5OTcwOTc4LWhiMjRuMmRzdGI0MG80NWQ0ZmV1bzJ1a3FtY2M2MzgxLmFwcHMuZ29vZ2xldXNlcmNvbnRlbnQuY29tIiwiZW1haWxfdmVyaWZpZWQiOiJ0cnVlIiwiZW1haWwiOiJiaWxsZDE2MDBAZ21haWwuY29tIiwibmFtZSI6IlRlc3QgVGVzdCIsImF1ZCI6IjEwMDg3MTk5NzA5NzgtaGIyNG4yZHN0YjQwbzQ1ZDRmZXVvMnVrcW1jYzYzODEuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJpYXQiOjE0MzM5NzgzNTMsImV4cCI6MTQzMzk4MTk1M30.GC1hAjr8DbAT5CkEL19wCUqZHsDH1SklFPL2ZJxezW8";

	ContainerRequest request = mock(ContainerRequest.class);
	HTTPResponse remoteResponse = mock(HTTPResponse.class);

	TokenVerifierGoogleRemote unit;

	@BeforeMethod
	public void setUp() throws URISyntaxException, IOException {
		unit = new TokenVerifierGoogleRemote(
				mock(URLFetchService.class),
				JacksonFactory.getDefaultInstance(),
				"web-client-id.apps.googleusercontent.com"
		);

		when(request.getRequestUri())
				.thenReturn(URI.create("https://example.com"));
		when(unit.urlFetchService.fetch(any(HTTPRequest.class)))
				.thenReturn(remoteResponse);

	}

	@Test
	public void testVerifyOk() throws Exception {
		URL resource = getClass().getResource("remote-response.ok.json");
		byte[] content = Resources.toByteArray(resource);

		when(remoteResponse.getResponseCode()).thenReturn(200);
		when(remoteResponse.getContent()).thenReturn(content);

		unit.verify(token);
	}

	@Test
	public void testVerifyInvalidValue() throws Exception {
		URL resource = getClass().getResource("remote-response.invalid-value.json");
		byte[] content = Resources.toByteArray(resource);
		when(remoteResponse.getResponseCode()).thenReturn(403);
		when(remoteResponse.getContent()).thenReturn(content);

		try {
			unit.verify(token);
		} catch (InvalidKeyException e ){
			assertThat(e.getMessage(), containsString("Invalid Value"));
			return;
		}
		fail();
	}
}
