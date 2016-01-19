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

import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken.Payload;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdTokenVerifier;
import com.google.api.client.json.JsonFactory;
import com.google.api.client.json.jackson2.JacksonFactory;
import org.joda.time.DateTime;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.testng.PowerMockTestCase;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import java.io.IOException;
import java.net.URISyntaxException;
import java.security.InvalidKeyException;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.is;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyLong;
import static org.mockito.Matchers.eq;
import static org.powermock.api.mockito.PowerMockito.*;
import static org.testng.Assert.fail;

/**
 * Using PowerMock because Google API libraries are test-hostile (final methods).
 *
 * Instead of extending PowerMockTestCase we could use @ObjectFactory, but that may trigger PowerMock bug
 * https://github.com/jayway/powermock/issues/434
 *
 * @author Dzmitry Lazerka
 */
@PrepareForTest(value = {GoogleIdTokenVerifier.class, GoogleIdToken.class})
public class TokenVerifierSignatureTest extends PowerMockTestCase {
	String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJzdWIiOiIxMTAxNjk0ODQ0NzQzODYyNzYzMzQiLCJhenAiOiIxMDA4NzE5OTcwOTc4LWhiMjRuMmRzdGI0MG80NWQ0ZmV1bzJ1a3FtY2M2MzgxLmFwcHMuZ29vZ2xldXNlcmNvbnRlbnQuY29tIiwiZW1haWxfdmVyaWZpZWQiOiJ0cnVlIiwiZW1haWwiOiJiaWxsZDE2MDBAZ21haWwuY29tIiwibmFtZSI6IlRlc3QgVGVzdCIsImF1ZCI6IjEwMDg3MTk5NzA5NzgtaGIyNG4yZHN0YjQwbzQ1ZDRmZXVvMnVrcW1jYzYzODEuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJpYXQiOjE0MzM5NzgzNTMsImV4cCI6MTQzMzk4MTk1M30.GC1hAjr8DbAT5CkEL19wCUqZHsDH1SklFPL2ZJxezW8";

	TokenVerifierSignature unit;
	private GoogleIdToken idToken;

	@BeforeMethod
	public void setUp() throws URISyntaxException, IOException {
		unit = new TokenVerifierSignature();
		unit.tokenVerifier = mock(GoogleIdTokenVerifier.class);
		unit.now = DateTime.parse("2015-12-15T20:43:28Z");
		when(unit.tokenVerifier.getJsonFactory())
				.thenReturn(JacksonFactory.getDefaultInstance());

		idToken = mock(GoogleIdToken.class);
		when(idToken.getPayload())
				.thenReturn(new Payload().setSubject("1234").setEmail("test@example.com"));
		mockStatic(GoogleIdToken.class);
		when(GoogleIdToken.parse(any(JsonFactory.class), any(String.class)))
				.thenReturn(idToken);

	}

	@Test
	public void testVerifyOk() throws Exception {
		when(unit.tokenVerifier.verify(idToken))
				.thenReturn(true);
		UserPrincipal userPrincipal = unit.verify(token);

		assertThat(userPrincipal.getId(), is("1234"));
	}

	@Test
	public void testVerify() throws Exception {
		when(unit.tokenVerifier.verify(token))
				.thenReturn(null);
		when(idToken.verifyTime(eq(unit.now.getMillis()), anyLong()))
				.thenReturn(false);

		try {
			unit.verify(token);
		} catch (InvalidKeyException e ){
			assertThat(e.getMessage(), containsString("test@example.com"));
			return;
		}
		fail();
	}
}
