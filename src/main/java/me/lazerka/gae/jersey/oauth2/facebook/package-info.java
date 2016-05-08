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

/**
 * Implementation of Facebook Login using API v2.6.
 *
 * Documentation: https://developers.facebook.com/docs/facebook-login/manually-build-a-login-flow#confirm
 *
 * There's two ways to authenticate user. Once user authorized our app at Facebook, Facebook issues user so
 * called authResponse, that contains `accessToken` and `signedRequest`. Both of them can be used to authenticate
 * user:
 * 1. Inspect `accessToken` using Facebook's endpoint /debug_token. See {@link me.lazerka.gae.jersey.oauth2.facebook.TokenVerifierFacebookInspectToken}.
 * 2. Parse signedRequest from Facebook's authResponse. Check it's signature and exchange it's `code` for
 *    an app access token.
 *
 * Both ways need one more call to Facebook to get user's email.
 *
 * @author Dzmitry Lazerka
 */
package me.lazerka.gae.jersey.oauth2.facebook;