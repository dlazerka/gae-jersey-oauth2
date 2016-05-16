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

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableSet;
import com.sun.jersey.api.model.AbstractMethod;
import com.sun.jersey.spi.container.ResourceFilter;
import com.sun.jersey.spi.container.ResourceFilterFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nullable;
import javax.annotation.security.DenyAll;
import javax.annotation.security.PermitAll;
import javax.annotation.security.RolesAllowed;
import javax.inject.Inject;
import javax.inject.Provider;
import javax.ws.rs.Path;
import java.lang.annotation.Annotation;
import java.util.ArrayList;
import java.util.List;

/**
 * Adds an AuthFilter to appropriately annotated resources.
 * If no annotations present, denies access.
 * For method/class annotations precedence, see {@link #internalCreate} code.
 */
public class AuthFilterFactory implements ResourceFilterFactory {
	private static final Logger logger = LoggerFactory.getLogger(AuthFilterFactory.class);

	private final List<String> httpMethods = ImmutableList.of("GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS");

	private final Provider<AuthFilter> authFilterProvider;

	@Inject
	public AuthFilterFactory(Provider<AuthFilter> authFilterProvider) {
		this.authFilterProvider = authFilterProvider;
	}

	@Override
	public List<ResourceFilter> create(AbstractMethod method) {
		ResourceFilter filter = internalCreate(method);

		logAppliedFilter(method, filter);

		return filter == null ? null : ImmutableList.of(filter);
	}

	@Nullable
	private ResourceFilter internalCreate(AbstractMethod method) {
		// DenyAll on the method take precedence over anything.
		if (method.isAnnotationPresent(DenyAll.class)) return getFilter(new String[]{});

		// RolesAllowed on method takes precedence over PermitAll.
		RolesAllowed methodRoles = method.getAnnotation(RolesAllowed.class);
		if (methodRoles != null) return getFilter(methodRoles.value());

		// PermitAll on method takes precedence over anything on class.
		if (method.isAnnotationPresent(PermitAll.class)) return null;

		// DenyAll on class take precedence over anything else on class.
		if (method.getResource().isAnnotationPresent(DenyAll.class)) return getFilter(new String[]{});

		// RolesAllowed on class takes precedence over PermitAll on class.
		RolesAllowed resourceRoles = method.getResource().getAnnotation(RolesAllowed.class);
		if (resourceRoles != null) return getFilter(resourceRoles.value());

		// PermitAll on class.
		if (method.getResource().isAnnotationPresent(PermitAll.class)) return null;

		// No annotations: deny by default.
		logger.warn("No auth annotations on resource: {}", method.getResource().getPath().getValue());
		return getFilter(new String[]{});
	}

	private ResourceFilter getFilter(String[] roles) {
		AuthFilter authFilter = authFilterProvider.get();
		authFilter.setRolesAllowed(ImmutableSet.copyOf(roles));
		return authFilter;
	}

	private void logAppliedFilter(AbstractMethod am, @Nullable ResourceFilter filter) {
		String resourcePath = am.getResource().getPath().getValue();
		Annotation[] annotations = am.getAnnotations();
		List<String> httpMethodsUsed = new ArrayList<>(2);
		String methodPath = "";
		for (Annotation annotation : annotations) {
			String name = annotation.annotationType().getSimpleName();
			if (httpMethods.contains(name)) {
				httpMethodsUsed.add(name);
			}
			else if (annotation instanceof Path) {
				methodPath = ((Path) annotation).value();
			}
		}
		logger.info("{} {} {} auth: {}", httpMethodsUsed, resourcePath, methodPath, filter == null ? "none" : filter);
	}
}
