package name.dlazerka.gae.jersey.oauth2;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.Sets;
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
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;

/**
 * Adds AuthFilter to appropriately annotated resources.
 */
public class AuthFilterFactory implements ResourceFilterFactory {
	private static final Logger logger = LoggerFactory.getLogger(AuthFilterFactory.class);

	private final List<String> httpMethods = ImmutableList.of("GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS");

	@Inject
	Provider<AuthFilter> authFilterProvider;

	@Override
	public List<ResourceFilter> create(AbstractMethod am) {
		ResourceFilter filter = internalCreate(am);
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
		logger.info("{} {}{} auth: {}", httpMethodsUsed, resourcePath, methodPath, filter == null ? "none" : filter);
		return filter == null ? null : ImmutableList.of(filter);
	}

	@Nullable
	private ResourceFilter internalCreate(AbstractMethod am) {
		// DenyAll on the method take precedence over RolesAllowed and PermitAll
		if (am.isAnnotationPresent(DenyAll.class))
			return getFilter(new String[]{});

		// RolesAllowed on the method takes precedence over PermitAll
		RolesAllowed rolesAllowed = am.getAnnotation(RolesAllowed.class);
		if (rolesAllowed != null) {
			return getFilter(rolesAllowed.value());
		}

		// PermitAll takes precedence over RolesAllowed on the class.
		if (am.isAnnotationPresent(PermitAll.class))
			return null;

		// DenyAll on the class take precedence over RolesAllowed and PermitAll on the class.
		if (am.getResource().isAnnotationPresent(DenyAll.class))
			return getFilter(new String[]{});

		// RolesAllowed on the class takes precedence over PermitAll
		rolesAllowed = am.getResource().getAnnotation(RolesAllowed.class);
		if (rolesAllowed != null)
			return getFilter(rolesAllowed.value());

		if (am.getResource().isAnnotationPresent(PermitAll.class))
			return null;

		// Deny by default.
		return getFilter(new String[]{});
	}

	private ResourceFilter getFilter(String[] roles) {
		LinkedHashSet<String> set = Sets.newLinkedHashSet(Arrays.asList(roles));
		AuthFilter authFilter = authFilterProvider.get();
		authFilter.setRoles(set);
		return authFilter;
	}

}
