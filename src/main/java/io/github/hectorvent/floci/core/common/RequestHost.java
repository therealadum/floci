package io.github.hectorvent.floci.core.common;

import io.vertx.core.http.HttpServerRequest;
import io.vertx.core.net.HostAndPort;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.core.HttpHeaders;

import java.net.URI;

/**
 * The one place a request's host is read.
 *
 * <p>HTTP/1.1 carries it in the {@code Host} header. HTTP/2 (RFC 9113) sends no {@code Host}
 * header; the host travels in the {@code :authority} pseudo header, which the container exposes as
 * the request URI authority and Vert.x as {@link HttpServerRequest#authority()}. The answer keeps
 * the port where the source carries it, exactly as {@code Host} would.
 */
public final class RequestHost {

    private static final String HOST = "Host";

    private RequestHost() {
    }

    /** The header when present and not blank, else the request URI's authority, else null. */
    public static String of(String hostHeader, URI requestUri) {
        if (hostHeader != null && !hostHeader.isBlank()) {
            return hostHeader;
        }
        return requestUri != null ? requestUri.getAuthority() : null;
    }

    public static String of(ContainerRequestContext requestContext) {
        URI requestUri = requestContext.getUriInfo() != null
                ? requestContext.getUriInfo().getRequestUri()
                : null;
        return of(requestContext, requestUri);
    }

    /** As {@link #of(ContainerRequestContext)}, falling back to a request URI the caller holds. */
    public static String of(ContainerRequestContext requestContext, URI requestUri) {
        return of(requestContext.getHeaderString(HOST), requestUri);
    }

    /** As {@link #of(String, URI)}, reading the header from JAX-RS headers, which may be null. */
    public static String of(HttpHeaders headers, URI requestUri) {
        return of(headers != null ? headers.getHeaderString(HOST) : null, requestUri);
    }

    public static String of(HttpServerRequest request) {
        String header = request.getHeader(HOST);
        if (header != null && !header.isBlank()) {
            return header;
        }
        HostAndPort authority = request.authority();
        if (authority == null || authority.host() == null) {
            return null;
        }
        return authority.port() >= 0 ? authority.host() + ":" + authority.port() : authority.host();
    }
}
