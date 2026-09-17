package io.github.hectorvent.floci.core.common;

import io.vertx.core.http.HttpServerRequest;
import io.vertx.core.net.HostAndPort;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.core.UriInfo;
import org.junit.jupiter.api.Test;

import java.net.URI;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class RequestHostTest {

    private static final URI HTTP2_URI = URI.create("https://grafana.a.localhost.floci.io:4566/api/health");

    @Test
    void headerWins() {
        assertEquals("other.localhost:4566", RequestHost.of("other.localhost:4566", HTTP2_URI));
    }

    @Test
    void absentHeaderFallsBackToUriAuthorityWithItsPort() {
        assertEquals("grafana.a.localhost.floci.io:4566", RequestHost.of((String) null, HTTP2_URI));
    }

    @Test
    void blankHeaderFallsBack() {
        assertEquals("grafana.a.localhost.floci.io:4566", RequestHost.of("  ", HTTP2_URI));
    }

    @Test
    void neitherYieldsNull() {
        assertNull(RequestHost.of((String) null, null));
        assertNull(RequestHost.of((String) null, URI.create("/relative/path")));
    }

    @Test
    void containerRequestContextReadsHeaderThenUriAuthority() {
        UriInfo uriInfo = mock(UriInfo.class);
        when(uriInfo.getRequestUri()).thenReturn(HTTP2_URI);
        ContainerRequestContext ctx = mock(ContainerRequestContext.class);
        when(ctx.getUriInfo()).thenReturn(uriInfo);
        when(ctx.getHeaderString("Host")).thenReturn(null);
        assertEquals("grafana.a.localhost.floci.io:4566", RequestHost.of(ctx));

        when(ctx.getHeaderString("Host")).thenReturn("h1.localhost:4566");
        assertEquals("h1.localhost:4566", RequestHost.of(ctx));
    }

    @Test
    void vertxFormReadsAuthorityWhenHeaderAbsent() {
        HttpServerRequest request = mock(HttpServerRequest.class);
        when(request.getHeader("Host")).thenReturn(null);
        when(request.authority()).thenReturn(HostAndPort.create("grafana.a.localhost.floci.io", 4566));
        assertEquals("grafana.a.localhost.floci.io:4566", RequestHost.of(request));

        when(request.authority()).thenReturn(HostAndPort.create("grafana.a.localhost.floci.io", -1));
        assertEquals("grafana.a.localhost.floci.io", RequestHost.of(request));

        when(request.authority()).thenReturn(null);
        assertNull(RequestHost.of(request));

        when(request.getHeader("Host")).thenReturn("h1.localhost:4566");
        assertEquals("h1.localhost:4566", RequestHost.of(request));
    }
}
