package io.github.hectorvent.floci.services.cloudfront;

import com.sun.net.httpserver.HttpServer;
import io.github.hectorvent.floci.services.cloudfront.model.DefaultCacheBehavior;
import io.github.hectorvent.floci.services.cloudfront.model.Distribution;
import io.github.hectorvent.floci.services.cloudfront.model.DistributionConfig;
import io.github.hectorvent.floci.services.cloudfront.model.Origin;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.QuarkusTestProfile;
import io.quarkus.test.junit.TestProfile;
import jakarta.inject.Inject;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

/**
 * Every viewer method a cache behavior's {@code AllowedMethods} declares is routed through the
 * distribution data plane to the origin; a method the matched behavior does not allow answers 405
 * with an {@code Allow} header listing the methods it does allow.
 */
@QuarkusTest
@TestProfile(CloudFrontAllowedMethodsServingTest.PrivateOriginProfile.class)
class CloudFrontAllowedMethodsServingTest {

    private static final List<String> ALL_METHODS =
            List.of("GET", "HEAD", "OPTIONS", "PUT", "POST", "PATCH", "DELETE");

    @Inject
    CloudFrontService cloudFrontService;

    private HttpServer originServer;

    @AfterEach
    void stopOrigin() {
        if (originServer != null) {
            originServer.stop(0);
        }
    }

    @Test
    void routesPostWithABodyToACustomOriginWhenTheBehaviorAllowsEveryMethod() throws Exception {
        AtomicReference<String> receivedMethod = new AtomicReference<>();
        AtomicReference<String> receivedBody = new AtomicReference<>();
        AtomicReference<String> receivedContentType = new AtomicReference<>();
        originServer = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        originServer.createContext("/", exchange -> {
            receivedMethod.set(exchange.getRequestMethod());
            receivedContentType.set(exchange.getRequestHeaders().getFirst("Content-Type"));
            receivedBody.set(new String(
                    exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
            byte[] body = "origin-post-body".getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(201, body.length);
            exchange.getResponseBody().write(body);
            exchange.close();
        });
        originServer.start();

        DefaultCacheBehavior behavior = defaultBehavior("grafana-origin");
        behavior.setAllowedMethods(ALL_METHODS);
        Distribution distribution = distribution(behavior, originServer.getAddress().getPort());

        given()
                .header("Host", distribution.getDomainName())
                .contentType("application/json")
                .body("{\"queries\":[]}")
                .when().post("/api/ds/query")
                .then().statusCode(201)
                .body(equalTo("origin-post-body"));

        assertEquals("POST", receivedMethod.get());
        assertEquals("{\"queries\":[]}", receivedBody.get());
        assertEquals("application/json", receivedContentType.get());
    }

    @Test
    void answers405WithAnAllowHeaderWhenTheBehaviorDoesNotAllowTheMethod() throws Exception {
        AtomicReference<String> receivedMethod = new AtomicReference<>();
        originServer = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        originServer.createContext("/", exchange -> {
            receivedMethod.set(exchange.getRequestMethod());
            exchange.sendResponseHeaders(204, -1);
            exchange.close();
        });
        originServer.start();

        DefaultCacheBehavior behavior = defaultBehavior("site-origin");
        behavior.setAllowedMethods(List.of("GET", "HEAD", "OPTIONS"));
        Distribution distribution = distribution(behavior, originServer.getAddress().getPort());

        given()
                .header("Host", distribution.getDomainName())
                .contentType("text/plain")
                .body("ignored")
                .when().post("/index.html")
                .then().statusCode(405)
                .header("Allow", equalTo("GET, HEAD, OPTIONS"))
                .body(equalTo("Invalid method."));

        assertNull(receivedMethod.get());
    }

    @Test
    void routesPutPatchAndDeleteToACustomOriginWhenTheBehaviorAllowsThem() throws Exception {
        AtomicReference<String> receivedMethod = new AtomicReference<>();
        AtomicReference<String> receivedBody = new AtomicReference<>();
        originServer = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        originServer.createContext("/", exchange -> {
            receivedMethod.set(exchange.getRequestMethod());
            receivedBody.set(new String(
                    exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
            exchange.sendResponseHeaders(204, -1);
            exchange.close();
        });
        originServer.start();

        DefaultCacheBehavior behavior = defaultBehavior("grafana-origin");
        behavior.setAllowedMethods(ALL_METHODS);
        Distribution distribution = distribution(behavior, originServer.getAddress().getPort());

        given()
                .header("Host", distribution.getDomainName())
                .contentType("application/json")
                .body("{\"put\":1}")
                .when().put("/api/dashboards")
                .then().statusCode(204);
        assertEquals("PUT", receivedMethod.get());
        assertEquals("{\"put\":1}", receivedBody.get());

        given()
                .header("Host", distribution.getDomainName())
                .contentType("application/json")
                .body("{\"patch\":1}")
                .when().patch("/api/dashboards")
                .then().statusCode(204);
        assertEquals("PATCH", receivedMethod.get());
        assertEquals("{\"patch\":1}", receivedBody.get());

        given()
                .header("Host", distribution.getDomainName())
                .when().delete("/api/dashboards/1")
                .then().statusCode(204);
        assertEquals("DELETE", receivedMethod.get());
    }

    private Distribution distribution(DefaultCacheBehavior behavior, int port) {
        Origin origin = new Origin();
        origin.setId(behavior.getTargetOriginId());
        origin.setDomainName("127.0.0.1");
        origin.setCustomOriginConfig(customOriginConfig(port));

        DistributionConfig config = new DistributionConfig();
        config.setEnabled(true);
        config.setOrigins(List.of(origin));
        config.setDefaultCacheBehavior(behavior);

        Distribution distribution = new Distribution();
        distribution.setConfig(config);
        return cloudFrontService.createDistribution(distribution, Map.of());
    }

    private static Map<String, Object> customOriginConfig(int port) {
        Map<String, Object> config = new LinkedHashMap<>();
        config.put("HTTPPort", String.valueOf(port));
        config.put("HTTPSPort", "443");
        config.put("OriginProtocolPolicy", "http-only");
        return config;
    }

    private static DefaultCacheBehavior defaultBehavior(String originId) {
        DefaultCacheBehavior behavior = new DefaultCacheBehavior();
        behavior.setTargetOriginId(originId);
        behavior.setViewerProtocolPolicy("allow-all");
        return behavior;
    }

    public static final class PrivateOriginProfile implements QuarkusTestProfile {
        @Override
        public Map<String, String> getConfigOverrides() {
            return Map.of("floci.services.cloudfront.allowed-private-origin-hosts", "127.0.0.1");
        }
    }
}
