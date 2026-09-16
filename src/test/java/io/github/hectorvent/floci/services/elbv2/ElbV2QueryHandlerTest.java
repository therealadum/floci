package io.github.hectorvent.floci.services.elbv2;

import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;

/**
 * An empty listing carries no pagination marker. AWS omits {@code NextMarker} when there is no
 * next page; an empty element reads as a marker and the SDK asks for the next page forever.
 */
class ElbV2QueryHandlerTest {

    private ElbV2QueryHandler handler;

    @BeforeEach
    void setUp() {
        handler = new ElbV2QueryHandler(mock(ElbV2Service.class));
    }

    @Test
    void describeLoadBalancers_omitsNextMarker() {
        assertNoMarker("DescribeLoadBalancers", "DescribeLoadBalancersResult");
    }

    @Test
    void describeTargetGroups_omitsNextMarker() {
        assertNoMarker("DescribeTargetGroups", "DescribeTargetGroupsResult");
    }

    @Test
    void describeListeners_omitsNextMarker() {
        assertNoMarker("DescribeListeners", "DescribeListenersResult");
    }

    @Test
    void describeRules_omitsNextMarker() {
        assertNoMarker("DescribeRules", "DescribeRulesResult");
    }

    @Test
    void describeAccountLimits_omitsNextMarker() {
        assertNoMarker("DescribeAccountLimits", "DescribeAccountLimitsResult");
    }

    @Test
    void describeListenerCertificates_omitsNextMarker() {
        assertNoMarker("DescribeListenerCertificates", "DescribeListenerCertificatesResult");
    }

    private void assertNoMarker(String action, String resultElement) {
        Response response = handler.handle(action, params(), "us-east-1");
        assertEquals(200, response.getStatus());
        String body = (String) response.getEntity();
        assertTrue(body.contains("<" + resultElement + ">"), body);
        assertFalse(body.contains("NextMarker"), body);
        assertFalse(body.contains("<Marker"), body);
        assertFalse(body.contains("NextToken"), body);
    }

    private MultivaluedMap<String, String> params() {
        return new MultivaluedHashMap<>();
    }
}
