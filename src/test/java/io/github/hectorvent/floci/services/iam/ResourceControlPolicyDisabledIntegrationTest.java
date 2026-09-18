package io.github.hectorvent.floci.services.iam;

import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.QuarkusTestProfile;
import io.quarkus.test.junit.TestProfile;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Map;

/**
 * The same unit, the same resource control policy, with organization policy enforcement off:
 * the policy is stored and attached, and nothing it says reaches a request.
 */
@QuarkusTest
@TestProfile(ResourceControlPolicyDisabledIntegrationTest.RcpDisabledProfile.class)
class ResourceControlPolicyDisabledIntegrationTest {

    private static ResourceControlPolicyFixture fixture;

    @BeforeEach
    void attachTheUnitsResourceControlPolicy() {
        if (fixture != null) {
            return;
        }
        fixture = ResourceControlPolicyFixture.create();
        fixture.attachDenyOutsideTheUnit();
    }

    @Test
    void aCallerOutsideTheUnitStillReachesEveryResourceInsideIt() {
        fixture.listBucket(fixture.bucket(), fixture.outsideAccount()).statusCode(200);
        fixture.getSecretValue(fixture.secretArn(), fixture.outsideAccount()).statusCode(200);
        fixture.assumeRole(fixture.roleArn(), fixture.outsideAccount()).statusCode(200);
    }

    public static final class RcpDisabledProfile implements QuarkusTestProfile {
        @Override
        public Map<String, String> getConfigOverrides() {
            return Map.of(
                    "floci.services.iam.enforcement-enabled", "true",
                    "floci.services.organizations.scp-enforcement-enabled", "false",
                    "floci.services.s3.global-bucket-namespace", "true");
        }
    }
}
