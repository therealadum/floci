package io.github.hectorvent.floci.services.iam;

import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.QuarkusTestProfile;
import io.quarkus.test.junit.TestProfile;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.hamcrest.Matchers.containsString;

/**
 * A resource control policy on an organizational unit bounds every principal's access to the
 * resources of the accounts under it — the accounts' own principals and outside ones alike —
 * and never grants.
 *
 * <p>The unit's policy here denies everything whose {@code aws:PrincipalOrgPaths} lies outside
 * the unit, which is section 6's "a resource control policy denies reaching in from outside it"
 * written as one document. It is proved against a bucket, a secret and the {@code AssumeRole} of
 * a role, the three of AWS's resource-control-policy services this emulator holds resources for.
 */
@QuarkusTest
@TestProfile(ResourceControlPolicyEnforcementIntegrationTest.RcpEnforcementProfile.class)
class ResourceControlPolicyEnforcementIntegrationTest {

    private static ResourceControlPolicyFixture fixture;

    /**
     * Builds the organization and attaches the policy once for the class. It is not a
     * {@code @BeforeAll}: RestAssured's port is set per test method under {@code @QuarkusTest},
     * so a call made before the first one reaches no server.
     */
    @BeforeEach
    void attachTheUnitsResourceControlPolicy() {
        if (fixture != null) {
            return;
        }
        fixture = ResourceControlPolicyFixture.create();
        fixture.attachDenyOutsideTheUnit();
    }

    @Test
    void aCallerOutsideTheUnitIsRefusedABucketInsideIt() {
        fixture.listBucket(fixture.bucket(), fixture.outsideAccount()).statusCode(403)
                .body(containsString("<Code>AccessDenied</Code>"));
        fixture.listBucket(fixture.bucket(), fixture.insideAccount()).statusCode(200);
    }

    @Test
    void aCallerOutsideTheUnitIsRefusedASecretInsideIt() {
        fixture.getSecretValue(fixture.secretArn(), fixture.outsideAccount()).statusCode(403)
                .body(containsString("AccessDenied"));
        fixture.getSecretValue(fixture.secretArn(), fixture.insideAccount()).statusCode(200);
    }

    @Test
    void aCallerOutsideTheUnitIsRefusedAssumeRoleOnARoleInsideIt() {
        fixture.assumeRole(fixture.roleArn(), fixture.outsideAccount()).statusCode(403);
        fixture.assumeRole(fixture.roleArn(), fixture.insideAccount()).statusCode(200);
    }

    @Test
    void theManagementAccountsOwnResourcesAreNotBound() {
        // The policy is attached to the unit and the management account is not under it; AWS
        // exempts the management account's resources from resource control policies outright.
        fixture.listBucket(fixture.managementBucket(), fixture.outsideAccount()).statusCode(200);
    }

    public static final class RcpEnforcementProfile implements QuarkusTestProfile {
        @Override
        public Map<String, String> getConfigOverrides() {
            return Map.of(
                    "floci.services.iam.enforcement-enabled", "true",
                    "floci.services.organizations.scp-enforcement-enabled", "true",
                    "floci.services.s3.global-bucket-namespace", "true");
        }
    }
}
