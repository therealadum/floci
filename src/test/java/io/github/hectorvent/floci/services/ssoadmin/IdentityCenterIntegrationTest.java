package io.github.hectorvent.floci.services.ssoadmin;

import io.github.hectorvent.floci.testing.RestAssuredJsonUtils;
import io.github.hectorvent.floci.testutil.AwsRequestSigner;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.QuarkusTestProfile;
import io.quarkus.test.junit.TestProfile;
import io.restassured.RestAssured;
import io.restassured.response.Response;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.emptyIterable;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

/**
 * Identity Center as the platform uses it: one instance from the start, the people the start
 * configuration provisions, groups and their members, permission sets, and assignments that
 * provision a role into the target account.
 *
 * <p>Every call here is a genuinely signed request from the seeded deployer principal, with IAM
 * enforcement and signature validation both on, so what is proven is the surface a deploy actually
 * meets rather than an unauthenticated one.
 */
@QuarkusTest
@TestProfile(IdentityCenterIntegrationTest.IdentityCenterProfile.class)
class IdentityCenterIntegrationTest {

    private static final String REGION = "us-east-1";
    private static final String DEPLOYER_KEY = "floci";
    private static final String DEPLOYER_SECRET = "floci";
    /** The deployer's own account: the one account a signed IAM call can read roles in. */
    private static final String ACCOUNT = "000000000000";
    private static final String JSON_1_1 = "application/x-amz-json-1.1";

    /** The two addresses {@link IdentityCenterProfile} provisions. */
    private static final String ADAM = "adam.shurson@localhost.floci.io";
    private static final String SECOND = "second.person@localhost.floci.io";
    /** An address the start configuration does not carry, so nothing may have created it. */
    private static final String STRANGER = "stranger@localhost.floci.io";

    private static String instanceArn;
    private static String identityStoreId;

    @BeforeEach
    void readTheInstance() {
        RestAssuredJsonUtils.configureAwsContentTypes();
        // Built lazily: the port is not set at @BeforeAll.
        if (instanceArn != null) {
            return;
        }
        Response instances = sso("ListInstances", "{}");
        instances.then().statusCode(200);
        instanceArn = instances.path("Instances[0].InstanceArn");
        identityStoreId = instances.path("Instances[0].IdentityStoreId");
    }

    // ── The instance ───────────────────────────────────────────────────────────

    @Test
    void oneInstanceExistsFromTheStartAndIsTheSameOneOnEveryCall() {
        sso("ListInstances", "{}").then().statusCode(200)
                .body("Instances", hasSize(1))
                .body("Instances[0].InstanceArn", containsString(":sso:::instance/ssoins-"))
                .body("Instances[0].IdentityStoreId", notNullValue())
                .body("Instances[0].InstanceArn", equalTo(instanceArn))
                .body("Instances[0].IdentityStoreId", equalTo(identityStoreId));
    }

    // ── The people the start configuration provisions ──────────────────────────

    @Test
    void everyConfiguredAddressIsAUserWithThatUserNameAndPrimaryEmail() {
        for (String address : new String[] {ADAM, SECOND}) {
            Response users = identityStore("ListUsers", """
                    {"IdentityStoreId":"%s","Filters":[{"AttributePath":"UserName","AttributeValue":"%s"}]}"""
                    .formatted(identityStoreId, address));
            users.then().statusCode(200)
                    .body("Users", hasSize(1))
                    .body("Users[0].UserName", equalTo(address))
                    .body("Users[0].Emails[0].Value", equalTo(address))
                    .body("Users[0].Emails[0].Primary", equalTo(true));

            String byUserName = identityStore("GetUserId", """
                    {"IdentityStoreId":"%s","AlternateIdentifier":{"UniqueAttribute":\
                    {"AttributePath":"userName","AttributeValue":"%s"}}}"""
                    .formatted(identityStoreId, address))
                    .then().statusCode(200).extract().path("UserId");
            assertEquals(users.path("Users[0].UserId"), byUserName);

            identityStore("GetUserId", """
                    {"IdentityStoreId":"%s","AlternateIdentifier":{"UniqueAttribute":\
                    {"AttributePath":"emails.value","AttributeValue":"%s"}}}"""
                    .formatted(identityStoreId, address))
                    .then().statusCode(200).body("UserId", equalTo(byUserName));
        }
        assertNotEquals(
                userId(ADAM), userId(SECOND), "each address is provisioned as its own person");
    }

    @Test
    void anAddressTheStartConfigurationDoesNotCarryIsNobody() {
        // This is the refusal `deploy management` is checking for before it runs: a member named
        // in the binding but never provisioned has no user to assign anything to.
        identityStore("ListUsers", """
                {"IdentityStoreId":"%s","Filters":[{"AttributePath":"UserName","AttributeValue":"%s"}]}"""
                .formatted(identityStoreId, STRANGER))
                .then().statusCode(200).body("Users", emptyIterable());
        identityStore("GetUserId", """
                {"IdentityStoreId":"%s","AlternateIdentifier":{"UniqueAttribute":\
                {"AttributePath":"userName","AttributeValue":"%s"}}}"""
                .formatted(identityStoreId, STRANGER))
                .then().statusCode(400).body("__type", equalTo("ResourceNotFoundException"));
    }

    // ── Groups and members ─────────────────────────────────────────────────────

    @Test
    void groupsMembersAndTheirLookupsFollowAws() {
        String displayName = "platform-administrators";
        String groupId = identityStore("CreateGroup",
                """
                {"IdentityStoreId":"%s","DisplayName":"%s","Description":"Administers every account."}"""
                        .formatted(identityStoreId, displayName))
                .then().statusCode(200).extract().path("GroupId");

        identityStore("CreateGroup",
                """
                {"IdentityStoreId":"%s","DisplayName":"%s"}""".formatted(identityStoreId, displayName))
                .then().statusCode(400).body("__type", equalTo("ConflictException"));

        identityStore("DescribeGroup",
                """
                {"IdentityStoreId":"%s","GroupId":"%s"}""".formatted(identityStoreId, groupId))
                .then().statusCode(200)
                .body("DisplayName", equalTo(displayName))
                .body("Description", equalTo("Administers every account."));

        identityStore("ListGroups", """
                {"IdentityStoreId":"%s","Filters":[{"AttributePath":"DisplayName","AttributeValue":"%s"}]}"""
                .formatted(identityStoreId, displayName))
                .then().statusCode(200).body("Groups", hasSize(1)).body("Groups[0].GroupId", equalTo(groupId));

        identityStore("GetGroupId", """
                {"IdentityStoreId":"%s","AlternateIdentifier":{"UniqueAttribute":\
                {"AttributePath":"displayName","AttributeValue":"%s"}}}"""
                .formatted(identityStoreId, displayName))
                .then().statusCode(200).body("GroupId", equalTo(groupId));

        String userId = userId(ADAM);
        String membershipId = identityStore("CreateGroupMembership", """
                {"IdentityStoreId":"%s","GroupId":"%s","MemberId":{"UserId":"%s"}}"""
                .formatted(identityStoreId, groupId, userId))
                .then().statusCode(200).extract().path("MembershipId");

        identityStore("CreateGroupMembership", """
                {"IdentityStoreId":"%s","GroupId":"%s","MemberId":{"UserId":"%s"}}"""
                .formatted(identityStoreId, groupId, userId))
                .then().statusCode(400).body("__type", equalTo("ConflictException"));

        identityStore("GetGroupMembershipId", """
                {"IdentityStoreId":"%s","GroupId":"%s","MemberId":{"UserId":"%s"}}"""
                .formatted(identityStoreId, groupId, userId))
                .then().statusCode(200).body("MembershipId", equalTo(membershipId));

        identityStore("DescribeGroupMembership", """
                {"IdentityStoreId":"%s","MembershipId":"%s"}""".formatted(identityStoreId, membershipId))
                .then().statusCode(200)
                .body("GroupId", equalTo(groupId))
                .body("MemberId.UserId", equalTo(userId));

        identityStore("ListGroupMemberships", """
                {"IdentityStoreId":"%s","GroupId":"%s"}""".formatted(identityStoreId, groupId))
                .then().statusCode(200)
                .body("GroupMemberships.MembershipId", hasItem(membershipId));

        identityStore("ListGroupMembershipsForMember", """
                {"IdentityStoreId":"%s","MemberId":{"UserId":"%s"}}""".formatted(identityStoreId, userId))
                .then().statusCode(200)
                .body("GroupMemberships.GroupId", hasItem(groupId));

        identityStore("DeleteGroupMembership", """
                {"IdentityStoreId":"%s","MembershipId":"%s"}""".formatted(identityStoreId, membershipId))
                .then().statusCode(200);
        identityStore("DescribeGroupMembership", """
                {"IdentityStoreId":"%s","MembershipId":"%s"}""".formatted(identityStoreId, membershipId))
                .then().statusCode(400).body("__type", equalTo("ResourceNotFoundException"));

        identityStore("DeleteGroup", """
                {"IdentityStoreId":"%s","GroupId":"%s"}""".formatted(identityStoreId, groupId))
                .then().statusCode(200);
        identityStore("DescribeGroup", """
                {"IdentityStoreId":"%s","GroupId":"%s"}""".formatted(identityStoreId, groupId))
                .then().statusCode(400).body("__type", equalTo("ResourceNotFoundException"));
    }

    @Test
    void aListPagesOnItsTokenAndTheLastPageCarriesNone() {
        for (int index = 0; index < 3; index++) {
            identityStore("CreateGroup", """
                    {"IdentityStoreId":"%s","DisplayName":"paged-group-%d"}"""
                    .formatted(identityStoreId, index))
                    .then().statusCode(200);
        }
        String token = null;
        int seen = 0;
        for (int page = 0; page < 10; page++) {
            String request = token == null
                    ? """
                      {"IdentityStoreId":"%s","MaxResults":1}""".formatted(identityStoreId)
                    : """
                      {"IdentityStoreId":"%s","MaxResults":1,"NextToken":"%s"}"""
                            .formatted(identityStoreId, token);
            Response response = identityStore("ListGroups", request);
            response.then().statusCode(200);
            seen += response.<java.util.List<?>>path("Groups").size();
            token = response.path("NextToken");
            if (token == null) {
                break;
            }
        }
        // The walk ended because a page carried no marker, not because the loop ran out.
        assertEquals(null, token, "the last page carries no NextToken");
        org.junit.jupiter.api.Assertions.assertTrue(seen >= 3, "every group was paged through");
    }

    // ── Permission sets ────────────────────────────────────────────────────────

    @Test
    void aPermissionSetCarriesItsSessionDurationTagsAndPolicies() {
        String arn = createPermissionSet("SessionShape", "PT8H");

        sso("DescribePermissionSet", """
                {"InstanceArn":"%s","PermissionSetArn":"%s"}""".formatted(instanceArn, arn))
                .then().statusCode(200)
                .body("PermissionSet.Name", equalTo("SessionShape"))
                .body("PermissionSet.SessionDuration", equalTo("PT8H"));

        sso("ListTagsForResource", """
                {"InstanceArn":"%s","ResourceArn":"%s"}""".formatted(instanceArn, arn))
                .then().statusCode(200).body("Tags.Key", hasItem("mycellium.module"));

        sso("UpdatePermissionSet", """
                {"InstanceArn":"%s","PermissionSetArn":"%s","SessionDuration":"PT1H"}"""
                .formatted(instanceArn, arn)).then().statusCode(200);
        sso("DescribePermissionSet", """
                {"InstanceArn":"%s","PermissionSetArn":"%s"}""".formatted(instanceArn, arn))
                .then().statusCode(200).body("PermissionSet.SessionDuration", equalTo("PT1H"));

        sso("AttachManagedPolicyToPermissionSet", """
                {"InstanceArn":"%s","PermissionSetArn":"%s",\
                "ManagedPolicyArn":"arn:aws:iam::aws:policy/AdministratorAccess"}"""
                .formatted(instanceArn, arn)).then().statusCode(200);
        sso("ListManagedPoliciesInPermissionSet", """
                {"InstanceArn":"%s","PermissionSetArn":"%s"}""".formatted(instanceArn, arn))
                .then().statusCode(200).body("AttachedManagedPolicies[0].Name", equalTo("AdministratorAccess"));

        sso("PutInlinePolicyToPermissionSet", """
                {"InstanceArn":"%s","PermissionSetArn":"%s","InlinePolicy":%s}"""
                .formatted(instanceArn, arn, quoted(INLINE_POLICY))).then().statusCode(200);
        sso("GetInlinePolicyForPermissionSet", """
                {"InstanceArn":"%s","PermissionSetArn":"%s"}""".formatted(instanceArn, arn))
                .then().statusCode(200).body("InlinePolicy", equalTo(INLINE_POLICY));

        sso("DetachManagedPolicyFromPermissionSet", """
                {"InstanceArn":"%s","PermissionSetArn":"%s",\
                "ManagedPolicyArn":"arn:aws:iam::aws:policy/AdministratorAccess"}"""
                .formatted(instanceArn, arn)).then().statusCode(200);
        sso("DeleteInlinePolicyFromPermissionSet", """
                {"InstanceArn":"%s","PermissionSetArn":"%s"}""".formatted(instanceArn, arn))
                .then().statusCode(200);
        sso("GetInlinePolicyForPermissionSet", """
                {"InstanceArn":"%s","PermissionSetArn":"%s"}""".formatted(instanceArn, arn))
                .then().statusCode(200).body("InlinePolicy", equalTo(""));

        sso("ListPermissionSets", """
                {"InstanceArn":"%s"}""".formatted(instanceArn))
                .then().statusCode(200).body("PermissionSets", hasItem(arn));

        sso("DeletePermissionSet", """
                {"InstanceArn":"%s","PermissionSetArn":"%s"}""".formatted(instanceArn, arn))
                .then().statusCode(200);
        sso("DescribePermissionSet", """
                {"InstanceArn":"%s","PermissionSetArn":"%s"}""".formatted(instanceArn, arn))
                .then().statusCode(400).body("__type", equalTo("ResourceNotFoundException"));
    }

    @Test
    void provisioningAPermissionSetFinishesAtOnce() {
        String arn = createPermissionSet("ProvisionAtOnce", "PT1H");
        String requestId = sso("ProvisionPermissionSet", """
                {"InstanceArn":"%s","PermissionSetArn":"%s","TargetType":"AWS_ACCOUNT","TargetId":"%s"}"""
                .formatted(instanceArn, arn, ACCOUNT))
                .then().statusCode(200)
                .body("PermissionSetProvisioningStatus.Status", equalTo("SUCCEEDED"))
                .extract().path("PermissionSetProvisioningStatus.RequestId");

        // The first poll is the last one: nothing is IN_PROGRESS on this emulator.
        sso("DescribePermissionSetProvisioningStatus", """
                {"InstanceArn":"%s","ProvisionPermissionSetRequestId":"%s"}"""
                .formatted(instanceArn, requestId))
                .then().statusCode(200)
                .body("PermissionSetProvisioningStatus.Status", equalTo("SUCCEEDED"))
                .body("PermissionSetProvisioningStatus.FailureReason", nullValue());
    }

    // ── Assignments and the role they provision ────────────────────────────────

    @Test
    void anAssignmentProvisionsTheReservedRoleIntoTheTargetAccount() {
        String name = "ReservedRoleShape";
        String arn = createPermissionSet(name, "PT8H");
        sso("AttachManagedPolicyToPermissionSet", """
                {"InstanceArn":"%s","PermissionSetArn":"%s",\
                "ManagedPolicyArn":"arn:aws:iam::aws:policy/AdministratorAccess"}"""
                .formatted(instanceArn, arn)).then().statusCode(200);
        sso("PutInlinePolicyToPermissionSet", """
                {"InstanceArn":"%s","PermissionSetArn":"%s","InlinePolicy":%s}"""
                .formatted(instanceArn, arn, quoted(INLINE_POLICY))).then().statusCode(200);

        String groupId = identityStore("CreateGroup", """
                {"IdentityStoreId":"%s","DisplayName":"reserved-role-group"}""".formatted(identityStoreId))
                .then().statusCode(200).extract().path("GroupId");

        String createRequestId = sso("CreateAccountAssignment", assignment(arn, groupId))
                .then().statusCode(200)
                .body("AccountAssignmentCreationStatus.Status", equalTo("SUCCEEDED"))
                .extract().path("AccountAssignmentCreationStatus.RequestId");
        sso("DescribeAccountAssignmentCreationStatus", """
                {"InstanceArn":"%s","AccountAssignmentCreationRequestId":"%s"}"""
                .formatted(instanceArn, createRequestId))
                .then().statusCode(200).body("AccountAssignmentCreationStatus.Status", equalTo("SUCCEEDED"));

        String roleName = "AWSReservedSSO_" + name + "_floci";
        String expectedArn = "arn:aws:iam::" + ACCOUNT
                + ":role/aws-reserved/sso.amazonaws.com/" + roleName;

        // The role exists in the target account's IAM, in AWS's ARN form, with the permission
        // set's session duration, trusted for SAML federation.
        iam(Map.of("Action", "GetRole", "RoleName", roleName)).then().statusCode(200)
                .body(containsString("<Arn>" + expectedArn + "</Arn>"))
                .body(containsString("<Path>/aws-reserved/sso.amazonaws.com/</Path>"))
                .body(containsString("<MaxSessionDuration>28800</MaxSessionDuration>"))
                .body(containsString("sts:AssumeRoleWithSAML"));

        iam(Map.of("Action", "ListAttachedRolePolicies", "RoleName", roleName)).then().statusCode(200)
                .body(containsString("arn:aws:iam::aws:policy/AdministratorAccess"));
        iam(Map.of("Action", "GetRolePolicy", "RoleName", roleName, "PolicyName", name))
                .then().statusCode(200).body(containsString("s3:ListAllMyBuckets"));

        sso("ListAccountAssignments", """
                {"InstanceArn":"%s","AccountId":"%s","PermissionSetArn":"%s"}"""
                .formatted(instanceArn, ACCOUNT, arn))
                .then().statusCode(200)
                .body("AccountAssignments[0].PrincipalId", equalTo(groupId))
                .body("AccountAssignments[0].PrincipalType", equalTo("GROUP"));
        sso("ListAccountsForProvisionedPermissionSet", """
                {"InstanceArn":"%s","PermissionSetArn":"%s"}""".formatted(instanceArn, arn))
                .then().statusCode(200).body("AccountIds", hasItem(ACCOUNT));
        sso("ListPermissionSetsProvisionedToAccount", """
                {"InstanceArn":"%s","AccountId":"%s"}""".formatted(instanceArn, ACCOUNT))
                .then().statusCode(200).body("PermissionSets", hasItem(arn));

        String deleteRequestId = sso("DeleteAccountAssignment", assignment(arn, groupId))
                .then().statusCode(200)
                .body("AccountAssignmentDeletionStatus.Status", equalTo("SUCCEEDED"))
                .extract().path("AccountAssignmentDeletionStatus.RequestId");
        sso("DescribeAccountAssignmentDeletionStatus", """
                {"InstanceArn":"%s","AccountAssignmentDeletionRequestId":"%s"}"""
                .formatted(instanceArn, deleteRequestId))
                .then().statusCode(200).body("AccountAssignmentDeletionStatus.Status", equalTo("SUCCEEDED"));

        // The last assignment went, so the provisioning and the role went with it.
        iam(Map.of("Action", "GetRole", "RoleName", roleName)).then().statusCode(404)
                .body(containsString("<Code>NoSuchEntity</Code>"));
        sso("ListAccountsForProvisionedPermissionSet", """
                {"InstanceArn":"%s","PermissionSetArn":"%s"}""".formatted(instanceArn, arn))
                .then().statusCode(200).body("AccountIds", emptyIterable());
    }

    @Test
    void theAccountsOwnPrincipalsCannotChangeTheReservedRole() {
        String name = "ReservedRoleGuard";
        String arn = createPermissionSet(name, "PT1H");
        String groupId = identityStore("CreateGroup", """
                {"IdentityStoreId":"%s","DisplayName":"reserved-role-guard-group"}"""
                .formatted(identityStoreId))
                .then().statusCode(200).extract().path("GroupId");
        sso("CreateAccountAssignment", assignment(arn, groupId)).then().statusCode(200);

        String roleName = "AWSReservedSSO_" + name + "_floci";
        // Full administrator on the account, and still refused: the role is the service's.
        iam(Map.of("Action", "PutRolePolicy", "RoleName", roleName, "PolicyName", "escalate",
                "PolicyDocument", INLINE_POLICY))
                .then().statusCode(403).body(containsString("<Code>AccessDenied</Code>"));
        iam(Map.of("Action", "UpdateAssumeRolePolicy", "RoleName", roleName,
                "PolicyDocument", INLINE_POLICY))
                .then().statusCode(403).body(containsString("<Code>AccessDenied</Code>"));
        iam(Map.of("Action", "AttachRolePolicy", "RoleName", roleName,
                "PolicyArn", "arn:aws:iam::aws:policy/AdministratorAccess"))
                .then().statusCode(403).body(containsString("<Code>AccessDenied</Code>"));
        iam(Map.of("Action", "DeleteRole", "RoleName", roleName))
                .then().statusCode(403).body(containsString("<Code>AccessDenied</Code>"));

        iam(Map.of("Action", "GetRole", "RoleName", roleName)).then().statusCode(200);
    }

    // ── Helpers ────────────────────────────────────────────────────────────────

    private static final String INLINE_POLICY =
            "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\","
                    + "\"Action\":\"s3:ListAllMyBuckets\",\"Resource\":\"*\"}]}";

    private String assignment(String permissionSetArn, String groupId) {
        return """
               {"InstanceArn":"%s","TargetId":"%s","TargetType":"AWS_ACCOUNT",\
               "PermissionSetArn":"%s","PrincipalType":"GROUP","PrincipalId":"%s"}"""
                .formatted(instanceArn, ACCOUNT, permissionSetArn, groupId);
    }

    private String createPermissionSet(String name, String sessionDuration) {
        return sso("CreatePermissionSet", """
                {"InstanceArn":"%s","Name":"%s","SessionDuration":"%s",\
                "Tags":[{"Key":"mycellium.module","Value":"management"}]}"""
                .formatted(instanceArn, name, sessionDuration))
                .then().statusCode(200).extract().path("PermissionSet.PermissionSetArn");
    }

    private String userId(String address) {
        return identityStore("GetUserId", """
                {"IdentityStoreId":"%s","AlternateIdentifier":{"UniqueAttribute":\
                {"AttributePath":"userName","AttributeValue":"%s"}}}"""
                .formatted(identityStoreId, address))
                .then().statusCode(200).extract().path("UserId");
    }

    /** A JSON string literal, for embedding a policy document in a request body. */
    private static String quoted(String value) {
        return "\"" + value.replace("\\", "\\\\").replace("\"", "\\\"") + "\"";
    }

    private static Response sso(String action, String body) {
        return jsonCall("sso", "SWBExternalService." + action, body);
    }

    private static Response identityStore(String action, String body) {
        return jsonCall("identitystore", "AWSIdentityStore." + action, body);
    }

    private static Response jsonCall(String service, String target, String body) {
        return given()
                .headers(sign("POST", body, service))
                .header("X-Amz-Target", target)
                .contentType(JSON_1_1)
                .body(body)
                .when().post("/");
    }

    private static Response iam(Map<String, String> parameters) {
        Map<String, String> all = new LinkedHashMap<>(parameters);
        all.put("Version", "2010-05-08");
        String body = AwsRequestSigner.formBody(all);
        return given()
                .headers(sign("POST", body, "iam"))
                .contentType("application/x-www-form-urlencoded")
                .body(body)
                .when().post("/");
    }

    private static Map<String, String> sign(String method, String body, String service) {
        try {
            return AwsRequestSigner.signedHeaders(method, "/", Map.of(),
                    "localhost:" + RestAssured.port, body.getBytes(StandardCharsets.UTF_8),
                    DEPLOYER_KEY, DEPLOYER_SECRET, REGION, service, Instant.now());
        } catch (Exception e) {
            throw new IllegalStateException("signing failed", e);
        }
    }

    public static final class IdentityCenterProfile implements QuarkusTestProfile {
        @Override
        public Map<String, String> getConfigOverrides() {
            return Map.of(
                    "floci.auth.validate-signatures", "true",
                    "floci.services.iam.enforcement-enabled", "true",
                    "floci.services.iam.seed-deployer-principal", "true",
                    "floci.services.identitystore.provisioned-users", ADAM + "," + SECOND);
        }
    }
}
