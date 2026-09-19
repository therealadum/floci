package io.github.hectorvent.floci.services.sns;

import io.github.hectorvent.floci.testing.RestAssuredJsonUtils;
import io.github.hectorvent.floci.testutil.AwsRequestSigner;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.QuarkusTestProfile;
import io.quarkus.test.junit.TestProfile;
import io.restassured.RestAssured;
import io.restassured.path.xml.XmlPath;
import io.restassured.response.Response;
import io.restassured.specification.RequestSpecification;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * A topic policy is evaluated, not only stored.
 *
 * <p>Until {@code SnsResourcePolicySource} existed, {@code SetTopicAttributes} wrote a topic
 * policy that nothing ever read back into a decision: every SNS call was settled by the caller's
 * identity policies alone. That is wrong in both directions the baseline depends on. The
 * notification topic carries a statement for {@code events.amazonaws.com} so that the break glass
 * rule can publish to it, and EventBridge has no identity policy anywhere, so without the topic
 * policy being read that statement means nothing. And a principal in another account reaching a
 * topic with no statement naming it is refused on AWS.</p>
 */
@QuarkusTest
@TestProfile(SnsTopicPolicyIntegrationTest.TopicPolicyProfile.class)
class SnsTopicPolicyIntegrationTest {

    private static final String REGION = "us-east-1";
    private static final String DEPLOYER_KEY = "floci";
    private static final String DEPLOYER_SECRET = "floci";
    private static final String OWNER = "000000000000";
    private static final String ENTRY_ROLE = "MycelliumEntry";
    private static final String JSON_1_1 = "application/x-amz-json-1.1";

    private static String memberAccount;
    private static String memberKey;
    private static String memberSecret;
    private static String memberToken;

    @BeforeEach
    void createAMemberAccountAndAssumeItsEntryRole() {
        RestAssuredJsonUtils.configureAwsContentTypes();
        // Built lazily: the port is not set at @BeforeAll.
        if (memberAccount != null) {
            return;
        }
        organizations("CreateOrganization", "{\"FeatureSet\":\"ALL\"}").then().statusCode(200);
        String name = "member-" + UUID.randomUUID().toString().substring(0, 8);
        memberAccount = organizations("CreateAccount", """
                {"AccountName":"%s","Email":"%s@floci.test","RoleName":"%s"}"""
                .formatted(name, name, ENTRY_ROLE))
                .then().statusCode(200).extract().path("CreateAccountStatus.AccountId");

        Response assumed = query("sts", DEPLOYER_KEY, DEPLOYER_SECRET, null, Map.of(
                "Action", "AssumeRole",
                "Version", "2011-06-15",
                "RoleArn", "arn:aws:iam::" + memberAccount + ":role/" + ENTRY_ROLE,
                "RoleSessionName", "topic-policy"));
        assumed.then().statusCode(200);
        XmlPath credentials = XmlPath.from(assumed.asString())
                .setRoot("AssumeRoleResponse.AssumeRoleResult.Credentials");
        memberKey = credentials.getString("AccessKeyId");
        memberSecret = credentials.getString("SecretAccessKey");
        memberToken = credentials.getString("SessionToken");
    }

    // ── The owner ──────────────────────────────────────────────────────────────

    @Test
    void theOwnerPublishesToATopicThatCarriesNoPolicy() {
        String topic = createTopic("owner-no-policy");
        publishAsOwner(topic).then().statusCode(200)
                .body(containsString("<PublishResponse"));
    }

    @Test
    void aDenyInTheTopicPolicyRefusesTheOwner() {
        String topic = createTopic("owner-denied");
        setTopicPolicy(topic, """
                {"Version":"2012-10-17","Statement":[{"Sid":"NoPublish","Effect":"Deny",\
                "Principal":{"AWS":"*"},"Action":"sns:Publish","Resource":"%s"}]}"""
                .formatted(topic));

        publishAsOwner(topic).then().statusCode(403)
                .body(containsString("AccessDenied"));
    }

    // ── A principal in another account ─────────────────────────────────────────

    @Test
    void anotherAccountsPrincipalIsRefusedWithoutAStatementForIt() {
        String topic = createTopic("cross-account-refused");
        publishAsMember(topic).then().statusCode(403)
                .body(containsString("AccessDenied"));
    }

    @Test
    void aStatementNamingThatPrincipalIsWhatTheDecisionReads() {
        String topic = createTopic("cross-account-named");
        publishAsMember(topic).then().statusCode(403);

        setTopicPolicy(topic, """
                {"Version":"2012-10-17","Statement":[{"Sid":"MemberPublishes","Effect":"Allow",\
                "Principal":{"AWS":"arn:aws:iam::%s:role/%s"},"Action":"sns:Publish",\
                "Resource":"%s"}]}"""
                .formatted(memberAccount, ENTRY_ROLE, topic));

        // The same call is no longer refused by authorization. It does not become a delivery:
        // the topic lives in the owner's partition and SNS looks a topic up in the caller's, so
        // the call now fails on the topic not being found there. That lookup is a separate gap
        // from the decision this case is about, and the two answers are told apart by their code.
        Response allowed = publishAsMember(topic);
        assertNotEquals(403, allowed.statusCode(),
                "the statement naming the principal is read, so the refusal is gone");
        assertTrue(allowed.asString().contains("NotFound"),
                "what is left is the cross-account topic lookup, not an authorization refusal: "
                        + allowed.asString());
    }

    // ── EventBridge, which has no identity policy anywhere ─────────────────────

    @Test
    void eventBridgeDeliversOnlyWhereTheTopicPolicyNamesTheService() {
        String suffix = UUID.randomUUID().toString().substring(0, 8);
        String topicName = "events-target-" + suffix;
        String queueName = "events-sink-" + suffix;
        String ruleName = "events-rule-" + suffix;
        String source = "floci.topic.policy." + suffix;

        String topic = createTopic(topicName);
        query("sqs", DEPLOYER_KEY, DEPLOYER_SECRET, null,
                Map.of("Action", "CreateQueue", "QueueName", queueName)).then().statusCode(200);
        String queueUrl = queueUrl(queueName);
        query("sns", DEPLOYER_KEY, DEPLOYER_SECRET, null, Map.of(
                "Action", "Subscribe", "TopicArn", topic, "Protocol", "sqs",
                "Endpoint", "arn:aws:sqs:" + REGION + ":" + OWNER + ":" + queueName))
                .then().statusCode(200);

        events("PutRule", """
                {"Name":"%s","EventPattern":"{\\"source\\":[\\"%s\\"]}"}"""
                .formatted(ruleName, source)).then().statusCode(200);
        events("PutTargets", """
                {"Rule":"%s","Targets":[{"Id":"T0","Arn":"%s"}]}"""
                .formatted(ruleName, topic)).then().statusCode(200)
                .body("FailedEntryCount", equalTo(0));

        // No statement for the service: the delivery is refused and nothing reaches the queue.
        putEvent(source);
        assertFalse(receiveBody(queueUrl).contains(source),
                "a topic with no statement for events.amazonaws.com takes no delivery");

        setTopicPolicy(topic, """
                {"Version":"2012-10-17","Statement":[{"Sid":"EventsPublishes","Effect":"Allow",\
                "Principal":{"Service":"events.amazonaws.com"},"Action":"sns:Publish",\
                "Resource":"%s"}]}""".formatted(topic));

        putEvent(source);
        assertTrue(receiveBody(queueUrl).contains(source),
                "the statement naming the service is what lets the delivery through");
    }

    // ── Helpers ────────────────────────────────────────────────────────────────

    private static String createTopic(String name) {
        Response created = query("sns", DEPLOYER_KEY, DEPLOYER_SECRET, null,
                Map.of("Action", "CreateTopic", "Name", name));
        created.then().statusCode(200);
        return XmlPath.from(created.asString())
                .getString("CreateTopicResponse.CreateTopicResult.TopicArn");
    }

    private static void setTopicPolicy(String topicArn, String policy) {
        query("sns", DEPLOYER_KEY, DEPLOYER_SECRET, null, Map.of(
                "Action", "SetTopicAttributes", "TopicArn", topicArn,
                "AttributeName", "Policy", "AttributeValue", policy))
                .then().statusCode(200);
    }

    private static Response publishAsOwner(String topicArn) {
        return query("sns", DEPLOYER_KEY, DEPLOYER_SECRET, null,
                Map.of("Action", "Publish", "TopicArn", topicArn, "Message", "hello"));
    }

    private static Response publishAsMember(String topicArn) {
        return query("sns", memberKey, memberSecret, memberToken,
                Map.of("Action", "Publish", "TopicArn", topicArn, "Message", "hello"));
    }

    private static String queueUrl(String queueName) {
        Response url = query("sqs", DEPLOYER_KEY, DEPLOYER_SECRET, null,
                Map.of("Action", "GetQueueUrl", "QueueName", queueName));
        url.then().statusCode(200);
        return XmlPath.from(url.asString())
                .getString("GetQueueUrlResponse.GetQueueUrlResult.QueueUrl");
    }

    private static void putEvent(String source) {
        events("PutEvents", """
                {"Entries":[{"Source":"%s","DetailType":"break-glass","Detail":"{}"}]}"""
                .formatted(source)).then().statusCode(200).body("FailedEntryCount", equalTo(0));
    }

    private static String receiveBody(String queueUrl) {
        Response received = query("sqs", DEPLOYER_KEY, DEPLOYER_SECRET, null, Map.of(
                "Action", "ReceiveMessage", "QueueUrl", queueUrl, "MaxNumberOfMessages", "10"));
        received.then().statusCode(200);
        return received.asString();
    }

    private static Response events(String action, String body) {
        return given()
                .headers(sign("events", "/", body))
                .header("X-Amz-Target", "AWSEvents." + action)
                .contentType(JSON_1_1)
                .body(body)
                .when().post("/");
    }

    private static Response organizations(String action, String body) {
        return given()
                .headers(sign("organizations", "/", body))
                .header("X-Amz-Target", "AWSOrganizationsV20161128." + action)
                .contentType(JSON_1_1)
                .body(body)
                .when().post("/");
    }

    private static Response query(String service, String accessKeyId, String secretKey,
                                  String sessionToken, Map<String, String> parameters) {
        String body = AwsRequestSigner.formBody(new LinkedHashMap<>(parameters));
        RequestSpecification request = given()
                .headers(signWith(service, accessKeyId, secretKey, body))
                .contentType("application/x-www-form-urlencoded")
                .body(body);
        if (sessionToken != null) {
            request = request.header("X-Amz-Security-Token", sessionToken);
        }
        return request.when().post("/");
    }

    private static Map<String, String> sign(String service, String path, String body) {
        return signedHeaders(service, path, DEPLOYER_KEY, DEPLOYER_SECRET, body);
    }

    private static Map<String, String> signWith(String service, String accessKeyId,
                                                String secretKey, String body) {
        return signedHeaders(service, "/", accessKeyId, secretKey, body);
    }

    private static Map<String, String> signedHeaders(String service, String path,
                                                     String accessKeyId, String secretKey,
                                                     String body) {
        try {
            return AwsRequestSigner.signedHeaders("POST", path, Map.of(),
                    "localhost:" + RestAssured.port, body.getBytes(StandardCharsets.UTF_8),
                    accessKeyId, secretKey, REGION, service, Instant.now());
        } catch (Exception e) {
            throw new IllegalStateException("signing failed", e);
        }
    }

    public static final class TopicPolicyProfile implements QuarkusTestProfile {
        @Override
        public Map<String, String> getConfigOverrides() {
            return Map.of(
                    "floci.auth.validate-signatures", "true",
                    "floci.services.iam.enforcement-enabled", "true",
                    "floci.services.iam.seed-deployer-principal", "true");
        }
    }
}
