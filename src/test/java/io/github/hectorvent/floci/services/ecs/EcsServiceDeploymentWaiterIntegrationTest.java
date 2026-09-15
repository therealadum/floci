package io.github.hectorvent.floci.services.ecs;

import io.github.hectorvent.floci.testing.RestAssuredJsonUtils;
import io.quarkus.test.junit.QuarkusTest;
import io.restassured.response.Response;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.util.List;

import static io.restassured.RestAssured.given;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Integration tests for the service-deployment sequence that terraform-provider-aws' ECS
 * service waiter walks after {@code CreateService} and {@code UpdateService}.
 *
 * <p>The provider reads the primary deployment from {@code DescribeServices}, takes the id
 * after the slash of its {@code ecs-svc/<id>}, then calls {@code ListServiceDeployments} and
 * accepts only a brief whose {@code targetServiceRevisionArn} <em>contains</em> that id. A
 * brief without the field — or with a revision ARN minted from an unrelated UUID — matches
 * nothing, so the provider polls as pending until its 20-minute timeout on every create and
 * every task-definition change.
 *
 * <p>The linkage is therefore a contract between two APIs, not cosmetic: the service revision
 * a deployment targets must be keyed on the same id the service reports for that deployment.
 */
@QuarkusTest
class EcsServiceDeploymentWaiterIntegrationTest {

    private static final String TARGET = "AmazonEC2ContainerServiceV20141113.";
    private static final String CT = "application/x-amz-json-1.1";

    @BeforeAll
    static void configure() {
        RestAssuredJsonUtils.configureAwsContentTypes();
    }

    private static Response call(String action, String body) {
        return given().contentType(CT).header("X-Amz-Target", TARGET + action)
                .body(body)
                .when().post("/")
                .then().statusCode(200)
                .extract().response();
    }

    private static String registerTaskDef(String family, String image) {
        return call("RegisterTaskDefinition", "{\"family\":\"" + family + "\","
                + "\"containerDefinitions\":[{\"name\":\"web\",\"image\":\"" + image + "\",\"memory\":128}]}")
                .jsonPath().getString("taskDefinition.taskDefinitionArn");
    }

    /** The primary deployment's id as the provider derives it: everything after the slash. */
    private static String primaryDeploymentId(String cluster, String service) {
        Response described = call("DescribeServices",
                "{\"cluster\":\"" + cluster + "\",\"services\":[\"" + service + "\"]}");
        String id = described.jsonPath().getString("services[0].deployments[0].id");
        assertNotNull(id, "DescribeServices must report a primary deployment");
        assertTrue(id.startsWith("ecs-svc/"), "deployment id is an ecs-svc/<id>: " + id);
        return id.substring(id.indexOf('/') + 1);
    }

    /** The brief the provider would select, or null when nothing matches — its pending case. */
    private static String matchingTargetRevisionArn(String cluster, String service, String deploymentId) {
        Response listed = call("ListServiceDeployments",
                "{\"cluster\":\"" + cluster + "\",\"service\":\"" + service + "\"}");
        List<String> revisionArns = listed.jsonPath().getList("serviceDeployments.targetServiceRevisionArn");
        assertNotNull(revisionArns, "every brief carries a targetServiceRevisionArn");
        assertFalse(revisionArns.contains(null), "every brief carries a targetServiceRevisionArn");
        return revisionArns.stream().filter(arn -> arn.contains(deploymentId)).findFirst().orElse(null);
    }

    @Test
    void createServiceMintsARevisionTheProviderWaiterCanMatch() {
        call("CreateCluster", "{\"clusterName\":\"waiter-create\"}");
        registerTaskDef("waiter-create-fam", "nginx:1");
        call("CreateService", "{\"cluster\":\"waiter-create\",\"serviceName\":\"waiter-create-svc\","
                + "\"taskDefinition\":\"waiter-create-fam\",\"desiredCount\":1}");

        String deploymentId = primaryDeploymentId("waiter-create", "waiter-create-svc");
        String revisionArn = matchingTargetRevisionArn("waiter-create", "waiter-create-svc", deploymentId);

        assertNotNull(revisionArn,
                "no brief's targetServiceRevisionArn contains deployment id " + deploymentId);
        // AWS scopes a service revision by cluster and service:
        // arn:aws:ecs:<region>:<account>:service-revision/<cluster>/<service>/<id>
        assertTrue(revisionArn.contains(":service-revision/waiter-create/waiter-create-svc/"),
                "revision ARN is cluster/service scoped: " + revisionArn);
    }

    @Test
    void taskDefinitionChangeMintsANewRevisionTheProviderWaiterCanMatch() {
        call("CreateCluster", "{\"clusterName\":\"waiter-update\"}");
        registerTaskDef("waiter-update-fam", "nginx:1");
        call("CreateService", "{\"cluster\":\"waiter-update\",\"serviceName\":\"waiter-update-svc\","
                + "\"taskDefinition\":\"waiter-update-fam\",\"desiredCount\":1}");
        String firstDeploymentId = primaryDeploymentId("waiter-update", "waiter-update-svc");
        String firstRevisionArn =
                matchingTargetRevisionArn("waiter-update", "waiter-update-svc", firstDeploymentId);
        assertNotNull(firstRevisionArn);

        String secondTaskDefArn = registerTaskDef("waiter-update-fam", "nginx:2");
        call("UpdateService", "{\"cluster\":\"waiter-update\",\"service\":\"waiter-update-svc\","
                + "\"taskDefinition\":\"" + secondTaskDefArn + "\"}");

        String secondDeploymentId = primaryDeploymentId("waiter-update", "waiter-update-svc");
        assertNotEquals(firstDeploymentId, secondDeploymentId,
                "a task-definition change rolls the deployment id over");

        String secondRevisionArn =
                matchingTargetRevisionArn("waiter-update", "waiter-update-svc", secondDeploymentId);
        assertNotNull(secondRevisionArn,
                "no brief's targetServiceRevisionArn contains deployment id " + secondDeploymentId);
        assertNotEquals(firstRevisionArn, secondRevisionArn,
                "the new deployment targets a new revision");
        // The earlier deployment stays listed and keeps matching only its own id, so the match is
        // a real correlation rather than "whatever came back first".
        assertEquals(firstRevisionArn,
                matchingTargetRevisionArn("waiter-update", "waiter-update-svc", firstDeploymentId),
                "the previous deployment still resolves to its own revision");
    }

    @Test
    void describeServiceDeploymentsCarriesTargetAndSourceRevisionSummaries() {
        call("CreateCluster", "{\"clusterName\":\"waiter-describe\"}");
        registerTaskDef("waiter-describe-fam", "nginx:1");
        call("CreateService", "{\"cluster\":\"waiter-describe\",\"serviceName\":\"waiter-describe-svc\","
                + "\"taskDefinition\":\"waiter-describe-fam\",\"desiredCount\":2}");
        String firstRevisionArn = matchingTargetRevisionArn("waiter-describe", "waiter-describe-svc",
                primaryDeploymentId("waiter-describe", "waiter-describe-svc"));

        String secondTaskDefArn = registerTaskDef("waiter-describe-fam", "nginx:2");
        call("UpdateService", "{\"cluster\":\"waiter-describe\",\"service\":\"waiter-describe-svc\","
                + "\"taskDefinition\":\"" + secondTaskDefArn + "\"}");

        Response listed = call("ListServiceDeployments",
                "{\"cluster\":\"waiter-describe\",\"service\":\"waiter-describe-svc\"}");
        // listServiceDeploymentsDetailed sorts newest first.
        String latestArn = listed.jsonPath().getString("serviceDeployments[0].serviceDeploymentArn");

        Response described = call("DescribeServiceDeployments",
                "{\"serviceDeploymentArns\":[\"" + latestArn + "\"]}");
        assertEquals(1, described.jsonPath().getList("serviceDeployments").size());
        // DescribeServiceDeployments carries ServiceRevisionSummary objects, not the bare ARN
        // string the brief flattens the target to.
        assertNotNull(described.jsonPath().getString("serviceDeployments[0].targetServiceRevision.arn"));
        assertEquals(2, described.jsonPath()
                .getInt("serviceDeployments[0].targetServiceRevision.requestedTaskCount"));
        assertEquals(firstRevisionArn,
                described.jsonPath().getString("serviceDeployments[0].sourceServiceRevisions[0].arn"),
                "the rollout replaces the revision the previous deployment targeted");
    }

    @Test
    void describeServiceRevisionsResolvesTheRevisionADeploymentTargets() {
        call("CreateCluster", "{\"clusterName\":\"waiter-revision\"}");
        String taskDefArn = registerTaskDef("waiter-revision-fam", "nginx:1");
        call("CreateService", "{\"cluster\":\"waiter-revision\",\"serviceName\":\"waiter-revision-svc\","
                + "\"taskDefinition\":\"waiter-revision-fam\",\"desiredCount\":1}");

        String revisionArn = matchingTargetRevisionArn("waiter-revision", "waiter-revision-svc",
                primaryDeploymentId("waiter-revision", "waiter-revision-svc"));

        Response described = call("DescribeServiceRevisions",
                "{\"serviceRevisionArns\":[\"" + revisionArn + "\"]}");
        assertEquals(revisionArn, described.jsonPath().getString("serviceRevisions[0].serviceRevisionArn"));
        assertEquals(taskDefArn, described.jsonPath().getString("serviceRevisions[0].taskDefinition"));
    }
}
