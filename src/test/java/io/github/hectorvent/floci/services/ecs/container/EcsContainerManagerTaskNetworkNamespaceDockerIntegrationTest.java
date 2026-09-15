package io.github.hectorvent.floci.services.ecs.container;

import com.github.dockerjava.api.DockerClient;
import com.github.dockerjava.core.command.WaitContainerResultCallback;
import io.github.hectorvent.floci.services.ecs.model.ContainerDefinition;
import io.github.hectorvent.floci.services.ecs.model.EcsTask;
import io.github.hectorvent.floci.services.ecs.model.NetworkMode;
import io.github.hectorvent.floci.services.ecs.model.PortMapping;
import io.github.hectorvent.floci.services.ecs.model.TaskDefinition;
import io.quarkus.test.junit.QuarkusTest;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Docker-backed proof that the containers of an {@code awsvpc} task share one network
 * namespace, as they do on Fargate: a sidecar reaches its neighbour on {@code 127.0.0.1}.
 *
 * <p>The app container serves a page with busybox httpd; the sidecar fetches it over loopback
 * and exits 0 only if it answered. With a container per IP — the pre-fix behaviour — nothing is
 * listening on the sidecar's own loopback and the fetch is refused on every retry.
 */
@QuarkusTest
class EcsContainerManagerTaskNetworkNamespaceDockerIntegrationTest {

    private static final String IMAGE = "public.ecr.aws/docker/library/busybox:latest";

    @Inject
    EcsContainerManager containerManager;

    @Inject
    DockerClient dockerClient;

    @BeforeEach
    void requireDocker() {
        Assumptions.assumeTrue(isDockerAvailable(),
                "Docker daemon must be available for ECS task network namespace integration tests");
    }

    @Test
    void sidecarReachesTheAppContainerOverLoopback() {
        String suffix = UUID.randomUUID().toString().substring(0, 8);

        ContainerDefinition app = new ContainerDefinition();
        app.setName("app");
        app.setImage(IMAGE);
        app.setPortMappings(List.of(new PortMapping(8080)));
        app.setCommand(List.of("sh", "-c", "echo shared-netns > /tmp/index.html; httpd -f -p 8080 -h /tmp"));

        ContainerDefinition sidecar = new ContainerDefinition();
        sidecar.setName("sidecar");
        sidecar.setImage(IMAGE);
        // Retries while the app's httpd binds; a refused connection is the failure this proves
        // against, so exiting non-zero after the loop is the point.
        sidecar.setCommand(List.of("sh", "-c",
                "for i in $(seq 30); do "
                        + "wget -q -O - http://127.0.0.1:8080/ | grep -qx shared-netns && exit 0; "
                        + "sleep 1; done; exit 1"));

        TaskDefinition taskDef = new TaskDefinition();
        taskDef.setFamily("netns-" + suffix);
        taskDef.setNetworkMode(NetworkMode.awsvpc);
        taskDef.setContainerDefinitions(List.of(app, sidecar));

        EcsTask task = new EcsTask();
        task.setTaskArn("arn:aws:ecs:us-east-1:000000000000:task/netns/" + suffix);

        EcsTaskHandle handle = containerManager.startTask(task, taskDef, List.of(), "us-east-1");
        try {
            int exitCode = dockerClient.waitContainerCmd(handle.getContainerIds().get("sidecar"))
                    .exec(new WaitContainerResultCallback())
                    .awaitStatusCode(90, TimeUnit.SECONDS);
            assertEquals(0, exitCode,
                    "the sidecar must reach the app container on 127.0.0.1, as it does on Fargate");
        } finally {
            containerManager.stopTask(handle);
        }
    }

    private boolean isDockerAvailable() {
        try {
            dockerClient.pingCmd().exec();
            return true;
        } catch (Exception e) {
            return false;
        }
    }
}
