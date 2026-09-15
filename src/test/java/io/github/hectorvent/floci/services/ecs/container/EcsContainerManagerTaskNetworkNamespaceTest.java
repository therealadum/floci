package io.github.hectorvent.floci.services.ecs.container;

import com.github.dockerjava.api.DockerClient;
import io.github.hectorvent.floci.config.EmulatorConfig;
import io.github.hectorvent.floci.core.common.RegionResolver;
import io.github.hectorvent.floci.core.common.docker.ContainerBuilder;
import io.github.hectorvent.floci.core.common.docker.ContainerDetector;
import io.github.hectorvent.floci.core.common.docker.ContainerLifecycleManager;
import io.github.hectorvent.floci.core.common.docker.ContainerLifecycleManager.ContainerInfo;
import io.github.hectorvent.floci.core.common.docker.ContainerLogStreamer;
import io.github.hectorvent.floci.core.common.docker.LaunchedContainerAwsEnv;
import io.github.hectorvent.floci.services.ecr.registry.EcrRegistryManager;
import io.github.hectorvent.floci.services.ecs.model.ContainerDefinition;
import io.github.hectorvent.floci.services.ecs.model.EcsTask;
import io.github.hectorvent.floci.services.ecs.model.NetworkMode;
import io.github.hectorvent.floci.services.ecs.model.PortMapping;
import io.github.hectorvent.floci.services.ecs.model.TaskDefinition;
import io.github.hectorvent.floci.services.secretsmanager.SecretsManagerService;
import io.github.hectorvent.floci.services.ssm.SsmService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.startsWith;
import static org.mockito.Mockito.RETURNS_DEEP_STUBS;
import static org.mockito.Mockito.RETURNS_SELF;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * On Fargate, and in {@code awsvpc} network mode generally, every container of a task shares
 * ONE network namespace: a sidecar reaches its neighbour on {@code 127.0.0.1}, and the task has
 * a single IP with one set of ports. Running each container as its own Docker container with
 * its own IP breaks every task built that way (an app plus an Envoy/OTel/nginx sidecar), and
 * the breakage is silent — the connection to {@code 127.0.0.1} is simply refused.
 *
 * <p>Floci reproduces the namespace by letting the first container definition own it and
 * creating the rest with Docker's {@code container:<id>} network mode. Docker rejects port
 * publishing, DNS servers and {@code /etc/hosts} entries on a container created that way, so
 * the owner carries the whole task's ports on everyone's behalf.
 *
 * <p>The builder and lifecycle manager are mocked, so these assert the arguments that
 * <em>would</em> reach Docker: they run under {@code mvn test} with no daemon.
 */
class EcsContainerManagerTaskNetworkNamespaceTest {

    private static final String TASK_ARN = "arn:aws:ecs:us-east-1:000000000000:task/test-cluster/abc123";

    private ContainerBuilder containerBuilder;
    /** One builder mock per newContainer() call, in container-definition order. */
    private List<ContainerBuilder.Builder> builders;
    private EmulatorConfig config;
    private ContainerDetector containerDetector;
    private EcsContainerManager manager;

    @BeforeEach
    void setUp() {
        builders = new ArrayList<>();
        containerBuilder = mock(ContainerBuilder.class);
        when(containerBuilder.newContainer(anyString())).thenAnswer(invocation -> {
            ContainerBuilder.Builder builder = mock(ContainerBuilder.Builder.class, RETURNS_SELF);
            builders.add(builder);
            return builder;
        });

        ContainerLifecycleManager lifecycleManager = mock(ContainerLifecycleManager.class);
        AtomicInteger created = new AtomicInteger();
        when(lifecycleManager.createAndStart(any()))
                .thenAnswer(invocation -> new ContainerInfo("docker-id-" + created.getAndIncrement(), Map.of()));
        // resolveNetworkBindings() inspects the container after launch; deep stubs make the
        // empty-binding readback (Map.get(...) -> null) NPE-free.
        DockerClient dockerClient = mock(DockerClient.class, RETURNS_DEEP_STUBS);
        when(lifecycleManager.getDockerClient()).thenReturn(dockerClient);

        ContainerLogStreamer logStreamer = mock(ContainerLogStreamer.class);
        containerDetector = mock(ContainerDetector.class);
        config = mock(EmulatorConfig.class, RETURNS_DEEP_STUBS);
        when(config.services().ecs().taskNetworkMode()).thenReturn("shared");
        when(config.services().ecs().dockerNetwork()).thenReturn(Optional.of("floci-net"));
        RegionResolver regionResolver = mock(RegionResolver.class);
        LaunchedContainerAwsEnv awsEnv = mock(LaunchedContainerAwsEnv.class);
        when(awsEnv.sdkBaselineEnv(any(), any())).thenReturn(List.of());
        SsmService ssmService = mock(SsmService.class);
        SecretsManagerService secretsManagerService = mock(SecretsManagerService.class);
        EcrRegistryManager ecrRegistryManager = mock(EcrRegistryManager.class);
        when(ecrRegistryManager.rewriteImageUri(anyString())).thenAnswer(inv -> inv.getArgument(0));

        manager = new EcsContainerManager(containerBuilder, lifecycleManager, logStreamer,
                containerDetector, config, regionResolver, awsEnv, ssmService, secretsManagerService,
                ecrRegistryManager);
    }

    private static ContainerDefinition containerDef(String name, List<PortMapping> portMappings) {
        ContainerDefinition def = new ContainerDefinition();
        def.setName(name);
        def.setImage(name + ":latest");
        def.setPortMappings(portMappings);
        return def;
    }

    private void startTask(NetworkMode networkMode, ContainerDefinition... defs) {
        TaskDefinition taskDef = new TaskDefinition();
        taskDef.setFamily("test-family");
        taskDef.setNetworkMode(networkMode);
        taskDef.setContainerDefinitions(List.of(defs));

        EcsTask task = new EcsTask();
        task.setTaskArn(TASK_ARN);

        manager.startTask(task, taskDef, List.of(), "us-east-1");
    }

    @Test
    void awsvpcSidecarJoinsTheFirstContainersNetworkNamespace() {
        when(containerDetector.isRunningInContainer()).thenReturn(false);

        startTask(NetworkMode.awsvpc,
                containerDef("app", List.of(new PortMapping(8080))),
                containerDef("sidecar", null));

        assertEquals(2, builders.size());
        // The sidecar is created into the app container's namespace, so a connection to
        // 127.0.0.1:8080 from the sidecar reaches the app, as it does on Fargate.
        verify(builders.get(1)).withNetworkMode("container:docker-id-0");
        verify(builders.get(0), never()).withNetworkMode(startsWith("container:"));
    }

    @Test
    void onlyTheNamespaceOwnerGetsANetworkDnsAndHostEntriesOfItsOwn() {
        when(containerDetector.isRunningInContainer()).thenReturn(false);

        startTask(NetworkMode.awsvpc,
                containerDef("app", null),
                containerDef("sidecar", null));

        // Docker fails container creation outright when any of these is combined with a
        // container: network mode, and the owner already carries them for the namespace.
        verify(builders.get(0), times(1)).withDockerNetwork(Optional.of("floci-net"));
        verify(builders.get(0), times(1)).withEmbeddedDns();
        verify(builders.get(0), times(1)).withHostDockerInternalOnLinux();
        verify(builders.get(1), never()).withDockerNetwork(any());
        verify(builders.get(1), never()).withEmbeddedDns();
        verify(builders.get(1), never()).withHostDockerInternalOnLinux();
    }

    @Test
    void theNamespaceOwnerPublishesEveryContainersPorts() {
        when(containerDetector.isRunningInContainer()).thenReturn(false);

        startTask(NetworkMode.awsvpc,
                containerDef("app", List.of(new PortMapping(8080))),
                containerDef("sidecar", List.of(new PortMapping(9901))));

        // The ports belong to the namespace, not to a container, so the task publishes each
        // exactly once — from its owner.
        verify(builders.get(0), times(1)).withDynamicPort(8080);
        verify(builders.get(0), times(1)).withDynamicPort(9901);
        verify(builders.get(1), never()).withDynamicPort(anyInt());
        verify(builders.get(1), never()).withExposedPort(anyInt());
    }

    @Test
    void perContainerModeKeepsEveryContainerOnTheTaskNetwork() {
        when(config.services().ecs().taskNetworkMode()).thenReturn("per-container");
        when(containerDetector.isRunningInContainer()).thenReturn(false);

        startTask(NetworkMode.awsvpc,
                containerDef("app", List.of(new PortMapping(8080))),
                containerDef("sidecar", List.of(new PortMapping(9901))));

        verify(builders.get(1), never()).withNetworkMode(startsWith("container:"));
        verify(builders.get(1), times(1)).withDockerNetwork(Optional.of("floci-net"));
        verify(builders.get(0), times(1)).withDynamicPort(8080);
        verify(builders.get(0), never()).withDynamicPort(9901);
        verify(builders.get(1), times(1)).withDynamicPort(9901);
    }

    @Test
    void bridgeTaskNeverSharesANamespace() {
        when(containerDetector.isRunningInContainer()).thenReturn(false);

        // AWS does not share a namespace across the containers of a bridge-mode task either;
        // they are linked by name on the docker bridge.
        startTask(NetworkMode.bridge,
                containerDef("app", null),
                containerDef("sidecar", null));

        verify(builders.get(1), never()).withNetworkMode(startsWith("container:"));
        verify(builders.get(1), times(1)).withDockerNetwork(Optional.of("floci-net"));
    }

    @Test
    void singleContainerAwsvpcTaskIsUnaffected() {
        when(containerDetector.isRunningInContainer()).thenReturn(false);

        startTask(NetworkMode.awsvpc, containerDef("app", List.of(new PortMapping(8080))));

        assertEquals(1, builders.size());
        verify(builders.get(0), never()).withNetworkMode(startsWith("container:"));
        verify(builders.get(0), times(1)).withDockerNetwork(Optional.of("floci-net"));
        verify(builders.get(0), times(1)).withDynamicPort(8080);
    }
}
