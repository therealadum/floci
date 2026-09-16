package io.github.hectorvent.floci.services.ecs;

import com.fasterxml.jackson.core.type.TypeReference;
import io.github.hectorvent.floci.config.EmulatorConfig;
import io.github.hectorvent.floci.core.common.RegionResolver;
import io.github.hectorvent.floci.core.storage.AccountAwareStorageBackend;
import io.github.hectorvent.floci.core.storage.StorageBackend;
import io.github.hectorvent.floci.core.storage.StorageFactory;
import io.github.hectorvent.floci.services.ecs.container.EcsContainerManager;
import io.github.hectorvent.floci.services.ecs.container.EcsTaskHandle;
import io.github.hectorvent.floci.services.ecs.model.AwsVpcConfiguration;
import io.github.hectorvent.floci.services.ecs.model.Container;
import io.github.hectorvent.floci.services.ecs.model.ContainerDefinition;
import io.github.hectorvent.floci.services.ecs.model.EcsLoadBalancer;
import io.github.hectorvent.floci.services.ecs.model.EcsServiceModel;
import io.github.hectorvent.floci.services.ecs.model.EcsTask;
import io.github.hectorvent.floci.services.ecs.model.LaunchType;
import io.github.hectorvent.floci.services.ecs.model.NetworkBinding;
import io.github.hectorvent.floci.services.ecs.model.NetworkConfiguration;
import io.github.hectorvent.floci.services.ecs.model.NetworkMode;
import io.github.hectorvent.floci.services.ecs.model.PortMapping;
import io.github.hectorvent.floci.services.ecs.model.TaskStatus;
import io.github.hectorvent.floci.services.elbv2.ElbV2Service;
import io.github.hectorvent.floci.services.elbv2.model.TargetGroup;
import io.github.hectorvent.floci.services.elbv2.model.TargetHealth;
import io.quarkus.test.junit.QuarkusTest;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.RETURNS_DEEP_STUBS;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * An ECS service with the {@code awsvpc} network mode and a {@code loadBalancers} entry registers
 * the task's own IP and the declared container port as a target in the {@code ip} target group when
 * the task starts, and deregisters it when the service scales to zero. This is the shape the
 * collector and Grafana run in: {@code awsvpc} tasks on Floci's Docker network, each behind a
 * target group of {@code TargetType} {@code ip}.
 * <p>
 * The whole service path is exercised — {@code createService}, the reconciler's task start, the
 * real {@link EcsLoadBalancerRegistrar} and a real {@link ElbV2Service} — with only the container
 * manager mocked, since {@code @QuarkusTest} runs no Docker containers. The mock reproduces what
 * {@code EcsContainerManager} reports for an {@code awsvpc} task with Floci in a container: a
 * network binding whose host port equals the container port, and a container host that is the
 * task's IP on the Docker network.
 */
@QuarkusTest
class EcsServiceAwsvpcIpTargetTest {

    private static final String REGION = "us-east-1";
    private static final String CLUSTER = "awsvpc-ip";
    private static final String TASK_IP = "172.19.0.7";
    private static final int CONTAINER_PORT = 4318;

    @Inject
    ElbV2Service elbV2Service;

    @Test
    void awsvpcServiceRegistersTaskIpTargetAndDeregistersOnScaleToZero() {
        String tgArn = createIpTargetGroup("awsvpc-ip-tg");
        EcsService service = newDockerModeService(tgArn);

        service.createCluster(CLUSTER, REGION);
        registerAwsvpcTaskDefinition(service, "awsvpc-fam");
        EcsServiceModel svc = service.createService(CLUSTER, "awsvpc-svc", "awsvpc-fam", 1,
                LaunchType.FARGATE, List.of(loadBalancer(tgArn)), awsvpcNetworkConfiguration(), REGION);

        service.reconcileServices();   // starts the task, which registers its target
        service.reconcileServices();   // sees it running
        assertEquals(1, svc.getRunningCount(), "the service runs one task");

        List<TargetHealth> health = elbV2Service.describeTargetHealth(REGION, tgArn, null);
        assertEquals(1, health.size(), "the task's container is one target in the group");
        assertEquals(TASK_IP, health.getFirst().getTarget().getId(),
                "an awsvpc task registers its own IP, not the Docker host");
        assertEquals(CONTAINER_PORT, health.getFirst().getTarget().getPort(),
                "an awsvpc task registers the container port");

        service.updateService(CLUSTER, "awsvpc-svc", null, 0, null, REGION);
        service.reconcileServices();   // stops the task, which deregisters its target
        service.reconcileServices();   // sees nothing running

        assertEquals(0, svc.getRunningCount(), "the service scaled to zero");
        assertTrue(elbV2Service.describeTargetHealth(REGION, tgArn, null).isEmpty(),
                "the stopped task's target is deregistered");
    }

    private String createIpTargetGroup(String name) {
        TargetGroup tg = elbV2Service.createTargetGroup(REGION, name, "HTTP", "HTTP1",
                CONTAINER_PORT, "vpc-awsvpc", "ip",
                null, null, false, null, null, null, null, null, null, null, Map.of());
        assertEquals("ip", tg.getTargetType());
        return tg.getTargetGroupArn();
    }

    private static EcsLoadBalancer loadBalancer(String tgArn) {
        EcsLoadBalancer lb = new EcsLoadBalancer();
        lb.setTargetGroupArn(tgArn);
        lb.setContainerName("app");
        lb.setContainerPort(CONTAINER_PORT);
        return lb;
    }

    private static NetworkConfiguration awsvpcNetworkConfiguration() {
        AwsVpcConfiguration vpc = new AwsVpcConfiguration();
        vpc.setSubnets(List.of("subnet-awsvpc"));
        NetworkConfiguration networkConfiguration = new NetworkConfiguration();
        networkConfiguration.setAwsvpcConfiguration(vpc);
        return networkConfiguration;
    }

    private static void registerAwsvpcTaskDefinition(EcsService service, String family) {
        ContainerDefinition cd = new ContainerDefinition();
        cd.setName("app");
        cd.setImage("collector:1");
        cd.setPortMappings(List.of(new PortMapping(CONTAINER_PORT)));
        service.registerTaskDefinition(family, List.of(cd), NetworkMode.awsvpc, "256", "512",
                null, null, List.of("FARGATE"), REGION);
    }

    /**
     * Docker mode with the real registrar over the injected ELBv2 service. The container manager
     * mock reports what an {@code awsvpc} task looks like once its container runs.
     */
    private EcsService newDockerModeService(String tgArn) {
        EmulatorConfig config = mock(EmulatorConfig.class, RETURNS_DEEP_STUBS);
        when(config.services().ecs().mock()).thenReturn(false);
        when(config.effectiveBaseUrl()).thenReturn("http://localhost:4566");

        EcsContainerManager containers = mock(EcsContainerManager.class);
        when(containers.resolveContainerHost(any())).thenReturn(TASK_IP);
        when(containers.startTask(any(), any(), any(), any())).thenAnswer(invocation -> {
            EcsTask task = invocation.getArgument(0);
            Container container = new Container();
            container.setName("app");
            // awsvpc with Floci in a container: expose-only, so hostPort == containerPort.
            container.setNetworkBindings(List.of(
                    new NetworkBinding("0.0.0.0", CONTAINER_PORT, CONTAINER_PORT, "tcp")));
            task.setContainers(List.of(container));
            task.setLastStatus(TaskStatus.RUNNING.name());
            return new EcsTaskHandle(task.getTaskArn(), Map.of(), Map.of());
        });

        EcsService service = new EcsService(
                new RegionResolver(REGION, "000000000000"),
                containers,
                config,
                new EcsLoadBalancerRegistrar(elbV2Service, containers),
                new InMemoryStorageFactory(),
                null);
        service.initializeStorage();
        return service;
    }

    private static final class InMemoryStorageFactory extends StorageFactory {
        private final Map<String, StorageBackend<String, ?>> stores = new HashMap<>();

        private InMemoryStorageFactory() {
            super(null, null);
        }

        @Override
        @SuppressWarnings("unchecked")
        public <V> AccountAwareStorageBackend<V> create(String serviceName,
                                                       String fileName,
                                                       TypeReference<Map<String, V>> typeReference) {
            return (AccountAwareStorageBackend<V>) stores.computeIfAbsent(fileName,
                    ignored -> AccountAwareStorageBackend.inMemory("000000000000"));
        }
    }
}
