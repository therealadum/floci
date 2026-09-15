package io.github.hectorvent.floci.services.ecs;

import com.fasterxml.jackson.core.type.TypeReference;
import io.github.hectorvent.floci.config.EmulatorConfig;
import io.github.hectorvent.floci.core.common.RegionResolver;
import io.github.hectorvent.floci.core.storage.AccountAwareStorageBackend;
import io.github.hectorvent.floci.core.storage.StorageBackend;
import io.github.hectorvent.floci.core.storage.StorageFactory;
import io.github.hectorvent.floci.services.ecs.container.EcsContainerManager;
import io.github.hectorvent.floci.services.ecs.container.EcsTaskHandle;
import io.github.hectorvent.floci.services.ecs.model.Container;
import io.github.hectorvent.floci.services.ecs.model.ContainerDefinition;
import io.github.hectorvent.floci.services.ecs.model.Deployment;
import io.github.hectorvent.floci.services.ecs.model.EcsLoadBalancer;
import io.github.hectorvent.floci.services.ecs.model.EcsServiceModel;
import io.github.hectorvent.floci.services.ecs.model.EcsTask;
import io.github.hectorvent.floci.services.ecs.model.LaunchType;
import io.github.hectorvent.floci.services.ecs.model.NetworkBinding;
import io.github.hectorvent.floci.services.ecs.model.ServiceDeployment;
import io.github.hectorvent.floci.services.ecs.model.TaskStatus;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.RETURNS_DEEP_STUBS;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * A load-balanced service's deployment reaches steady state only once every task's target in every
 * one of its target groups is healthy, as on AWS: "the service scheduler waits for the load balancer
 * target group health check to return a healthy status before counting the task" (ECS service
 * definition parameters). Until then {@code rolloutState} is {@code IN_PROGRESS} and the
 * {@code DescribeServiceDeployments} status the terraform provider's waiter reads is not
 * {@code SUCCESSFUL}. A service without load balancers is reported exactly as before.
 */
class EcsServiceLoadBalancerRolloutTest {

    private static final String REGION = "us-east-1";
    private static final String CLUSTER = "lb-roll";
    private static final String TG = "arn:aws:elasticloadbalancing:us-east-1:000000000000:targetgroup/otlp/1";

    private final EcsLoadBalancerRegistrar registrar = mock(EcsLoadBalancerRegistrar.class);
    private final EcsService service = newDockerModeService(registrar);

    @Test
    void healthyTargetsCompleteTheDeployment() {
        service.createCluster(CLUSTER, REGION);
        registerTaskDef("healthy-fam");
        EcsServiceModel svc = service.createService(CLUSTER, "healthy-svc", "healthy-fam", 1,
                LaunchType.FARGATE, List.of(lb()), null, REGION);

        assertEquals("IN_PROGRESS", primary(svc).getRolloutState());
        assertEquals("IN_PROGRESS", serviceDeployment("healthy-svc").getStatus());
        assertNull(serviceDeployment("healthy-svc").getFinishedAt());

        when(registrar.pendingTargetReason(any(), any(), any())).thenReturn(Optional.empty());
        service.reconcileServices(); // launches the task
        service.reconcileServices(); // sees it running and healthy

        assertEquals("COMPLETED", primary(svc).getRolloutState());
        ServiceDeployment deployment = serviceDeployment("healthy-svc");
        assertEquals("SUCCESSFUL", deployment.getStatus());
        assertNotNull(deployment.getFinishedAt());
    }

    @Test
    void unhealthyTargetKeepsTheDeploymentInProgress() {
        service.createCluster(CLUSTER, REGION);
        registerTaskDef("sick-fam");
        EcsServiceModel svc = service.createService(CLUSTER, "sick-svc", "sick-fam", 1,
                LaunchType.FARGATE, List.of(lb()), null, REGION);

        String reason = "target 10.0.0.5:4318 in target group " + TG + " is unhealthy (Target.Timeout: Request timed out)";
        when(registrar.pendingTargetReason(any(), any(), any())).thenReturn(Optional.of(reason));
        service.reconcileServices();
        service.reconcileServices();
        service.reconcileServices();

        assertEquals(1, svc.getRunningCount(), "the task runs; it is its target that is not healthy");
        Deployment primary = primary(svc);
        assertEquals("IN_PROGRESS", primary.getRolloutState());
        assertTrue(primary.getRolloutStateReason().contains(reason), primary.getRolloutStateReason());
        assertEquals("IN_PROGRESS", serviceDeployment("sick-svc").getStatus());

        // The target recovers: the deployment completes, and stays completed.
        when(registrar.pendingTargetReason(any(), any(), any())).thenReturn(Optional.empty());
        service.reconcileServices();
        assertEquals("COMPLETED", primary(svc).getRolloutState());
        assertEquals("SUCCESSFUL", serviceDeployment("sick-svc").getStatus());

        when(registrar.pendingTargetReason(any(), any(), any())).thenReturn(Optional.of(reason));
        service.reconcileServices();
        assertEquals("COMPLETED", primary(svc).getRolloutState());
    }

    @Test
    void newDeploymentStopsTheOneStillInProgress() {
        service.createCluster(CLUSTER, REGION);
        registerTaskDef("super-fam");
        service.createService(CLUSTER, "super-svc", "super-fam", 1,
                LaunchType.FARGATE, List.of(lb()), null, REGION);
        String first = serviceDeployment("super-svc").getServiceDeploymentArn();

        service.updateService(CLUSTER, "super-svc", null, null, null, null, true, REGION);

        List<ServiceDeployment> deployments = service.listServiceDeploymentsDetailed("super-svc", CLUSTER, null, REGION);
        assertEquals(2, deployments.size());
        ServiceDeployment stopped = deployments.stream()
                .filter(d -> first.equals(d.getServiceDeploymentArn())).findFirst().orElseThrow();
        assertEquals("STOPPED", stopped.getStatus());
        assertNotNull(stopped.getFinishedAt());
        assertTrue(deployments.stream().anyMatch(d -> "IN_PROGRESS".equals(d.getStatus())));
    }

    @Test
    void serviceWithoutLoadBalancersIsUnchanged() {
        service.createCluster(CLUSTER, REGION);
        registerTaskDef("plain-fam");
        EcsServiceModel svc = service.createService(CLUSTER, "plain-svc", "plain-fam", 1,
                LaunchType.FARGATE, List.of(), null, REGION);

        assertEquals("SUCCESSFUL", serviceDeployment("plain-svc").getStatus());

        service.reconcileServices();
        service.reconcileServices();

        assertEquals("COMPLETED", primary(svc).getRolloutState());
        verify(registrar, never()).pendingTargetReason(any(), any(), any());
    }

    private Deployment primary(EcsServiceModel svc) {
        return service.deploymentsFor(svc).getFirst();
    }

    private ServiceDeployment serviceDeployment(String serviceName) {
        List<ServiceDeployment> deployments = service.listServiceDeploymentsDetailed(serviceName, CLUSTER, null, REGION);
        assertEquals(1, deployments.size());
        return deployments.getFirst();
    }

    private void registerTaskDef(String family) {
        ContainerDefinition cd = new ContainerDefinition();
        cd.setName("app");
        cd.setImage("app:1");
        service.registerTaskDefinition(family, List.of(cd), null, null, null,
                null, null, List.of(), REGION);
    }

    private static EcsLoadBalancer lb() {
        EcsLoadBalancer lb = new EcsLoadBalancer();
        lb.setTargetGroupArn(TG);
        lb.setContainerName("app");
        lb.setContainerPort(4318);
        return lb;
    }

    /** Docker mode, with a container manager that starts each task straight into RUNNING. */
    private static EcsService newDockerModeService(EcsLoadBalancerRegistrar registrar) {
        EmulatorConfig config = mock(EmulatorConfig.class, RETURNS_DEEP_STUBS);
        when(config.services().ecs().mock()).thenReturn(false);
        when(config.effectiveBaseUrl()).thenReturn("http://localhost:4566");
        EcsContainerManager containers = mock(EcsContainerManager.class);
        when(containers.startTask(any(), any(), any(), any())).thenAnswer(invocation -> {
            EcsTask task = invocation.getArgument(0);
            Container container = new Container();
            container.setName("app");
            container.setNetworkBindings(List.of(new NetworkBinding("0.0.0.0", 4318, 4318, "tcp")));
            task.setContainers(List.of(container));
            task.setLastStatus(TaskStatus.RUNNING.name());
            return new EcsTaskHandle(task.getTaskArn(), Map.of(), Map.of());
        });
        EcsService service = new EcsService(
                new RegionResolver(REGION, "000000000000"),
                containers,
                config,
                registrar,
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
