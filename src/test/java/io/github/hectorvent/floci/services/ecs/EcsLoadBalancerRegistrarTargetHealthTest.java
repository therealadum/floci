package io.github.hectorvent.floci.services.ecs;

import io.github.hectorvent.floci.services.ecs.container.EcsContainerManager;
import io.github.hectorvent.floci.services.ecs.model.Container;
import io.github.hectorvent.floci.services.ecs.model.EcsLoadBalancer;
import io.github.hectorvent.floci.services.ecs.model.EcsServiceModel;
import io.github.hectorvent.floci.services.ecs.model.EcsTask;
import io.github.hectorvent.floci.services.ecs.model.NetworkBinding;
import io.github.hectorvent.floci.services.elbv2.ElbV2Service;
import io.github.hectorvent.floci.services.elbv2.model.TargetDescription;
import io.github.hectorvent.floci.services.elbv2.model.TargetHealth;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * {@link EcsLoadBalancerRegistrar#pendingTargetReason}: a load-balanced task counts only once its
 * target in every one of the service's target groups is {@code healthy} by that group's own
 * health check.
 */
class EcsLoadBalancerRegistrarTargetHealthTest {

    private static final String REGION = "us-east-1";
    private static final String QUERY_TG = "arn:aws:elasticloadbalancing:us-east-1:000000000000:targetgroup/query/1";
    private static final String OTLP_TG = "arn:aws:elasticloadbalancing:us-east-1:000000000000:targetgroup/otlp/2";

    private final ElbV2Service elb = mock(ElbV2Service.class);
    private final EcsContainerManager containers = mock(EcsContainerManager.class);
    private final EcsLoadBalancerRegistrar registrar = new EcsLoadBalancerRegistrar(elb, containers);

    @Test
    void allTargetsHealthyInEveryGroupIsNotPending() {
        when(containers.resolveContainerHost(any())).thenReturn("10.0.0.5");
        stubHealth(QUERY_TG, 3200, "healthy", null, null);
        stubHealth(OTLP_TG, 4318, "healthy", null, null);

        assertEquals(Optional.empty(), registrar.pendingTargetReason(task(), service(), REGION));
    }

    @Test
    void oneUnhealthyGroupIsPendingWithItsReason() {
        when(containers.resolveContainerHost(any())).thenReturn("10.0.0.5");
        stubHealth(QUERY_TG, 3200, "healthy", null, null);
        stubHealth(OTLP_TG, 4318, "unhealthy", "Target.Timeout", "Request timed out");

        String reason = registrar.pendingTargetReason(task(), service(), REGION).orElseThrow();
        assertTrue(reason.contains(OTLP_TG), reason);
        assertTrue(reason.contains("unhealthy (Target.Timeout: Request timed out)"), reason);
    }

    @Test
    void initialTargetIsStillPending() {
        when(containers.resolveContainerHost(any())).thenReturn("10.0.0.5");
        stubHealth(QUERY_TG, 3200, "initial", "Elb.InitialHealthChecking", "Initial health checks in progress");
        stubHealth(OTLP_TG, 4318, "healthy", null, null);

        String reason = registrar.pendingTargetReason(task(), service(), REGION).orElseThrow();
        assertTrue(reason.contains("initial (Elb.InitialHealthChecking"), reason);
    }

    @Test
    void containerWithoutABindingForTheTargetIsPending() {
        EcsTask task = task();
        task.getContainers().getFirst().setNetworkBindings(List.of(new NetworkBinding("0.0.0.0", 3200, 3200, "tcp")));
        when(containers.resolveContainerHost(any())).thenReturn("10.0.0.5");
        stubHealth(QUERY_TG, 3200, "healthy", null, null);

        String reason = registrar.pendingTargetReason(task, service(), REGION).orElseThrow();
        assertTrue(reason.contains("has no target for container app:4318"), reason);
    }

    private void stubHealth(String tgArn, int port, String state, String reason, String description) {
        TargetDescription target = new TargetDescription();
        target.setId("10.0.0.5");
        target.setPort(port);
        TargetHealth health = new TargetHealth();
        health.setTarget(target);
        health.setState(state);
        health.setReason(reason);
        health.setDescription(description);
        when(elb.describeTargetHealth(eq(REGION), eq(tgArn), anyList())).thenReturn(List.of(health));
    }

    private static EcsTask task() {
        Container container = new Container();
        container.setName("app");
        container.setNetworkBindings(List.of(
                new NetworkBinding("0.0.0.0", 3200, 3200, "tcp"),
                new NetworkBinding("0.0.0.0", 4318, 4318, "tcp")));
        EcsTask task = new EcsTask();
        task.setTaskArn("arn:aws:ecs:us-east-1:000000000000:task/c/health");
        task.setContainers(List.of(container));
        return task;
    }

    private static EcsServiceModel service() {
        EcsServiceModel svc = new EcsServiceModel();
        svc.setServiceName("tempo");
        svc.setLoadBalancers(List.of(lb(QUERY_TG, 3200), lb(OTLP_TG, 4318)));
        return svc;
    }

    private static EcsLoadBalancer lb(String tgArn, int port) {
        EcsLoadBalancer lb = new EcsLoadBalancer();
        lb.setTargetGroupArn(tgArn);
        lb.setContainerName("app");
        lb.setContainerPort(port);
        return lb;
    }
}
