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
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.jboss.logging.Logger;

import java.util.List;
import java.util.Optional;
import java.util.function.BiConsumer;

/**
 * Bridges ECS services to ELBv2: when an ECS service declares a {@code loadBalancers}
 * block, this registrar registers each running task container as a target in the named
 * ELBv2 target group (and deregisters it when the task stops).
 * <p>
 * One-way dependency ECS → ELBv2; the ELBv2 data plane reaches the container over plain
 * TCP and never calls back into ECS, so there is no cycle.
 */
@ApplicationScoped
public class EcsLoadBalancerRegistrar {

    private static final Logger LOG = Logger.getLogger(EcsLoadBalancerRegistrar.class);

    private final ElbV2Service elbV2Service;
    private final EcsContainerManager containerManager;

    @Inject
    public EcsLoadBalancerRegistrar(ElbV2Service elbV2Service, EcsContainerManager containerManager) {
        this.elbV2Service = elbV2Service;
        this.containerManager = containerManager;
    }

    /** Registers the task's load-balanced containers as ELBv2 targets. */
    public void registerTask(EcsTask task, EcsServiceModel svc, String region) {
        forEachTarget(task, svc, (tgArn, td) -> {
            try {
                elbV2Service.registerTargets(region, tgArn, List.of(td));
                LOG.infov("Registered ECS task target {0}:{1} into target group {2}",
                        td.getId(), td.getPort(), tgArn);
            } catch (Exception e) {
                LOG.warnv("Could not register ECS target into {0}: {1}", tgArn, e.getMessage());
            }
        });
    }

    /** Deregisters the task's load-balanced containers from their ELBv2 target groups. */
    public void deregisterTask(EcsTask task, EcsServiceModel svc, String region) {
        forEachTarget(task, svc, (tgArn, td) -> {
            try {
                elbV2Service.deregisterTargets(region, tgArn, List.of(td));
                LOG.infov("Deregistered ECS task target {0}:{1} from target group {2}",
                        td.getId(), td.getPort(), tgArn);
            } catch (Exception e) {
                LOG.warnv("Could not deregister ECS target from {0}: {1}", tgArn, e.getMessage());
            }
        });
    }

    /**
     * Why the task does not yet count as healthy behind its load balancers, or empty when its
     * registered target in every one of the service's target groups is {@code healthy} by that
     * group's own health check.
     * <p>
     * On AWS a load-balanced service counts a task only once the target group health check
     * reports it healthy ("the service scheduler waits for the load balancer target group health
     * check to return a healthy status before counting the task", ECS service definition
     * parameters). {@code initial}, {@code unhealthy}, {@code draining} and {@code unused} all
     * keep it out, and so does a target that was never registered.
     */
    public Optional<String> pendingTargetReason(EcsTask task, EcsServiceModel svc, String region) {
        if (svc == null || svc.getLoadBalancers() == null) {
            return Optional.empty();
        }
        for (EcsLoadBalancer lb : svc.getLoadBalancers()) {
            if (lb.getTargetGroupArn() == null || lb.getTargetGroupArn().isBlank()) {
                continue;
            }
            TargetDescription td = resolveTarget(task, lb);
            if (td == null) {
                return Optional.of("task " + task.getTaskArn() + " has no target for container "
                        + lb.getContainerName() + ":" + lb.getContainerPort()
                        + " in target group " + lb.getTargetGroupArn());
            }
            List<TargetHealth> health;
            try {
                health = elbV2Service.describeTargetHealth(region, lb.getTargetGroupArn(), List.of(td));
            } catch (Exception e) {
                return Optional.of("target group " + lb.getTargetGroupArn() + " could not be read: " + e.getMessage());
            }
            TargetHealth th = health.isEmpty() ? null : health.getFirst();
            if (th == null || !"healthy".equals(th.getState())) {
                String state = th == null ? "unknown" : th.getState();
                String reason = th == null ? null : th.getReason();
                String description = th == null ? null : th.getDescription();
                return Optional.of("target " + td.getId() + ":" + td.getPort() + " in target group "
                        + lb.getTargetGroupArn() + " is " + state
                        + (reason == null ? "" : " (" + reason + (description == null ? "" : ": " + description) + ")"));
            }
        }
        return Optional.empty();
    }

    private void forEachTarget(EcsTask task, EcsServiceModel svc,
                               BiConsumer<String, TargetDescription> action) {
        if (svc == null || svc.getLoadBalancers() == null || svc.getLoadBalancers().isEmpty()) {
            return;
        }
        for (EcsLoadBalancer lb : svc.getLoadBalancers()) {
            if (lb.getTargetGroupArn() == null || lb.getTargetGroupArn().isBlank()) {
                continue;
            }
            TargetDescription td = resolveTarget(task, lb);
            if (td != null) {
                action.accept(lb.getTargetGroupArn(), td);
            }
        }
    }

    /** The target a task's container registers for one load balancer entry, or null if it has none. */
    private TargetDescription resolveTarget(EcsTask task, EcsLoadBalancer lb) {
        if (task.getContainers() == null || task.getContainers().isEmpty()) {
            return null;
        }
        Container container = task.getContainers().stream()
                .filter(c -> lb.getContainerName() == null
                        || lb.getContainerName().equals(c.getName()))
                .findFirst()
                .orElse(null);
        if (container == null || container.getNetworkBindings() == null) {
            return null;
        }
        NetworkBinding binding = container.getNetworkBindings().stream()
                .filter(b -> lb.getContainerPort() == null
                        || lb.getContainerPort() == b.containerPort())
                .findFirst()
                .orElse(null);
        if (binding == null) {
            return null;
        }
        TargetDescription td = new TargetDescription();
        td.setId(containerManager.resolveContainerHost(container));
        td.setPort(binding.hostPort());
        return td;
    }
}
