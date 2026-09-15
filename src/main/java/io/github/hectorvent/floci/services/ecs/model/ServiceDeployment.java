package io.github.hectorvent.floci.services.ecs.model;

import io.quarkus.runtime.annotations.RegisterForReflection;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

/**
 * The {@code DescribeServiceDeployments} / {@code ListServiceDeployments} view of one rollout
 * of a service. Distinct from {@link Deployment}, which is the {@code services[].deployments}
 * shape inside {@code DescribeServices}; the two are linked by their id: the service revision
 * this deployment targets carries the same id as the {@code ecs-svc/<id>} deployment that
 * {@code DescribeServices} reports, because clients correlate them that way.
 */
@RegisterForReflection
public class ServiceDeployment {

    private String serviceDeploymentArn;
    private String serviceArn;
    private String clusterArn;
    private String taskDefinition;
    private String status;
    private Instant createdAt;
    private Instant updatedAt;
    private Instant startedAt;
    private Instant finishedAt;
    /** ARN of the {@link ServiceRevision} this deployment rolls out. */
    private String targetServiceRevisionArn;
    /** ARNs of the revisions this deployment replaces; empty for a service's first deployment. */
    private List<String> sourceServiceRevisionArns = new ArrayList<>();

    public String getServiceDeploymentArn() { return serviceDeploymentArn; }
    public void setServiceDeploymentArn(String serviceDeploymentArn) { this.serviceDeploymentArn = serviceDeploymentArn; }

    public String getServiceArn() { return serviceArn; }
    public void setServiceArn(String serviceArn) { this.serviceArn = serviceArn; }

    public String getClusterArn() { return clusterArn; }
    public void setClusterArn(String clusterArn) { this.clusterArn = clusterArn; }

    public String getTaskDefinition() { return taskDefinition; }
    public void setTaskDefinition(String taskDefinition) { this.taskDefinition = taskDefinition; }

    public String getStatus() { return status; }
    public void setStatus(String status) { this.status = status; }

    public Instant getCreatedAt() { return createdAt; }
    public void setCreatedAt(Instant createdAt) { this.createdAt = createdAt; }

    public Instant getUpdatedAt() { return updatedAt; }
    public void setUpdatedAt(Instant updatedAt) { this.updatedAt = updatedAt; }

    public Instant getStartedAt() { return startedAt; }
    public void setStartedAt(Instant startedAt) { this.startedAt = startedAt; }

    public Instant getFinishedAt() { return finishedAt; }
    public void setFinishedAt(Instant finishedAt) { this.finishedAt = finishedAt; }

    public String getTargetServiceRevisionArn() { return targetServiceRevisionArn; }
    public void setTargetServiceRevisionArn(String targetServiceRevisionArn) {
        this.targetServiceRevisionArn = targetServiceRevisionArn;
    }

    public List<String> getSourceServiceRevisionArns() { return sourceServiceRevisionArns; }
    public void setSourceServiceRevisionArns(List<String> sourceServiceRevisionArns) {
        this.sourceServiceRevisionArns = sourceServiceRevisionArns == null
                ? new ArrayList<>() : new ArrayList<>(sourceServiceRevisionArns);
    }
}
