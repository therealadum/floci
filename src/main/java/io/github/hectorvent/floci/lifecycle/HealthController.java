package io.github.hectorvent.floci.lifecycle;

import io.github.hectorvent.floci.core.common.ServiceRegistry;
import io.github.hectorvent.floci.services.ecs.EcsService;
import jakarta.inject.Inject;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

@Path("/health")
@Produces(MediaType.APPLICATION_JSON)
public class HealthController {

    private final ServiceRegistry serviceRegistry;
    private final EcsService ecsService;
    private final String version;

    @Inject
    public HealthController(ServiceRegistry serviceRegistry, EcsService ecsService) {
        this.serviceRegistry = serviceRegistry;
        this.ecsService = ecsService;
        this.version = resolveVersion();
    }

    @GET
    public Response health() {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("services", serviceRegistry.getServices());
        body.put("edition", "community");
        body.put("original_edition", "floci-always-free");
        body.put("version", version);
        // A recreated emulator serves what its volume holds only once every persisted ECS service
        // restored at start has converged. Until then this is 503 and names each service still
        // pending with its reason, and the Docker health check settles on healthy only after.
        Optional<Map<String, String>> pending = ecsService.pendingRestoredServices();
        if (pending.isEmpty()) {
            return Response.ok(body).build();
        }
        body.put("pending_services", pending.get());
        return Response.status(Response.Status.SERVICE_UNAVAILABLE).entity(body).build();
    }

    static String resolveVersion() {
        String env = System.getenv("FLOCI_VERSION");
        if (env != null && !env.isBlank()) {
            return env;
        }
        return "dev";
    }
}
