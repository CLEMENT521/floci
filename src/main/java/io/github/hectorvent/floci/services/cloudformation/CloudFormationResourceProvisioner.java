package io.github.hectorvent.floci.services.cloudformation;

import io.github.hectorvent.floci.core.common.AwsArnUtils;
import io.github.hectorvent.floci.services.cloudformation.model.StackResource;
import io.github.hectorvent.floci.services.cloudformation.model.StackEvent;
import io.github.hectorvent.floci.services.cloudformation.provisioners.OpenApiDocuments;
import io.github.hectorvent.floci.services.cloudformation.provisioners.ReplacementCleanup;
import io.github.hectorvent.floci.services.cloudformation.provisioners.CfnRollback;
import io.github.hectorvent.floci.services.cloudformation.provisioners.CloudFormationResourceRegistry;
import io.github.hectorvent.floci.services.cloudformation.provisioners.ProvisionContext;
import io.github.hectorvent.floci.services.cloudformation.provisioners.CfnDynamicReferences;
import io.github.hectorvent.floci.services.cloudformation.provisioners.CfnResourceProvisioner;
import io.github.hectorvent.floci.services.cloudformation.provisioners.UpdateCleanupResult;
import io.github.hectorvent.floci.services.eventbridge.model.Target;
import io.github.hectorvent.floci.services.iam.IamService;
import io.github.hectorvent.floci.services.iam.model.IamRole;
import io.github.hectorvent.floci.services.lambda.LambdaService;
import io.github.hectorvent.floci.services.pipes.model.DesiredState;
import io.github.hectorvent.floci.services.ssm.model.Parameter;
import io.github.hectorvent.floci.services.apigatewayv2.model.*;
import io.github.hectorvent.floci.config.EmulatorConfig;
import io.github.hectorvent.floci.core.common.AwsException;
import io.github.hectorvent.floci.core.common.docker.ContainerReachableEndpoint;
import io.github.hectorvent.floci.services.lambda.model.InvocationType;
import io.github.hectorvent.floci.services.lambda.model.InvokeResult;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.jboss.logging.Logger;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.TimeoutException;
import java.util.function.Consumer;
import java.util.regex.Pattern;

/**
 * Provisions individual CloudFormation resource types using Floci's existing service implementations.
 */
@ApplicationScoped
public class CloudFormationResourceProvisioner {

    private static final Logger LOG = Logger.getLogger(CloudFormationResourceProvisioner.class);
    static final String UPDATE_ROLLBACK_RESTORED_ATTR = CfnRollback.UPDATE_ROLLBACK_RESTORED_ATTR;
    static final String UPDATE_ROLLBACK_FAILURE_ATTR = CfnRollback.UPDATE_ROLLBACK_FAILURE_ATTR;
    private static final int GENERATED_NAME_SUFFIX_LENGTH = 12;

    /**
     * Types whose delete needs the whole {@link StackResource} — a create-time attribute (the
     * rule's event bus, the authorizer's api id, the nodegroup's cluster) or the stashed
     * custom-resource properties. Deleting one of these from type and physical id alone silently
     * no-ops and leaves the resource live, so they route through
     * {@link #deleteUsingCreateTimeAttributes} instead.
     *
     * <p>Gates that method, so the set cannot drift from its branches. When one of these types
     * moves to a per-service provisioner, its logic moves into that provisioner's
     * {@code delete(StackResource, String)} override and its entry leaves this set;
     * {@code CfnDeletePrecedenceTest} fails while both claim it.
     */
    static final Set<String> DELETE_NEEDS_STACK_RESOURCE = Set.of(
            "AWS::CloudFormation::CustomResource");

    /**
     * Every resource type the switch in {@link #provision} still serves. Load-bearing: the
     * default arm throws for a member of this set, so deleting an arm during the migration to
     * per-service provisioners without deleting its entry here fails loudly instead of
     * silently stubbing the resource. Kept in step with the registry by
     * {@code CfnResourceInventoryTest}.
     */
    static final Set<String> LEGACY_SWITCH_TYPES = Set.of(
            "AWS::CloudFormation::CustomResource");

    /** Reserved attribute keys used to carry custom-resource state to the later Delete invocation. */
    private static final String CR_SERVICE_TOKEN_ATTR = "__FlociServiceToken";
    private static final String CR_PROPERTIES_ATTR = "__FlociResourceProperties";
    /**
     * How long to wait for the Lambda's ResponseURL callback after the synchronous invoke returns.
     * The invoke already blocks until the handler finishes, so this only covers a PUT that lands
     * fractionally after the container returns control.
     */
    private static final Duration CR_RESPONSE_TIMEOUT = Duration.ofSeconds(10);

    private final LambdaService lambdaService;
    private final IamService iamService;
    private final ObjectMapper objectMapper;
    private final CustomResourceResponseStore customResourceResponseStore;
    private final ContainerReachableEndpoint reachableEndpoint;
    // Item 15 decomposition: extracted per-service provisioners are consulted before the switch
    // below. As types migrate, their switch cases and provisionXxx methods are removed here; the
    // now-dead service deps above are cleared in the final cleanup once the switch is empty.
    private final CloudFormationResourceRegistry resourceRegistry;
    private final CfnDynamicReferences dynamicReferences;
    private final EmulatorConfig config;

    @Inject
    public CloudFormationResourceProvisioner(LambdaService lambdaService,
                                             IamService iamService,
                                             ObjectMapper objectMapper,
                                             CustomResourceResponseStore customResourceResponseStore,
                                             ContainerReachableEndpoint reachableEndpoint,
                                             CloudFormationResourceRegistry resourceRegistry,
                                             CfnDynamicReferences dynamicReferences,
                                             EmulatorConfig config) {
        this.config = config;
        this.lambdaService = lambdaService;
        this.iamService = iamService;
        this.objectMapper = objectMapper;
        this.customResourceResponseStore = customResourceResponseStore;
        this.reachableEndpoint = reachableEndpoint;
        this.resourceRegistry = resourceRegistry;
        this.dynamicReferences = dynamicReferences;
    }

    /**
     * Provisions a single resource. Returns the populated StackResource (physicalId + attributes set).
     *
     * <p>A resource type with no provisioner is stubbed: a synthetic physical id, an
     * {@code arn:aws:stub:::} ARN attribute and {@code CREATE_COMPLETE}, logged at warn and
     * carrying a status reason saying nothing was created. With
     * {@code floci.services.cloudformation.allow-stub-unsupported-resource-types} off it comes back
     * {@code CREATE_FAILED} instead, with no physical id.
     */
    public StackResource provision(String logicalId, String resourceType, JsonNode properties,
                                   CloudFormationTemplateEngine engine, String region, String accountId,
                                   String stackName) {
        return provision(logicalId, resourceType, properties, engine, region, accountId, stackName, null);
    }

    public StackResource provision(String logicalId, String resourceType, JsonNode properties,
                                   CloudFormationTemplateEngine engine, String region, String accountId,
                                   String stackName, String existingPhysicalId) {
        return provision(logicalId, resourceType, properties, engine, region, accountId, stackName,
                existingPhysicalId, Map.of());
    }

    public StackResource provision(String logicalId, String resourceType, JsonNode properties,
                                   CloudFormationTemplateEngine engine, String region, String accountId,
                                   String stackName, String existingPhysicalId,
                                   Map<String, String> existingAttributes) {
        return provision(logicalId, resourceType, properties, engine, region, accountId, stackName,
                existingPhysicalId, existingAttributes, event -> {});
    }

    public StackResource provision(String logicalId, String resourceType, JsonNode properties,
                                   CloudFormationTemplateEngine engine, String region, String accountId,
                                   String stackName, String existingPhysicalId,
                                   Map<String, String> existingAttributes, Consumer<StackEvent> progress) {
        StackResource resource = new StackResource();
        resource.setLogicalId(logicalId);
        resource.setResourceType(resourceType);
        resource.setPhysicalId(existingPhysicalId);
        resource.setAttributes(new HashMap<>(existingAttributes != null ? existingAttributes : Map.of()));

        try {
            CfnResourceProvisioner extracted = resourceRegistry.forType(resourceType).orElse(null);
            if (extracted != null) {
                extracted.provision(resource, properties,
                        new ProvisionContext(engine, region, accountId, stackName, existingPhysicalId, progress));
                resource.setStatus("CREATE_COMPLETE");
                return resource;
            }
            switch (resourceType) {
                case "AWS::CloudFormation::CustomResource" ->
                        provisionCustomResource(resource, properties, engine, region, accountId, stackName);
                default -> {
                    if (resourceType != null && resourceType.startsWith("Custom::")) {
                        provisionCustomResource(resource, properties, engine, region, accountId, stackName);
                    } else if (LEGACY_SWITCH_TYPES.contains(resourceType)) {
                        // A declared legacy type reaching the default arm means its case was removed
                        // without removing its LEGACY_SWITCH_TYPES entry (or without registering a
                        // provisioner). Stubbing it would report CREATE_COMPLETE with a fake ARN and
                        // hide the mistake, so fail instead.
                        throw new IllegalStateException("No switch arm for declared legacy type "
                                + resourceType + " — remove its LEGACY_SWITCH_TYPES entry when it "
                                + "moves to a per-service provisioner.");
                    } else if (!stubUnsupportedResourceTypesAllowed()) {
                        // Before the physical id below is assigned, so the Cloud Control path sees
                        // a resource with none and reports this message rather than a success. On
                        // the stack path the catch below turns it into CREATE_FAILED with the same
                        // sentence, which rolls the stack back.
                        throw new AwsException("ValidationError",
                                unsupportedResourceTypeMessage(resourceType), 400);
                    } else {
                        // Warn, not debug, and a status reason on the resource: the stub reports
                        // CREATE_COMPLETE while creating nothing, so without both the stack is
                        // indistinguishable from one where every resource was really provisioned.
                        // The reason reaches DescribeStackEvents through the event
                        // CloudFormationService already builds from it.
                        LOG.warnv("Stubbing unsupported resource type {0} ({1}): nothing is created "
                                        + "for it. Set floci.services.cloudformation."
                                        + "allow-stub-unsupported-resource-types=false to fail the "
                                        + "stack instead.",
                                resourceType, logicalId);
                        resource.setStatusReason(unsupportedResourceTypeMessage(resourceType)
                                + " It was stubbed and nothing was created for it.");
                        resource.setPhysicalId(logicalId + "-" + UUID.randomUUID().toString().substring(0, 8));
                        resource.getAttributes().put("Arn", "arn:aws:stub:::" + logicalId);
                    }
                }
            }
            resource.setStatus("CREATE_COMPLETE");
        } catch (Exception e) {
            LOG.warnv("Failed to provision {0} ({1}): {2}", resourceType, logicalId, e.getMessage());
            resource.setStatus("CREATE_FAILED");
            resource.setStatusReason(e.getMessage());
        }
        return resource;
    }

    /**
     * Whether a resource type with no provisioner may be stubbed. The provisioners hand-built in
     * unit tests carry no config; absent configuration means the documented default, which here is
     * the lenient behaviour, so the test reads {@code config == null ||}.
     */
    private boolean stubUnsupportedResourceTypesAllowed() {
        return config == null || config.services().cloudformation().allowStubUnsupportedResourceTypes();
    }

    /** The one sentence Floci says about a resource type it has no provisioner for. */
    static String unsupportedResourceTypeMessage(String resourceType) {
        return "Resource type " + resourceType + " is not supported by Floci.";
    }

    /**
     * Provision a single resource with no enclosing CloudFormation stack — the Cloud Control
     * {@code CreateResource} path. Cloud Control DesiredState carries resolved values (no
     * intrinsics), so a minimal template engine suffices. Reuses the same 114-type provisioning
     * that CloudFormation stacks use, so any type a stack can create, Cloud Control can too.
     */
    public StackResource provisionStandalone(String resourceType, JsonNode properties, String region, String accountId) {
        CloudFormationTemplateEngine engine = new CloudFormationTemplateEngine(
                accountId, region, "cloudcontrol", "cloudcontrol",
                Map.of(), new HashMap<>(), new HashMap<>(), Map.of(), Map.of(), objectMapper, name -> null,
                value -> dynamicReferences.resolveDynamicReferences(value, region, false));
        return provision("resource", resourceType, properties, engine, region, accountId, "cloudcontrol");
    }

    /** Delete a resource by type + physical id — the Cloud Control {@code DeleteResource} path. */
    public void deleteStandalone(String resourceType, String identifier, String region) {
        deleteStandalone(resourceType, identifier, region, Map.of());
    }

    /**
     * As above, with the attributes recorded when the resource was created. Custom resources, EKS
     * nodegroups and IAM inline policies cannot be deleted from type and physical id alone, so
     * without these their delete silently no-ops.
     */
    public void deleteStandalone(String resourceType, String identifier, String region,
                                 Map<String, String> attributes) {
        deleteStandalone(resourceType, identifier, region, "000000000000", attributes);
    }

    /** Account-aware standalone delete used by Cloud Control. */
    public void deleteStandalone(String resourceType, String identifier, String region,
                                 String accountId, Map<String, String> attributes) {
        StackResource resource = new StackResource();
        resource.setResourceType(resourceType);
        resource.setPhysicalId(identifier);
        resource.setAttributes(new HashMap<>(attributes == null ? Map.of() : attributes));
        delete(resource, region, accountId);
    }

    /**
     * Deletes a provisioned resource. Custom resources are re-invoked with {@code RequestType=Delete}
     * (using the ServiceToken + properties stashed at create time); everything else delegates to the
     * type-keyed {@link #delete(String, String, String)}.
     */
    public void delete(StackResource resource, String region) {
        delete(resource, region, "000000000000");
    }

    public void delete(StackResource resource, String region, String accountId) {
        String resourceType = resource.getResourceType();
        // Registry first. An extracted provisioner owns its type outright, and gets the whole
        // resource so an attribute-aware delete can read its create-time attributes. Consulting it
        // ahead of the branches below means an exact match always beats the Custom:: prefix branch
        // (which is how Custom::DynamoDBReplica moved to DynamoDbCfnProvisioner), and that migrating one of the
        // DELETE_NEEDS_STACK_RESOURCE types cannot silently keep using the stale branch here.
        CfnResourceProvisioner extractedForDelete = resourceRegistry.forType(resourceType).orElse(null);
        if (extractedForDelete != null) {
            extractedForDelete.delete(resource, region);
            return;
        }
        if (DELETE_NEEDS_STACK_RESOURCE.contains(resourceType)) {
            deleteUsingCreateTimeAttributes(resource, region);
            return;
        }
        if (resourceType != null && resourceType.startsWith("Custom::")) {
            deleteCustomResource(resource, region);
            return;
        }
        delete(resourceType, resource.getPhysicalId(), region);
    }

    /**
     * Deletes one of the {@link #DELETE_NEEDS_STACK_RESOURCE} types, whose delete needs state the
     * type/physicalId path cannot supply — a create-time attribute, or the stashed custom-resource
     * properties. Reached only through that set, so the set and these branches stay in step: a
     * listed type with no branch throws rather than silently no-opping.
     */
    private void deleteUsingCreateTimeAttributes(StackResource resource, String region) {
        String resourceType = resource.getResourceType();
        if ("AWS::CloudFormation::CustomResource".equals(resourceType)) {
            deleteCustomResource(resource, region);
            return;
        }
        throw new IllegalStateException("DELETE_NEEDS_STACK_RESOURCE lists " + resourceType
                + " but no branch here deletes it — deleting it by physical id alone would "
                + "silently no-op and leave the resource live.");
    }

    /**
     * Deletes a single resource by type + physical id. Failures propagate to the caller
     * (CloudFormationService#deleteStackResources) so the stack transitions to DELETE_FAILED,
     * matching AWS — e.g. deleting a non-empty S3 bucket raises BucketNotEmpty and must not be
     * silently reported as a successful stack deletion. Resource types that AWS itself treats
     * leniently keep their dedicated handling: the {@code *Safe} helpers below swallow expected
     * conflicts, and KMS keys are intentionally left for scheduled deletion.
     */
    public void delete(String resourceType, String physicalId, String region) {
        CfnResourceProvisioner extracted = resourceRegistry.forType(resourceType).orElse(null);
        if (extracted != null) {
            extracted.delete(resourceType, physicalId, region);
            return;
        }
        switch (resourceType) {
            // Warn for the same reason the create path does: the delete reports success over a
            // type nothing here removes, and at debug that is invisible at the default log level.
            // The line names the physical id without claiming a resource survives it: this arm
            // takes both a type the create switch provisioned and one it only stubbed, and only
            // the first leaves something behind.
            default -> LOG.warnv("No delete implemented for resource type {0}: {1} is not removed "
                    + "here.", resourceType, physicalId);
        }
    }

    // ── CloudWatch Logs ─────────────────────────────────────────────────────────

    // ── Auto Scaling ────────────────────────────────────────────────────────────

    // ── EKS ─────────────────────────────────────────────────────────────────────

    // ── Pipes ──────────────────────────────────────────────────────────────────

    /**
     * One attempt at deleting what this update's replacement displaced, delegated to the
     * provisioner that owns the type. Step Functions was the last type answering here without an
     * extracted provisioner, so this is now pure delegation.
     */
    UpdateCleanupResult completeUpdate(StackResource resource) {
        return resourceRegistry.forType(resource.getResourceType())
                .map(owner -> owner.completeUpdate(resource))
                .filter(UpdateCleanupResult::applicable)
                .orElseGet(UpdateCleanupResult::notApplicable);
    }
    /**
     * The physical id this update displaced, announced as DELETE_IN_PROGRESS before the stack
     * update closes. A type whose {@code UpdateReplacePolicy} is {@code Retain} owes no cleanup.
     */
    String updateCleanupPhysicalId(StackResource resource) {
        if ("Retain".equals(resource.getUpdateReplacePolicy())) {
            return null;
        }
        return resourceRegistry.forType(resource.getResourceType())
                .map(owner -> owner.updateCleanupPhysicalId(resource))
                .orElse(null);
    }

    /** Only an opted-in provisioner may identify cleanup owed by an UPDATE_FAILED resource. */
    boolean hasPendingRollbackCleanup(StackResource resource) {
        return resourceRegistry.forType(resource.getResourceType())
                .map(owner -> owner.hasPendingRollbackCleanup(resource))
                .orElse(false);
    }

    /** Only an opted-in provisioner may keep a failed update attempt in place of the previous resource. */
    boolean retainsFailedUpdateState(StackResource resource) {
        return resourceRegistry.forType(resource.getResourceType())
                .map(owner -> owner.retainsFailedUpdateState(resource))
                .orElse(false);
    }

    /**
     * Whether this update replaced the resource's physical entity, so the stack has cleanup
     * pending.
     */
    boolean hasReplacementUpdate(StackResource resource) {
        return resourceRegistry.forType(resource.getResourceType())
                .map(owner -> owner.hasReplacementUpdate(resource))
                .orElse(false);
    }
    /** Drops the cleanup bookkeeping this update left on the resource. */
    void clearUpdate(StackResource resource) {
        resourceRegistry.forType(resource.getResourceType())
                .ifPresent(owner -> owner.clearUpdate(resource));
    }

    /**
     * Puts the physical entity back to its pre-update configuration when a later resource fails
     * the stack update, delegated to the provisioner that owns the type.
     */
    boolean rollbackUpdate(StackResource resource) {
        return rollbackUpdate(resource, event -> {});
    }

    boolean rollbackUpdate(StackResource resource, Consumer<StackEvent> progress) {
        return resourceRegistry.forType(resource.getResourceType())
                .map(owner -> owner.rollbackUpdate(resource, progress))
                .orElse(false);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    // ── ApiGateway (V1) ──────────────────────────────────────────────────────

    /**
     * Carries ownership discovered by a failed update onto the last known-good resource metadata
     * that CloudFormation restores. Only additive cleanup tracking belongs here; normal attempted
     * attributes must not overwrite the committed resource state.
     */
    void mergeFailedUpdateResourceTracking(StackResource previous, StackResource attempted) {
        // Any provisioner using ReplacementCleanup: an entity the failed attempt created and could
        // not remove is owed to the next cleanup, which runs on the restored resource.
        ReplacementCleanup.mergeDisplaced(previous, attempted);
        if (!Objects.equals(previous.getResourceType(), attempted.getResourceType())) {
            return;
        }
        // Extracted provisioners that track their own generated sub-resources (ApiGatewayV2's Api
        // body routes/integrations/authorizers) carry that tracking forward themselves.
        resourceRegistry.forType(previous.getResourceType())
                .ifPresent(owner -> owner.mergeFailedUpdateResourceTracking(previous, attempted));
    }

    // ── CloudFormation Custom Resources ──────────────────────────────────────
    //
    // A Custom::* / AWS::CloudFormation::CustomResource is backed by a Lambda named by its
    // ServiceToken. CloudFormation invokes that Lambda with a request event and the Lambda PUTs its
    // result to the event's ResponseURL (it does NOT return it). Floci points ResponseURL at
    // CfnResponseController and, because the invoke is synchronous, reads the captured response as
    // soon as the handler returns. Pattern 1 only — single-Lambda synchronous handlers (e.g. CDK
    // BucketDeployment). The async Provider framework (onEvent/isComplete polling) is not emulated.

    private void provisionCustomResource(StackResource r, JsonNode props, CloudFormationTemplateEngine engine,
                                         String region, String accountId, String stackName) {
        if (props == null || !props.has("ServiceToken")) {
            throw new AwsException("ValidationError",
                    "Custom resource " + r.getLogicalId() + " is missing ServiceToken", 400);
        }
        String serviceToken = engine.resolve(props.get("ServiceToken"));
        if (serviceToken == null || serviceToken.isBlank()) {
            throw new AwsException("ValidationError",
                    "Custom resource " + r.getLogicalId() + " has an unresolved ServiceToken", 400);
        }

        // Resolve intrinsics to concrete values. CloudFormation keeps ServiceToken inside
        // ResourceProperties (and also surfaces it at the top level of the event), so we leave it
        // in place here. CloudFormation stringifies every scalar in ResourceProperties
        // (true -> "true", 5 -> "5") while preserving list/map structure; handlers (e.g. CDK's)
        // rely on this and call String methods on the values, so we must match it.
        JsonNode resolvedProps = engine.resolveNode(props);
        ObjectNode resolved = resolvedProps.isObject()
                ? ((ObjectNode) resolvedProps).deepCopy()
                : objectMapper.createObjectNode();
        ObjectNode resourceProperties = (ObjectNode) stringifyScalars(resolved);

        boolean isUpdate = r.getPhysicalId() != null;
        String requestType = isUpdate ? "Update" : "Create";
        String priorPhysicalId = isUpdate ? r.getPhysicalId() : null;

        // On Update, CloudFormation includes the previous ResourceProperties so the handler can diff.
        // The prior values were stashed at the last create/update; read them before we overwrite below.
        ObjectNode oldResourceProperties = isUpdate ? readStashedProperties(r) : null;

        // CloudFormation invokes a custom resource's Update handler only when its resolved
        // properties changed (UserGuide/template-custom-resources-sns.md: "During a stack update,
        // if no changes are made to a custom resource, CloudFormation will not send any requests
        // to it."). Replaying every custom resource during an unrelated stack update can repeat
        // non-idempotent side effects. The prior resolved properties are already stashed on the
        // resource, so an exact match is a safe no-op that preserves physical ID and attributes.
        if (oldResourceProperties != null && oldResourceProperties.equals(resourceProperties)) {
            return;
        }

        JsonNode response = invokeCustomResourceHandler(serviceToken, requestType, r.getLogicalId(),
                r.getResourceType(), priorPhysicalId, resourceProperties, oldResourceProperties,
                region, accountId, stackName);

        String status = response.path("Status").asText("FAILED");
        if (!"SUCCESS".equals(status)) {
            throw new AwsException("CustomResourceFailed",
                    "Custom resource handler reported FAILED: "
                            + response.path("Reason").asText("(no reason given)"), 400);
        }

        String returnedPhysicalId = response.path("PhysicalResourceId").asText(null);
        if (returnedPhysicalId != null && !returnedPhysicalId.isBlank()) {
            r.setPhysicalId(returnedPhysicalId);
        } else if (priorPhysicalId != null) {
            r.setPhysicalId(priorPhysicalId);
        } else {
            r.setPhysicalId(r.getLogicalId() + "-" + UUID.randomUUID().toString().substring(0, 12));
        }

        // Data.* become Fn::GetAtt attributes on the custom resource.
        JsonNode data = response.path("Data");
        if (data.isObject()) {
            data.fields().forEachRemaining(e ->
                    r.getAttributes().put(e.getKey(), nodeToAttributeValue(e.getValue())));
        }

        // Stash what a later Delete invocation needs (delete() only gets the StackResource).
        r.getAttributes().put(CR_SERVICE_TOKEN_ATTR, serviceToken);
        r.getAttributes().put(CR_PROPERTIES_ATTR, resourceProperties.toString());
    }

    private void deleteCustomResource(StackResource r, String region) {
        String serviceToken = r.getAttributes().get(CR_SERVICE_TOKEN_ATTR);
        if (serviceToken == null || serviceToken.isBlank()) {
            LOG.debugv("Custom resource {0} has no stored ServiceToken; skipping Delete", r.getLogicalId());
            return;
        }
        ObjectNode stashed = readStashedProperties(r);
        ObjectNode resourceProperties = stashed != null ? stashed : objectMapper.createObjectNode();
        try {
            JsonNode response = invokeCustomResourceHandler(serviceToken, "Delete", r.getLogicalId(),
                    r.getResourceType(), r.getPhysicalId(), resourceProperties, null, region,
                    accountFromArn(serviceToken), "");
            if (!"SUCCESS".equals(response.path("Status").asText("FAILED"))) {
                LOG.warnv("Custom resource {0} Delete reported FAILED: {1}",
                        r.getLogicalId(), response.path("Reason").asText("(no reason given)"));
            }
        } catch (Exception e) {
            // Best-effort, consistent with the rest of delete().
            LOG.debugv("Custom resource {0} Delete invocation failed: {1}", r.getLogicalId(), e.getMessage());
        }
    }

    // Reads the ResourceProperties stashed at the last create/update (CR_PROPERTIES_ATTR).
    // Returns null when nothing is stashed or it cannot be parsed.
    private ObjectNode readStashedProperties(StackResource r) {
        String stored = r.getAttributes().get(CR_PROPERTIES_ATTR);
        if (stored == null) {
            return null;
        }
        try {
            JsonNode parsed = objectMapper.readTree(stored);
            return parsed.isObject() ? (ObjectNode) parsed : null;
        } catch (Exception e) {
            LOG.debugv("Could not parse stored properties for custom resource {0}: {1}",
                    r.getLogicalId(), e.getMessage());
            return null;
        }
    }

    private JsonNode invokeCustomResourceHandler(String serviceToken, String requestType, String logicalId,
                                                 String resourceType, String physicalId,
                                                 ObjectNode resourceProperties, ObjectNode oldResourceProperties,
                                                 String region, String accountId, String stackName) {
        String token = customResourceResponseStore.register();
        try {
            ObjectNode event = objectMapper.createObjectNode();
            event.put("RequestType", requestType);
            event.put("ResponseURL", reachableEndpoint.baseUrl() + "/cfn-response/" + token);
            event.put("StackId", AwsArnUtils.Arn.of("cloudformation", region, accountId, "stack/"
                    + (stackName == null ? "" : stackName) + "/" + UUID.randomUUID()).toString());
            event.put("RequestId", UUID.randomUUID().toString());
            event.put("ResourceType", resourceType);
            event.put("LogicalResourceId", logicalId);
            if (physicalId != null) {
                event.put("PhysicalResourceId", physicalId);
            }
            event.put("ServiceToken", serviceToken);
            event.set("ResourceProperties", resourceProperties);
            if (oldResourceProperties != null) {
                event.set("OldResourceProperties", oldResourceProperties);
            }

            byte[] payload = objectMapper.writeValueAsBytes(event);
            InvokeResult result = lambdaService.invoke(region, serviceToken, payload,
                    InvocationType.RequestResponse);
            if (result.getFunctionError() != null) {
                String body = result.getPayload() != null
                        ? new String(result.getPayload(), StandardCharsets.UTF_8) : "";
                throw new AwsException("CustomResourceFailed",
                        "Custom resource handler errored (" + result.getFunctionError() + "): " + body, 400);
            }

            return customResourceResponseStore.await(token, CR_RESPONSE_TIMEOUT, serviceToken, region);
        } catch (AwsException e) {
            throw e;
        } catch (TimeoutException e) {
            throw new AwsException("CustomResourceTimeout",
                    "Timed out waiting for custom resource " + logicalId
                            + " to PUT its response to ResponseURL: " + e.getMessage(), 504);
        } catch (Exception e) {
            throw new AwsException("CustomResourceFailed",
                    "Failed to invoke custom resource " + logicalId + ": " + e.getMessage(), 500);
        }
    }

    private static String nodeToAttributeValue(JsonNode node) {
        if (node == null || node.isNull()) {
            return "";
        }
        return node.isValueNode() ? node.asText() : node.toString();
    }

    /**
     * Mirrors CloudFormation's stringification of custom-resource ResourceProperties: every scalar
     * (boolean, number, text) becomes a string, while object and array structure is preserved.
     * Null is left as-is.
     */
    private JsonNode stringifyScalars(JsonNode node) {
        if (node == null || node.isNull()) {
            return node;
        }
        if (node.isObject()) {
            ObjectNode out = objectMapper.createObjectNode();
            node.fields().forEachRemaining(e -> out.set(e.getKey(), stringifyScalars(e.getValue())));
            return out;
        }
        if (node.isArray()) {
            var out = objectMapper.createArrayNode();
            node.forEach(e -> out.add(stringifyScalars(e)));
            return out;
        }
        return objectMapper.getNodeFactory().textNode(node.asText());
    }

    private static String accountFromArn(String arn) {
        String account = AwsArnUtils.accountOrDefault(arn, "000000000000");
        return account.matches("\\d{12}") ? account : "000000000000";
    }

    private static String textOrNull(JsonNode node, String field) {
        return node != null && node.hasNonNull(field) ? node.path(field).asText() : null;
    }

    // ── CloudFront ────────────────────────────────────────────────────────────

    private String resolveOptional(JsonNode props, String name, CloudFormationTemplateEngine engine) {
        if (props == null || !props.has(name) || props.get(name).isNull()) {
            return null;
        }
        return engine.resolve(props.get(name));
    }

    /**
     * Resolves CloudFormation dynamic references in a provisioned property value. Delegates to
     * {@link CfnDynamicReferences}. {@code allowSsmSecure} is {@code true} only for the RDS
     * master-credential properties resolved here directly; every other property value reaches
     * {@link CfnDynamicReferences} through {@link CloudFormationTemplateEngine#resolveNode}, which
     * disallows {@code ssm-secure} the same way the general path does.
     */
    private String resolveDynamicReferences(String value, String region, boolean allowSsmSecure) {
        return dynamicReferences.resolveDynamicReferences(value, region, allowSsmSecure);
    }

    private String resolveOrDefault(JsonNode props, String name,
                                    CloudFormationTemplateEngine engine, String defaultValue) {
        String value = resolveOptional(props, name, engine);
        return (value != null && !value.isBlank()) ? value : defaultValue;
    }

    /**
     * Generate an AWS-like physical name: {stackName}-{logicalId}-{randomSuffix}.
     * Mirrors the naming pattern AWS CloudFormation uses when no explicit name is provided.
     */
    private String generatePhysicalName(String stackName, String logicalId, int maxLength, boolean lowercase) {
        String suffix = UUID.randomUUID().toString().replace("-", "")
                .substring(0, GENERATED_NAME_SUFFIX_LENGTH);
        String base = stackName + "-" + logicalId;
        if (lowercase) {
            base = base.toLowerCase();
        }
        String name = base + "-" + suffix;
        if (maxLength > 0 && name.length() > maxLength) {
            // Truncate the descriptive prefix but always keep the trailing uniqueness token. When a
            // stack's name approaches the length limit, distinct logical resources still get distinct
            // physical names — CloudFormation preserves the random suffix when it shortens a generated
            // name. Truncating the whole string (suffix included) would collapse every such resource
            // onto one name and break Ref/GetAtt-based lookup (e.g. a custom resource's ServiceToken
            // resolving to the wrong Lambda).
            int keep = Math.max(0, maxLength - suffix.length() - 1);
            String prefix = base.length() > keep ? base.substring(0, keep) : base;
            while (prefix.endsWith("-")) {
                prefix = prefix.substring(0, prefix.length() - 1);
            }
            name = prefix.isEmpty() ? suffix : prefix + "-" + suffix;
        }
        return name;
    }
}
