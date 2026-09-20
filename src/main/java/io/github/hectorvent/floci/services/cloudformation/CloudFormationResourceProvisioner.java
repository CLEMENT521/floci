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
import io.github.hectorvent.floci.services.lambda.LambdaLayerService;
import io.github.hectorvent.floci.services.lambda.model.LambdaFileSystemConfig;
import io.github.hectorvent.floci.services.lambda.model.LambdaFunction;
import io.github.hectorvent.floci.services.lambda.model.LambdaLayerVersion;
import io.github.hectorvent.floci.services.pipes.model.DesiredState;
import io.github.hectorvent.floci.services.s3.S3Service;
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

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.TimeoutException;
import java.util.function.Consumer;
import java.util.regex.Pattern;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

/**
 * Provisions individual CloudFormation resource types using Floci's existing service implementations.
 */
@ApplicationScoped
public class CloudFormationResourceProvisioner {

    private static final Logger LOG = Logger.getLogger(CloudFormationResourceProvisioner.class);
    private static final String LAMBDA_CODE_IDENTITY_ATTR = "FlociLambdaCodeIdentity";
    private static final String LAMBDA_NAME_MODE_ATTR = "FlociLambdaFunctionNameMode";
    private static final String LAMBDA_PACKAGE_TYPE_ATTR = "FlociLambdaPackageType";
    static final String UPDATE_ROLLBACK_RESTORED_ATTR = CfnRollback.UPDATE_ROLLBACK_RESTORED_ATTR;
    static final String UPDATE_ROLLBACK_FAILURE_ATTR = CfnRollback.UPDATE_ROLLBACK_FAILURE_ATTR;
    private static final String NAME_MODE_EXPLICIT = "explicit";
    private static final String NAME_MODE_GENERATED = "generated";
    private static final int GENERATED_NAME_SUFFIX_LENGTH = 12;
    private static final int LAMBDA_DEFAULT_TIMEOUT_SECONDS = 3;
    private static final int LAMBDA_DEFAULT_MEMORY_MB = 128;
    private static final int LAMBDA_DEFAULT_EPHEMERAL_STORAGE_MB = 512;
    private static final String LAMBDA_DEFAULT_TRACING_MODE = "PassThrough";

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
            "AWS::CloudFormation::CustomResource",
            "AWS::Lambda::Function",
            "AWS::Lambda::LayerVersion");

    /** Reserved attribute keys used to carry custom-resource state to the later Delete invocation. */
    private static final String CR_SERVICE_TOKEN_ATTR = "__FlociServiceToken";
    private static final String CR_PROPERTIES_ATTR = "__FlociResourceProperties";
    /**
     * How long to wait for the Lambda's ResponseURL callback after the synchronous invoke returns.
     * The invoke already blocks until the handler finishes, so this only covers a PUT that lands
     * fractionally after the container returns control.
     */
    private static final Duration CR_RESPONSE_TIMEOUT = Duration.ofSeconds(10);

    private final S3Service s3Service;
    private final LambdaService lambdaService;
    private final IamService iamService;
    private final LambdaLayerService lambdaLayerService;
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
    public CloudFormationResourceProvisioner(S3Service s3Service,
                                             LambdaService lambdaService,
                                             IamService iamService,
                                             LambdaLayerService lambdaLayerService,
                                             ObjectMapper objectMapper,
                                             CustomResourceResponseStore customResourceResponseStore,
                                             ContainerReachableEndpoint reachableEndpoint,
                                             CloudFormationResourceRegistry resourceRegistry,
                                             CfnDynamicReferences dynamicReferences,
                                             EmulatorConfig config) {
        this.config = config;
        this.s3Service = s3Service;
        this.lambdaService = lambdaService;
        this.iamService = iamService;
        this.lambdaLayerService = lambdaLayerService;
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
                case "AWS::Lambda::Function" -> provisionLambda(resource, properties, engine, region, accountId, stackName);
                case "AWS::Lambda::LayerVersion" ->
                        provisionLambdaLayerVersion(resource, properties, engine, region, stackName);
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
            case "AWS::Lambda::Function" -> deleteLambdaFunctionSafe(physicalId, region);
            // No bus context on the type/physicalId path (e.g. CREATE-rollback); targets the default bus.
            case "AWS::Lambda::LayerVersion" -> deleteLambdaLayerVersion(physicalId, region);
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

    /**
     * Whether {@code physicalId} matches the exact shape {@link #generatePhysicalName} produces for
     * this stack/logical id/maxLength: its base-and-truncation logic (minus the random suffix itself)
     * followed by exactly 12 lowercase hex characters. Used to infer a legacy resource's name mode
     * (explicit vs. generated) when it predates whatever attribute would otherwise record that.
     *
     * <p>Assumes the {@code generatePhysicalName} call this mirrors used {@code lowercase=false} (true
     * of both current callers, LogGroup and Lambda) and a {@code maxLength} large enough that the
     * truncated prefix is never empty, i.e. {@code maxLength > 13} (also true of both: 512 and 64). A
     * future caller with {@code lowercase=true} or a smaller limit would need this generalized further.
     */
    private boolean isGeneratedName(String physicalId, String stackName, String logicalId, int maxLength) {
        if (physicalId == null || physicalId.length() < 13) {
            return false;
        }
        String suffix = physicalId.substring(physicalId.length() - 12);
        for (int i = 0; i < suffix.length(); i++) {
            char c = suffix.charAt(i);
            boolean hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
            if (!hex) {
                return false;
            }
        }
        if (physicalId.charAt(physicalId.length() - 13) != '-') {
            return false;
        }
        String actualPrefix = physicalId.substring(0, physicalId.length() - 13);
        return actualPrefix.equals(expectedGeneratedNamePrefix(stackName, logicalId, maxLength));
    }

    /** Mirrors {@link #generatePhysicalName}'s base-and-truncation logic, without the random suffix. */
    private String expectedGeneratedNamePrefix(String stackName, String logicalId, int maxLength) {
        String base = stackName + "-" + logicalId;
        if (maxLength <= 0 || base.length() + 1 + 12 <= maxLength) {
            return base;
        }
        int keep = Math.max(0, maxLength - 12 - 1);
        String prefix = base.length() > keep ? base.substring(0, keep) : base;
        while (prefix.endsWith("-")) {
            prefix = prefix.substring(0, prefix.length() - 1);
        }
        return prefix;
    }

    // ── Auto Scaling ────────────────────────────────────────────────────────────

    // ── EKS ─────────────────────────────────────────────────────────────────────

    // ── Lambda ────────────────────────────────────────────────────────────────

    private void provisionLambda(StackResource r, JsonNode props, CloudFormationTemplateEngine engine,
                                 String region, String accountId, String stackName) {
        LambdaDesiredState desired = buildLambdaDesiredState(r, props, engine, region, accountId, stackName);
        LambdaFunction existing = getExistingLambda(region, r.getPhysicalId());
        boolean replacement = lambdaRequiresReplacement(r, desired, existing);

        LambdaFunction func;
        if (existing == null || replacement) {
            if (replacement && desired.functionName().equals(r.getPhysicalId())) {
                throw new AwsException("ValidationError",
                        "Cannot replace Lambda function " + r.getPhysicalId()
                                + " without a new FunctionName", 400);
            }
            func = createLambdaFunction(region, desired, !replacement);
            if (replacement && r.getPhysicalId() != null) {
                deleteReplacedLambda(region, r.getPhysicalId());
            }
        } else {
            func = updateLambdaFunction(region, existing, desired, r);
        }

        applyLambdaReservedConcurrency(region, func, desired);

        r.setPhysicalId(desired.functionName());
        r.getAttributes().put("Arn", func.getFunctionArn());
        r.getAttributes().put(LAMBDA_CODE_IDENTITY_ATTR, desired.code().identity());
        r.getAttributes().put(LAMBDA_NAME_MODE_ATTR,
                desired.explicitFunctionName() ? NAME_MODE_EXPLICIT : NAME_MODE_GENERATED);
        r.getAttributes().put(LAMBDA_PACKAGE_TYPE_ATTR, desired.packageType());
    }

    private LambdaDesiredState buildLambdaDesiredState(StackResource r, JsonNode props,
                                                       CloudFormationTemplateEngine engine,
                                                       String region, String accountId,
                                                       String stackName) {
        String explicitName = resolveOptional(props, "FunctionName", engine);
        boolean hasExplicitName = explicitName != null && !explicitName.isBlank();
        String packageType = resolveOrDefault(props, "PackageType", engine, "Zip");
        String previousNameMode = r.getAttributes().get(LAMBDA_NAME_MODE_ATTR);
        if (previousNameMode == null && r.getPhysicalId() != null) {
            // Functions persisted before LAMBDA_NAME_MODE_ATTR existed have no recorded mode, but an
            // auto-generated name always has the deterministic shape generatePhysicalName produces,
            // so anything else must have been explicit (see #1965/#2152 for the LogGroup precedent
            // this mirrors, and #2163 for this gap).
            previousNameMode = isGeneratedName(r.getPhysicalId(), stackName, r.getLogicalId(), 64)
                    ? NAME_MODE_GENERATED
                    : NAME_MODE_EXPLICIT;
            if (NAME_MODE_GENERATED.equals(previousNameMode) && !hasExplicitName) {
                // This inference is what decides explicitRemoved below, and it's the one direction
                // that can be wrong with no way for Floci to tell: a legacy FunctionName that was
                // actually pinned explicitly, but happens to exactly match generatePhysicalName's
                // shape (e.g. a user who deliberately reused a name Floci had previously generated),
                // is indistinguishable from a name that really was auto-generated all along - the raw
                // property value from that far back was never persisted to check against. Logged so
                // an operator relying on this FunctionName removal to trigger a replacement has a
                // chance to notice it silently didn't, rather than this being an invisible guess.
                LOG.warnv("Lambda {0} in stack {1}: inferring legacy FunctionName ''{2}'' as "
                                + "auto-generated because it matches the generated-name shape; if it "
                                + "was actually set explicitly, removing FunctionName here will not "
                                + "trigger the replacement AWS would perform",
                        r.getLogicalId(), stackName, r.getPhysicalId());
            }
        }
        String oldPackageType = r.getAttributes().get(LAMBDA_PACKAGE_TYPE_ATTR);
        boolean packageTypeReplacement = r.getPhysicalId() != null
                && oldPackageType != null
                && !Objects.equals(oldPackageType, packageType);
        boolean explicitRemoved = r.getPhysicalId() != null
                && !hasExplicitName
                && NAME_MODE_EXPLICIT.equals(previousNameMode);

        String functionName;
        if (hasExplicitName) {
            functionName = explicitName;
        } else if (r.getPhysicalId() != null && !explicitRemoved && !packageTypeReplacement) {
            functionName = r.getPhysicalId();
        } else {
            functionName = generatePhysicalName(stackName, r.getLogicalId(), 64, false);
        }

        Map<String, Object> createRequest = new HashMap<>();
        Map<String, Object> configRequest = new HashMap<>();
        createRequest.put("FunctionName", functionName);
        createRequest.put("PackageType", packageType);

        String role = resolveOrDefault(props, "Role", engine,
                AwsArnUtils.Arn.of("iam", "", accountId, "role/default").toString());
        createRequest.put("Role", role);
        configRequest.put("Role", role);

        String runtime = null;
        String handler = null;
        if ("Zip".equals(packageType)) {
            runtime = resolveOrDefault(props, "Runtime", engine, "nodejs18.x");
            handler = resolveOrDefault(props, "Handler", engine, "index.handler");
            createRequest.put("Runtime", runtime);
            createRequest.put("Handler", handler);
            configRequest.put("Runtime", runtime);
            configRequest.put("Handler", handler);
        } else {
            runtime = resolveOptional(props, "Runtime", engine);
            handler = resolveOptional(props, "Handler", engine);
            if (runtime != null) {
                createRequest.put("Runtime", runtime);
                configRequest.put("Runtime", runtime);
            }
            if (handler != null) {
                createRequest.put("Handler", handler);
                configRequest.put("Handler", handler);
            }
        }

        LambdaCodeSpec code = resolveLambdaCode(props, engine, handler, runtime);
        createRequest.put("Code", code.request());

        configRequest.put("Timeout", intOrDefault(resolveOptional(props, "Timeout", engine),
                LAMBDA_DEFAULT_TIMEOUT_SECONDS));
        configRequest.put("MemorySize", intOrDefault(resolveOptional(props, "MemorySize", engine),
                LAMBDA_DEFAULT_MEMORY_MB));
        configRequest.put("Description", resolveOptional(props, "Description", engine));
        configRequest.put("KMSKeyArn", resolveOptional(props, "KMSKeyArn", engine));
        configRequest.put("Environment", Map.of("Variables", resolveLambdaEnvironment(props, engine)));
        putStringListIfPresent(configRequest, props, "Architectures", "Architectures", engine);
        configRequest.put("Layers", resolveStringListOrEmpty(props, "Layers", engine));
        configRequest.put("EphemeralStorage", resolveMapOrDefault(props, "EphemeralStorage", engine,
                Map.of("Size", LAMBDA_DEFAULT_EPHEMERAL_STORAGE_MB)));
        configRequest.put("TracingConfig", resolveMapOrDefault(props, "TracingConfig", engine,
                Map.of("Mode", LAMBDA_DEFAULT_TRACING_MODE)));
        configRequest.put("DeadLetterConfig", resolveMapOrDefault(props, "DeadLetterConfig", engine,
                mapWithNullValue("TargetArn")));
        configRequest.put("VpcConfig", resolveMapOrDefault(props, "VpcConfig", engine, Map.of()));
        configRequest.put("FileSystemConfigs",
                resolveObjectListOrEmpty(props, "FileSystemConfigs", engine));
        putResolvedMapIfPresent(configRequest, props, "ImageConfig", "ImageConfig", engine);

        createRequest.putAll(configRequest);
        Integer reservedConcurrentExecutions = null;
        String reserved = resolveOptional(props, "ReservedConcurrentExecutions", engine);
        if (reserved != null) {
            try {
                reservedConcurrentExecutions = Integer.parseInt(reserved);
            } catch (NumberFormatException ignored) {
                throw new AwsException("InvalidParameterValueException",
                        "ReservedConcurrentExecutions must be an integer", 400);
            }
        }

        return new LambdaDesiredState(functionName, hasExplicitName, packageType,
                createRequest, code, configRequest, props != null && props.has("ReservedConcurrentExecutions"),
                reservedConcurrentExecutions);
    }

    /**
     * Whether an unreadable explicit {@code Code} reference may fall back to the stub handler.
     * The provisioners hand-built in unit tests carry no config; absent configuration means the
     * documented default, which is the strict behaviour.
     */
    private boolean stubLambdaCodeAllowed() {
        return config != null && config.services().cloudformation().allowStubLambdaCode();
    }

    private LambdaCodeSpec resolveLambdaCode(JsonNode props, CloudFormationTemplateEngine engine,
                                             String handler, String runtime) {
        if (props != null && props.has("Code")) {
            JsonNode codeNode = engine.resolveNode(props.get("Code"));

            String s3Bucket = codeNode.path("S3Bucket").asText(null);
            String s3Key = codeNode.path("S3Key").asText(null);
            if (s3Bucket != null && s3Key != null) {
                // A template that names its code explicitly must fail if that code cannot be
                // read, the way real CloudFormation does. Substituting the stub handler here
                // let a stack reach CREATE_COMPLETE running code the template never referenced
                // — or, when the handler was not "index.handler", fail with a handler error
                // that pointed away from the real problem (issue #2648). The stub below is for
                // a template that supplies no Code at all, which is a different case.
                //
                // allow-stub-lambda-code opts back in to the old fallback, for a stack that
                // deliberately leaves its Lambda packages unbuilt and only cares about the
                // other resources. Off by default: silently serving a placeholder is the more
                // dangerous of the two behaviours.
                //
                // headObject, not getObject: this only needs to know whether the code is
                // readable. getObject additionally reads the whole body, which is then thrown
                // away, and LambdaService reads it again for real during CreateFunction. That
                // is a second full copy of the package per Lambda per stack operation, for a
                // question a metadata lookup answers (issue #2675). Both resolve the object
                // through the same getObjectMetadata call, so a missing key or bucket still
                // fails here exactly as before.
                try {
                    s3Service.headObject(s3Bucket, s3Key);
                    return new LambdaCodeSpec(Map.of("S3Bucket", s3Bucket, "S3Key", s3Key),
                            "s3:" + s3Bucket + "\n" + s3Key);
                } catch (Exception e) {
                    if (!stubLambdaCodeAllowed()) {
                        throw new AwsException("ValidationError",
                                "Error occurred while GetObject. S3 Error Message: " + e.getMessage()
                                        + " (bucket: " + s3Bucket + ", key: " + s3Key + ")", 400);
                    }
                    LOG.warnv("S3 code not found for Lambda ({0}/{1}), using default handler because "
                                    + "floci.services.cloudformation.allow-stub-lambda-code is enabled: {2}",
                            s3Bucket, s3Key, e.getMessage());
                }
            }

            String zipFile = codeNode.path("ZipFile").asText(null);
            if (zipFile != null) {
                String effectiveHandler = handler != null ? handler : "index.handler";
                String effectiveRuntime = runtime != null ? runtime : "nodejs18.x";
                return new LambdaCodeSpec(Map.of("ZipFile", sourceToZipBase64(zipFile, effectiveHandler, effectiveRuntime)),
                        "inline:" + effectiveRuntime + "\n" + effectiveHandler + "\n" + zipFile);
            }

            String imageUri = codeNode.path("ImageUri").asText(null);
            if (imageUri != null) {
                return new LambdaCodeSpec(Map.of("ImageUri", imageUri), "image:" + imageUri);
            }
        }
        return new LambdaCodeSpec(Map.of("ZipFile", defaultHandlerZipBase64()), "default-handler");
    }

    private LambdaFunction getExistingLambda(String region, String functionName) {
        if (functionName == null || functionName.isBlank()) {
            return null;
        }
        try {
            return lambdaService.getFunction(region, functionName);
        } catch (AwsException e) {
            if ("ResourceNotFoundException".equals(e.getErrorCode()) || e.getHttpStatus() == 404) {
                return null;
            }
            throw e;
        }
    }

    private boolean lambdaRequiresReplacement(StackResource r, LambdaDesiredState desired,
                                              LambdaFunction existing) {
        if (existing == null || r.getPhysicalId() == null) {
            return false;
        }
        if (!Objects.equals(r.getPhysicalId(), desired.functionName())) {
            return true;
        }
        String existingPackageType = existing.getPackageType() != null ? existing.getPackageType() : "Zip";
        return !Objects.equals(existingPackageType, desired.packageType());
    }

    private LambdaFunction createLambdaFunction(String region, LambdaDesiredState desired, boolean allowAdopt) {
        try {
            return lambdaService.createFunction(region, desired.createRequest());
        } catch (AwsException e) {
            if (allowAdopt && ("ResourceConflictException".equals(e.getErrorCode())
                    || (e.getMessage() != null && e.getMessage().contains("Function already exist")))) {
                return lambdaService.getFunction(region, desired.functionName());
            }
            throw e;
        }
    }

    private LambdaFunction updateLambdaFunction(String region,
                                                LambdaFunction existing,
                                                LambdaDesiredState desired,
                                                StackResource r) {
        LambdaFunction current = existing;
        if (lambdaConfigurationChanged(current, desired.configRequest())) {
            current = lambdaService.updateFunctionConfiguration(region, current.getFunctionName(),
                    desired.configRequest());
        }
        if (lambdaCodeChanged(current, desired.code(), r.getAttributes().get(LAMBDA_CODE_IDENTITY_ATTR))) {
            current = lambdaService.updateFunctionCode(region, current.getFunctionName(), desired.code().request());
        }
        return current;
    }

    private void deleteReplacedLambda(String region, String functionName) {
        try {
            lambdaService.deleteFunction(region, functionName);
        } catch (AwsException e) {
            if (!"ResourceNotFoundException".equals(e.getErrorCode()) && e.getHttpStatus() != 404) {
                throw e;
            }
        }
    }

    private void applyLambdaReservedConcurrency(
            String region,
            LambdaFunction fn,
            LambdaDesiredState desired) {
        if (desired.reservedConcurrentExecutionsPresent()) {
            if (!Objects.equals(fn.getReservedConcurrentExecutions(), desired.reservedConcurrentExecutions())) {
                lambdaService.putFunctionConcurrency(region, fn.getFunctionName(),
                        desired.reservedConcurrentExecutions());
            }
        } else if (fn.getReservedConcurrentExecutions() != null) {
            lambdaService.deleteFunctionConcurrency(region, fn.getFunctionName());
        }
    }

    private boolean lambdaCodeChanged(LambdaFunction fn,
                                      LambdaCodeSpec code, String previousIdentity) {
        if (previousIdentity != null) {
            return !previousIdentity.equals(code.identity());
        }
        Map<String, Object> request = code.request();
        if (request.containsKey("ImageUri")) {
            return !Objects.equals(fn.getImageUri(), request.get("ImageUri"));
        }
        if (request.containsKey("S3Bucket") && request.containsKey("S3Key")) {
            return !Objects.equals(fn.getS3Bucket(), request.get("S3Bucket"))
                    || !Objects.equals(fn.getS3Key(), request.get("S3Key"));
        }
        if (request.containsKey("ZipFile")) {
            String desiredSha256 = sha256Base64((String) request.get("ZipFile"));
            return !Objects.equals(fn.getCodeSha256(), desiredSha256);
        }
        return false;
    }

    private boolean lambdaConfigurationChanged(
            LambdaFunction fn,
            Map<String, Object> request) {
        for (var entry : request.entrySet()) {
            String key = entry.getKey();
            Object desired = entry.getValue();
            switch (key) {
                case "Description" -> {
                    if (!Objects.equals(fn.getDescription(), desired)) return true;
                }
                case "Handler" -> {
                    if (!Objects.equals(fn.getHandler(), desired)) return true;
                }
                case "MemorySize" -> {
                    if (fn.getMemorySize() != toIntValue(desired, fn.getMemorySize())) return true;
                }
                case "Role" -> {
                    if (!Objects.equals(fn.getRole(), desired)) return true;
                }
                case "Runtime" -> {
                    if (!Objects.equals(fn.getRuntime(), desired)) return true;
                }
                case "Timeout" -> {
                    if (fn.getTimeout() != toIntValue(desired, fn.getTimeout())) return true;
                }
                case "Environment" -> {
                    if (!Objects.equals(fn.getEnvironment(), environmentVariables(desired))) return true;
                }
                case "Architectures" -> {
                    if (!Objects.equals(fn.getArchitectures(), desired)) return true;
                }
                case "EphemeralStorage" -> {
                    if (fn.getEphemeralStorageSize() != mapInt(desired, "Size", fn.getEphemeralStorageSize())) {
                        return true;
                    }
                }
                case "TracingConfig" -> {
                    if (!Objects.equals(fn.getTracingMode(), mapString(desired, "Mode"))) return true;
                }
                case "DeadLetterConfig" -> {
                    if (!Objects.equals(fn.getDeadLetterTargetArn(), mapString(desired, "TargetArn"))) return true;
                }
                case "Layers" -> {
                    if (!Objects.equals(fn.getLayers(), desired)) return true;
                }
                case "KMSKeyArn" -> {
                    if (!Objects.equals(fn.getKmsKeyArn(), desired)) return true;
                }
                case "VpcConfig" -> {
                    if (!Objects.equals(normalizeForCompare(fn.getVpcConfig()), normalizeForCompare(desired))) {
                        return true;
                    }
                }
                case "FileSystemConfigs" -> {
                    if (!Objects.equals(normalizeForCompare(fileSystemConfigs(fn)),
                            normalizeForCompare(desired))) {
                        return true;
                    }
                }
                case "ImageConfig" -> {
                    if (imageConfigurationChanged(fn, desired)) return true;
                }
                default -> {
                    // Properties outside UpdateFunctionConfiguration are ignored here.
                }
            }
        }
        return false;
    }

    private boolean imageConfigurationChanged(
            LambdaFunction fn,
            Object desired) {
        if (!(desired instanceof Map<?, ?> map)) {
            return false;
        }
        if (map.containsKey("Command")
                && !Objects.equals(fn.getImageConfigCommand(), stringList(map.get("Command")))) {
            return true;
        }
        if (map.containsKey("EntryPoint")
                && !Objects.equals(fn.getImageConfigEntryPoint(), stringList(map.get("EntryPoint")))) {
            return true;
        }
        return map.containsKey("WorkingDirectory")
                && !Objects.equals(fn.getImageConfigWorkingDirectory(), mapString(map, "WorkingDirectory"));
    }

    private static List<Map<String, String>> fileSystemConfigs(LambdaFunction fn) {
        if (fn.getFileSystemConfigs() == null) {
            return List.of();
        }
        return fn.getFileSystemConfigs().stream()
                .map(CloudFormationResourceProvisioner::fileSystemConfig)
                .toList();
    }

    private static Map<String, String> fileSystemConfig(LambdaFileSystemConfig config) {
        Map<String, String> value = new LinkedHashMap<>();
        value.put("Arn", config.getArn());
        value.put("LocalMountPath", config.getLocalMountPath());
        return value;
    }

    private static String sha256Base64(String zipFileBase64) {
        byte[] zipBytes = Base64.getDecoder().decode(zipFileBase64);
        try {
            byte[] digest = java.security.MessageDigest.getInstance("SHA-256").digest(zipBytes);
            return Base64.getEncoder().encodeToString(digest);
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    private static Map<String, String> environmentVariables(Object value) {
        if (!(value instanceof Map<?, ?> envBlock)) {
            return Map.of();
        }
        Object variables = envBlock.get("Variables");
        if (!(variables instanceof Map<?, ?> vars)) {
            return Map.of();
        }
        Map<String, String> out = new HashMap<>();
        vars.forEach((k, v) -> out.put(String.valueOf(k), v != null ? String.valueOf(v) : null));
        return out;
    }

    private static String mapString(Object value, String key) {
        if (!(value instanceof Map<?, ?> map)) {
            return null;
        }
        Object found = map.get(key);
        return found != null ? found.toString() : null;
    }

    private static int mapInt(Object value, String key, int defaultValue) {
        if (!(value instanceof Map<?, ?> map)) {
            return defaultValue;
        }
        return toIntValue(map.get(key), defaultValue);
    }

    private static int toIntValue(Object value, int defaultValue) {
        if (value instanceof Number number) {
            return number.intValue();
        }
        if (value instanceof String s && !s.isBlank()) {
            return Integer.parseInt(s);
        }
        return defaultValue;
    }

    private static List<String> stringList(Object value) {
        if (!(value instanceof List<?> list)) {
            return null;
        }
        return list.stream().map(Object::toString).toList();
    }

    private static Object normalizeForCompare(Object value) {
        if (value instanceof Map<?, ?> map) {
            Map<String, Object> normalized = new TreeMap<>();
            map.forEach((k, v) -> normalized.put(String.valueOf(k), normalizeForCompare(v)));
            return normalized;
        }
        if (value instanceof List<?> list) {
            return list.stream().map(CloudFormationResourceProvisioner::normalizeForCompare).toList();
        }
        return value;
    }

    private static int intOrDefault(String value, int defaultValue) {
        return value != null ? Integer.parseInt(value) : defaultValue;
    }

    private Map<String, String> resolveLambdaEnvironment(JsonNode props, CloudFormationTemplateEngine engine) {
        if (props == null || !props.has("Environment") || props.get("Environment").isNull()) {
            return Map.of();
        }
        JsonNode envNode = engine.resolveNode(props.get("Environment"));
        if (envNode == null || !envNode.has("Variables") || !envNode.get("Variables").isObject()) {
            return Map.of();
        }
        Map<String, String> vars = new HashMap<>();
        envNode.get("Variables").fields()
                .forEachRemaining(e -> vars.put(e.getKey(), e.getValue().asText()));
        return vars;
    }

    private List<String> resolveStringListOrEmpty(JsonNode props, String source,
                                                  CloudFormationTemplateEngine engine) {
        if (props == null || !props.has(source) || props.get(source).isNull()) {
            return List.of();
        }
        JsonNode resolved = engine.resolveNode(props.get(source));
        if (resolved == null || !resolved.isArray()) {
            return List.of();
        }
        List<String> values = new ArrayList<>();
        resolved.forEach(v -> values.add(v.asText()));
        return values;
    }

    private List<Object> resolveObjectListOrEmpty(JsonNode props, String source,
                                                  CloudFormationTemplateEngine engine) {
        if (props == null || !props.has(source) || props.get(source).isNull()) {
            return List.of();
        }
        JsonNode resolved = engine.resolveNode(props.get(source));
        if (resolved == null) {
            return List.of();
        }
        if (!resolved.isArray()) {
            throw new AwsException("ValidationError", source + " must be a list", 400);
        }
        List<Object> values = new ArrayList<>();
        resolved.forEach(value -> values.add(jsonNodeToValue(value)));
        return values;
    }

    private Map<String, Object> resolveMapOrDefault(JsonNode props, String source,
                                                    CloudFormationTemplateEngine engine,
                                                    Map<String, Object> defaultValue) {
        if (props == null || !props.has(source) || props.get(source).isNull()) {
            return defaultValue;
        }
        JsonNode resolved = engine.resolveNode(props.get(source));
        return resolved != null && resolved.isObject() ? jsonObjectToMap(resolved) : defaultValue;
    }

    private static Map<String, Object> mapWithNullValue(String key) {
        Map<String, Object> map = new HashMap<>();
        map.put(key, null);
        return map;
    }

    private void putStringListIfPresent(Map<String, Object> request, JsonNode props, String source,
                                        String target, CloudFormationTemplateEngine engine) {
        if (props == null || !props.has(source) || props.get(source).isNull()) {
            return;
        }
        JsonNode resolved = engine.resolveNode(props.get(source));
        if (resolved != null && resolved.isArray()) {
            List<String> values = new ArrayList<>();
            resolved.forEach(v -> values.add(v.asText()));
            request.put(target, values);
        }
    }

    private void putResolvedMapIfPresent(Map<String, Object> request, JsonNode props, String source,
                                         String target, CloudFormationTemplateEngine engine) {
        if (props == null || !props.has(source) || props.get(source).isNull()) {
            return;
        }
        JsonNode resolved = engine.resolveNode(props.get(source));
        if (resolved != null && resolved.isObject()) {
            request.put(target, jsonObjectToMap(resolved));
        }
    }

    private Map<String, Object> jsonObjectToMap(JsonNode node) {
        Map<String, Object> out = new LinkedHashMap<>();
        node.fields().forEachRemaining(e -> out.put(e.getKey(), jsonNodeToValue(e.getValue())));
        return out;
    }

    private Object jsonNodeToValue(JsonNode node) {
        if (node == null || node.isNull()) {
            return null;
        }
        if (node.isObject()) {
            return jsonObjectToMap(node);
        }
        if (node.isArray()) {
            List<Object> values = new ArrayList<>();
            node.forEach(v -> values.add(jsonNodeToValue(v)));
            return values;
        }
        if (node.isBoolean()) {
            return node.asBoolean();
        }
        if (node.isIntegralNumber()) {
            return node.asLong();
        }
        if (node.isFloatingPointNumber()) {
            return node.asDouble();
        }
        return node.asText();
    }

    private record LambdaDesiredState(String functionName,
                                      boolean explicitFunctionName,
                                      String packageType,
                                      Map<String, Object> createRequest,
                                      LambdaCodeSpec code,
                                      Map<String, Object> configRequest,
                                      boolean reservedConcurrentExecutionsPresent,
                                      Integer reservedConcurrentExecutions) {}

    private record LambdaCodeSpec(Map<String, Object> request, String identity) {}

    private static String sourceToZipBase64(String source, String handler, String runtime) {
        return InlineZipPackager.sourceToZipBase64(source, handler, runtime);
    }

    private static String defaultHandlerZipBase64() {
        try {
            var baos = new ByteArrayOutputStream();
            try (var zos = new ZipOutputStream(baos)) {
                zos.putNextEntry(new ZipEntry("index.js"));
                zos.write("exports.handler=async(e)=>({statusCode:200})".getBytes(StandardCharsets.UTF_8));
                zos.closeEntry();
            }
            return Base64.getEncoder().encodeToString(baos.toByteArray());
        } catch (Exception e) {
            throw new RuntimeException("Failed to create default handler zip", e);
        }
    }

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

    // ── Lambda LayerVersion ──────────────────────────────────────────────────
    //
    // Without this, layer versions (e.g. CDK's AwsCliLayer) fall through to the stub, so the
    // function's Layers ARN can't be resolved and the layer content is never copied into /opt.

    private void provisionLambdaLayerVersion(StackResource r, JsonNode props,
                                             CloudFormationTemplateEngine engine, String region,
                                             String stackName) {
        if (props == null || !props.has("Content")) {
            throw new AwsException("ValidationError",
                    "Lambda LayerVersion " + r.getLogicalId() + " is missing Content", 400);
        }
        String layerName = resolveOptional(props, "LayerName", engine);
        if (layerName == null || layerName.isBlank()) {
            layerName = generatePhysicalName(stackName, r.getLogicalId(), 140, false);
        }

        Map<String, Object> request = new HashMap<>();
        request.put("Content", jsonObjectToMap(engine.resolveNode(props.get("Content"))));
        String description = resolveOptional(props, "Description", engine);
        if (description != null) {
            request.put("Description", description);
        }
        String licenseInfo = resolveOptional(props, "LicenseInfo", engine);
        if (licenseInfo != null) {
            request.put("LicenseInfo", licenseInfo);
        }
        List<String> runtimes = resolveStringListOrEmpty(props, "CompatibleRuntimes", engine);
        if (!runtimes.isEmpty()) {
            request.put("CompatibleRuntimes", runtimes);
        }
        List<String> architectures = resolveStringListOrEmpty(props, "CompatibleArchitectures", engine);
        if (!architectures.isEmpty()) {
            request.put("CompatibleArchitectures", architectures);
        }

        LambdaLayerVersion layer = lambdaLayerService.publishLayerVersion(region, layerName, request);
        // CloudFormation Ref on a LayerVersion returns the version ARN; the Lambda's Layers list
        // references it, and ContainerLauncher resolves it back to disk via resolveLayerByArn.
        r.setPhysicalId(layer.getLayerVersionArn());
        r.getAttributes().put("Arn", layer.getLayerVersionArn());
        r.getAttributes().put("LayerVersionArn", layer.getLayerVersionArn());
    }

    private void deleteLambdaLayerVersion(String physicalId, String region) {
        LambdaLayerVersion layer = lambdaLayerService.resolveLayerByArn(physicalId);
        if (layer != null) {
            lambdaLayerService.deleteLayerVersion(region, layer.getLayerName(), layer.getVersion());
        }
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

    private void deleteLambdaFunctionSafe(String functionName, String region) {
        try {
            lambdaService.deleteFunction(region, functionName);
        } catch (AwsException e) {
            if (!"ResourceNotFoundException".equals(e.getErrorCode())) {
                throw e;
            }
            LOG.debugv("Lambda function already gone, treating as deleted: {0}", functionName);
        }
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
