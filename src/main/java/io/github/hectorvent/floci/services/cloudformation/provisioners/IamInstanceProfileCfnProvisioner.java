package io.github.hectorvent.floci.services.cloudformation.provisioners;

import com.fasterxml.jackson.databind.JsonNode;
import io.github.hectorvent.floci.core.common.AwsArnUtils;
import io.github.hectorvent.floci.services.cloudformation.model.StackResource;
import io.github.hectorvent.floci.services.iam.IamService;
import io.github.hectorvent.floci.services.iam.model.InstanceProfile;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.jboss.logging.Logger;

import java.util.Set;

/**
 * CloudFormation provisioning for {@code AWS::IAM::InstanceProfile}. {@code Ref} returns the
 * instance profile name (the primary identifier) and {@code Fn::GetAtt Arn} its arn.
 */
@ApplicationScoped
public class IamInstanceProfileCfnProvisioner implements CfnResourceProvisioner {

    private static final Logger LOG = Logger.getLogger(IamInstanceProfileCfnProvisioner.class);

    private static final String TYPE = "AWS::IAM::InstanceProfile";

    private final IamService iamService;

    @Inject
    public IamInstanceProfileCfnProvisioner(IamService iamService) {
        this.iamService = iamService;
    }

    @Override
    public Set<String> resourceTypes() {
        return Set.of(TYPE);
    }

    @Override
    public void provision(StackResource r, JsonNode props, ProvisionContext ctx) {
        String name = ctx.resolveOptional(props, "InstanceProfileName");
        if (name == null || name.isBlank()) {
            name = ctx.generatePhysicalName(r.getLogicalId(), 128, false);
        }
        r.setPhysicalId(name);
        try {
            InstanceProfile profile = iamService.createInstanceProfile(name, "/");
            r.getAttributes().put("Arn", profile.getArn());
        } catch (RuntimeException e) {
            // A create collision (the profile already exists) is tolerated as the legacy switch did:
            // synthesize the arn so Fn::GetAtt Arn still resolves rather than failing the stack.
            LOG.debugv("createInstanceProfile fell back to a synthesized arn for {0}: {1}",
                    name, e.getMessage());
            r.getAttributes().put("Arn",
                    AwsArnUtils.Arn.of("iam", "", ctx.accountId(), "instance-profile/" + name).toString());
        }
    }

    @Override
    public void delete(String resourceType, String physicalId, String region) {
        // deleteInstanceProfile still throws DeleteConflict when roles are attached, which must
        // propagate so the stack reports DELETE_FAILED; only the already-gone case is tolerated.
        CfnDeletes.safeDelete("IAM instance profile", physicalId,
                () -> iamService.deleteInstanceProfile(physicalId), "NoSuchEntity");
    }
}
