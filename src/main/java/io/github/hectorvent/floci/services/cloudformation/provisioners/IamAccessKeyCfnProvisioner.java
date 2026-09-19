package io.github.hectorvent.floci.services.cloudformation.provisioners;

import com.fasterxml.jackson.databind.JsonNode;
import io.github.hectorvent.floci.services.cloudformation.model.StackResource;
import io.github.hectorvent.floci.services.iam.IamService;
import io.github.hectorvent.floci.services.iam.model.AccessKey;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import java.util.Set;

/**
 * CloudFormation provisioning for {@code AWS::IAM::AccessKey}. {@code Ref} returns the access key
 * id (the primary identifier), and {@code Fn::GetAtt} exposes the same id plus the one-time
 * {@code SecretAccessKey}.
 *
 * <p>No delete is overridden: removing an access key needs the owning user name, which the
 * id-only delete path does not carry, so the legacy switch left it a no-op. Storing the user name
 * and deleting the key is a follow-up.
 */
@ApplicationScoped
public class IamAccessKeyCfnProvisioner implements CfnResourceProvisioner {

    private static final String TYPE = "AWS::IAM::AccessKey";

    private final IamService iamService;

    @Inject
    public IamAccessKeyCfnProvisioner(IamService iamService) {
        this.iamService = iamService;
    }

    @Override
    public Set<String> resourceTypes() {
        return Set.of(TYPE);
    }

    @Override
    public void provision(StackResource r, JsonNode props, ProvisionContext ctx) {
        String userName = ctx.resolveOptional(props, "UserName");
        if (userName != null) {
            AccessKey key = iamService.createAccessKey(userName);
            r.setPhysicalId(key.getAccessKeyId());
            r.getAttributes().put("Id", key.getAccessKeyId());
            r.getAttributes().put("SecretAccessKey", key.getSecretAccessKey());
        }
    }
}
