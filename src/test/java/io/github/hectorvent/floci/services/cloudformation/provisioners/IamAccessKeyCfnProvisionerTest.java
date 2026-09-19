package io.github.hectorvent.floci.services.cloudformation.provisioners;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.hectorvent.floci.services.cloudformation.CloudFormationTemplateEngine;
import io.github.hectorvent.floci.services.cloudformation.model.StackResource;
import io.github.hectorvent.floci.services.iam.IamService;
import io.github.hectorvent.floci.services.iam.model.AccessKey;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * {@code AWS::IAM::AccessKey} in isolation: the id backs Ref and Fn::GetAtt, the secret is
 * published, and an absent UserName creates nothing.
 */
class IamAccessKeyCfnProvisionerTest {

    private static final String TYPE = "AWS::IAM::AccessKey";

    private final IamService iam = mock(IamService.class);
    private final IamAccessKeyCfnProvisioner provisioner = new IamAccessKeyCfnProvisioner(iam);
    private final ObjectMapper mapper = new ObjectMapper();

    @Test
    void publishesTheIdAndSecret() throws Exception {
        AccessKey key = new AccessKey();
        key.setAccessKeyId("AKIA123");
        key.setSecretAccessKey("secret-xyz");
        when(iam.createAccessKey("alice")).thenReturn(key);

        StackResource r = resource();
        provisioner.provision(r, props("{\"UserName\": \"alice\"}"), ctx());

        assertEquals("AKIA123", r.getPhysicalId());
        assertEquals(Set.of("Id", "SecretAccessKey"), r.getAttributes().keySet());
        assertEquals("AKIA123", r.getAttributes().get("Id"));
        assertEquals("secret-xyz", r.getAttributes().get("SecretAccessKey"));
        verify(iam).createAccessKey("alice");
    }

    @Test
    void absentUserNameCreatesNothing() throws Exception {
        StackResource r = resource();
        provisioner.provision(r, props("{}"), ctx());

        verifyNoInteractions(iam);
    }

    private ProvisionContext ctx() {
        CloudFormationTemplateEngine engine = mock(CloudFormationTemplateEngine.class);
        when(engine.resolve(any())).thenAnswer(inv -> {
            JsonNode node = inv.getArgument(0);
            return node == null ? null : node.asText();
        });
        return new ProvisionContext(engine, "us-east-1", "000000000000", "my-stack");
    }

    private JsonNode props(String json) throws Exception {
        return mapper.readTree(json);
    }

    private static StackResource resource() {
        StackResource r = new StackResource();
        r.setLogicalId("Key");
        r.setResourceType(TYPE);
        r.setAttributes(new HashMap<>());
        return r;
    }
}
