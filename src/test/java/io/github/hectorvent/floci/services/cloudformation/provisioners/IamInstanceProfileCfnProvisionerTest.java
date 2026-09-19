package io.github.hectorvent.floci.services.cloudformation.provisioners;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.hectorvent.floci.core.common.AwsException;
import io.github.hectorvent.floci.services.cloudformation.CloudFormationTemplateEngine;
import io.github.hectorvent.floci.services.cloudformation.model.StackResource;
import io.github.hectorvent.floci.services.iam.IamService;
import io.github.hectorvent.floci.services.iam.model.InstanceProfile;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * {@code AWS::IAM::InstanceProfile} in isolation: Ref is the name, Fn::GetAtt Arn is the arn, the
 * generated name, the synthesized-arn fallback on a create collision, and the delete tolerance.
 */
class IamInstanceProfileCfnProvisionerTest {

    private static final String TYPE = "AWS::IAM::InstanceProfile";

    private final IamService iam = mock(IamService.class);
    private final IamInstanceProfileCfnProvisioner provisioner = new IamInstanceProfileCfnProvisioner(iam);
    private final ObjectMapper mapper = new ObjectMapper();

    @Test
    void publishesNameAndArn() throws Exception {
        InstanceProfile profile = new InstanceProfile();
        profile.setArn("arn:aws:iam::000000000000:instance-profile/web");
        when(iam.createInstanceProfile("web", "/")).thenReturn(profile);

        StackResource r = resource();
        provisioner.provision(r, props("{\"InstanceProfileName\": \"web\"}"), ctx());

        assertEquals("web", r.getPhysicalId());
        assertEquals(Set.of("Arn"), r.getAttributes().keySet());
        assertEquals("arn:aws:iam::000000000000:instance-profile/web", r.getAttributes().get("Arn"));
    }

    @Test
    void absentNameIsGeneratedFromStackAndLogicalId() throws Exception {
        InstanceProfile profile = new InstanceProfile();
        profile.setArn("arn:aws:iam::000000000000:instance-profile/generated");
        when(iam.createInstanceProfile(anyString(), eq("/"))).thenReturn(profile);

        StackResource r = resource();
        provisioner.provision(r, props("{}"), ctx());

        assertTrue(r.getPhysicalId().matches("my-stack-Profile-[0-9a-f]{12}"), r.getPhysicalId());
    }

    @Test
    void aCreateCollisionFallsBackToASynthesizedArn() throws Exception {
        when(iam.createInstanceProfile("web", "/"))
                .thenThrow(new AwsException("EntityAlreadyExists", "exists", 409));

        StackResource r = resource();
        provisioner.provision(r, props("{\"InstanceProfileName\": \"web\"}"), ctx());

        assertEquals("web", r.getPhysicalId());
        assertEquals("arn:aws:iam::000000000000:instance-profile/web", r.getAttributes().get("Arn"));
    }

    @Test
    void deleteRemovesTheProfile() {
        provisioner.delete(TYPE, "web", "us-east-1");

        org.mockito.Mockito.verify(iam).deleteInstanceProfile("web");
    }

    @Test
    void deleteToleratesAProfileAlreadyGone() {
        doThrow(new AwsException("NoSuchEntity", "gone", 404))
                .when(iam).deleteInstanceProfile("web");

        assertDoesNotThrow(() -> provisioner.delete(TYPE, "web", "us-east-1"));
    }

    @Test
    void deletePropagatesADeleteConflict() {
        doThrow(new AwsException("DeleteConflict", "roles attached", 409))
                .when(iam).deleteInstanceProfile("web");

        AwsException failure = assertThrows(AwsException.class,
                () -> provisioner.delete(TYPE, "web", "us-east-1"));
        assertEquals("DeleteConflict", failure.getErrorCode());
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
        r.setLogicalId("Profile");
        r.setResourceType(TYPE);
        r.setAttributes(new HashMap<>());
        return r;
    }
}
