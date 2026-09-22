package io.github.hectorvent.floci.services.iam;

import io.github.hectorvent.floci.testing.IamEnforcementProfile;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.TestProfile;
import org.junit.jupiter.api.Test;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.containsString;

/**
 * With enforcement on, an access key that exists nowhere must be rejected rather than waved
 * through. Before this was closed, any string in the credential scope authorized the request.
 */
@QuarkusTest
@TestProfile(IamEnforcementProfile.class)
class UnknownAccessKeyEnforcementIntegrationTest {

    private static final String UNKNOWN_KEY_AUTH =
            "AWS4-HMAC-SHA256 Credential=AKIADOESNOTEXIST0000/20260101/us-east-1/%s/aws4_request, "
                    + "SignedHeaders=host, Signature=not-a-real-signature";

    @Test
    void jsonServiceRejectsAnUnknownAccessKey() {
        given()
                .header("Authorization", UNKNOWN_KEY_AUTH.formatted("lambda"))
                .contentType("application/json")
        .when()
                .get("/2015-03-31/functions")
        .then()
                .statusCode(403)
                .body(containsString("UnrecognizedClientException"));
    }

    @Test
    void s3RejectsAnUnknownAccessKeyWithTheS3ErrorCode() {
        given()
                .header("Authorization", UNKNOWN_KEY_AUTH.formatted("s3"))
        .when()
                .get("/")
        .then()
                .statusCode(403)
                .body(containsString("InvalidAccessKeyId"));
    }

    @Test
    void theRootStandInKeyStillWorks() {
        given()
                .header("Authorization", "AWS4-HMAC-SHA256 Credential=test/20260101/us-east-1/s3/aws4_request, "
                        + "SignedHeaders=host, Signature=whatever")
        .when()
                .get("/")
        .then()
                .statusCode(200);
    }
}
