package io.github.hectorvent.floci.core.common;

import io.github.hectorvent.floci.testing.PartitionCleanup;
import io.github.hectorvent.floci.testing.PartitionMatrix;
import io.quarkus.test.junit.QuarkusTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.not;

/**
 * A SigV4 scope region that no partition publishes or admits by its region pattern is refused,
 * as moto and LocalStack refuse it by default; a label of a published shape that the vendored
 * data does not list yet is served, which is the AWS SDKs' own rule. The escape hatch serves any
 * label with its own namespace.
 */
@QuarkusTest
class PartitionUnknownRegionIntegrationTest {

    static final String UNKNOWN = "polygondwanaland-west-1";
    static final String UNPUBLISHED_BUT_SHAPED = "eu-south-9";

    @RegisterExtension
    final PartitionCleanup cleanup = new PartitionCleanup();

    @Test
    void aQueryRequestSignedForAnUnknownRegionIsRefusedWithTheSignatureError() {
        given()
            .header("Authorization", PartitionMatrix.sigV4Auth(UNKNOWN, "sqs"))
            .contentType("application/x-www-form-urlencoded")
            .formParam("Action", "ListQueues")
        .when().post("/").then().statusCode(400)
            .header("X-Amzn-Errortype", "InvalidSignatureException")
            .body("__type", equalTo("InvalidSignatureException"))
            .body("message", containsString(UNKNOWN));
    }

    @Test
    void anS3RequestSignedForAnUnknownRegionGetsS3sMalformedHeaderError() {
        given()
            .header("Authorization", PartitionMatrix.sigV4Auth(UNKNOWN, "s3"))
        .when().get("/").then().statusCode(400)
            .body(containsString("<Code>AuthorizationHeaderMalformed</Code>"))
            .body(containsString("the region &apos;" + UNKNOWN + "&apos; is wrong"));
    }

    @Test
    void aPatternAdmittedRegionTheDataDoesNotListIsServed() {
        String name = "shaped-" + Long.toString(System.nanoTime(), 36);
        cleanup.register(() -> deleteQueue(UNPUBLISHED_BUT_SHAPED, name));
        given()
            .header("Authorization", PartitionMatrix.sigV4Auth(UNPUBLISHED_BUT_SHAPED, "sqs"))
            .contentType("application/x-www-form-urlencoded")
            .formParam("Action", "CreateQueue")
            .formParam("QueueName", name)
        .when().post("/").then().statusCode(200)
            .body(containsString(name));
        given()
            .header("Authorization", PartitionMatrix.sigV4Auth(UNPUBLISHED_BUT_SHAPED, "s3"))
        .when().get("/").then().statusCode(200)
            .body(not(containsString("AuthorizationHeaderMalformed")));
    }

    static void deleteQueue(String region, String name) {
        // Spell the envelope out: AwsQueryResponse.envelope wraps the result as
        // <GetQueueUrlResponse><GetQueueUrlResult><QueueUrl>. XmlPath reads "**" as a parameter
        // reference rather than a deep scan, so it threw before the delete ever ran and
        // PartitionCleanup swallowed it, leaving the queue behind in the shared emulator.
        String url = given()
                .header("Authorization", PartitionMatrix.sigV4Auth(region, "sqs"))
                .contentType("application/x-www-form-urlencoded")
                .formParam("Action", "GetQueueUrl")
                .formParam("QueueName", name)
            .when().post("/").xmlPath()
                .getString("GetQueueUrlResponse.GetQueueUrlResult.QueueUrl");
        if (url == null || url.isBlank()) {
            throw new IllegalStateException("GetQueueUrl returned no QueueUrl for " + name
                    + " in " + region + "; the queue would leak into the shared emulator");
        }
        given()
            .header("Authorization", PartitionMatrix.sigV4Auth(region, "sqs"))
            .contentType("application/x-www-form-urlencoded")
            .formParam("Action", "DeleteQueue")
            .formParam("QueueUrl", url)
        .when().post("/");
    }
}
