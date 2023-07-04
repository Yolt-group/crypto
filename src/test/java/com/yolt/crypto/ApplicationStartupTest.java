package com.yolt.crypto;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.HttpStatus;

@IntegrationTest
public class ApplicationStartupTest {

    @Value("${local.management.port}")
    private int managementPort;

    @Autowired
    private TestRestTemplate restTemplate;

    @Test
    public void applicationStartsUp() {
        HttpStatus statusCode = restTemplate.getForEntity("http://localhost:" + managementPort + "/actuator/info", String.class).getStatusCode();
        Assertions.assertEquals(HttpStatus.OK, statusCode);
    }
}
