package org.example.marketplacebackend;

import java.util.List;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.jdbc.Sql;
import org.springframework.test.context.jdbc.Sql.ExecutionPhase;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

@Testcontainers
@SpringBootTest(webEnvironment = WebEnvironment.RANDOM_PORT)
public class AuthTests {

  @LocalServerPort
  private int port;

  @Container
  private static final PostgreSQLContainer<?> DB = new PostgreSQLContainer<>(
      "postgres:16-alpine"
  )
      .withInitScript("schema.sql");

  @DynamicPropertySource
  private static void configureProperties(DynamicPropertyRegistry registry) {
    registry.add("spring.datasource.url", DB::getJdbcUrl);
    registry.add("spring.datasource.username", DB::getUsername);
    registry.add("spring.datasource.password", DB::getPassword);
  }

  private final TestRestTemplate restTemplate = new TestRestTemplate();

  @Sql(executionPhase = ExecutionPhase.BEFORE_TEST_METHOD, statements = "INSERT INTO account (first_name, last_name, date_of_birth, email, password, username) VALUES ('John','Doe','2024-04-20','john@example.org','$2a$10$Fl73LSgJaTUaSfKvbjhOLO1s4eIXnWtJCq6g4gNIkU9BNtqETE4bG','johndoe')")
  @Sql(executionPhase = ExecutionPhase.AFTER_TEST_METHOD, statements = "DELETE FROM account WHERE username = 'johndoe'")
  @Test
  public void testAuth() {
    // fetch XSRF token cookie by pinging any endpoint that doesn't require XSRF token
    ResponseEntity<String> xsrfResponse = restTemplate.exchange(
        "http://localhost:" + port + "/v1/accounts/me", HttpMethod.GET, null, String.class);

    List<String> cookies = xsrfResponse.getHeaders().get(HttpHeaders.SET_COOKIE);
    Assertions.assertNotNull(cookies, "No cookies were returned");

    String xsrfCookie = null;
    for (String cookie : cookies) {
      if (cookie.startsWith("XSRF-TOKEN=")) {
        xsrfCookie = cookie;
      }
    }
    Assertions.assertNotNull(xsrfCookie, "No XSRF token cookie was returned");

    String xsrfToken = xsrfCookie.split("=")[1].split(";")[0];
    Assertions.assertNotNull(xsrfToken, "No XSRF token was returned");

    HttpHeaders loginHeaders = new HttpHeaders();
    loginHeaders.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
    loginHeaders.add(HttpHeaders.COOKIE, xsrfCookie);
    loginHeaders.add("X-XSRF-TOKEN", xsrfToken);
    HttpEntity<String> loginRequest = new HttpEntity<>("username=johndoe&password=bruh",
        loginHeaders);

    ResponseEntity<String> loginResponse = restTemplate.postForEntity(
        "http://localhost:" + port + "/v1/accounts/login", loginRequest,
        String.class);
    Assertions.assertEquals(HttpStatus.OK, loginResponse.getStatusCode(), "Authentication failed");

    cookies = loginResponse.getHeaders().get(HttpHeaders.SET_COOKIE);
    Assertions.assertNotNull(cookies, "No cookies were returned");

    // try to find session cookie
    String sessionCookie = null;
    for (String cookie : cookies) {
      if (cookie.startsWith("JSESSIONID=")) {
        sessionCookie = cookie;
        break;
      }
    }
    Assertions.assertNotNull(sessionCookie, "No session cookie was returned");

    // set up authenticated request
    HttpHeaders authenticatedRequestHeaders = new HttpHeaders();
    authenticatedRequestHeaders.add(HttpHeaders.COOKIE, xsrfCookie);
    authenticatedRequestHeaders.add("X-XSRF-TOKEN", xsrfToken);
    authenticatedRequestHeaders.add(HttpHeaders.COOKIE, sessionCookie);
    HttpEntity<String> authenticatedRequest = new HttpEntity<>(authenticatedRequestHeaders);

    // perform authenticated request to test endpoint
    ResponseEntity<String> authenticatedResponse = restTemplate.exchange(
        "http://localhost:" + port + "/v1/tests/username", HttpMethod.GET, authenticatedRequest,
        String.class);
    Assertions.assertEquals(HttpStatus.OK, authenticatedResponse.getStatusCode(), "Authentication failed");
    Assertions.assertEquals("{\"username\": \"johndoe\"}", authenticatedResponse.getBody(), "Wrong username returned");

    // perform logout request
    ResponseEntity<String> logoutResponse = restTemplate.exchange(
        "http://localhost:" + port + "/v1/accounts/logout", HttpMethod.POST, authenticatedRequest,
        String.class);
    Assertions.assertEquals(HttpStatus.OK, logoutResponse.getStatusCode(), "Logout failed");
  }

}
