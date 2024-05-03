package org.example.marketplacebackend;

import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.json.JsonMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import java.util.UUID;
import org.example.marketplacebackend.DTO.outgoing.InboxGetAllResponseDTO;
import org.example.marketplacebackend.model.Account;
import org.example.marketplacebackend.model.Inbox;
import org.example.marketplacebackend.repository.InboxRepository;
import org.example.marketplacebackend.service.UserService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.jdbc.Sql;
import org.springframework.test.context.jdbc.Sql.ExecutionPhase;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

@SpringBootTest
@AutoConfigureMockMvc
@Testcontainers
public class TestInboxEndpoints {
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

  @Autowired
  private MockMvc mockMvc;

  @Autowired
  private UserService userService;

  @Autowired
  private InboxRepository inboxRepository;

  @Test
  @WithMockUser(username="usernameInbox", roles = "USER")
  @Sql(executionPhase = ExecutionPhase.BEFORE_TEST_METHOD, statements = {
      "INSERT INTO account (id, username, first_name, last_name, date_of_birth, email, password) VALUES ('c70a38f9-b770-4f2d-8c64-32cc583aac95', 'usernameInbox', 'firstnameInbox', 'lastnameInbox', '1990-01-01', 'inbox@example.com', '$2a$10$YltQfNKzHoF4Db1oUHtP/eODkthW90lPaouBw6Q1k/7keLcctilpm')",
      "INSERT INTO inbox (id, receiver_id, message, is_read, sent_at) VALUES ('d24b4a00-22f1-4ef2-a081-2c9b95f76156','c70a38f9-b770-4f2d-8c64-32cc583aac95', 'Test message', false, now())"
  })
  //v1/inbox/{id}
  public void getMessageById() throws Exception {
    Account account = userService.getAccountOrException(UUID.fromString("c70a38f9-b770-4f2d-8c64-32cc583aac95"));
    Inbox inbox = inboxRepository.findByIdAndReceiver(UUID.fromString("d24b4a00-22f1-4ef2-a081-2c9b95f76156"), account).orElseThrow();

    InboxGetAllResponseDTO expectedResponseBody = new InboxGetAllResponseDTO(
        inbox.getId(),
        inbox.getMessage(),
        inbox.getIsRead(),
        inbox.getSentAt()
    );

    ObjectMapper objectMapper = JsonMapper.builder()
        .addModule(new JavaTimeModule())
        .build();

    ResultActions getMessage = mockMvc.perform(MockMvcRequestBuilders.get("/v1/inbox/d24b4a00-22f1-4ef2-a081-2c9b95f76156")
        .principal(()-> "usernameInbox"));
    getMessage
        .andExpect(status().isOk())
        .andExpect(content().contentType(MediaType.APPLICATION_JSON))
        .andExpect(content().json(objectMapper.writeValueAsString(expectedResponseBody)));
  }

  @AfterEach
  @Sql(statements = {
      "DELETE FROM inbox WHERE id = 'd24b4a00-22f1-4ef2-a081-2c9b95f76156'",
      "DELETE FROM account WHERE id = 'c70a38f9-b770-4f2d-8c64-32cc583aac95'"
  })
  public void afterTest() {
  }

}
