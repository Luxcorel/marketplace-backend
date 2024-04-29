package org.example.marketplacebackend;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.List;
import java.util.UUID;
import org.example.marketplacebackend.model.ProductCategory;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.jdbc.Sql;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;

@SpringBootTest
@AutoConfigureMockMvc
public class TestProductCategoryEndpoints {

  @Autowired
  private MockMvc mockMvc;

  @Test
  @Sql(statements = "INSERT INTO product_category (id, name) VALUES ('fdeb0281-1481-45f9-b005-e02bba579085', 'test category')")
  public void getCategoryList() throws Exception {
    ProductCategory productCategory = new ProductCategory();
    productCategory.setName("test category");
    productCategory.setId(UUID.fromString("fdeb0281-1481-45f9-b005-e02bba579085"));
    List<ProductCategory> categories = List.of(productCategory);

    ObjectMapper objectMapper = new ObjectMapper();

    ResultActions getCategory = mockMvc.perform(get("/v1/categories"));
    getCategory
        .andExpect(status().isOk())
        .andExpect(content().contentType(MediaType.APPLICATION_JSON));
    //.andExpect(content().json(objectMapper.writeValueAsString(categories)))
  }

  @AfterEach
  @Test
  @Sql(statements = "DELETE FROM product_category WHERE id = 'fdeb0281-1481-45f9-b005-e02bba579085'")
  public void cleanup() {
  }

}
