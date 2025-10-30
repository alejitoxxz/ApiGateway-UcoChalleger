package co.edu.uco.apigatewayservice.test;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

@RestController
public class TestController {

  @GetMapping("/api/public/ping")
  public Mono<String> publicPing() {
    return Mono.just("public-ok");
  }

  @GetMapping("/api/user/hello")
  public Mono<String> userHello() {
    return Mono.just("user-ok");
  }

  @GetMapping("/api/admin/hello")
  public Mono<String> adminHello() {
    return Mono.just("admin-ok");
  }
}

