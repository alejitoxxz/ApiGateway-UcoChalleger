package co.edu.uco.apigatwayservice.controllers;

import co.edu.uco.apigatwayservice.dto.ApiMessageResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping(path = "/api/admin", produces = MediaType.APPLICATION_JSON_VALUE)
public class AdminController {

    @GetMapping("/dashboard")
    public ResponseEntity<ApiMessageResponse> dashboard() {
        ApiMessageResponse response = new ApiMessageResponse(
                "Panel administrativo disponible.",
                "administrador",
                "dashboard"
        );
        return ResponseEntity.status(HttpStatus.OK).body(response);
    }
}
