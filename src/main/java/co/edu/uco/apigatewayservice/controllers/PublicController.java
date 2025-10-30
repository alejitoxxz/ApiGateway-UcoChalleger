package co.edu.uco.apigatewayservice.controllers;

import co.edu.uco.apigatewayservice.dto.ApiMessageResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping(path = "/api/public", produces = MediaType.APPLICATION_JSON_VALUE)
public class PublicController {

    @GetMapping
    public ResponseEntity<ApiMessageResponse> publicEndpoint() {
        ApiMessageResponse response = new ApiMessageResponse(
                "Acceso público disponible sin autenticación.",
                "anonymous",
                "public"
        );
        return ResponseEntity.status(HttpStatus.OK).body(response);
    }
}
