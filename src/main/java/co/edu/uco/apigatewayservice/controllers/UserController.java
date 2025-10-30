package co.edu.uco.apigatewayservice.controllers;

import co.edu.uco.apigatewayservice.dto.ApiMessageResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping(path = "/api/user", produces = MediaType.APPLICATION_JSON_VALUE)
public class UserController {

    @GetMapping("/profile")
    public ResponseEntity<ApiMessageResponse> profile() {
        ApiMessageResponse response = new ApiMessageResponse(
                "Perfil de usuario básico disponible para cuentas autenticadas.",
                "usuario",
                "profile"
        );
        return ResponseEntity.status(HttpStatus.OK).body(response);
    }
}
