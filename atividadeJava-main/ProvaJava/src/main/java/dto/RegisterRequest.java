package dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class RegisterRequest {

    @NotBlank(message = "nome é obrigatório")
    private String name;

    @NotBlank(message = "e-mail é obrigatório")
    @Email(message = "e-mail inválido")
    private String email;

    @NotBlank(message = "senha é obrigatória")
    private String password;

    @NotBlank(message = "papel do usuário é obrigatório")
    private String role;
}
