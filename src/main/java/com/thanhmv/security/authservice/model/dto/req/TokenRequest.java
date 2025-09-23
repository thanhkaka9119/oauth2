package com.thanhmv.security.authservice.model.dto.req;
import jakarta.validation.constraints.NotBlank;
import lombok.Getter; import lombok.Setter;

@Getter
@Setter
public class TokenRequest {
    @NotBlank
    private String grant_type;

    // password grant
    private String username;
    private String password;
    private String scope; // mã bất kỳ, sẽ echo lại

    // refresh_token grant
    private String refresh_token;
}
