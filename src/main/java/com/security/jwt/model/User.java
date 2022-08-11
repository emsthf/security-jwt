package com.security.jwt.model;

import lombok.Data;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

@Data
@Entity
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private long id;
    private String username;
    private String password;
    private String roles;  // USER, ADMIN

    // Enum을 사용하지 않고 ,로 구분해서 ROLE을 입력하고 그것을 파싱해서 사용
    public List<String> getRoleList() {
        if (this.roles.length() > 0) {
            return Arrays.asList(this.roles.split(","));  // ,로 유저 역할 구분
        }
        return new ArrayList<>();
    }
}
