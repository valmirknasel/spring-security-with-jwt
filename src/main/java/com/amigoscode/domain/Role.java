package com.amigoscode.domain;

import lombok.*;

import javax.persistence.*;

@Entity (name = "tb_role")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor

public class Role {

    @Id @GeneratedValue(strategy = GenerationType.SEQUENCE)
    @Column(name = "role_id")
    private Long id;
    private String name;
}
