package com.chandler.security.dto;

import java.util.List;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter@Setter
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class JwtResponse {
	private Long id;
//	private String username;
	private String email;

	private String tokenType;
	private String jwt;
	private Integer tokenExpirationMs;

	private List<String> roles;// = new HashSet<>();
}
