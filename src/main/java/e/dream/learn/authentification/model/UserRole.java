package e.dream.learn.authentification.model;

import org.springframework.data.relational.core.mapping.Table;

@Table("user_role")
public record UserRole(String role) {
}
