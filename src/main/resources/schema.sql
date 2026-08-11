begin;

-- drop all the table. (Only on development)
drop table if exists active_tokens cascade;
drop table if exists registered_device cascade;
drop table if exists user_role cascade;
drop table if exists users cascade;

-- users table
create table users
(
    id bigserial primary key ,
    username varchar(255) not null ,
    email varchar(100) not null unique ,
    password_hash varchar(255) not null ,
    is_enabled boolean not null default true,
    created_at timestamp with time zone default current_timestamp
);
create index idx_user_username on users(username);
create index idx_user_email on users(email);

-- user_roles table
create table user_role
(
    user_id bigint not null ,
    role varchar(20) not null default 'employee' check ( role in ('administrator', 'technician', 'employee' ) ),

    primary key (user_id, role),
    constraint fk_user_role foreign key (user_id) references users(id) on delete cascade
);

-- registered device table
create table registered_device
(
    id bigserial primary key ,
    user_id bigint not null ,
    mac_address varchar(50) not null ,
    device_name varchar(100),
    is_approved boolean not null default false,
    registered_at timestamp with time zone default current_timestamp,

    constraint unique_user_mac unique (user_id, mac_address),
    constraint fk_registered_device_user_id foreign key (user_id) references users(id) on delete cascade
);
create index idx_registered_device_mac_address on registered_device(user_id, mac_address);

-- tokens table
create table active_tokens
(
    id bigserial primary key ,
    user_id bigint not null ,
    device_id bigint not null ,

    refresh_token varchar(500) not null unique ,
    access_token_id varchar(255) not null ,

    is_revoked boolean not null default false,
    expires_at timestamp with time zone not null ,
    created_at timestamp with time zone default current_timestamp,

    constraint fk_active_tokens_user_id foreign key (user_id) references users(id) on delete cascade ,
    constraint fk_active_tokens_device_id foreign key (device_id) references registered_device(id) on delete cascade
);
create index idx_active_token_refresh_token on active_tokens(refresh_token);

end;
