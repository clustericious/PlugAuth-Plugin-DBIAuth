# PlugAuth::Plugin::DBIAuth [![Build Status](https://secure.travis-ci.org/clustericious/PlugAuth-Plugin-DBIAuth.png)](http://travis-ci.org/clustericious/PlugAuth-Plugin-DBIAuth)

DBI Authentication back end for PlugAuth

# SYNOPSIS

In your PlugAuth.conf file:

    ---
    plugins:
      - PlugAuth::Plugin::DBIAuth:
          db:
            dsn: 'dbi:SQLite:dbname=/path/to/dbfile.sqlite'
            user: ''
            pass: ''
          sql:
            init: 'CREATE TABLE IF NOT EXISTS users (username VARCHAR UNIQUE, password VARCHAR)'
            check_credentials: 'SELECT password FROM users WHERE username = ?'
            all_users: 'SELECT username FROM users'

# DESCRIPTION

This plugin provides an authentication mechanism for PlugAuth using any
database supported by DBI as a backend.  It is configured as above, with
two hashes, db and sql.

## encryption

Specifies the encryption method to use.  This is only used when creating
new users, or changing their passwords.  Existing passwords will remain
in their existing formats and will be decrypted automatically in the 
correct format.

If provided, must be one of:

- unix

    Traditional UNIX crypt()

- unix\_md5

    UNIX MD5

- apache\_md5 \[ default \]

    Apache MD5

## db

The db hash provides the required parameters for the plugin needed to
connect to the database.

### dsn

The DNS passed into DBI.  See the documentation for your database driver
for the exact format ([DBD::SQLite](https://metacpan.org/pod/DBD::SQLite), [DBD::Pg](https://metacpan.org/pod/DBD::Pg), [DBD::mysql](https://metacpan.org/pod/DBD::mysql) ... ).

### user

The database user.

### pass

The database password.

## sql

The sql hash provides SQL statements which are executed for each 
operation.  They are all optional.  The examples shown here assumes
a simple table with usernames and passwords:

    CREATE TABLE IF NOT EXISTS users (
      username VARCHAR UNIQUE,
      password VARCHAR
    );

### init

Arbitrary SQL executed when the plugin is started.

### check\_credentials

The SQL statement used to fetch the encrypted password of a
user.  The username is the first bind value when executed.
Example:

    SELECT password FROM users WHERE username = ?

### all\_users

The SQL statement used to fetch the list of users.  Example:

    SELECT username FROM users

### create\_user

The SQL statement used to create a new user.  Example:

    INSERT INTO users (username, password) VALUES (?,?)

### change\_password

The SQL statement used to change the password of an existing user.  Example:

    UPDATE users SET password = ? WHERE username = ?

### delete\_user

The SQL statement used to delete an existing user.  Example:

    DELETE FROM users WHERE username = ?

### dbh

Returns the dbh handle used to query the database.

### created\_encrypted\_password

Given a new plain text password, return the encrypted version.

# SEE ALSO

[DBI](https://metacpan.org/pod/DBI),
[PlugAuth](https://metacpan.org/pod/PlugAuth)

# AUTHOR

Graham Ollis &lt;gollis@sesda3.com>

# COPYRIGHT AND LICENSE

This software is copyright (c) 2015 by Graham Ollis.

This is free software; you can redistribute it and/or modify it under
the same terms as the Perl 5 programming language system itself.
