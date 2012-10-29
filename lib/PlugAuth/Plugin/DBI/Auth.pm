package PlugAuth::Plugin::DBI::Auth;

use strict;
use warnings;
use DBI;
use Log::Log4perl qw/:easy/;
use Role::Tiny::With;
use Crypt::PasswdMD5 qw( unix_md5_crypt apache_md5_crypt );

with 'PlugAuth::Role::Plugin';
with 'PlugAuth::Role::Auth';

# ABSTRACT: DBI Authentication back end for PlugAuth
# VERSION

=head1 SYNOPSIS

PlugAuth.conf:

 ---
 plugins:
   - PlugAuth::Plugin::DBI::Auth:
       db:
         dsn: 'dbi:SQLite:dbname=/path/to/dbfile.sqlite'
         user: ''
         pass: ''
       sql:
         init: 'CREATE TABLE IF NOT EXISTS users (username VARCHAR UNIQUE, password VARCHAR)'
         check_credentials: 'SELECT password FROM users WHERE username = ?'
         all_users: 'SELECT username FROM users'

=head1 DESCRIPTION

This plugin provides an authentication mechanism for PlugAuth using any
database supported by DBI as a backend.  It is configured as above, with
two hashes, db and sql.

=head2 db

The db hash provides the required parameters for the plugin needed to
connect to the database.

=head3 dsn

The DNS passed into DBI.  See the documentation for your database driver
for the exact format (L<DBD::SQLite>, L<DBD::Pg>, L<DBD::mysql> ... ).

=head3 user

The database user.

=head3 pass

The database password.

=head2 sql

The sql hash provides SQL statements which are executed for each 
operation.  They are all optional.  The examples shown here assumes
a simple table with usernames and passwords:

 CREATE TABLE IF NOT EXISTS users (
   username VARCHAR UNIQUE,
   password VARCHAR
 );

=head3 init

Arbitrary SQL executed when the plugin is started.

=cut

sub init
{
  my($self) = @_;
  my %db  = $self->plugin_config->db;
  my %sql = $self->plugin_config->sql;

  $self->{dbh} = DBI->connect($db{dsn}, $db{user}, $db{pass}, 
    { RaiseError => 1, AutoCommit => 1 }
  );
  
  $self->{dbh}->do($sql{init})
    if defined $sql{init};
  
  foreach my $name (qw( check_credentials all_users ))
  {
    $self->{$name} = $self->{dbh}->prepare($sql{$name})
      if defined $sql{$name};
  }
}

=head3 check_credentials

The SQL statement used to fetch the encrypted password of a
user.  The username is the first bind value when executed.
Example:

 SELECT password FROM users WHERE username = ?

=cut

sub check_credentials
{
  my($self, $user, $pass) = @_;

  if(defined $self->{check_credentials})
  {
    $self->{check_credentials}->execute($user);
    my($encrypted) = $self->{check_credentials}->fetchrow_array;
    $self->{check_credentials}->finish;
    if($encrypted)
    {
      return 1 if crypt($pass, $encrypted) eq $encrypted;
      
        $DB::single = 1;
      if($encrypted =~ /^\$(\w+)\$/)
      {
        return 1 if $1 eq 'apr1' && apache_md5_crypt( $pass, $encrypted ) eq $encrypted;
        return 1 if $1 eq '1'    && unix_md5_crypt  ( $pass, $encrypted ) eq $encrypted;
      }
    }
  }

  $self->deligate_check_credentials($user, $pass);
}

=head3 all_users

The SQL statement used to fetch the list of users.  Example:

 SELECT username FROM users

=cut

sub all_users 
{
  my($self) = @_;
  
  my @list;
  
  if(defined $self->{all_users})
  {
    $self->{all_users}->execute;
    while(my $row = $self->{all_users}->fetchrow_arrayref)
    {
      push @list, $row->[0];
    }
  }
  
  @list;
}

# sub create_user {
#   my($self, $user, $pass) = @_;
# }
#
# sub change_password {
#   my($self, $user, $pass) = @_;
# }
#
# sub delete_user {
#   my($self, $user) = @_;
# } 

sub dbh { shift->{dbh} }

1;
