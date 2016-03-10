# == Class: openstack_project::puppetdb
#
class openstack_project::puppetdb (
  $puppetboard = true,
) {

  # The puppetlabs postgres module does not manage the postgres user
  # and group for us. Create them here to ensure concat can create
  # dirs and files owned by this user and group.
  user { 'postgres':
    ensure  => present,
    gid     => 'postgres',
    system  => true,
    require => Group['postgres'],
  }

  group { 'postgres':
    ensure => present,
    system => true,
  }

  class { 'puppetdb::database::postgresql':
    require         => [User['postgres'],
      Class['openstack_project::template'],],
  }

  class { '::puppetdb::server':
    database_host      => 'localhost',
    ssl_listen_address => '0.0.0.0', # works for ipv6 too
    java_args          => { '-Xmx' => '512m', '-Xms' => '256m' },
    require            => [ User['postgres'],
      Class['puppetdb::database::postgresql'],],
  }

  if $puppetboard {
    class { 'openstack_project::puppetboard': }
  }

}
